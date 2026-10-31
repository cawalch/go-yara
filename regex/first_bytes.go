package regex

import (
	"math"
	"math/bits"
)

const maxUsefulByteSetSize = 96

// Keep fixed-sequence specialization bounded. Larger exact regexes continue
// through the regular VM and atom prefilters instead of duplicating large
// byte-set tables in every compiled rule.
const maxFixedByteSetSequenceLength = 256

// ByteSet is a compact set of possible byte values.
type ByteSet struct {
	words [4]uint64
}

// ByteSetAtom describes a restrictive byte set that every regex match must
// consume. Offsets are measured in input characters before that byte.
type ByteSetAtom struct {
	Set       ByteSet
	MinOffset int
	MaxOffset int
}

// NewByteSet constructs a byte set containing values. Duplicate values are
// ignored.
func NewByteSet(values []byte) ByteSet {
	var set ByteSet
	for _, value := range values {
		set.add(value)
	}
	return set
}

// Values returns the members of the set in ascending order.
func (set ByteSet) Values() []byte {
	values := make([]byte, 0, set.Count())
	for value := range 256 {
		if set.Contains(byte(value)) {
			values = append(values, byte(value))
		}
	}
	return values
}

// Contains reports whether value belongs to the set.
func (set ByteSet) Contains(value byte) bool {
	return set.words[value>>6]&(uint64(1)<<uint(value&63)) != 0
}

// Count returns the number of byte values in the set.
func (set ByteSet) Count() int {
	return bits.OnesCount64(set.words[0]) +
		bits.OnesCount64(set.words[1]) +
		bits.OnesCount64(set.words[2]) +
		bits.OnesCount64(set.words[3])
}

// ContiguousRange reports whether the set is one non-empty inclusive byte
// range and returns its bounds.
func (set ByteSet) ContiguousRange() (byte, byte, bool) {
	count := set.Count()
	if count == 0 {
		return 0, 0, false
	}
	lower := 0
	for lower < 256 && !set.Contains(byte(lower)) {
		lower++
	}
	upper := 255
	for upper >= 0 && !set.Contains(byte(upper)) {
		upper--
	}
	if lower < 0 || lower > 255 || upper < 0 || upper > 255 {
		return 0, 0, false
	}
	if upper-lower+1 != count {
		return 0, 0, false
	}
	return byte(lower), byte(upper), true
}

// ASCIIFolded returns a set expanded so either ASCII case is accepted whenever
// one case was already possible.
func (set ByteSet) ASCIIFolded() ByteSet {
	for lower := byte('a'); lower <= 'z'; lower++ {
		upper := lower - ('a' - 'A')
		if set.Contains(lower) || set.Contains(upper) {
			set.add(lower)
			set.add(upper)
		}
	}
	return set
}

// FixedByteSets returns an exact byte-set sequence when ast describes a fixed-
// width Cartesian product of consuming bytes. Regexes with alternatives,
// variable repetition, or zero-width assertions are deliberately rejected:
// those constructs need the full VM to preserve matching semantics.
func FixedByteSets(ast *AST, flags Flags) ([]ByteSet, bool) {
	if ast == nil || ast.Root == nil {
		return nil, false
	}
	sets, ok := fixedByteSets(ast.Root, flags, maxFixedByteSetSequenceLength)
	if !ok || len(sets) == 0 {
		return nil, false
	}
	return sets, true
}

func fixedByteSets(node *Node, flags Flags, remaining int) ([]ByteSet, bool) {
	if node == nil || remaining < 0 {
		return nil, false
	}

	switch node.Kind {
	case NodeGroup:
		return fixedByteSets(firstChild(node), flags, remaining)
	case NodeEmpty:
		return []ByteSet{}, true
	case NodeConcat:
		sets := make([]ByteSet, 0, min(len(node.Children), remaining))
		for _, child := range node.Children {
			childSets, ok := fixedByteSets(child, flags, remaining-len(sets))
			if !ok || len(childSets) > remaining-len(sets) {
				return nil, false
			}
			sets = append(sets, childSets...)
		}
		return sets, true
	case NodeRange:
		if node.Start != node.End || len(node.Children) != 1 {
			return nil, false
		}
		childSets, ok := fixedByteSets(node.Children[0], flags, remaining)
		if !ok {
			return nil, false
		}
		count := int(node.Start)
		if len(childSets) != 0 && count > remaining/len(childSets) {
			return nil, false
		}
		sets := make([]ByteSet, 0, len(childSets)*count)
		for range count {
			sets = append(sets, childSets...)
		}
		return sets, true
	default:
		set, ok := fixedConsumingByteSet(node, flags)
		if !ok || remaining == 0 {
			return nil, false
		}
		return []ByteSet{set}, true
	}
}

func fixedConsumingByteSet(node *Node, flags Flags) (ByteSet, bool) {
	noCase := flags&FlagsNoCase != 0
	switch node.Kind {
	case NodeGroup:
		return fixedConsumingByteSet(firstChild(node), flags)
	case NodeLiteral:
		set := byteSetOf(node.Value)
		if noCase {
			set = set.ASCIIFolded()
		}
		return set, true
	case NodeNotLiteral:
		excluded := byteSetOf(node.Value)
		if noCase {
			excluded = excluded.ASCIIFolded()
		}
		return complementByteSet(excluded), true
	case NodeMaskedLiteral:
		return maskedByteSet(node.Value, node.Mask, false), true
	case NodeMaskedNotLiteral:
		return maskedByteSet(node.Value, node.Mask, true), true
	case NodeClass:
		if node.Class == nil {
			return ByteSet{}, false
		}
		set := positiveClassByteSet(node.Class)
		if noCase {
			set = set.ASCIIFolded()
		}
		if node.Class.Negated {
			set = complementByteSet(set)
		}
		return set, true
	case NodeWordChar:
		return predicateByteSet(isWord), true
	case NodeNonWordChar:
		return predicateByteSet(notWord), true
	case NodeSpace:
		return predicateByteSet(isSpace), true
	case NodeNonSpace:
		return predicateByteSet(notSpace), true
	case NodeDigit:
		return predicateByteSet(isDigit), true
	case NodeNonDigit:
		return predicateByteSet(notDigit), true
	case NodeAny:
		set := fullByteSet()
		if flags&FlagsDotAll == 0 {
			set.remove('\n')
		}
		return set, true
	default:
		return ByteSet{}, false
	}
}

// MandatoryByteSetAtoms returns restrictive byte sets that must be consumed by
// every match accepted by ast.
func MandatoryByteSetAtoms(ast *AST) []ByteSetAtom {
	if ast == nil || ast.Root == nil {
		return nil
	}
	return cloneByteSetAtoms(analyzeAtoms(ast.Root).byteAtoms)
}

func classByteSet(class *Class) ByteSet {
	if class == nil {
		return fullByteSet()
	}
	set := positiveClassByteSet(class)
	if class.Negated {
		return complementByteSet(set)
	}
	return set
}

func positiveClassByteSet(class *Class) ByteSet {
	var set ByteSet
	for value := 0; value < 256; value++ {
		member := class.Bitmap[value/8]&(byte(1)<<uint(value%8)) != 0
		if member {
			set.add(byte(value))
		}
	}
	return set
}

func complementByteSet(set ByteSet) ByteSet {
	for index := range set.words {
		set.words[index] = ^set.words[index]
	}
	return set
}

func maskedByteSet(value, mask byte, negated bool) ByteSet {
	var set ByteSet
	for candidate := 0; candidate < 256; candidate++ {
		matches := byte(candidate)&mask == value&mask
		if matches != negated {
			set.add(byte(candidate))
		}
	}
	return set
}

func predicateByteSet(predicate func(byte) bool) ByteSet {
	var set ByteSet
	for value := 0; value < 256; value++ {
		if predicate(byte(value)) {
			set.add(byte(value))
		}
	}
	return set
}

func byteSetOf(value byte) ByteSet {
	var set ByteSet
	set.add(value)
	return set
}

func fullByteSet() ByteSet {
	return ByteSet{words: [4]uint64{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)}}
}

func usefulByteSetAtom(set ByteSet) []ByteSetAtom {
	count := set.Count()
	if count == 0 || count > maxUsefulByteSetSize {
		return nil
	}
	return []ByteSetAtom{{Set: set, MaxOffset: 0}}
}

func (set ByteSet) singletonValue() (byte, bool) {
	lower, upper, ok := set.ContiguousRange()
	return lower, ok && lower == upper
}

func (set *ByteSet) add(value byte) {
	set.words[value>>6] |= uint64(1) << uint(value&63)
}

func (set *ByteSet) remove(value byte) {
	set.words[value>>6] &^= uint64(1) << uint(value&63)
}

func (set *ByteSet) union(other ByteSet) {
	for i := range set.words {
		set.words[i] |= other.words[i]
	}
}

// FirstByteSet returns the set of all bytes that can begin a non-empty match of ast.
// If the regex is nullable (can match the empty string), or if all 256 bytes can match,
// ok returns false because first-byte pruning is not restrictive.
func FirstByteSet(ast *AST, flags Flags) (ByteSet, bool) {
	if ast == nil || ast.Root == nil {
		return ByteSet{}, false
	}
	flags |= ast.Flags
	set, nullable, ok := nodeFirstByteSet(ast.Root, flags)
	if !ok || nullable || set.Count() == 0 || set.Count() > maxUsefulByteSetSize {
		return ByteSet{}, false
	}
	return set, true
}

func nodeFirstByteSet(node *Node, flags Flags) (ByteSet, bool, bool) {
	node = unwrapGroups(node)
	if node == nil {
		return ByteSet{}, false, false
	}

	switch node.Kind {
	case NodeGroup:
		return nodeFirstByteSet(firstChild(node), flags)
	case NodeEmpty, NodeAnchorStart, NodeAnchorEnd, NodeWordBoundary, NodeNonWordBoundary:
		return ByteSet{}, true, true
	case NodeRangeAny:
		set := fullByteSet()
		if flags&FlagsDotAll == 0 {
			set.remove('\n')
		}
		return set, node.Start == 0, true
	case NodeStar:
		if len(node.Children) == 0 {
			return ByteSet{}, true, true
		}
		childSet, _, ok := nodeFirstByteSet(node.Children[0], flags)
		if !ok {
			return ByteSet{}, true, false
		}
		return childSet, true, true
	case NodePlus:
		if len(node.Children) == 0 {
			return ByteSet{}, false, false
		}
		childSet, childNullable, ok := nodeFirstByteSet(node.Children[0], flags)
		if !ok {
			return ByteSet{}, true, false
		}
		return childSet, childNullable, true
	case NodeRange:
		if len(node.Children) == 0 {
			return ByteSet{}, false, false
		}
		childSet, childNullable, ok := nodeFirstByteSet(node.Children[0], flags)
		if !ok {
			return ByteSet{}, true, false
		}
		return childSet, childNullable || node.Start == 0, true
	case NodeConcat:
		var totalSet ByteSet
		nullable := true
		for _, child := range node.Children {
			childSet, childNullable, ok := nodeFirstByteSet(child, flags)
			if !ok {
				if nullable {
					return ByteSet{}, true, false
				}
				break
			}
			totalSet.union(childSet)
			if !childNullable {
				nullable = false
				break
			}
		}
		return totalSet, nullable, true
	case NodeAlt:
		if len(node.Children) == 0 {
			return ByteSet{}, true, true
		}
		var totalSet ByteSet
		nullable := false
		for _, child := range node.Children {
			childSet, childNullable, ok := nodeFirstByteSet(child, flags)
			if !ok {
				return ByteSet{}, true, false
			}
			totalSet.union(childSet)
			if childNullable {
				nullable = true
			}
		}
		return totalSet, nullable, true
	default:
		if set, ok := nodeByteSet(node, flags); ok {
			return set, false, true
		}
		return ByteSet{}, true, false
	}
}

// ReversePrefixInfo describes constraints on bytes preceding a mandatory atom.
type ReversePrefixInfo struct {
	HasPrecedingByteSet bool
	PrecedingByteSet    ByteSet
	ExactPrefixSuffix   []byte
	HasPrefixRepeat     bool
	PrefixRepeatClass   ByteSet
	PrefixRepeatMin     int
	PrefixRepeatMax     int
}

// ReversePrefixAnalysis returns preceding byte and repeat constraints for atom in ast.
func ReversePrefixAnalysis(ast *AST, atom []byte, flags Flags) ReversePrefixInfo {
	return ReversePrefixAnalysisWithOffset(ast, atom, -1, flags)
}

//nolint:revive // argument-limit: explicit parameters avoid query struct allocation in hot paths
func ReversePrefixAnalysisWithOffset(ast *AST, atom []byte, minOffset int, flags Flags) ReversePrefixInfo {
	if ast == nil || ast.Root == nil || len(atom) == 0 {
		return ReversePrefixInfo{}
	}
	flags |= ast.Flags
	nodes := flattenConcatNodes(ast.Root)
	if len(nodes) < len(atom) {
		return ReversePrefixInfo{}
	}

	atomLen := len(atom)
	for i := 0; i <= len(nodes)-atomLen; i++ {
		matches := true
		for k := 0; k < atomLen; k++ {
			if !nodeMatchesAtomByte(nodes[i+k], atom[k], flags) {
				matches = false
				break
			}
		}
		if !matches {
			continue
		}

		if minOffset >= 0 {
			curMinOffset := 0
			for idx := 0; idx < i; idx++ {
				curMinOffset = addLength(curMinOffset, analyzeAtoms(nodes[idx]).minLength)
			}
			if curMinOffset != minOffset {
				continue
			}
		}

		var info ReversePrefixInfo
		var exactPrefixRev []byte
		curr := i - 1
		for curr >= 0 {
			currNode := unwrapGroups(nodes[curr])
			if currNode == nil {
				curr--
				continue
			}
			if currNode.Kind != NodeLiteral {
				break
			}
			val := currNode.Value
			if flags&FlagsNoCase != 0 {
				val = toLowerASCII(val)
			}
			exactPrefixRev = append(exactPrefixRev, val)
			curr--
		}

		if len(exactPrefixRev) > 0 {
			exactPrefix := make([]byte, len(exactPrefixRev))
			for idx := range exactPrefixRev {
				exactPrefix[idx] = exactPrefixRev[len(exactPrefixRev)-1-idx]
			}
			info.ExactPrefixSuffix = exactPrefix
			info.HasPrecedingByteSet = true
			lastByte := exactPrefix[len(exactPrefix)-1]
			info.PrecedingByteSet = byteSetOf(lastByte)
			if flags&FlagsNoCase != 0 {
				info.PrecedingByteSet = info.PrecedingByteSet.ASCIIFolded()
			}
		}

		if curr >= 0 {
			extractPrefixRepeatOrClass(nodes[curr], flags, &info)
		}

		return info
	}

	return ReversePrefixInfo{}
}

func extractPrefixRepeatOrClass(node *Node, flags Flags, info *ReversePrefixInfo) {
	hasExactPrefix := len(info.ExactPrefixSuffix) > 0
	if repClass, minC, maxC, ok := nodeRepeatInfo(node, flags); ok {
		info.HasPrefixRepeat = true
		info.PrefixRepeatClass = repClass
		info.PrefixRepeatMin = minC
		info.PrefixRepeatMax = maxC
		if !hasExactPrefix && minC > 0 {
			info.HasPrecedingByteSet = true
			info.PrecedingByteSet = repClass
		}
		return
	}
	if !hasExactPrefix {
		if set, ok := nodeByteSet(node, flags); ok {
			info.HasPrecedingByteSet = true
			info.PrecedingByteSet = set
		}
	}
}

func flattenConcatNodes(node *Node) []*Node {
	node = unwrapGroups(node)
	if node == nil {
		return nil
	}
	if node.Kind != NodeConcat {
		return []*Node{node}
	}
	var list []*Node
	for _, child := range node.Children {
		child = unwrapGroups(child)
		if child == nil {
			continue
		}
		if child.Kind == NodeConcat {
			list = append(list, flattenConcatNodes(child)...)
		} else {
			list = append(list, child)
		}
	}
	return list
}

func nodeByteSet(node *Node, flags Flags) (ByteSet, bool) {
	node = unwrapGroups(node)
	if node == nil {
		return ByteSet{}, false
	}
	// Prefix filters may conservatively accept any byte when the class is
	// unknown; fixed-width specialization must still reject it.
	if node.Kind == NodeClass && node.Class == nil {
		return fullByteSet(), true
	}
	return fixedConsumingByteSet(node, flags)
}

func nodeRepeatInfo(node *Node, flags Flags) (class ByteSet, minCount, maxCount int, ok bool) {
	node = unwrapGroups(node)
	if node == nil {
		return ByteSet{}, 0, 0, false
	}
	switch node.Kind {
	case NodePlus:
		if len(node.Children) != 1 {
			return ByteSet{}, 0, 0, false
		}
		set, ok := nodeByteSet(node.Children[0], flags)
		if !ok {
			return ByteSet{}, 0, 0, false
		}
		return set, 1, -1, true
	case NodeStar:
		if len(node.Children) != 1 {
			return ByteSet{}, 0, 0, false
		}
		set, ok := nodeByteSet(node.Children[0], flags)
		if !ok {
			return ByteSet{}, 0, 0, false
		}
		return set, 0, -1, true
	case NodeRange:
		if len(node.Children) != 1 {
			return ByteSet{}, 0, 0, false
		}
		set, ok := nodeByteSet(node.Children[0], flags)
		if !ok {
			return ByteSet{}, 0, 0, false
		}
		maxC := int(node.End)
		if node.End == math.MaxUint16 {
			maxC = -1
		}
		return set, int(node.Start), maxC, true
	case NodeRangeAny:
		set := fullByteSet()
		if flags&FlagsDotAll == 0 {
			set.remove('\n')
		}
		maxC := int(node.End)
		if node.End == math.MaxUint16 {
			maxC = -1
		}
		return set, int(node.Start), maxC, true
	default:
		return ByteSet{}, 0, 0, false
	}
}

func nodeMatchesAtomByte(node *Node, b byte, flags Flags) bool {
	node = unwrapGroups(node)
	if node == nil {
		return false
	}
	if node.Kind == NodeLiteral {
		if flags&FlagsNoCase != 0 {
			return toLowerASCII(node.Value) == toLowerASCII(b)
		}
		return node.Value == b
	}
	if node.Kind == NodeClass && node.Class != nil {
		set := classByteSet(node.Class)
		if flags&FlagsNoCase != 0 {
			set = set.ASCIIFolded()
		}
		return set.Contains(b)
	}
	return false
}
