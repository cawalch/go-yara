package regex

import "math/bits"

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
	return analyzeAtoms(ast.Root).byteAtoms
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
