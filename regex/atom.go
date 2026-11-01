package regex

import (
	"bytes"
	"math"
	"sort"
)

// LiteralAtom describes a literal that every match of a regex must contain.
// Offsets are measured in input characters before the literal. MaxOffset is
// -1 when the amount of preceding input is unbounded. MaxSuffix is -1 when
// the amount of succeeding input after the literal is unbounded.
type LiteralAtom struct {
	Data      []byte
	MinOffset int
	MaxOffset int
	MaxSuffix int
}

// LeadingByteGapPlan describes regexes that begin with one constrained byte,
// followed by a repeated byte class and a suffix covered by literal atoms.
// A scanner can find the suffix atoms first, walk the repeated gap backwards,
// and recover exact candidate starts without probing every leading byte.
type LeadingByteGapPlan struct {
	AtomGroups [][]LiteralAtom
	LeadingSet ByteSet
	GapSet     ByteSet
	GapMin     int
	GapMax     int
}

type atomAnalysis struct {
	atoms     []LiteralAtom
	byteAtoms []ByteSetAtom
	exact     []byte
	minLength int
	maxLength int
	isExact   bool
}

const (
	maxLiteralAlternatives     = 256
	maxLiteralAlternativeBytes = 16 << 10
)

// MandatoryLiteralAtoms returns only literals that are present in every match
// accepted by ast. The caller can use their offset bounds to turn literal
// occurrences into a conservative set of regex start positions.
func MandatoryLiteralAtoms(ast *AST) []LiteralAtom {
	if ast == nil || ast.Root == nil {
		return nil
	}
	// analyzeAtoms results are memoized on AST nodes; never hand them out.
	return cloneLiteralAtoms(analyzeAtoms(ast.Root).atoms)
}

// MandatoryASCIIFoldedLiteralAtoms returns literals formed by required runs of
// pure ASCII case-pair classes such as [Pp][Aa][Ss][Ss]. Data is normalized to
// lowercase and must be searched with ASCII case folding. A maximal adjacent
// class run containing any wider class is rejected as a whole.
func MandatoryASCIIFoldedLiteralAtoms(ast *AST) []LiteralAtom {
	if ast == nil || ast.Root == nil {
		return nil
	}
	return cloneLiteralAtoms(analyzeASCIIFoldedLiteralAtoms(ast.Root))
}

func analyzeASCIIFoldedLiteralAtoms(node *Node) []LiteralAtom {
	node = unwrapGroups(node)
	if node == nil {
		return nil
	}

	switch node.Kind {
	case NodeConcat:
		return analyzeConcatASCIIFoldedLiteralAtoms(node.Children)
	case NodeAlt:
		analyses := make([]atomAnalysis, len(node.Children))
		for index, child := range node.Children {
			analyses[index].atoms = analyzeASCIIFoldedLiteralAtoms(child)
		}
		return intersectMandatoryAtoms(analyses)
	case NodePlus:
		return literalAtomsWithSuffix(analyzeASCIIFoldedLiteralAtoms(firstChild(node)), repeatTailLength(node, 1))
	case NodeRange:
		if node.Start > 0 {
			return literalAtomsWithSuffix(analyzeASCIIFoldedLiteralAtoms(firstChild(node)), repeatTailLength(node, 1))
		}
	}
	return nil
}

func analyzeConcatASCIIFoldedLiteralAtoms(children []*Node) []LiteralAtom {
	var atoms []LiteralAtom
	prefixMin := 0
	prefixMax := 0

	suffixMax := literalSuffixLengths(children)

	for index := 0; index < len(children); {
		if isClassNode(children[index]) {
			runMinOffset := prefixMin
			runMaxOffset := prefixMax
			runValid := true
			run := make([]byte, 0, len(children)-index)
			for index < len(children) && isClassNode(children[index]) {
				value, ok := asciiCasePairValue(children[index])
				if !ok {
					runValid = false
				} else {
					run = append(run, value)
				}
				analysis := analyzeAtoms(children[index])
				prefixMin = addLength(prefixMin, analysis.minLength)
				prefixMax = addLength(prefixMax, analysis.maxLength)
				index++
			}
			if runValid && len(run) > 0 {
				atoms = append(atoms, LiteralAtom{
					Data:      run,
					MinOffset: runMinOffset,
					MaxOffset: runMaxOffset,
					MaxSuffix: suffixMax[index],
				})
			}
			continue
		}

		for _, atom := range analyzeASCIIFoldedLiteralAtoms(children[index]) {
			shifted := shiftLiteralAtom(atom, prefixMin, prefixMax)
			if suffixMax[index+1] < 0 || atom.MaxSuffix < 0 {
				shifted.MaxSuffix = -1
			} else {
				shifted.MaxSuffix = addLength(atom.MaxSuffix, suffixMax[index+1])
			}
			atoms = append(atoms, shifted)
		}
		analysis := analyzeAtoms(children[index])
		prefixMin = addLength(prefixMin, analysis.minLength)
		prefixMax = addLength(prefixMax, analysis.maxLength)
		index++
	}
	return atoms
}

func isClassNode(node *Node) bool {
	node = unwrapGroups(node)
	return node != nil && node.Kind == NodeClass
}

func asciiCasePairValue(node *Node) (byte, bool) {
	node = unwrapGroups(node)
	if node == nil || node.Kind != NodeClass {
		return 0, false
	}
	set := classByteSet(node.Class)
	if set.Count() != 2 {
		return 0, false
	}
	for lower := byte('a'); lower <= 'z'; lower++ {
		upper := lower - ('a' - 'A')
		if set.Contains(lower) && set.Contains(upper) {
			return lower, true
		}
	}
	return 0, false
}

// LiteralAlternatives returns the exact, non-empty literal branches when the
// entire consuming portion of ast is an alternation. Zero-width assertions may
// surround the alternation; the regex VM still verifies them at each candidate
// start. Mixed or variable branches return nil so callers never use a branch
// atom as though it covered the whole regex language.
func LiteralAlternatives(ast *AST) []LiteralAtom {
	leaves := alternativeLeaves(ast)
	if len(leaves) == 0 {
		return nil
	}

	totalBytes := 0
	alternatives := make([]LiteralAtom, 0, len(leaves))
	for _, leaf := range leaves {
		analysis := analyzeAtoms(leaf)
		if !analysis.isExact || len(analysis.exact) == 0 {
			return nil
		}
		totalBytes += len(analysis.exact)
		if totalBytes > maxLiteralAlternativeBytes {
			return nil
		}
		alternatives = append(alternatives, LiteralAtom{
			Data:      append([]byte(nil), analysis.exact...),
			MaxOffset: 0,
		})
	}
	return alternatives
}

// AlternativeMandatoryLiteralAtoms returns one group of mandatory literals
// for every branch when the entire consuming portion of ast is an
// alternation. Callers must select at least one usable atom from every group;
// omitting a group would make the candidate plan incomplete.
func AlternativeMandatoryLiteralAtoms(ast *AST) [][]LiteralAtom {
	leaves := alternativeLeaves(ast)
	if len(leaves) == 0 {
		return nil
	}

	totalBytes := 0
	alternatives := make([][]LiteralAtom, 0, len(leaves))
	for _, leaf := range leaves {
		atoms := analyzeAtoms(leaf).atoms
		if len(atoms) == 0 {
			return nil
		}
		for _, atom := range atoms {
			totalBytes += len(atom.Data)
			if totalBytes > maxLiteralAlternativeBytes {
				return nil
			}
		}
		alternatives = append(alternatives, cloneLiteralAtoms(atoms))
	}
	return alternatives
}

func analyzeAtoms(node *Node) atomAnalysis {
	if node == nil {
		return atomAnalysis{maxLength: 0, isExact: true}
	}
	node.atomsOnce.Do(func() {
		computed := analyzeAtomsUncached(node)
		node.atoms = &computed
	})
	return *node.atoms
}

func analyzeAtomsUncached(node *Node) atomAnalysis {

	switch node.Kind {
	case NodeGroup:
		return analyzeAtoms(firstChild(node))
	case NodeLiteral:
		data := []byte{node.Value}
		return atomAnalysis{
			minLength: 1,
			maxLength: 1,
			atoms:     []LiteralAtom{{Data: data, MaxOffset: 0}},
			byteAtoms: usefulByteSetAtom(byteSetOf(node.Value)),
			exact:     data,
			isExact:   true,
		}
	case NodeConcat:
		return analyzeConcatAtoms(node.Children)
	case NodeAlt:
		return analyzeAltAtoms(node.Children)
	case NodeStar:
		return analyzeStarAtoms(node)
	case NodePlus:
		return analyzePlusAtoms(node)
	case NodeRange:
		return analyzeRangeAtoms(node)
	case NodeEmpty, NodeAnchorStart, NodeAnchorEnd, NodeWordBoundary, NodeNonWordBoundary:
		return atomAnalysis{maxLength: 0, isExact: true}
	case NodeMaskedLiteral:
		return singleByteAtomAnalysis(maskedByteSet(node.Value, node.Mask, false))
	case NodeMaskedNotLiteral:
		return singleByteAtomAnalysis(maskedByteSet(node.Value, node.Mask, true))
	case NodeNotLiteral:
		set := fullByteSet()
		set.remove(node.Value)
		return singleByteAtomAnalysis(set)
	case NodeClass:
		return singleByteAtomAnalysis(classByteSet(node.Class))
	case NodeWordChar:
		return singleByteAtomAnalysis(predicateByteSet(isWord))
	case NodeNonWordChar:
		return singleByteAtomAnalysis(predicateByteSet(notWord))
	case NodeSpace:
		return singleByteAtomAnalysis(predicateByteSet(isSpace))
	case NodeNonSpace:
		return singleByteAtomAnalysis(predicateByteSet(notSpace))
	case NodeDigit:
		return singleByteAtomAnalysis(predicateByteSet(isDigit))
	case NodeNonDigit:
		return singleByteAtomAnalysis(predicateByteSet(notDigit))
	case NodeAny:
		return atomAnalysis{minLength: 1, maxLength: 1}
	case NodeRangeAny:
		maxLength := int(node.End)
		if node.End == math.MaxUint16 {
			maxLength = -1
		}
		return atomAnalysis{minLength: int(node.Start), maxLength: maxLength}
	default:
		return atomAnalysis{maxLength: -1}
	}
}

func singleByteAtomAnalysis(set ByteSet) atomAnalysis {
	result := atomAnalysis{
		minLength: 1,
		maxLength: 1,
		byteAtoms: usefulByteSetAtom(set),
	}
	if value, ok := set.singletonValue(); ok {
		data := []byte{value}
		result.atoms = []LiteralAtom{{Data: data, MaxOffset: 0}}
		result.exact = data
		result.isExact = true
	}
	return result
}

// ASTMaxLength returns the maximum match length accepted by the AST, or -1 if unbounded.
func ASTMaxLength(ast *AST) int {
	if ast == nil || ast.Root == nil {
		return 0
	}
	return nodeMaxLength(ast.Root)
}

func analyzeConcatAtoms(children []*Node) atomAnalysis {
	result := atomAnalysis{maxLength: 0, isExact: true}
	if len(children) == 0 {
		return result
	}

	analyses := make([]atomAnalysis, len(children))
	for i, child := range children {
		analyses[i] = analyzeAtoms(child)
	}

	suffixMax := literalSuffixLengths(children)

	runMinOffset := 0
	runMaxOffset := 0
	runActive := false
	var run []byte
	runEndChildIdx := 0

	flushRun := func() {
		if !runActive || len(run) == 0 {
			run = run[:0]
			runActive = false
			return
		}
		result.atoms = append(result.atoms, LiteralAtom{
			Data:      append([]byte(nil), run...),
			MinOffset: runMinOffset,
			MaxOffset: runMaxOffset,
			MaxSuffix: suffixMax[runEndChildIdx],
		})
		run = run[:0]
		runActive = false
	}

	for i, analysis := range analyses {
		for _, atom := range analysis.atoms {
			shifted := shiftLiteralAtom(atom, result.minLength, result.maxLength)
			if suffixMax[i+1] < 0 || atom.MaxSuffix < 0 {
				shifted.MaxSuffix = -1
			} else {
				shifted.MaxSuffix = addLength(atom.MaxSuffix, suffixMax[i+1])
			}
			result.atoms = append(result.atoms, shifted)
		}
		for _, atom := range analysis.byteAtoms {
			result.byteAtoms = append(result.byteAtoms, shiftByteSetAtom(atom, result.minLength, result.maxLength))
		}

		if analysis.isExact {
			if !runActive {
				runMinOffset = result.minLength
				runMaxOffset = result.maxLength
				runActive = true
			}
			run = append(run, analysis.exact...)
			runEndChildIdx = i + 1
		} else {
			flushRun()
			result.isExact = false
		}

		result.minLength = addLength(result.minLength, analysis.minLength)
		result.maxLength = addLength(result.maxLength, analysis.maxLength)
		if result.isExact {
			result.exact = append(result.exact, analysis.exact...)
		}
	}
	flushRun()
	return result
}

func analyzeAltAtoms(children []*Node) atomAnalysis {
	if len(children) == 0 {
		return atomAnalysis{maxLength: 0, isExact: true}
	}

	first := analyzeAtoms(children[0])
	result := atomAnalysis{
		minLength: first.minLength,
		maxLength: first.maxLength,
		exact:     append([]byte(nil), first.exact...),
		isExact:   first.isExact,
	}
	analyses := make([]atomAnalysis, 0, len(children))
	analyses = append(analyses, first)

	for _, child := range children[1:] {
		analysis := analyzeAtoms(child)
		analyses = append(analyses, analysis)
		result.minLength = min(result.minLength, analysis.minLength)
		result.maxLength = maxLength(result.maxLength, analysis.maxLength)
		if !analysis.isExact || !result.isExact || !bytes.Equal(result.exact, analysis.exact) {
			result.isExact = false
			result.exact = nil
		}
	}

	result.byteAtoms = mergeAlternativeByteSetAtoms(analyses)
	if result.isExact && len(result.exact) > 0 {
		result.atoms = []LiteralAtom{{Data: append([]byte(nil), result.exact...), MaxOffset: 0}}
		return result
	}
	result.atoms = intersectMandatoryAtoms(analyses)
	return result
}

func analyzeStarAtoms(node *Node) atomAnalysis {
	child := firstChildAnalysis(node)
	if child.maxLength == 0 {
		return atomAnalysis{maxLength: 0, isExact: true}
	}
	return atomAnalysis{maxLength: -1}
}

func analyzePlusAtoms(node *Node) atomAnalysis {
	child := firstChildAnalysis(node)
	result := atomAnalysis{
		minLength: child.minLength,
		maxLength: -1,
		atoms:     literalAtomsWithSuffix(child.atoms, repeatTailLength(node, 1)),
		byteAtoms: cloneByteSetAtoms(child.byteAtoms),
	}
	if child.maxLength == 0 {
		result.maxLength = 0
		result.exact = append([]byte(nil), child.exact...)
		result.isExact = child.isExact
	}
	if child.isExact && len(child.exact) > 0 {
		result.atoms = append(result.atoms, LiteralAtom{Data: append([]byte(nil), child.exact...), MaxSuffix: repeatTailLength(node, 1)})
	}
	return result
}

func analyzeRangeAtoms(node *Node) atomAnalysis {
	child := firstChildAnalysis(node)
	minimum := int(node.Start)
	maximum := int(node.End)
	result := atomAnalysis{
		minLength: multiplyLength(child.minLength, minimum),
		maxLength: multiplyLength(child.maxLength, maximum),
	}
	if node.End == math.MaxUint16 && child.maxLength > 0 {
		result.maxLength = -1
	}
	if minimum > 0 {
		result.atoms = literalAtomsWithSuffix(child.atoms, repeatTailLength(node, 1))
		result.byteAtoms = cloneByteSetAtoms(child.byteAtoms)
		if child.isExact && len(child.exact) > 0 {
			result.atoms = append(result.atoms, LiteralAtom{
				Data:      repeatLiteral(child.exact, minimum),
				MaxSuffix: repeatTailLength(node, minimum),
			})
		}
	}
	if minimum == maximum && child.isExact {
		result.exact = repeatLiteral(child.exact, minimum)
		result.isExact = true
	}
	return result
}

// repeatTailLength bounds the copies following an atom in the required prefix.
func repeatTailLength(node *Node, copies int) int {
	childMax := firstChildAnalysis(node).maxLength
	if childMax == 0 {
		return 0
	}
	if node.Kind == NodePlus || (node.End == math.MaxUint16 && node.Start != node.End) {
		return -1
	}
	if int(node.End) <= copies {
		return 0
	}
	return multiplyLength(childMax, int(node.End)-copies)
}

func literalAtomsWithSuffix(atoms []LiteralAtom, suffix int) []LiteralAtom {
	result := cloneLiteralAtoms(atoms)
	for i := range result {
		result[i].MaxSuffix = addLength(result[i].MaxSuffix, suffix)
	}
	return result
}

func literalSuffixLengths(children []*Node) []int {
	suffix := make([]int, len(children)+1)
	for i := len(children) - 1; i >= 0; i-- {
		suffix[i] = addLength(analyzeAtoms(children[i]).maxLength, suffix[i+1])
	}
	return suffix
}

func firstChildAnalysis(node *Node) atomAnalysis {
	if len(node.Children) == 0 {
		return atomAnalysis{maxLength: 0, isExact: true}
	}
	return analyzeAtoms(node.Children[0])
}

func shiftLiteralAtom(atom LiteralAtom, minOffset, maxOffset int) LiteralAtom {
	return LiteralAtom{
		Data:      append([]byte(nil), atom.Data...),
		MinOffset: addLength(minOffset, atom.MinOffset),
		MaxOffset: addLength(maxOffset, atom.MaxOffset),
		MaxSuffix: atom.MaxSuffix,
	}
}

func shiftByteSetAtom(atom ByteSetAtom, minOffset, maxOffset int) ByteSetAtom {
	return ByteSetAtom{
		Set:       atom.Set,
		MinOffset: addLength(minOffset, atom.MinOffset),
		MaxOffset: addLength(maxOffset, atom.MaxOffset),
	}
}

func cloneLiteralAtoms(atoms []LiteralAtom) []LiteralAtom {
	result := make([]LiteralAtom, len(atoms))
	for i, atom := range atoms {
		result[i] = LiteralAtom{
			Data:      append([]byte(nil), atom.Data...),
			MinOffset: atom.MinOffset,
			MaxOffset: atom.MaxOffset,
			MaxSuffix: atom.MaxSuffix,
		}
	}
	return result
}

func cloneAtomGroups(groups [][]LiteralAtom) [][]LiteralAtom {
	if groups == nil {
		return nil
	}
	result := make([][]LiteralAtom, len(groups))
	for i, group := range groups {
		result[i] = cloneLiteralAtoms(group)
	}
	return result
}

func cloneByteSetAtoms(atoms []ByteSetAtom) []ByteSetAtom {
	return append([]ByteSetAtom(nil), atoms...)
}

func mergeAlternativeByteSetAtoms(analyses []atomAnalysis) []ByteSetAtom {
	if len(analyses) == 0 {
		return nil
	}
	var merged ByteSetAtom
	for index, analysis := range analyses {
		candidate, ok := bestByteSetAtom(analysis.byteAtoms)
		if !ok {
			return nil
		}
		if index == 0 {
			merged = candidate
			continue
		}
		merged.Set.union(candidate.Set)
		merged.MinOffset = min(merged.MinOffset, candidate.MinOffset)
		merged.MaxOffset = maxLength(merged.MaxOffset, candidate.MaxOffset)
	}
	if merged.Set.Count() > maxUsefulByteSetSize {
		return nil
	}
	return []ByteSetAtom{merged}
}

func bestByteSetAtom(atoms []ByteSetAtom) (ByteSetAtom, bool) {
	var best ByteSetAtom
	found := false
	for _, candidate := range atoms {
		if !found || betterByteSetAtom(candidate, best) {
			best = candidate
			found = true
		}
	}
	return best, found
}

func betterByteSetAtom(candidate, current ByteSetAtom) bool {
	candidateBounded := candidate.MaxOffset >= 0
	currentBounded := current.MaxOffset >= 0
	if candidateBounded != currentBounded {
		return candidateBounded
	}
	if candidate.Set.Count() != current.Set.Count() {
		return candidate.Set.Count() < current.Set.Count()
	}
	if candidateBounded {
		candidateWidth := candidate.MaxOffset - candidate.MinOffset
		currentWidth := current.MaxOffset - current.MinOffset
		if candidateWidth != currentWidth {
			return candidateWidth < currentWidth
		}
	}
	return true
}

func intersectMandatoryAtoms(analyses []atomAnalysis) []LiteralAtom {
	if len(analyses) == 0 || len(analyses[0].atoms) == 0 {
		return nil
	}
	const maxAlternativeAtomBytes = 16 * 1024
	totalBytes := 0
	for _, analysis := range analyses {
		for _, atom := range analysis.atoms {
			totalBytes += len(atom.Data)
			if totalBytes > maxAlternativeAtomBytes {
				return nil
			}
		}
	}

	const maxWidth = 8
	for width := maxWidth; width >= 2; width-- {
		windows := make([]map[string]LiteralAtom, len(analyses))
		usable := true
		for i, analysis := range analyses {
			windows[i] = mandatoryAtomWindows(analysis.atoms, width)
			if len(windows[i]) == 0 {
				usable = false
				break
			}
		}
		if !usable {
			continue
		}
		common := intersectAtomWindows(windows)
		if len(common) > 0 {
			return common
		}
	}
	return nil
}

func mandatoryAtomWindows(atoms []LiteralAtom, width int) map[string]LiteralAtom {
	windows := make(map[string]LiteralAtom)
	for _, atom := range atoms {
		for offset := 0; offset+width <= len(atom.Data); offset++ {
			key := string(atom.Data[offset : offset+width])
			candidate := LiteralAtom{
				Data:      []byte(key),
				MinOffset: addLength(atom.MinOffset, offset),
				MaxOffset: addLength(atom.MaxOffset, offset),
				MaxSuffix: addLength(atom.MaxSuffix, len(atom.Data)-(offset+width)),
			}
			current, exists := windows[key]
			if !exists || literalAtomOffsetWidth(candidate) < literalAtomOffsetWidth(current) {
				windows[key] = candidate
			}
		}
	}
	return windows
}

func intersectAtomWindows(windows []map[string]LiteralAtom) []LiteralAtom {
	keys := make([]string, 0, len(windows[0]))
	for key := range windows[0] {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]LiteralAtom, 0, len(keys))
	for _, key := range keys {
		atom := windows[0][key]
		common := true
		for _, alternatives := range windows[1:] {
			alternative, ok := alternatives[key]
			if !ok {
				common = false
				break
			}
			atom.MinOffset = min(atom.MinOffset, alternative.MinOffset)
			atom.MaxOffset = maxLength(atom.MaxOffset, alternative.MaxOffset)
			atom.MaxSuffix = maxLength(atom.MaxSuffix, alternative.MaxSuffix)
		}
		if common {
			result = append(result, atom)
		}
	}
	return result
}

func literalAtomOffsetWidth(atom LiteralAtom) int {
	if atom.MaxOffset < 0 {
		return math.MaxInt
	}
	return atom.MaxOffset - atom.MinOffset
}

func addLength(left, right int) int {
	if left < 0 || right < 0 {
		return -1
	}
	if left > math.MaxInt-right {
		return -1
	}
	return left + right
}

func multiplyLength(length, count int) int {
	if length < 0 {
		return -1
	}
	if length != 0 && count > math.MaxInt/length {
		return -1
	}
	return length * count
}

func maxLength(left, right int) int {
	if left < 0 || right < 0 {
		return -1
	}
	return max(left, right)
}

func repeatLiteral(data []byte, count int) []byte {
	if len(data) == 0 || count <= 0 {
		return nil
	}
	if count > math.MaxInt/len(data) {
		return nil
	}
	result := make([]byte, 0, len(data)*count)
	for range count {
		result = append(result, data...)
	}
	return result
}
