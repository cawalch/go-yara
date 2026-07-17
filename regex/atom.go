package regex

import (
	"bytes"
	"math"
	"sort"
)

// LiteralAtom describes a literal that every match of a regex must contain.
// Offsets are measured in input characters before the literal. MaxOffset is
// -1 when the amount of preceding input is unbounded.
type LiteralAtom struct {
	Data      []byte
	MinOffset int
	MaxOffset int
}

type atomAnalysis struct {
	minLength int
	maxLength int
	atoms     []LiteralAtom
	byteAtoms []ByteSetAtom
	exact     []byte
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
	return analyzeAtoms(ast.Root).atoms
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

// LiteralAtomCover returns groups of literals that collectively cover every
// match accepted by ast. At least one literal from every returned group must
// be selected by the caller. Unlike AlternativeMandatoryLiteralAtoms, the
// covered alternation may be nested inside a required concatenation or repeat.
// minimumLength excludes atoms too short for the caller's prefilter.
func LiteralAtomCover(ast *AST, minimumLength int) [][]LiteralAtom {
	if ast == nil || ast.Root == nil {
		return nil
	}
	minimumLength = max(1, minimumLength)
	if cover, ok := literalAtomCoverFromAlternatives(AlternativeMandatoryLiteralAtoms(ast), minimumLength); ok {
		return cover.groups
	}
	cover, ok := literalAtomCover(ast.Root, minimumLength)
	if !ok {
		return nil
	}
	return cover.groups
}

func literalAtomCoverFromAlternatives(
	alternatives [][]LiteralAtom,
	minimumLength int,
) (literalAtomCoverPlan, bool) {
	if len(alternatives) < 2 {
		return literalAtomCoverPlan{}, false
	}
	groups := make([][]LiteralAtom, 0, len(alternatives))
	for _, alternative := range alternatives {
		cover, ok := literalAtomCoverFromMandatory(alternative, minimumLength)
		if !ok {
			return literalAtomCoverPlan{}, false
		}
		groups = append(groups, cover.groups[0])
	}
	return newLiteralAtomCoverPlan(groups)
}

type literalAtomCoverPlan struct {
	groups       [][]LiteralAtom
	fullyBounded bool
	score        int
	totalBytes   int
}

func literalAtomCover(node *Node, minimumLength int) (literalAtomCoverPlan, bool) {
	if node == nil {
		return literalAtomCoverPlan{}, false
	}
	if cover, ok := literalAtomCoverFromMandatory(analyzeAtoms(node).atoms, minimumLength); ok {
		return cover, true
	}

	switch node.Kind {
	case NodeConcat:
		return literalConcatAtomCover(node.Children, minimumLength)
	case NodeAlt:
		return literalAlternativeAtomCover(node.Children, minimumLength)
	case NodePlus:
		return literalAtomCover(firstChild(node), minimumLength)
	case NodeRange:
		if node.Start > 0 {
			return literalAtomCover(firstChild(node), minimumLength)
		}
	}
	return literalAtomCoverPlan{}, false
}

func literalAtomCoverFromMandatory(atoms []LiteralAtom, minimumLength int) (literalAtomCoverPlan, bool) {
	group := make([]LiteralAtom, 0, len(atoms))
	for _, atom := range atoms {
		if len(atom.Data) < minimumLength {
			continue
		}
		group = append(group, LiteralAtom{
			Data:      append([]byte(nil), atom.Data...),
			MinOffset: atom.MinOffset,
			MaxOffset: atom.MaxOffset,
		})
	}
	if len(group) == 0 {
		return literalAtomCoverPlan{}, false
	}
	return newLiteralAtomCoverPlan([][]LiteralAtom{group})
}

func literalConcatAtomCover(children []*Node, minimumLength int) (literalAtomCoverPlan, bool) {
	prefixMin := 0
	prefixMax := 0
	var best literalAtomCoverPlan
	found := false
	for _, child := range children {
		cover, ok := literalAtomCover(child, minimumLength)
		if ok {
			cover = shiftLiteralAtomCover(cover, prefixMin, prefixMax)
			if !found || betterLiteralAtomCover(cover, best) {
				best = cover
				found = true
			}
		}
		analysis := analyzeAtoms(child)
		prefixMin = addLength(prefixMin, analysis.minLength)
		prefixMax = addLength(prefixMax, analysis.maxLength)
	}
	return best, found
}

func literalAlternativeAtomCover(children []*Node, minimumLength int) (literalAtomCoverPlan, bool) {
	if len(children) < 2 {
		return literalAtomCoverPlan{}, false
	}
	groups := make([][]LiteralAtom, 0, len(children))
	for _, child := range children {
		cover, ok := literalAtomCover(child, minimumLength)
		if !ok || len(groups) > maxLiteralAlternatives-len(cover.groups) {
			return literalAtomCoverPlan{}, false
		}
		groups = append(groups, cover.groups...)
	}
	return newLiteralAtomCoverPlan(groups)
}

func newLiteralAtomCoverPlan(groups [][]LiteralAtom) (literalAtomCoverPlan, bool) {
	cover := literalAtomCoverPlan{groups: groups, fullyBounded: len(groups) > 0}
	for _, group := range groups {
		bounded := false
		bestLength := 0
		for _, atom := range group {
			cover.totalBytes += len(atom.Data)
			if cover.totalBytes > maxLiteralAlternativeBytes {
				return literalAtomCoverPlan{}, false
			}
			bounded = bounded || atom.MaxOffset >= 0
			bestLength = max(bestLength, len(atom.Data))
		}
		if !bounded {
			cover.fullyBounded = false
		}
		cover.score += bestLength
	}
	return cover, len(groups) > 0
}

func shiftLiteralAtomCover(cover literalAtomCoverPlan, minOffset, maxOffset int) literalAtomCoverPlan {
	for groupIndex := range cover.groups {
		for atomIndex := range cover.groups[groupIndex] {
			cover.groups[groupIndex][atomIndex] = shiftLiteralAtom(
				cover.groups[groupIndex][atomIndex], minOffset, maxOffset,
			)
		}
	}
	if maxOffset < 0 {
		cover.fullyBounded = false
	}
	return cover
}

func betterLiteralAtomCover(candidate, current literalAtomCoverPlan) bool {
	if candidate.fullyBounded != current.fullyBounded {
		return candidate.fullyBounded
	}
	if len(candidate.groups) != len(current.groups) {
		return len(candidate.groups) < len(current.groups)
	}
	if candidate.score != current.score {
		return candidate.score > current.score
	}
	return candidate.totalBytes < current.totalBytes
}

func firstChild(node *Node) *Node {
	if node == nil || len(node.Children) == 0 {
		return nil
	}
	return node.Children[0]
}

func alternativeLeaves(ast *AST) []*Node {
	if ast == nil || ast.Root == nil {
		return nil
	}

	node := ast.Root
	if node.Kind == NodeConcat {
		var consuming *Node
		for _, child := range node.Children {
			analysis := analyzeAtoms(child)
			if analysis.minLength == 0 && analysis.maxLength == 0 {
				continue
			}
			if consuming != nil {
				return nil
			}
			consuming = child
		}
		if consuming == nil {
			return nil
		}
		node = consuming
	}
	if node.Kind != NodeAlt {
		return nil
	}

	leaves := make([]*Node, 0, len(node.Children))
	if !appendAlternativeLeaves(&leaves, node) {
		return nil
	}
	return leaves
}

func appendAlternativeLeaves(dst *[]*Node, node *Node) bool {
	if node == nil {
		return false
	}
	if node.Kind != NodeAlt {
		if len(*dst) >= maxLiteralAlternatives {
			return false
		}
		*dst = append(*dst, node)
		return true
	}
	for _, child := range node.Children {
		if !appendAlternativeLeaves(dst, child) {
			return false
		}
	}
	return true
}

func analyzeAtoms(node *Node) atomAnalysis {
	if node == nil {
		return atomAnalysis{maxLength: 0, isExact: true}
	}

	switch node.Kind {
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

func analyzeConcatAtoms(children []*Node) atomAnalysis {
	result := atomAnalysis{maxLength: 0, isExact: true}
	runMinOffset := 0
	runMaxOffset := 0
	runActive := false
	var run []byte

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
		})
		run = run[:0]
		runActive = false
	}

	for _, child := range children {
		analysis := analyzeAtoms(child)
		for _, atom := range analysis.atoms {
			result.atoms = append(result.atoms, shiftLiteralAtom(atom, result.minLength, result.maxLength))
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
		atoms:     cloneLiteralAtoms(child.atoms),
		byteAtoms: cloneByteSetAtoms(child.byteAtoms),
	}
	if child.maxLength == 0 {
		result.maxLength = 0
		result.exact = append([]byte(nil), child.exact...)
		result.isExact = child.isExact
	}
	if child.isExact && len(child.exact) > 0 {
		result.atoms = append(result.atoms, LiteralAtom{Data: append([]byte(nil), child.exact...), MaxOffset: 0})
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
		result.atoms = cloneLiteralAtoms(child.atoms)
		result.byteAtoms = cloneByteSetAtoms(child.byteAtoms)
		if child.isExact && len(child.exact) > 0 {
			result.atoms = append(result.atoms, LiteralAtom{
				Data:      repeatLiteral(child.exact, minimum),
				MaxOffset: 0,
			})
		}
	}
	if minimum == maximum && child.isExact {
		result.exact = repeatLiteral(child.exact, minimum)
		result.isExact = true
	}
	return result
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
		}
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
