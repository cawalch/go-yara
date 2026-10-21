package regex

import (
	"math"
)

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
		return cloneAtomGroups(cover.groups)
	}
	cover, ok := literalAtomCover(ast.Root, minimumLength)
	if !ok {
		return nil
	}
	return cloneAtomGroups(cover.groups)
}

// RequiredLiteralAlternationAtoms returns one mandatory-literal group for
// every branch of a required alternation anywhere in ast. Unlike
// LiteralAtomCover, it deliberately preserves the alternation even when a
// shorter literal is common to the entire regex. Callers must keep every
// returned group; a match may contain an atom from any one of them.
func RequiredLiteralAlternationAtoms(ast *AST, minimumLength int) [][]LiteralAtom {
	if ast == nil || ast.Root == nil {
		return nil
	}
	minimumLength = max(1, minimumLength)
	cover, ok := requiredLiteralAlternationCover(ast.Root, minimumLength)
	if !ok {
		return nil
	}
	return cloneAtomGroups(cover.groups)
}

func requiredLiteralAlternationCover(node *Node, minimumLength int) (literalAtomCoverPlan, bool) {
	node = unwrapGroups(node)
	if node == nil {
		return literalAtomCoverPlan{}, false
	}

	switch node.Kind {
	case NodeAlt:
		leaves := make([]*Node, 0, len(node.Children))
		if !appendAlternativeLeaves(&leaves, node) {
			return literalAtomCoverPlan{}, false
		}
		groups := make([][]LiteralAtom, 0, len(leaves))
		for _, leaf := range leaves {
			cover, ok := literalAtomCover(leaf, minimumLength)
			if !ok || len(groups) > maxLiteralAlternatives-len(cover.groups) {
				return literalAtomCoverPlan{}, false
			}
			groups = append(groups, cover.groups...)
		}
		return newLiteralAtomCoverPlan(groups)
	case NodeConcat:
		prefixMin := 0
		prefixMax := 0
		var best literalAtomCoverPlan
		found := false
		for _, child := range node.Children {
			cover, ok := requiredLiteralAlternationCover(child, minimumLength)
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
		if expanded, ok := expandBoundedConcatAlternationCover(node.Children, minimumLength); ok {
			if !found || betterLiteralAtomCover(expanded, best) {
				best = expanded
				found = true
			}
		}
		return best, found
	case NodePlus:
		return requiredLiteralAlternationCover(firstChild(node), minimumLength)
	case NodeRange:
		if node.Start > 0 {
			return requiredLiteralAlternationCover(firstChild(node), minimumLength)
		}
	}
	return literalAtomCoverPlan{}, false
}

const (
	maxExpandedConcatBranches   = 16
	maxExpandedConcatClassBytes = 8
)

func expandBoundedConcatAlternationCover(children []*Node, minimumLength int) (literalAtomCoverPlan, bool) {
	prefixMin := 0
	prefixMax := 0
	var best literalAtomCoverPlan
	found := false

	for index := 0; index < len(children); {
		branches, isMulti, ok := exactConcatChildBranches(children[index])
		if !ok {
			analysis := analyzeAtoms(children[index])
			prefixMin = addLength(prefixMin, analysis.minLength)
			prefixMax = addLength(prefixMax, analysis.maxLength)
			index++
			continue
		}

		runMinOffset := prefixMin
		runMaxOffset := prefixMax
		expanded := [][]byte{nil}
		seenMulti := false
		trailingExactBytes := 0
		validRun := true

		for index < len(children) {
			childBranches, childMulti, childOK := exactConcatChildBranches(children[index])
			if !childOK {
				break
			}
			if len(expanded)*len(childBranches) > maxExpandedConcatBranches {
				validRun = false
			}
			if validRun {
				next := make([][]byte, 0, len(expanded)*len(childBranches))
				for _, prefix := range expanded {
					for _, suffix := range childBranches {
						combined := make([]byte, 0, len(prefix)+len(suffix))
						combined = append(combined, prefix...)
						combined = append(combined, suffix...)
						next = append(next, combined)
					}
				}
				expanded = next
				if childMulti {
					seenMulti = true
					trailingExactBytes = 0
				} else if seenMulti && len(childBranches) == 1 {
					trailingExactBytes += len(childBranches[0])
				}
			}
			analysis := analyzeAtoms(children[index])
			prefixMin = addLength(prefixMin, analysis.minLength)
			prefixMax = addLength(prefixMax, analysis.maxLength)
			index++
		}
		_ = branches
		_ = isMulti

		if !validRun || !seenMulti || trailingExactBytes == 0 || len(expanded) < 2 {
			continue
		}
		groups := make([][]LiteralAtom, 0, len(expanded))
		allLongEnough := true
		for _, branch := range expanded {
			if len(branch) < minimumLength {
				allLongEnough = false
				break
			}
			groups = append(groups, []LiteralAtom{{
				Data:      branch,
				MinOffset: runMinOffset,
				MaxOffset: runMaxOffset,
			}})
		}
		if !allLongEnough {
			continue
		}
		if cover, coverOK := newLiteralAtomCoverPlan(groups); coverOK {
			if !found || betterLiteralAtomCover(cover, best) {
				best = cover
				found = true
			}
		}
	}
	return best, found
}

func exactConcatChildBranches(node *Node) ([][]byte, bool, bool) {
	analysis := analyzeAtoms(node)
	if analysis.isExact {
		return [][]byte{analysis.exact}, false, true
	}
	unwrapped := unwrapGroups(node)
	if unwrapped == nil {
		return nil, false, false
	}
	switch unwrapped.Kind {
	case NodeRange:
		if unwrapped.Start == 0 && unwrapped.End == 1 {
			inner := analyzeAtoms(firstChild(unwrapped))
			if inner.isExact && len(inner.exact) > 0 {
				return [][]byte{nil, inner.exact}, true, true
			}
		}
	case NodeClass:
		set := classByteSet(unwrapped.Class)
		count := set.Count()
		if count >= 2 && count <= maxExpandedConcatClassBytes {
			branches := make([][]byte, 0, count)
			for value := range 256 {
				if set.Contains(byte(value)) {
					branches = append(branches, []byte{byte(value)})
				}
			}
			return branches, true, true
		}
	case NodeAlt:
		leaves := make([]*Node, 0, len(unwrapped.Children))
		if !appendAlternativeLeaves(&leaves, unwrapped) || len(leaves) < 2 || len(leaves) > maxExpandedConcatBranches {
			return nil, false, false
		}
		branches := make([][]byte, 0, len(leaves))
		maxLeafLen := 0
		for _, leaf := range leaves {
			leafAnalysis := analyzeAtoms(leaf)
			if !leafAnalysis.isExact || len(leafAnalysis.exact) == 0 {
				return nil, false, false
			}
			maxLeafLen = max(maxLeafLen, len(leafAnalysis.exact))
			branches = append(branches, leafAnalysis.exact)
		}
		if maxLeafLen <= 2 {
			return branches, true, true
		}
	}
	return nil, false, false
}

// LeadingByteGapAtomCover returns a candidate plan for regexes shaped like
// <one byte><repeated byte class><literal-bearing suffix>. The suffix may be
// an alternation; every returned group must contribute one atom to keep the
// plan complete. GapMax is -1 for an unbounded repeat.
func LeadingByteGapAtomCover(ast *AST, flags Flags, minimumLength int) (LeadingByteGapPlan, bool) {
	if ast == nil || ast.Root == nil {
		return LeadingByteGapPlan{}, false
	}
	root := unwrapGroups(ast.Root)
	if root == nil || root.Kind != NodeConcat || len(root.Children) < 3 {
		return LeadingByteGapPlan{}, false
	}
	children := root.Children
	leadingSet, ok := fixedConsumingByteSet(children[0], flags)
	if !ok {
		return LeadingByteGapPlan{}, false
	}
	gapSet, gapMin, gapMax, ok := repeatedSingleByteSet(children[1], flags)
	if !ok {
		return LeadingByteGapPlan{}, false
	}

	suffix := children[2]
	if len(children) > 3 {
		suffix = &Node{Kind: NodeConcat, Children: children[2:], Greedy: true}
	}
	groups, ok := suffixLiteralAtomGroups(suffix, max(1, minimumLength))
	if !ok {
		return LeadingByteGapPlan{}, false
	}
	return LeadingByteGapPlan{
		LeadingSet: leadingSet,
		GapSet:     gapSet,
		GapMin:     gapMin,
		GapMax:     gapMax,
		AtomGroups: cloneAtomGroups(groups),
	}, true
}

func repeatedSingleByteSet(node *Node, flags Flags) (ByteSet, int, int, bool) {
	if node == nil || len(node.Children) != 1 {
		return ByteSet{}, 0, 0, false
	}
	minimum := 0
	maximum := -1
	switch node.Kind {
	case NodeGroup:
		return repeatedSingleByteSet(firstChild(node), flags)
	case NodeStar:
	case NodePlus:
		minimum = 1
	case NodeRange:
		minimum = int(node.Start)
		maximum = int(node.End)
		if node.End == math.MaxUint16 {
			maximum = -1
		}
	default:
		return ByteSet{}, 0, 0, false
	}
	set, ok := fixedConsumingByteSet(node.Children[0], flags)
	return set, minimum, maximum, ok
}

func suffixLiteralAtomGroups(node *Node, minimumLength int) ([][]LiteralAtom, bool) {
	leaves := alternativeLeaves(&AST{Root: node})
	if len(leaves) == 0 {
		leaves = []*Node{node}
	}
	groups := make([][]LiteralAtom, 0, len(leaves))
	for _, leaf := range leaves {
		analysis := analyzeAtoms(leaf)
		group := make([]LiteralAtom, 0, len(analysis.atoms))
		for _, atom := range analysis.atoms {
			if len(atom.Data) < minimumLength || atom.MaxOffset < 0 {
				continue
			}
			group = append(group, LiteralAtom{
				Data:      append([]byte(nil), atom.Data...),
				MinOffset: atom.MinOffset,
				MaxOffset: atom.MaxOffset,
				MaxSuffix: atom.MaxSuffix,
			})
		}
		if len(group) == 0 {
			return nil, false
		}
		groups = append(groups, group)
	}
	return groups, len(groups) > 0
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
	case NodeGroup:
		return literalAtomCover(firstChild(node), minimumLength)
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
			MaxSuffix: atom.MaxSuffix,
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
	candidateQuality := candidate.score * len(current.groups)
	currentQuality := current.score * len(candidate.groups)
	if candidateQuality != currentQuality {
		// Compare average best-literal length before group count. A smaller
		// cover of short atoms can produce far more VM candidates than a
		// slightly larger cover of selective literals.
		return candidateQuality > currentQuality
	}
	if len(candidate.groups) != len(current.groups) {
		return len(candidate.groups) < len(current.groups)
	}
	return candidate.totalBytes < current.totalBytes
}

func firstChild(node *Node) *Node {
	if node == nil || len(node.Children) == 0 {
		return nil
	}
	return node.Children[0]
}

func unwrapGroups(node *Node) *Node {
	for node != nil && node.Kind == NodeGroup {
		node = firstChild(node)
	}
	return node
}

func alternativeLeaves(ast *AST) []*Node {
	if ast == nil || ast.Root == nil {
		return nil
	}

	node := unwrapGroups(ast.Root)
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
		node = unwrapGroups(consuming)
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
	node = unwrapGroups(node)
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
