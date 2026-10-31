package compiler

import (
	"slices"

	"github.com/cawalch/go-yara/regex"
)

// Bound static prefix expansion, like the regex atom-cover analysis. Large
// finite prefix languages use symbolic verification; unsupported trees retain
// their existing policy.
const (
	maxLiteralAffixPrefixes = 256
	maxLiteralAffixBytes    = 16 << 10
)

type literalAtomPart struct {
	node        *regex.Node
	branches    []boundedRegexBranch
	quality     int
	alternative bool
}

func compileLiteralAffixes(root *regex.Node, fullword, dual bool) (*regexBoundedAlternation, error) {
	if isLiteralRegexNode(root) {
		return nil, nil
	}
	nodes, ok := literalAffixNodes(nil, root)
	if !ok {
		return nil, nil
	}
	parts, overlap, err := literalAtomParts(nodes)
	if err != nil || !overlap || len(parts) < 2 {
		return nil, err
	}
	selected := selectLiteralAtomPart(parts)
	part := parts[selected]
	if part.quality < 0 {
		return nil, nil
	}
	// An unbounded repetition's own atoms require verification across every
	// copy. Only a winning prefix atom can use this finite-prefix plan.
	if part.node.Kind != regex.NodeAlt && part.alternative &&
		(part.node.Kind != regex.NodeRange || part.node.End == 65535) {
		return nil, nil
	}
	prefixes, ok := expandLiteralAtomPrefixes(parts[:selected])
	plan := &regexBoundedAlternation{Fullword: fullword}
	if !ok || !plan.appendAffixedBranches(prefixes, parts[selected].branches) {
		prefix := &regex.Node{Kind: regex.NodeConcat}
		for _, part := range parts[:selected] {
			if len(part.branches) == 0 || part.node.Kind == regex.NodePlus || part.node.Kind == regex.NodeStar ||
				part.node.Kind == regex.NodeRange && part.node.End == 65535 {
				return nil, nil
			}
			prefix.Children = append(prefix.Children, part.node)
		}
		plan.Prefix, err = regex.Compile(&regex.AST{Root: prefix})
		if err != nil {
			return nil, err
		}
		plan.Branches = parts[selected].branches
	}
	// Prefix paths may be enumerated or symbolic. Alternatives after the atom must
	// retain forward priority, even when another endpoint would pass fullword.
	tail := &regex.Node{Kind: regex.NodeConcat}
	if part.node.Kind == regex.NodeRange {
		tail.Children = append(tail.Children, &regex.Node{
			Kind: regex.NodeRange, Start: part.node.Start - 1, End: part.node.End - 1,
			Greedy: part.node.Greedy, Children: part.node.Children,
		})
	}
	for _, part := range parts[selected+1:] {
		tail.Children = append(tail.Children, part.node)
	}
	code, err := regex.Compile(&regex.AST{Root: tail})
	if err != nil {
		return nil, err
	}
	plan.Tail = code
	plan.prepareEncodingOrder(dual)
	return plan, nil
}

func literalAtomParts(nodes []*regex.Node) ([]literalAtomPart, bool, error) {
	var parts []literalAtomPart
	overlap := false
	for i := 0; i < len(nodes); {
		node := nodes[i]
		alt := literalAtomAlternation(node)
		part := literalAtomPart{node: node, alternative: alt != nil}
		if part.alternative {
			if !isLiteralRegexAlternation(alt) {
				// An atomless alternative can follow a selected prefix, but
				// cannot supply an atom or an enumerated backward prefix.
				part.quality = -1
				parts = append(parts, part)
				overlap = true
				i++
				continue
			}
			scratch := &regexBoundedAlternation{}
			if err := scratch.appendPrefixes(alt); err != nil {
				return nil, false, err
			}
			part.branches = scratch.Branches
			overlap = overlap || scratch.overlappingPrefixes()
			i++
		} else {
			start := i
			var literal []byte
			for i < len(nodes) && nodes[i].Kind == regex.NodeLiteral {
				literal = append(literal, nodes[i].Value)
				i++
			}
			part.node = &regex.Node{Kind: regex.NodeConcat, Children: nodes[start:i]}
			part.branches = []boundedRegexBranch{{Literal: literal, AtomOffset: regexLiteralAtomOffset(literal)}}
		}
		part.quality = bestLiteralAtomQuality(part.branches[0].Literal)
		for _, branch := range part.branches {
			part.quality = min(part.quality, bestLiteralAtomQuality(branch.Literal))
		}
		if node.Kind == regex.NodeStar || node.Kind == regex.NodeRange && node.Start == 0 {
			part.quality = -1 // Optional copies cannot provide a required atom.
		}
		parts = append(parts, part)
	}
	return parts, overlap, nil
}

// Libyara appends an alternative atom group before flushing the preceding
// literal run. The first highest-quality candidate wins, including those ties.
func selectLiteralAtomPart(parts []literalAtomPart) int {
	selected, quality := 0, -1
	consider := func(i int) {
		if parts[i].quality > quality {
			selected, quality = i, parts[i].quality
		}
	}
	for i, part := range parts {
		if part.alternative {
			consider(i)
			if i > 0 && !parts[i-1].alternative {
				consider(i - 1)
			}
		} else if i == len(parts)-1 {
			consider(i)
		}
	}
	return selected
}

func expandLiteralAtomPrefixes(parts []literalAtomPart) ([][]byte, bool) {
	prefixes := [][]byte{nil}
	for _, part := range parts {
		if len(part.branches) == 0 || part.node.Kind == regex.NodePlus || part.node.Kind == regex.NodeStar ||
			part.node.Kind == regex.NodeRange && part.node.End == 65535 {
			return nil, false
		}
		minCopies, maxCopies := 1, 1
		if part.node.Kind == regex.NodeRange {
			minCopies, maxCopies = int(part.node.Start), int(part.node.End)
		}
		shortest := len(part.branches[0].Literal)
		for _, branch := range part.branches {
			shortest = min(shortest, len(branch.Literal))
		}
		if minCopies > maxLiteralAffixBytes/shortest {
			return nil, false
		}
		var accepted literalPrefixSet
		for count := 0; ; count++ {
			if count >= minCopies {
				for _, prefix := range prefixes {
					if !accepted.add(prefix) {
						return nil, false
					}
				}
			}
			if count == maxCopies {
				break
			}
			var next literalPrefixSet
			for _, prefix := range prefixes {
				for _, branch := range part.branches {
					if !next.add(append(slices.Clone(prefix), branch.Literal...)) {
						return nil, false
					}
				}
			}
			prefixes = next.values
		}
		prefixes = accepted.values
	}
	return prefixes, true
}

type literalPrefixSet struct {
	values [][]byte
	seen   map[string]bool
	bytes  int
}

func (set *literalPrefixSet) add(literal []byte) bool {
	if set.seen[string(literal)] {
		return true
	}
	if len(set.values) == maxLiteralAffixPrefixes || set.bytes+len(literal) > maxLiteralAffixBytes {
		return false
	}
	if set.seen == nil {
		set.seen = make(map[string]bool)
	}
	set.seen[string(literal)] = true
	set.bytes += len(literal)
	set.values = append(set.values, literal)
	return true
}

func (plan *regexBoundedAlternation) appendAffixedBranches(prefixes [][]byte, branches []boundedRegexBranch) bool {
	total := 0
	// Branch-major order preserves the selected atom group's source order.
	// Duplicate prefix decompositions cannot change the endpoint at a fixed start.
	for _, branch := range branches {
		for _, prefix := range prefixes {
			total += len(prefix) + len(branch.Literal)
			if total > maxLiteralAffixBytes {
				return false
			}
			literal := append(slices.Clone(prefix), branch.Literal...)
			plan.Branches = append(plan.Branches, boundedRegexBranch{Literal: literal, AtomOffset: len(prefix) + branch.AtomOffset})
		}
	}
	return true
}

func literalAffixNodes(nodes []*regex.Node, node *regex.Node) ([]*regex.Node, bool) {
	node = ungroupRegexNode(node)
	if node.Kind == regex.NodeConcat {
		for _, child := range node.Children {
			var ok bool
			nodes, ok = literalAffixNodes(nodes, child)
			if !ok {
				return nil, false
			}
		}
		return nodes, true
	}
	if node.Kind == regex.NodeLiteral || literalAtomAlternation(node) != nil {
		return append(nodes, node), true
	}
	return nil, false
}

func literalAtomAlternation(node *regex.Node) *regex.Node {
	switch node.Kind {
	case regex.NodePlus, regex.NodeStar, regex.NodeRange:
		if len(node.Children) != 1 {
			return nil
		}
		body := ungroupRegexNode(node.Children[0])
		if body.Kind == regex.NodeAlt && !regexHasLiteralAtom(node) {
			return body
		}
		node = body
	}
	if isLiteralRegexAlternation(node) {
		return node
	}
	return nil
}
