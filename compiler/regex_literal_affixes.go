package compiler

import (
	"slices"

	"github.com/cawalch/go-yara/regex"
)

// Bound static prefix expansion, like the regex atom-cover analysis. Unsupported
// trees and over-budget prefixes retain their existing compiled policy.
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
	prefixes, ok := expandLiteralAtomPrefixes(parts[:selected])
	if !ok {
		return nil, nil
	}
	plan := &regexBoundedAlternation{Fullword: fullword}
	if !plan.appendAffixedBranches(prefixes, parts[selected].branches) {
		return nil, nil
	}
	// Only the prefix is enumerated. Alternatives after the selected atom must
	// retain forward priority, even when another endpoint would pass fullword.
	tail := &regex.Node{Kind: regex.NodeConcat}
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
		part := literalAtomPart{node: node, alternative: node.Kind == regex.NodeAlt}
		if part.alternative {
			scratch := &regexBoundedAlternation{}
			if err := scratch.appendPrefixes(node); err != nil {
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
		var next [][]byte
		seen := map[string]bool{}
		total := 0
		for _, prefix := range prefixes {
			for _, branch := range part.branches {
				literal := append(slices.Clone(prefix), branch.Literal...)
				if seen[string(literal)] {
					continue
				}
				total += len(literal)
				if len(next) == maxLiteralAffixPrefixes || total > maxLiteralAffixBytes {
					return nil, false
				}
				seen[string(literal)] = true
				next = append(next, literal)
			}
		}
		prefixes = next
	}
	return prefixes, true
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
	if node.Kind == regex.NodeLiteral || isLiteralRegexAlternation(node) {
		return append(nodes, node), true
	}
	return nil, false
}
