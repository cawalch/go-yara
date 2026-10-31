package compiler

import "github.com/cawalch/go-yara/regex"

// greedyLiteralAlternation recognizes a repeated literal alternation followed
// by an optional literal suffix, with no preceding input. Libyara can verify
// an atom in the last repetition (or suffix), then enumerate preceding repeats
// backwards. Its greedy occurrence list keeps the longest match at each start.
// A forward-only verifier must retain alternative continuations to find it.
//
// Do not generalize this to arbitrary greedy expressions: a preceding literal
// can become the selected atom, leaving branch priority to the forward VM.
func greedyLiteralAlternation(parsed *regex.AST) bool {
	node := ungroupRegexNode(parsed.Root)
	var suffix []*regex.Node
	if node.Kind == regex.NodeConcat {
		suffix = node.Children[1:]
		node = ungroupRegexNode(node.Children[0])
	}
	if !node.Greedy || len(node.Children) != 1 {
		return false
	}
	switch node.Kind {
	case regex.NodePlus:
	case regex.NodeStar:
		if len(suffix) == 0 {
			return false // No required atom; libyara uses forward priority.
		}
	default:
		return false
	}
	for _, part := range suffix {
		if !isLiteralRegexNode(part) {
			return false
		}
	}
	if !isLiteralRegexAlternation(node.Children[0]) {
		return false
	}
	// Prefix-free branches already reach the same endpoint with priority
	// execution. Fold ASCII here so nocase patterns get the same protection.
	alternatives := regex.LiteralAlternatives(&regex.AST{Root: node.Children[0]})
	for _, shorter := range alternatives {
		for _, longer := range alternatives {
			if len(shorter.Data) < len(longer.Data) && equalRegexPrefixFold(longer.Data, shorter.Data, false) {
				return true
			}
		}
	}
	return false
}

func isLiteralRegexAlternation(node *regex.Node) bool {
	node = ungroupRegexNode(node)
	if node.Kind != regex.NodeAlt || len(node.Children) < 2 {
		return false
	}
	for _, child := range node.Children {
		if !isLiteralRegexNode(child) && !isLiteralRegexAlternation(child) {
			return false
		}
	}
	return true
}

func ungroupRegexNode(node *regex.Node) *regex.Node {
	for node.Kind == regex.NodeGroup && len(node.Children) == 1 {
		node = node.Children[0]
	}
	return node
}

func isLiteralRegexNode(node *regex.Node) bool {
	node = ungroupRegexNode(node)
	if node.Kind == regex.NodeLiteral {
		return true
	}
	if node.Kind != regex.NodeConcat || len(node.Children) == 0 {
		return false
	}
	for _, child := range node.Children {
		if !isLiteralRegexNode(child) {
			return false
		}
	}
	return true
}
