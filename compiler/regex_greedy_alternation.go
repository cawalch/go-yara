package compiler

import "github.com/cawalch/go-yara/regex"

// greedyLiteralAlternation recognizes a repeated literal alternation with
// optional literal affixes, when its selected atoms permit exhaustive endpoints.
// Libyara can verify an atom in the last repetition (or suffix), then enumerate
// preceding repeats backwards. A forward-only verifier must retain alternative
// continuations to reach the same endpoint.
//
// Do not generalize this to arbitrary greedy expressions: a preceding literal
// can become the selected atom, leaving branch priority to the forward VM.
func greedyLiteralAlternation(parsed *regex.AST, flags regex.Flags, fullword bool) bool {
	node := ungroupRegexNode(parsed.Root)
	var prefix, suffix []*regex.Node
	if node.Kind == regex.NodeConcat {
		children := node.Children
		i := 0
		for i < len(children) && isLiteralRegexNode(children[i]) {
			i++
		}
		if i == len(children) {
			return false
		}
		prefix, suffix = children[:i], children[i+1:]
		node = ungroupRegexNode(children[i])
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
	alternatives := regex.LiteralAlternatives(&regex.AST{Root: node.Children[0]})
	if len(prefix) > 0 && !repeatAtomPermitsExhaustive(node, prefix, suffix, alternatives, flags, fullword) {
		return false
	}
	// Prefix-free branches already reach the same endpoint with priority
	// execution. Fold ASCII here so nocase patterns get the same protection.
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

// Bare lazy literal pluses supply an atom in each repetition. Word-only
// alternatives can also retry: every intermediate endpoint is followed by a
// word character, so at most one endpoint per start can pass fullword. Branch
// length and atom order cannot change that accepted endpoint. Nonword branches
// can expose several boundaries and still need atom-specific verification.
func lazyFullwordPlus(parsed *regex.AST) bool {
	node := ungroupRegexNode(parsed.Root)
	if node.Kind != regex.NodePlus || node.Greedy || len(node.Children) != 1 {
		return false
	}
	if isLiteralRegexNode(node.Children[0]) {
		return true
	}
	if !isLiteralRegexAlternation(node.Children[0]) {
		return false
	}
	// Inspect all literal leaves without depending on atom-extraction budgets.
	for _, b := range appendLiteralRegexBytes(nil, node.Children[0]) {
		if !isWordChar(b) {
			return false
		}
	}
	return true
}

// A suffix atom permits exhaustive backward verification. A repetition atom
// also does so when it covers each branch: its end then orders candidates
// by their accepted endpoint. Fullword additionally requires word-only branches.
// Longer branches can end after a later atom and must retain the existing
// policy until atom-specific verification is available.
//
//nolint:revive // atom selection compares both affixes, branches, and encoding
func repeatAtomPermitsExhaustive(node *regex.Node, prefix, suffix []*regex.Node, alternatives []regex.LiteralAtom, flags regex.Flags, fullword bool) bool {
	prefixQuality := literalSequenceQuality(prefix)
	suffixQuality := literalSequenceQuality(suffix)
	altQuality, atomCoversBranches := -1, true
	if node.Kind == regex.NodePlus && len(alternatives) > 0 {
		altQuality = bestLiteralAtomQuality(alternatives[0].Data)
		width := 4
		if flags&regex.FlagsWide != 0 {
			width = 2
		}
		for _, branch := range alternatives {
			altQuality = min(altQuality, bestLiteralAtomQuality(branch.Data))
			atomCoversBranches = atomCoversBranches && len(branch.Data) <= width
			// Word-only branches cannot expose an earlier fullword boundary
			// inside a continuation that the forward VM would greedily reject.
			for _, b := range branch.Data {
				atomCoversBranches = atomCoversBranches && (!fullword || isWordChar(b))
			}
		}
	}
	// The alternative atom set is visited before the pending prefix leaf, so
	// it wins equal-quality ties. The suffix follows both and needs higher quality.
	if suffixQuality > max(prefixQuality, altQuality) {
		return true
	}
	return altQuality >= prefixQuality && atomCoversBranches
}

func literalSequenceQuality(nodes []*regex.Node) int {
	var data []byte
	for _, node := range nodes {
		data = appendLiteralRegexBytes(data, node)
	}
	return bestLiteralAtomQuality(data)
}

func appendLiteralRegexBytes(data []byte, node *regex.Node) []byte {
	node = ungroupRegexNode(node)
	if node.Kind == regex.NodeLiteral {
		return append(data, node.Value)
	}
	for _, child := range node.Children {
		data = appendLiteralRegexBytes(data, child)
	}
	return data
}

func bestLiteralAtomQuality(data []byte) int {
	if len(data) == 0 {
		return -1
	}
	offset := regexLiteralAtomOffset(data)
	return regexLiteralAtomQuality(data[offset : offset+min(4, len(data))])
}
