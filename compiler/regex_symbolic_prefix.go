package compiler

import "github.com/cawalch/go-yara/regex"

// Large finite prefix languages share VM states instead of materializing their
// strings. Each reachable boundary uses the existing atom/tail verifier.
//
//nolint:revive // verifier arguments keep the whole-match start explicit
func (plan *regexBoundedAlternation) execPrefix(bs *regex.VMBatch, data []byte, flags regex.Flags, start int, done <-chan struct{}) (int, boundedAtomOrder) {
	if len(plan.Branches) == 0 || plan.Fullword && !isFullwordStart(data, start, flags&regex.FlagsWide != 0) {
		return -1, boundedAtomOrder{}
	}
	ends, err := regex.ExecMatchEndsBatchWithCancel(bs, plan.Prefix, data, flags&^regex.FlagsFullwordEnd, start, done)
	if err != nil || len(ends) == 0 {
		return -1, boundedAtomOrder{}
	}
	bestEnd := -1
	var bestOrder boundedAtomOrder
	indices := plan.asciiOrder
	if flags&regex.FlagsWide != 0 {
		indices = plan.wideOrder
	}
	greedy := flags&regex.FlagsGreedy != 0
	bound := indices[0]
	if greedy {
		bound = indices[len(indices)-1]
	}
	atomEnd := plan.Branches[bound].baseOrder(bound, flags&regex.FlagsWide != 0).end
	for i := range ends {
		if greedy {
			i = len(ends) - 1 - i
		}
		pos := ends[i]
		// Prefix boundaries are ordered; once even the extremal atom end
		// cannot beat the winner, no remaining boundary needs verification.
		if bestEnd >= 0 && (greedy && pos-start+atomEnd < bestOrder.end || !greedy && pos-start+atomEnd > bestOrder.end) {
			break
		}
		if scanCanceled(done) {
			return -1, boundedAtomOrder{}
		}
		end, order := plan.execBranches(bs, data, flags, start, pos, done)
		if end >= 0 && (bestEnd < 0 || (flags&regex.FlagsGreedy != 0) == bestOrder.before(order)) {
			bestEnd, bestOrder = end, order
		}
	}
	return bestEnd, bestOrder
}

func compileSymbolicPrefix(parts []literalAtomPart) ([]byte, error) {
	prefix := &regex.Node{Kind: regex.NodeConcat}
	for _, part := range parts {
		if len(part.branches) == 0 || part.node.Kind == regex.NodePlus || part.node.Kind == regex.NodeStar ||
			part.node.Kind == regex.NodeRange && part.node.End == 65535 {
			return nil, nil
		}
		prefix.Children = append(prefix.Children, symbolicPrefixNode(part))
	}
	code, err := regex.Compile(&regex.AST{Root: prefix})
	if err == nil {
		return code, nil
	}
	// Class bitmaps can be larger than their split/literal encoding.
	// Keep valid source programs within the original bytecode budget.
	for i, part := range parts {
		prefix.Children[i] = part.node
	}
	return regex.Compile(&regex.AST{Root: prefix})
}

// Prefix verification needs the language, not branch priority or captures.
// Collapse one-byte alternatives into the existing class instruction, avoiding
// split/jump work for each byte. The original AST remains untouched.
func symbolicPrefixNode(part literalAtomPart) *regex.Node {
	if part.node.Kind != regex.NodeAlt {
		return part.node
	}
	class := &regex.Class{}
	for _, branch := range part.branches {
		if len(branch.Literal) != 1 {
			return part.node
		}
		value := branch.Literal[0]
		class.Bitmap[value/8] |= 1 << (value % 8)
	}
	return &regex.Node{Kind: regex.NodeClass, Class: class}
}
