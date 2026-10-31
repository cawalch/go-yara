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
