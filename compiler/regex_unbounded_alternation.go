package compiler

import (
	"slices"
	"sync"

	"github.com/cawalch/go-yara/regex"
)

// A repeated language is represented by its literal branches, not by expanded
// prefix paths. Candidate ordering remains in the enclosing atom plan.
type regexRepeatPlan struct {
	Prefix, Suffix                 []byte
	Branches                       []boundedRegexBranch
	Greedy, AtomInRepeat, Required bool
	maxLength                      int
}

func compileUnboundedAlternation(parsed *regex.AST, fullword, dual bool) (*regexBoundedAlternation, error) {
	if parsed == nil {
		return nil, nil
	}
	nodes, ok := literalAffixNodes(nil, parsed.Root)
	if !ok {
		return nil, nil
	}
	parts, overlap, err := literalAtomParts(nodes)
	if err != nil {
		return nil, err
	}
	repeatIndex := -1
	for i, part := range parts {
		if part.node.Kind == regex.NodePlus || part.node.Kind == regex.NodeStar {
			if repeatIndex >= 0 || len(part.branches) == 0 {
				return nil, nil
			}
			repeatIndex = i
		} else if part.alternative {
			return nil, nil
		}
	}
	if repeatIndex < 0 || !overlap && !fullword && !dual {
		return nil, nil
	}
	selected := selectLiteralAtomPart(parts)
	if selected < repeatIndex || parts[selected].quality < 0 {
		return nil, nil
	}
	repeated := parts[repeatIndex]
	rp := &regexRepeatPlan{Branches: repeated.branches, Greedy: repeated.node.Greedy, AtomInRepeat: selected == repeatIndex, Required: repeated.node.Kind == regex.NodePlus}
	for _, part := range parts[:repeatIndex] {
		rp.Prefix = appendLiteralRegexBytes(rp.Prefix, part.node)
	}
	for _, part := range parts[repeatIndex+1:] {
		rp.Suffix = appendLiteralRegexBytes(rp.Suffix, part.node)
	}
	plan := &regexBoundedAlternation{Branches: parts[selected].branches, Repeat: rp, Fullword: fullword}
	plan.prepareEncodingOrder(dual)
	return plan, nil
}

func cloneRepeatPlan(plan *regexRepeatPlan) *regexRepeatPlan {
	if plan == nil {
		return nil
	}
	cloned := &regexRepeatPlan{Prefix: slices.Clone(plan.Prefix), Suffix: slices.Clone(plan.Suffix), Branches: slices.Clone(plan.Branches), Greedy: plan.Greedy, AtomInRepeat: plan.AtomInRepeat, Required: plan.Required}
	for i := range cloned.Branches {
		cloned.Branches[i].Literal = slices.Clone(cloned.Branches[i].Literal)
	}
	return cloned
}

type repeatScratch struct {
	reachable []uint64
	ends      []int
}

var repeatScratchPool = sync.Pool{New: func() any { return &repeatScratch{} }}

func (s *repeatScratch) mark(index int) {
	word := index / 64
	for len(s.reachable) <= word {
		s.reachable = append(s.reachable, 0)
	}
	s.reachable[word] |= uint64(1) << uint(index%64)
}
func (s *repeatScratch) has(index int) bool {
	return index >= 0 && index/64 < len(s.reachable) && s.reachable[index/64]&(uint64(1)<<uint(index%64)) != 0
}
func (s *repeatScratch) release() {
	// mark zeroes every word as it restores the slice length.
	s.reachable = s.reachable[:0]
	if cap(s.reachable) > 1<<16 {
		s.reachable = nil
	}
	if cap(s.ends) > 4096 {
		s.ends = nil
	}
	repeatScratchPool.Put(s)
}

// Reachability uses one bit per input unit. Only the next max-branch-length
// continuation results are needed by the backwards dynamic-programming pass.
// No candidate runs another regex VM over an already-verified suffix.
//
//nolint:revive // exact verifier parameters avoid an options allocation
func (plan *regexBoundedAlternation) execRepeat(data []byte, flags regex.Flags, start int, done <-chan struct{}) (int, boundedAtomOrder) {
	rp := plan.Repeat
	wide := flags&regex.FlagsWide != 0
	if plan.Fullword && !isFullwordStart(data, start, wide) {
		return -1, boundedAtomOrder{}
	}
	base, ok := boundedLiteralEnd(data, start, rp.Prefix, flags)
	if !ok {
		return -1, boundedAtomOrder{}
	}
	step := 1
	if wide {
		step = 2
	}
	scratch := repeatScratchPool.Get().(*repeatScratch)
	defer scratch.release()
	scratch.mark(0)
	frontier := 0
	// With an empty lazy continuation, the first copy always accepts. Every
	// later copy has a later atom end, so it cannot replace that first event.
	firstCopy := !rp.Greedy && !plan.Fullword && len(rp.Suffix) == 0
	for pos := 0; !firstCopy && pos <= frontier; pos++ {
		if scanCanceled(done) {
			return -1, boundedAtomOrder{}
		}
		if !scratch.has(pos) {
			continue
		}
		for _, branch := range rp.Branches {
			end, matched := boundedLiteralEnd(data, base+pos*step, branch.Literal, flags)
			if matched {
				next := (end - base) / step
				scratch.mark(next)
				frontier = max(frontier, next)
			}
		}
	}
	size := min(rp.maxLength, frontier) + 1
	if cap(scratch.ends) < size {
		scratch.ends = make([]int, size)
	} else {
		scratch.ends = scratch.ends[:size]
	}
	for i := range scratch.ends {
		scratch.ends[i] = -1
	}
	bestEnd := -1
	var bestOrder boundedAtomOrder
	for pos := frontier; pos >= 0; pos-- {
		if scanCanceled(done) {
			return -1, boundedAtomOrder{}
		}
		if !scratch.has(pos) {
			scratch.ends[pos%size] = -1
			continue
		}
		absolute := base + pos*step
		suffixEnd, suffixMatch := boundedLiteralEnd(data, absolute, rp.Suffix, flags)
		continuation := -1
		if suffixMatch {
			continuation = suffixEnd
		}
		// Forward branch priority is independent of the selected atom's rank.
		follow := rp.Greedy || continuation < 0
		for i, branch := range plan.Branches {
			next, matches := boundedLiteralEnd(data, absolute, branch.Literal, flags)
			if !matches {
				continue
			}
			end := next
			if rp.AtomInRepeat && !firstCopy {
				unit := (next - base) / step
				if unit > frontier || !scratch.has(unit) {
					continue
				}
				end = scratch.ends[unit%size]
				// Selected body atoms are already visited in source order; reuse
				// their verification for the forward continuation as well.
				if follow && end >= 0 {
					continuation, follow = end, false
				}
			} else if !rp.AtomInRepeat && rp.Required && pos == 0 {
				continue
			}
			if end < 0 || plan.Fullword && !isFullwordMatch(data, start, end-start, wide) {
				continue
			}
			order := branch.order(data, absolute, i, wide)
			order.end += absolute - start
			if bestEnd < 0 || (flags&regex.FlagsGreedy != 0) == bestOrder.before(order) {
				bestEnd, bestOrder = end, order
			}
		}
		scratch.ends[pos%size] = continuation
	}
	return bestEnd, bestOrder
}
