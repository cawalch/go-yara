package compiler

import "slices"

// regexCandidateRange keeps raw range counts (before filtering/deduplication)
// so all collectors retain their existing candidate-budget fallback behavior.
//
//nolint:revive // offsets, input bound, and encoding step define the range
func regexCandidateRange(atomStart, minOffset, maxOffset, dataLength, step int) (first, last, count int) {
	first = max(0, atomStart-maxOffset)
	last = min(dataLength, atomStart-minOffset)
	if first > last {
		return first, last, 0
	}
	if step == 2 && first&1 != atomStart&1 {
		first++
	}
	return first, last, (last-first)/step + 1
}

func sortedUniqueRegexStarts(starts []int) []int {
	slices.Sort(starts)
	return slices.Compact(starts)
}

// Bound each retained buffer to 32 KiB on 64-bit platforms. Candidate and
// atom-hit storage are separate so expansion cannot overwrite unread hits.
func retainedRegexCandidates(starts []int) []int {
	if cap(starts) > 4096 {
		return nil
	}
	return starts[:0]
}

func (ctx *MatchContext) retainRegexCandidates(starts []int) {
	ctx.regexCandidates = retainedRegexCandidates(starts)
}

// verifySortedCandidateStarts streams deduplicated step-1 candidate starts
// without materializing an intermediate slice. Returns (false, false) if
// candidates are unsorted or exceed limit.
//
//nolint:revive // argument-limit: hot-path avoids slice allocation
func verifySortedCandidateStarts(
	candidates []int,
	minOffset, maxOffset, dataLength, limit int,
	done <-chan struct{},
	verify func(start int),
) (handled, canceled bool) {
	prev := -1
	totalCount := 0
	for _, atomStart := range candidates {
		if atomStart < prev {
			return false, false
		}
		prev = atomStart
		_, _, count := regexCandidateRange(atomStart, minOffset, maxOffset, dataLength, 1)
		if count < 0 || totalCount > limit-count {
			return false, false
		}
		totalCount += count
	}
	nextMin := 0
	verified := 0
	for _, atomStart := range candidates {
		first, last, count := regexCandidateRange(atomStart, minOffset, maxOffset, dataLength, 1)
		if count == 0 {
			continue
		}
		start := max(first, nextMin)
		for ; start <= last; start++ {
			if scanCanceledAt(done, verified) {
				return true, true
			}
			verify(start)
			verified++
		}
		if last+1 > nextMin {
			nextMin = last + 1
		}
	}
	return true, false
}
