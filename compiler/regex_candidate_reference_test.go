package compiler

import (
	"slices"

	"github.com/cawalch/go-yara/regex"
)

//nolint:revive // retain the pre-refactor collector as a differential oracle
func referenceRegexAtomCandidateStarts(
	data, atom []byte,
	pattern RegexPattern,
	flags regex.Flags,
	isWide bool,
	done <-chan struct{},
) ([]int, bool) {
	if pattern.atomASCIINoCase {
		flags |= regex.FlagsNoCase
	}
	searcher := newRegexLiteralSearcher(data, atom, flags)
	first := searcher.index(0)
	if first < 0 {
		return nil, true
	}
	if pattern.atomMaxOffset < 0 {
		return nil, false
	}

	limit := max(1024, len(data)/4)
	atomStarts := make([]int, 0, min(limit, 64))
	atomStarts = append(atomStarts, first)
	for checkpoint, searchFrom := 0, first+1; searchFrom <= len(data); checkpoint++ {
		if scanCanceledAt(done, checkpoint) {
			return nil, true
		}
		next := searcher.index(searchFrom)
		if next < 0 {
			break
		}
		atomStarts = append(atomStarts, next)
		if len(atomStarts) > limit {
			return nil, false
		}
		searchFrom = next + 1
	}

	minOffset := pattern.atomMinOffset
	step := 1
	if isWide {
		minOffset *= 2
		step = 2
	}

	fixedOffset := pattern.atomMinOffset == pattern.atomMaxOffset && !pattern.hasPrefixRepeat
	var starts []int
	if fixedOffset {
		// Each ordered atom hit yields at most one start at the same offset.
		// Filtering in place cannot overwrite an unread hit.
		starts = atomStarts[:0]
	} else {
		starts = make([]int, 0, min(limit, len(atomStarts)*2))
	}
	for _, atomStart := range atomStarts {
		effMaxOffset, ok := pattern.atomOccurrenceValid(data, atomStart, isWide)
		if !ok {
			continue
		}

		first := max(0, atomStart-effMaxOffset)
		last := min(len(data), atomStart-minOffset)
		if first > last {
			continue
		}
		if isWide && first&1 != atomStart&1 {
			first++
		}
		count := (last-first)/step + 1
		if count <= 0 || len(starts) > limit-count {
			return nil, false
		}
		for start := first; start <= last; start += step {
			if !pattern.startMatchesFirstByte(data, start, isWide) {
				continue
			}
			starts = append(starts, start)
		}
	}

	if fixedOffset || len(starts) < 2 {
		return starts, true
	}
	slices.Sort(starts)
	unique := 1
	for _, start := range starts[1:] {
		if start == starts[unique-1] {
			continue
		}
		starts[unique] = start
		unique++
	}
	return starts[:unique], true
}

//nolint:revive // cancellation signal stays explicit in the candidate hot path
func leadingGapRegexCandidateStarts(
	data []byte,
	plan *regexLeadingGapPlan,
	flags regex.Flags,
	done <-chan struct{},
) ([]int, bool) {
	return leadingGapRegexCandidateStartsInto(nil, data, plan, flags, done)
}

//nolint:revive // argument-limit: hot path avoids allocating an options struct
func regexAtomCandidateStarts(data, atom []byte, pattern RegexPattern, flags regex.Flags, isWide bool, done <-chan struct{}) ([]int, bool) {
	return regexAtomCandidateStartsInto(&MatchContext{}, data, atom, pattern, flags, isWide, done)
}

//nolint:revive // argument-limit: shared by local and Aho-Corasick candidate paths
func collectRegexCandidateStarts(
	atomStarts []int,
	minOffset, maxOffset int,
	isWide bool,
	dataLength, limit int,
) ([]int, bool) {
	return collectRegexCandidateStartsInto(nil, atomStarts, minOffset, maxOffset, isWide, dataLength, limit)
}
