package compiler

import (
	"cmp"
	"slices"

	"github.com/cawalch/go-yara/regex"
)

// MatchContext holds pattern matching state
type MatchContext struct {
	Data             []byte
	Blocks           []MemoryBlock
	Matches          map[string][]Match // Pattern -> list of matches
	matchBuffers     map[string][]Match
	spans            map[string][]matchSpan
	spanBuffers      map[string][]matchSpan
	cancelDone       <-chan struct{}
	regexBatch       regex.VMBatch
	moduleCache      *moduleCallCache
	assertionResults []assertionResult
	FileSize         int64
	EntryPoint       int64
	// maxMatchesPerPattern bounds retained occurrences. Zero means unlimited.
	maxMatchesPerPattern int
	// maxMatchSpan bounds the maximum byte length of a single regex match. Zero means unlimited.
	maxMatchSpan int
	compact      bool
}

func (mc *MatchContext) dataRange(offset, size int64) ([]byte, bool) {
	if mc == nil || offset < 0 || size < 0 {
		return nil, false
	}
	if mc.Data != nil {
		if offset > int64(len(mc.Data)) || size > int64(len(mc.Data))-offset {
			return nil, false
		}
		return mc.Data[offset : offset+size], true
	}
	for _, block := range mc.Blocks {
		if offset < block.Base {
			continue
		}
		relative := offset - block.Base
		if relative <= int64(len(block.Data)) && size <= int64(len(block.Data))-relative {
			return block.Data[relative : relative+size], true
		}
	}
	return nil, false
}

// matchSpan is the scanner's compact representation of a match. Pattern is
// supplied by the containing map and public Match values are materialized only
// at the result boundary, keeping the evaluation hot path to offset and length.
type matchSpan struct {
	Offset int64
	Length int
}

// Match represents a pattern match
type Match struct {
	Pattern              string
	MatchedData          []byte
	ContextBefore        []byte
	ContextAfter         []byte
	Captures             []Capture
	Offset               int64
	Length               int
	Base                 int64 // Base address for match
	MatchedDataTruncated bool
}

// AddMatch adds a match to the context
func (mc *MatchContext) AddMatch(m Match) {
	if m.Pattern == "" {
		return
	}
	if mc.maxMatchesPerPattern > 0 && mc.matchCount(m.Pattern) >= mc.maxMatchesPerPattern {
		return
	}
	if mc.compact {
		mc.addMatchSpan(m.Pattern, matchSpan{Offset: m.Offset, Length: m.Length})
		return
	}
	if mc.Matches == nil {
		mc.Matches = make(map[string][]Match)
	}
	matches, exists := mc.Matches[m.Pattern]
	if !exists && mc.matchBuffers != nil {
		matches = mc.matchBuffers[m.Pattern]
	}
	mc.Matches[m.Pattern] = append(matches, m)
}

func (mc *MatchContext) addMatchSpan(id string, span matchSpan) {
	if id == "" {
		return
	}
	if mc.maxMatchesPerPattern > 0 && mc.matchCount(id) >= mc.maxMatchesPerPattern {
		return
	}
	if mc.spans == nil {
		mc.spans = make(map[string][]matchSpan)
	}
	spans, exists := mc.spans[id]
	if !exists && mc.spanBuffers != nil {
		spans = mc.spanBuffers[id]
	}
	mc.spans[id] = append(spans, span)
}

func (mc *MatchContext) matchCount(id string) int {
	if mc == nil {
		return 0
	}
	if mc.compact {
		return len(mc.spans[id])
	}
	return len(mc.Matches[id])
}

func (mc *MatchContext) matchAt(id string, index int) (matchSpan, bool) {
	if mc == nil || index < 0 {
		return matchSpan{}, false
	}
	if mc.compact {
		spans := mc.spans[id]
		if index >= len(spans) {
			return matchSpan{}, false
		}
		return spans[index], true
	}
	matches := mc.Matches[id]
	if index >= len(matches) {
		return matchSpan{}, false
	}
	return matchSpan{Offset: matches[index].Offset, Length: matches[index].Length}, true
}

func (mc *MatchContext) eachMatch(id string, visit func(matchSpan) bool) {
	if mc == nil || visit == nil {
		return
	}
	if mc.compact {
		for _, span := range mc.spans[id] {
			if !visit(span) {
				return
			}
		}
		return
	}
	for _, match := range mc.Matches[id] {
		if !visit(matchSpan{Offset: match.Offset, Length: match.Length}) {
			return
		}
	}
}

func (mc *MatchContext) anyMatch(id string, predicate func(matchSpan) bool) bool {
	found := false
	mc.eachMatch(id, func(span matchSpan) bool {
		if predicate(span) {
			found = true
			return false
		}
		return true
	})
	return found
}

// hasMatchAt returns true if string id has a match at targetOffset in O(log N) time.
func (mc *MatchContext) hasMatchAt(id string, targetOffset int64) bool {
	if mc == nil || targetOffset < 0 {
		return false
	}
	if mc.compact {
		return hasSpanAt(mc.spans[id], targetOffset)
	}
	return hasMatchObjAt(mc.Matches[id], targetOffset)
}

func hasSpanAt(spans []matchSpan, targetOffset int64) bool {
	n := len(spans)
	if n == 0 || spans[0].Offset > targetOffset || spans[n-1].Offset < targetOffset {
		return false
	}
	idx, found := slices.BinarySearchFunc(spans, targetOffset, func(span matchSpan, target int64) int {
		return cmp.Compare(span.Offset, target)
	})
	if found && idx < n {
		return true
	}
	if spans[0].Offset > spans[n-1].Offset {
		for _, span := range spans {
			if span.Offset == targetOffset {
				return true
			}
		}
	}
	return false
}

func hasMatchObjAt(matches []Match, targetOffset int64) bool {
	n := len(matches)
	if n == 0 || matches[0].Offset > targetOffset || matches[n-1].Offset < targetOffset {
		return false
	}
	idx, found := slices.BinarySearchFunc(matches, targetOffset, func(m Match, target int64) int {
		return cmp.Compare(m.Offset, target)
	})
	if found && idx < n {
		return true
	}
	if matches[0].Offset > matches[n-1].Offset {
		for _, m := range matches {
			if m.Offset == targetOffset {
				return true
			}
		}
	}
	return false
}

// hasMatchInRange returns true if string id has at least one match with Offset in [minOffset, maxOffset] in O(log N) time.
func (mc *MatchContext) hasMatchInRange(id string, minOffset, maxOffset int64) bool {
	if mc == nil || minOffset > maxOffset || maxOffset < 0 {
		return false
	}
	if mc.compact {
		return hasSpanInRange(mc.spans[id], minOffset, maxOffset)
	}
	return hasMatchObjInRange(mc.Matches[id], minOffset, maxOffset)
}

func hasSpanInRange(spans []matchSpan, minOffset, maxOffset int64) bool {
	n := len(spans)
	if n == 0 || spans[0].Offset > maxOffset || spans[n-1].Offset < minOffset {
		return false
	}
	idx, _ := slices.BinarySearchFunc(spans, minOffset, func(span matchSpan, target int64) int {
		return cmp.Compare(span.Offset, target)
	})
	if idx < n && spans[idx].Offset <= maxOffset {
		return true
	}
	if spans[0].Offset > spans[n-1].Offset {
		for _, span := range spans {
			if span.Offset >= minOffset && span.Offset <= maxOffset {
				return true
			}
		}
	}
	return false
}

func hasMatchObjInRange(matches []Match, minOffset, maxOffset int64) bool {
	n := len(matches)
	if n == 0 || matches[0].Offset > maxOffset || matches[n-1].Offset < minOffset {
		return false
	}
	idx, _ := slices.BinarySearchFunc(matches, minOffset, func(m Match, target int64) int {
		return cmp.Compare(m.Offset, target)
	})
	if idx < n && matches[idx].Offset <= maxOffset {
		return true
	}
	if matches[0].Offset > matches[n-1].Offset {
		for _, m := range matches {
			if m.Offset >= minOffset && m.Offset <= maxOffset {
				return true
			}
		}
	}
	return false
}

// hasProximity tests whether there exists a pair of matches (matchA, matchB) such that
// minDist <= matchB.Offset - matchA.Offset <= maxDist.
// Because matches are ordered monotonically by offset, this runs in O(N + M) time
// via a two-pointer linear scan with zero allocations.
//
//nolint:revive // argument-limit: internal helper requires (idA, idB, minDist, maxDist)
func (mc *MatchContext) hasProximity(idA, idB string, minDist, maxDist int64) bool {
	if mc == nil || minDist > maxDist {
		return false
	}
	if mc.compact {
		return hasProximitySpans(mc.spans[idA], mc.spans[idB], minDist, maxDist)
	}
	return hasProximityMatches(mc.Matches[idA], mc.Matches[idB], minDist, maxDist)
}

//nolint:revive // argument-limit: internal helper requires (spansA, spansB, minDist, maxDist)
func hasProximitySpans(spansA, spansB []matchSpan, minDist, maxDist int64) bool {
	nA, nB := len(spansA), len(spansB)
	if nA == 0 || nB == 0 {
		return false
	}
	if !isSortedSpans(spansA) {
		spansA = cloneAndSortSpans(spansA)
	}
	if !isSortedSpans(spansB) {
		spansB = cloneAndSortSpans(spansB)
	}
	i, j := 0, 0
	for i < nA && j < nB {
		diff := spansB[j].Offset - spansA[i].Offset
		switch {
		case diff < minDist:
			j++
		case diff > maxDist:
			i++
		default:
			return true
		}
	}
	return false
}

//nolint:revive // argument-limit: internal helper requires (matchesA, matchesB, minDist, maxDist)
func hasProximityMatches(matchesA, matchesB []Match, minDist, maxDist int64) bool {
	nA, nB := len(matchesA), len(matchesB)
	if nA == 0 || nB == 0 {
		return false
	}
	if !isSortedMatches(matchesA) {
		matchesA = cloneAndSortMatches(matchesA)
	}
	if !isSortedMatches(matchesB) {
		matchesB = cloneAndSortMatches(matchesB)
	}
	i, j := 0, 0
	for i < nA && j < nB {
		diff := matchesB[j].Offset - matchesA[i].Offset
		switch {
		case diff < minDist:
			j++
		case diff > maxDist:
			i++
		default:
			return true
		}
	}
	return false
}

func isSortedSpans(spans []matchSpan) bool {
	for k := 1; k < len(spans); k++ {
		if spans[k].Offset < spans[k-1].Offset {
			return false
		}
	}
	return true
}

func cloneAndSortSpans(spans []matchSpan) []matchSpan {
	cloned := slices.Clone(spans)
	slices.SortFunc(cloned, func(a, b matchSpan) int {
		if a.Offset < b.Offset {
			return -1
		}
		if a.Offset > b.Offset {
			return 1
		}
		return 0
	})
	return cloned
}

func isSortedMatches(matches []Match) bool {
	for k := 1; k < len(matches); k++ {
		if matches[k].Offset < matches[k-1].Offset {
			return false
		}
	}
	return true
}

func cloneAndSortMatches(matches []Match) []Match {
	cloned := slices.Clone(matches)
	slices.SortFunc(cloned, func(a, b Match) int {
		if a.Offset < b.Offset {
			return -1
		}
		if a.Offset > b.Offset {
			return 1
		}
		return 0
	})
	return cloned
}

func (mc *MatchContext) matchIDs() []string {
	if mc == nil {
		return nil
	}
	if mc.compact {
		ids := make([]string, 0, len(mc.spans))
		for id := range mc.spans {
			ids = append(ids, id)
		}
		return ids
	}
	ids := make([]string, 0, len(mc.Matches))
	for id := range mc.Matches {
		ids = append(ids, id)
	}
	return ids
}
