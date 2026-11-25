package compiler

import (
	"cmp"
	"slices"

	"github.com/cawalch/go-yara/regex"
)

// MatchContext holds pattern matching state
type MatchContext struct {
	Data                      []byte
	Blocks                    []MemoryBlock
	Matches                   map[string][]Match // Pattern -> list of matches (populated by BuildMatchContext/PopulateMatchContext)
	slotRule                  *CompiledRule
	spansByIndex              [][]matchSpan
	touchedSlots              []int
	spans                     map[string][]matchSpan
	spanBuffers               map[string][]matchSpan
	cancelDone                <-chan struct{}
	regexAtomHits             []int
	regexCandidates           []int
	regexVerifiedStarts       map[int]regexVerifiedSpan
	regexBatch                regex.VMBatch
	moduleCache               *moduleCallCache
	assertionResults          []assertionResult
	externalValues            map[string]externalValue
	FileSize                  int64
	EntryPoint                int64
	HasEntryPoint             bool
	entryPointChecked         bool
	verificationBudgetRejects uint32
	// maxMatchesPerPattern bounds retained occurrences. Zero means unlimited.
	maxMatchesPerPattern int
	// matchFilter rejects provisional streaming occurrences before retention.
	matchFilter func(string, matchSpan) bool
	// maxMatchSpan bounds the maximum byte length of a single regex match. Zero means unlimited.
	maxMatchSpan int
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
	mc.addMatchSpan(m.Pattern, matchSpan{Offset: m.Offset, Length: m.Length})
}

func (mc *MatchContext) hasSpans() bool {
	if mc == nil {
		return false
	}
	if mc.slotRule != nil {
		for _, slot := range mc.touchedSlots {
			if slot >= 0 && slot < len(mc.spansByIndex) && len(mc.spansByIndex[slot]) > 0 {
				return true
			}
		}
		return false
	}
	return len(mc.spans) > 0
}

func (mc *MatchContext) spansForSlot(slot int, id string) []matchSpan {
	if mc == nil {
		return nil
	}
	if mc.slotRule != nil {
		if slot >= 0 && slot < len(mc.spansByIndex) {
			return mc.spansByIndex[slot]
		}
		return nil
	}
	return mc.spans[id]
}

func (mc *MatchContext) spansFor(id string) []matchSpan {
	if mc == nil {
		return nil
	}
	if mc.slotRule != nil {
		if slot, ok := mc.slotRule.StringIDToIndex[id]; ok && slot >= 0 && slot < len(mc.spansByIndex) {
			return mc.spansByIndex[slot]
		}
		return nil
	}
	return mc.spans[id]
}

func (mc *MatchContext) forEachSpanSlice(fn func(id string, spans []matchSpan)) {
	if mc == nil {
		return
	}
	if mc.slotRule != nil {
		for _, slot := range mc.touchedSlots {
			if slot >= 0 && slot < len(mc.spansByIndex) && len(mc.spansByIndex[slot]) > 0 {
				fn(mc.slotRule.IndexToStringID[slot], mc.spansByIndex[slot])
			}
		}
		return
	}
	for id, spans := range mc.spans {
		if len(spans) > 0 {
			fn(id, spans)
		}
	}
}

func (mc *MatchContext) addMatchSpansSlot(slot int, id string, matches []matchSpan) {
	if len(matches) == 0 {
		return
	}
	if mc.slotRule != nil && slot >= 0 && slot < len(mc.spansByIndex) {
		if mc.maxMatchesPerPattern <= 0 && mc.matchFilter == nil {
			if len(mc.spansByIndex[slot]) == 0 {
				mc.touchedSlots = append(mc.touchedSlots, slot)
			}
			mc.spansByIndex[slot] = append(mc.spansByIndex[slot], matches...)
			return
		}
		for _, match := range matches {
			mc.addMatchSpanSlot(slot, id, match)
		}
		return
	}
	for _, match := range matches {
		mc.addMatchSpan(id, match)
	}
}

func (mc *MatchContext) addMatchSpanSlot(slot int, id string, span matchSpan) {
	if slot < 0 || slot >= len(mc.spansByIndex) {
		return
	}
	existing := mc.spansByIndex[slot]
	if mc.maxMatchesPerPattern > 0 && len(existing) >= mc.maxMatchesPerPattern {
		return
	}
	if mc.matchFilter != nil && !mc.matchFilter(id, span) {
		return
	}
	if len(existing) == 0 {
		mc.touchedSlots = append(mc.touchedSlots, slot)
	}
	mc.spansByIndex[slot] = append(existing, span)
}

func (mc *MatchContext) addMatchSpan(id string, span matchSpan) {
	if id == "" {
		return
	}
	if mc.slotRule != nil {
		if slot, ok := mc.slotRule.StringIDToIndex[id]; ok {
			mc.addMatchSpanSlot(slot, id, span)
			return
		}
	}
	if mc.maxMatchesPerPattern > 0 && mc.matchCount(id) >= mc.maxMatchesPerPattern {
		return
	}
	if mc.matchFilter != nil && !mc.matchFilter(id, span) {
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
	if !mc.hasSpans() && len(mc.Matches) > 0 {
		return len(mc.Matches[id])
	}
	return len(mc.spansFor(id))
}

func (mc *MatchContext) matchCountSlot(slot int, id string) int {
	if mc == nil {
		return 0
	}
	if mc.slotRule != nil && slot >= 0 && slot < len(mc.spansByIndex) {
		return len(mc.spansByIndex[slot])
	}
	return mc.matchCount(id)
}

func (mc *MatchContext) matchAt(id string, index int) (matchSpan, bool) {
	if mc == nil || index < 0 {
		return matchSpan{}, false
	}
	if !mc.hasSpans() && len(mc.Matches) > 0 {
		matches := mc.Matches[id]
		if index >= len(matches) {
			return matchSpan{}, false
		}
		return matchSpan{Offset: matches[index].Offset, Length: matches[index].Length}, true
	}
	spans := mc.spansFor(id)
	if index >= len(spans) {
		return matchSpan{}, false
	}
	return spans[index], true
}

func (mc *MatchContext) eachMatch(id string, visit func(matchSpan) bool) {
	if mc == nil || visit == nil {
		return
	}
	if !mc.hasSpans() && len(mc.Matches) > 0 {
		for _, match := range mc.Matches[id] {
			if !visit(matchSpan{Offset: match.Offset, Length: match.Length}) {
				return
			}
		}
		return
	}
	for _, span := range mc.spansFor(id) {
		if !visit(span) {
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
	return mc.hasMatchInRange(id, targetOffset, targetOffset)
}

func (mc *MatchContext) hasMatchAtSlot(slot int, id string, targetOffset int64) bool {
	if mc == nil || targetOffset < 0 {
		return false
	}
	if mc.slotRule != nil && slot >= 0 && slot < len(mc.spansByIndex) {
		return hasSpanInRange(mc.spansByIndex[slot], targetOffset, targetOffset)
	}
	return mc.hasMatchAt(id, targetOffset)
}

// hasMatchInRange returns true if string id has at least one match with Offset in [minOffset, maxOffset] in O(log N) time.
func (mc *MatchContext) hasMatchInRange(id string, minOffset, maxOffset int64) bool {
	if mc == nil || minOffset > maxOffset || maxOffset < 0 {
		return false
	}
	if !mc.hasSpans() && len(mc.Matches) > 0 {
		for _, m := range mc.Matches[id] {
			if m.Offset >= minOffset && m.Offset <= maxOffset {
				return true
			}
		}
		return false
	}
	return hasSpanInRange(mc.spansFor(id), minOffset, maxOffset)
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
	if !mc.hasSpans() && len(mc.Matches) > 0 {
		return hasProximitySpans(matchesToSpans(mc.Matches[idA]), matchesToSpans(mc.Matches[idB]), minDist, maxDist)
	}
	return hasProximitySpans(mc.spansFor(idA), mc.spansFor(idB), minDist, maxDist)
}

func matchesToSpans(matches []Match) []matchSpan {
	if len(matches) == 0 {
		return nil
	}
	spans := make([]matchSpan, len(matches))
	for i, m := range matches {
		spans[i] = matchSpan{Offset: m.Offset, Length: m.Length}
	}
	return spans
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

func (mc *MatchContext) matchIDs() []string {
	if mc == nil {
		return nil
	}
	if !mc.hasSpans() && len(mc.Matches) > 0 {
		ids := make([]string, 0, len(mc.Matches))
		for id := range mc.Matches {
			ids = append(ids, id)
		}
		return ids
	}
	if mc.slotRule != nil {
		ids := make([]string, 0, len(mc.touchedSlots))
		for _, slot := range mc.touchedSlots {
			if slot >= 0 && slot < len(mc.spansByIndex) && len(mc.spansByIndex[slot]) > 0 {
				ids = append(ids, mc.slotRule.IndexToStringID[slot])
			}
		}
		return ids
	}
	ids := make([]string, 0, len(mc.spans))
	for id := range mc.spans {
		ids = append(ids, id)
	}
	return ids
}
