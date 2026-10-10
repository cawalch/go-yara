package compiler

import (
	"context"
	"fmt"
	"math"
	"slices"

	"github.com/cawalch/go-yara/regex"
)

func (s *Scanner) getNonTextMatches(
	cache *nonTextMatchCache,
	index int,
	useSharedAutomaton bool,
) ([]matchSpan, bool) {
	if matches, ready := cache.get(index); ready {
		return matches, true
	}
	if useSharedAutomaton && index >= 0 && index < len(s.program.sharedNonTextCaches) &&
		s.program.sharedNonTextCaches[index] {
		return nil, true
	}
	return nil, false
}

// extractGlobalMatchesInt uses the SharedLookup table for O(1) integer routing
// instead of parsing colon-delimited string IDs.
func (s *Scanner) extractGlobalMatchesInt(
	ctx context.Context,
	data []byte,
) error {
	lookup := s.program.SharedLookup
	rules := s.program.Rules
	globalByRule := s.globalMatches
	fastSeen := s.fastSeen
	if s.fastScan {
		if fastSeen == nil {
			fastSeen = make(map[uint64]bool)
			s.fastSeen = fastSeen
		} else {
			clear(fastSeen)
		}
	}
	// Keep the non-cancellable iterator as a distinct branch: routing an
	// iterator through an interface adds two allocations to clean Matches calls.
	//nolint:nestif // duplicated hot paths preserve the zero-allocation default
	if ctx.Done() == nil {
		for match := range s.program.SharedAutomaton.SearchIter(data) {
			if match.StringIndex < 0 || match.StringIndex >= len(lookup) {
				continue
			}

			entry := lookup[match.StringIndex]
			if entry.Kind == StringKindRegex || entry.Kind == StringKindHex {
				if len(s.prefilterCandidates[match.StringIndex]) == 0 {
					s.touchedPrefilterCandidates = append(s.touchedPrefilterCandidates, match.StringIndex)
				}
				s.prefilterCandidates[match.StringIndex] = append(
					s.prefilterCandidates[match.StringIndex],
					match.Backtrack,
				)
				continue
			}
			if entry.RuleIndex < 0 || entry.RuleIndex >= len(rules) {
				continue
			}

			rule := rules[entry.RuleIndex]
			if entry.StringIdx < 0 || entry.StringIdx >= len(rule.IndexToStringID) {
				continue
			}

			info := s.program.SharedAutomaton.strings[match.StringIndex]
			strID := rule.IndexToStringID[entry.StringIdx]
			globalEntry := globalMatchEntry{
				strID:    strID,
				span:     matchSpan{Offset: int64(match.Backtrack), Length: info.Length},
				isWide:   (info.Flags & regex.FlagsWide) != 0,
				isNocase: (info.Flags & regex.FlagsNoCase) != 0,
				pattern:  info.Data,
			}
			if s.fastScan && rule.FastScanSafe {
				key, ok := packFastScanKey(entry.RuleIndex, entry.StringIdx)
				if !ok {
					continue
				}
				if fastSeen[key] {
					continue
				}
				candidate := Match{
					Pattern: strID,
					Offset:  globalEntry.span.Offset,
					Length:  globalEntry.span.Length,
				}
				if !verifyTextMatch(data, candidate, globalEntry.pattern, globalEntry.isNocase) ||
					!matchPassesModifiers(data, candidate, rule.StringModifiers[strID], globalEntry.isWide) {
					continue
				}
				fastSeen[key] = true
			}
			if len(globalByRule[entry.RuleIndex]) == 0 {
				s.touchedGlobalMatches = append(s.touchedGlobalMatches, entry.RuleIndex)
			}
			globalByRule[entry.RuleIndex] = append(globalByRule[entry.RuleIndex], globalEntry)
			s.markCandidateRule(entry.RuleIndex)
		}
	} else {
		for match := range s.program.SharedAutomaton.searchIterWithCancel(data, ctx.Done()) {
			if match.StringIndex < 0 || match.StringIndex >= len(lookup) {
				continue
			}

			entry := lookup[match.StringIndex]
			if entry.Kind == StringKindRegex || entry.Kind == StringKindHex {
				if len(s.prefilterCandidates[match.StringIndex]) == 0 {
					s.touchedPrefilterCandidates = append(s.touchedPrefilterCandidates, match.StringIndex)
				}
				s.prefilterCandidates[match.StringIndex] = append(
					s.prefilterCandidates[match.StringIndex],
					match.Backtrack,
				)
				continue
			}
			if entry.RuleIndex < 0 || entry.RuleIndex >= len(rules) {
				continue
			}

			rule := rules[entry.RuleIndex]
			if entry.StringIdx < 0 || entry.StringIdx >= len(rule.IndexToStringID) {
				continue
			}

			info := s.program.SharedAutomaton.strings[match.StringIndex]
			strID := rule.IndexToStringID[entry.StringIdx]
			globalEntry := globalMatchEntry{
				strID:    strID,
				span:     matchSpan{Offset: int64(match.Backtrack), Length: info.Length},
				isWide:   (info.Flags & regex.FlagsWide) != 0,
				isNocase: (info.Flags & regex.FlagsNoCase) != 0,
				pattern:  info.Data,
			}
			if s.fastScan && rule.FastScanSafe {
				key, ok := packFastScanKey(entry.RuleIndex, entry.StringIdx)
				if !ok {
					continue
				}
				if fastSeen[key] {
					continue
				}
				candidate := Match{
					Pattern: strID,
					Offset:  globalEntry.span.Offset,
					Length:  globalEntry.span.Length,
				}
				if !verifyTextMatch(data, candidate, globalEntry.pattern, globalEntry.isNocase) ||
					!matchPassesModifiers(data, candidate, rule.StringModifiers[strID], globalEntry.isWide) {
					continue
				}
				fastSeen[key] = true
			}
			if len(globalByRule[entry.RuleIndex]) == 0 {
				s.touchedGlobalMatches = append(s.touchedGlobalMatches, entry.RuleIndex)
			}
			globalByRule[entry.RuleIndex] = append(globalByRule[entry.RuleIndex], globalEntry)
			s.markCandidateRule(entry.RuleIndex)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.populateNonTextPrefilterCache(ctx, data, &s.nonTextCache)
}

// addStaticMatchesInt adds matches routed by integer indices to the match context.
//
//nolint:revive // hot path keeps prepared match state explicit
func (s *Scanner) addStaticMatchesInt(
	ctx context.Context,
	rule *CompiledRule,
	data []byte,
	entries []globalMatchEntry,
) error {
	done := ctx.Done()
	for index, e := range entries {
		if scanCanceledAt(done, index) {
			return ctx.Err()
		}
		if s.matchCtx.maxMatchesPerPattern > 0 && s.matchCtx.matchCount(e.strID) > 0 {
			continue
		}
		m := Match{Pattern: e.strID, Offset: e.span.Offset, Length: e.span.Length}
		// Re-verify the candidate bytes against the stored pattern. The shared
		// automaton registers both ASCII cases for nocase strings, so a
		// case-sensitive string whose output state lies on a nocase path could
		// fire on the wrong case; reject those false candidates here.
		if !verifyTextMatch(data, m, e.pattern, e.isNocase) {
			continue
		}
		modifiers := rule.StringModifiers[m.Pattern]
		if matchPassesModifiers(data, m, modifiers, e.isWide) {
			s.matchCtx.AddMatch(m)
		}
	}
	return ctx.Err()
}

func packFastScanKey(ruleIndex, stringIndex int) (uint64, bool) {
	if ruleIndex < 0 || stringIndex < 0 ||
		uint64(ruleIndex) > math.MaxUint32 || uint64(stringIndex) > math.MaxUint32 {
		return 0, false
	}
	key := uint64(ruleIndex)<<32 | uint64(stringIndex)
	return key, true
}

func (s *Scanner) addLocalTextMatches(ctx context.Context, rule *CompiledRule, data []byte) error {
	if rule == nil || rule.Automaton == nil || len(data) == 0 {
		return ctx.Err()
	}
	//nolint:nestif // separate iterator branches preserve zero-allocation Scan
	if s.matchCtx.maxMatchesPerPattern <= 0 {
		if ctx.Done() == nil {
			for match := range rule.Automaton.SearchIter(data) {
				acceptAutomatonMatch(s.matchCtx, rule, data, match)
			}
		} else {
			for match := range rule.Automaton.searchIterWithCancel(data, ctx.Done()) {
				acceptAutomatonMatch(s.matchCtx, rule, data, match)
			}
		}
		return ctx.Err()
	}

	matched := make(map[string]bool, len(rule.TextPatterns))
	//nolint:nestif // separate iterator branches preserve zero-allocation Scan
	if ctx.Done() == nil {
		for match := range rule.Automaton.SearchIter(data) {
			if matched[match.StringID] {
				continue
			}
			if acceptAutomatonMatch(s.matchCtx, rule, data, match) {
				matched[match.StringID] = true
				if len(matched) == len(rule.TextPatterns) {
					break
				}
			}
		}
	} else {
		for match := range rule.Automaton.searchIterWithCancel(data, ctx.Done()) {
			if matched[match.StringID] {
				continue
			}
			if acceptAutomatonMatch(s.matchCtx, rule, data, match) {
				matched[match.StringID] = true
				if len(matched) == len(rule.TextPatterns) {
					break
				}
			}
		}
	}
	return ctx.Err()
}

func (s *Scanner) populateFixedRegexCache(
	ctx context.Context,
	data []byte,
	cache *nonTextMatchCache,
) error {
	dispatch := s.program.fixedRegexScan
	if dispatch == nil || len(data) == 0 || !shouldUseFixedRegexDispatch(data, dispatch) {
		return ctx.Err()
	}
	done := ctx.Done()
	for position, value := range data {
		if scanCanceledAt(done, position) {
			return ctx.Err()
		}
		for _, entryIndex := range dispatch.buckets[value] {
			entry := dispatch.entries[entryIndex]
			if entry.wide && (position+1 >= len(data) || data[position+1] != 0) {
				continue
			}
			start := position - entry.atomOffset
			if start < 0 {
				continue
			}
			flags := entry.pattern.Flags &^ regex.FlagsWide
			if entry.wide {
				flags |= regex.FlagsWide
			}
			matched, startOffset, endOffset := execRegexMatchAt(nil, entry.pattern, data, flags, entry.wide, start, ctx.Done())
			if !matched {
				continue
			}
			absoluteStart := start + startOffset
			absoluteEnd := start + endOffset
			if absoluteEnd < absoluteStart {
				continue
			}
			match := Match{Offset: int64(absoluteStart), Length: absoluteEnd - absoluteStart}
			if matchPassesModifiers(data, match, entry.modifiers, entry.wide) {
				cache.matches[entry.cacheIndex] = append(cache.matches[entry.cacheIndex], matchSpan{
					Offset: match.Offset,
					Length: match.Length,
				})
			}
		}
	}
	for _, order := range dispatch.cacheOrder {
		matches := cache.matches[order.cacheIndex]
		slices.SortStableFunc(matches, func(left, right matchSpan) int {
			leftWide := left.Length == order.wideLength
			rightWide := right.Length == order.wideLength
			switch {
			case leftWide == rightWide:
				return 0
			case leftWide:
				return -1
			default:
				return 1
			}
		})
	}
	for _, cacheIndex := range dispatch.cacheIndices {
		cache.set(cacheIndex, cache.matches[cacheIndex])
	}
	return ctx.Err()
}

func shouldUseSharedPatternAutomaton(data []byte, program *CompiledProgram) bool {
	if program == nil || program.SharedAutomaton == nil || len(program.SharedLookup) == 0 {
		return false
	}
	// Text strings rely on the shared automaton, and large non-text sets have
	// already crossed the compile-time threshold where one pass wins broadly.
	if len(program.SharedLookup) >= minSharedNonTextEntries {
		return true
	}
	for _, entry := range program.SharedLookup {
		if entry.Kind == StringKindText || entry.alternativeAtom || entry.forceShared {
			return true
		}
	}

	// Small non-text automata are profitable when their root bytes are sparse
	// in the input. Candidate-dense roots make the AC state machine more
	// expensive than independent SIMD literal searches, so sample the input.
	//
	// The independent path performs one search per entry, while the sparse-root
	// automaton performs one search per distinct root byte. Scale the tolerated
	// root density by that entries-per-root reuse ratio. This retains the old
	// one-hit-per-32-bytes crossover when every entry has its own root, while
	// avoiding repeated full-input scans when many entries share a root.
	if len(data) == 0 || len(program.SharedAutomaton.rootBytes) == 0 {
		return false
	}
	const (
		sampleBlocks     = 8
		sampleBlockSize  = 32
		rootDensityScale = 32
	)
	samples := 0
	rootHits := 0
	rootTransitions := &program.SharedAutomaton.states[0].transitions
	sampleAt := func(position int) {
		// A compiled automaton's goto table is closed over failure links, so an
		// absent root edge reads back as 0 rather than -1. No real transition can
		// target the root, so 0 is the "no root edge" test. Comparing against -1
		// here would count every byte as a root hit and stop the shared automaton
		// from ever being selected.
		if rootTransitions[data[position]] != 0 {
			rootHits++
		}
		samples++
	}
	if len(data) <= sampleBlocks*sampleBlockSize {
		for position := range data {
			sampleAt(position)
		}
	} else {
		maxStart := len(data) - sampleBlockSize
		for block := range sampleBlocks {
			start := block * maxStart / (sampleBlocks - 1)
			for position := start; position < start+sampleBlockSize; position++ {
				sampleAt(position)
			}
		}
	}
	return rootHits*rootDensityScale*len(program.SharedAutomaton.rootBytes) <
		samples*len(program.SharedLookup)
}

func shouldUseFixedRegexDispatch(data []byte, dispatch *fixedRegexDispatch) bool {
	if len(data) == 0 || dispatch == nil {
		return false
	}
	const maxSamples = 1024
	stride := max(1, len(data)/maxSamples)
	if stride > 1 {
		stride++
	}
	samples := 0
	bucketHits := 0
	for position := 0; position < len(data) && samples < maxSamples; position += stride {
		bucketHits += len(dispatch.buckets[data[position]])
		samples++
	}
	// Below roughly one routed pattern per sixteen sampled bytes, SIMD-backed
	// per-pattern searches are cheaper than scalar dispatch over the whole file.
	return bucketHits*16 >= samples
}

//nolint:revive // cache and cancellation state stay explicit on the matching hot path
func (s *Scanner) addLocalNonTextMatches(
	ctx context.Context,
	rule *CompiledRule,
	data []byte,
	cache *nonTextMatchCache,
	useSharedAutomaton bool,
) error {
	if rule == nil {
		return ctx.Err()
	}
	for id, regexInfo := range rule.RegexPatterns {
		if err := ctx.Err(); err != nil {
			return err
		}
		if matches, ok := s.getNonTextMatches(cache, regexInfo.cacheIndex, useSharedAutomaton); ok {
			addCachedMatches(s.matchCtx, id, matches)
			continue
		}
		modifiers := rule.StringModifiers[id]
		addRegexMatchesWithModifiersCached(s.matchCtx, id, regexInfo, data, modifiers, &s.regexByteSetCache)
		if s.matchCtx.maxMatchesPerPattern <= 0 && regexInfo.cacheIndex >= 0 && regexInfo.cacheIndex < len(cache.matches) {
			dst := cache.matches[regexInfo.cacheIndex][:0]
			dst = append(dst, s.matchCtx.spans[id]...)
			cache.set(regexInfo.cacheIndex, dst)
		}
	}
	for id, pattern := range rule.HexPatterns {
		if err := ctx.Err(); err != nil {
			return err
		}
		if pattern != nil {
			if matches, ok := s.getNonTextMatches(cache, pattern.cacheIndex, useSharedAutomaton); ok {
				addCachedMatches(s.matchCtx, id, matches)
				continue
			}
		}
		for _, m := range findHexMatches(pattern, data, ctx.Done()) {
			m.Pattern = id
			if matchPassesModifiers(data, m, rule.StringModifiers[id], false) {
				s.matchCtx.AddMatch(m)
			}
		}
		if s.matchCtx.maxMatchesPerPattern <= 0 && pattern != nil && pattern.cacheIndex >= 0 && pattern.cacheIndex < len(cache.matches) {
			dst := cache.matches[pattern.cacheIndex][:0]
			dst = append(dst, s.matchCtx.spans[id]...)
			cache.set(pattern.cacheIndex, dst)
		}
	}
	return ctx.Err()
}

func addCachedMatches(ctx *MatchContext, id string, matches []matchSpan) {
	for _, match := range matches {
		ctx.addMatchSpan(id, match)
	}
}

func (s *Scanner) prepareInterpreter(rule *CompiledRule) {
	s.interp.stringArena = s.interp.stringArena[:0]

	s.interp.SetCurrentRule(rule.Name)
	s.interp.SetMatchContext(s.matchCtx)
	s.interp.SetRuleResults(s.ruleResults)

	if rule.Automaton != nil {
		for idx, str := range rule.Automaton.strings {
			s.interp.SetMemoryString(idx, str.Identifier)
		}
	}
	s.setExternalVariables(rule)
	s.setGlobalVariables(rule)
}

func (s *Scanner) setExternalVariables(rule *CompiledRule) {
	for name, slot := range rule.ExternalSlots {
		value, ok := s.externalValues[name]
		if !ok {
			s.interp.memory[slot] = Value{Type: ValueTypeUndefined}
			continue
		}
		s.interp.memory[slot] = value.toInterpreterValue(s.interp)
	}
}

func (s *Scanner) setGlobalVariables(rule *CompiledRule) {
	for name, slot := range rule.GlobalSlots {
		value, ok := rule.GlobalValues[name]
		if !ok {
			s.interp.memory[slot] = Value{Type: ValueTypeUndefined}
			continue
		}
		s.interp.memory[slot] = value.toInterpreterValue(s.interp)
	}
}

func (v compiledGlobalValue) toInterpreterValue(interp *Interpreter) Value {
	switch v.valueType {
	case ValueTypeInt:
		return Value{Type: ValueTypeInt, IntVal: v.intVal}
	case ValueTypeDouble:
		return Value{Type: ValueTypeDouble, DoubleVal: v.doubleVal}
	case ValueTypeString:
		idx := len(interp.stringArena)
		interp.stringArena = append(interp.stringArena, v.stringVal)
		return Value{Type: ValueTypeString, StringRef: int64(idx)}
	default:
		return Value{Type: ValueTypeUndefined}
	}
}

// SetExternalVariables replaces runtime values for declared external variables.
func (s *Scanner) SetExternalVariables(vars map[string]any) error {
	values, err := normalizeExternalVariables(s.program, vars)
	if err != nil {
		return err
	}
	s.externalValues = values
	s.externalErr = nil
	return nil
}

type externalValue struct {
	valueType ValueType
	intVal    int64
	doubleVal float64
	stringVal string
}

func (v externalValue) toInterpreterValue(interp *Interpreter) Value {
	switch v.valueType {
	case ValueTypeInt:
		return Value{Type: ValueTypeInt, IntVal: v.intVal}
	case ValueTypeDouble:
		return Value{Type: ValueTypeDouble, DoubleVal: v.doubleVal}
	case ValueTypeString:
		idx := len(interp.stringArena)
		interp.stringArena = append(interp.stringArena, v.stringVal)
		return Value{Type: ValueTypeString, StringRef: int64(idx)}
	default:
		return Value{Type: ValueTypeUndefined}
	}
}

func normalizeExternalVariables(program *CompiledProgram, vars map[string]any) (map[string]externalValue, error) {
	if program != nil && program.preparationErr != nil {
		return nil, program.preparationErr
	}
	if len(vars) == 0 {
		return nil, nil
	}

	declared := declaredExternalVariables(program)
	values := make(map[string]externalValue, len(vars))
	for name, raw := range vars {
		if !declared[name] {
			return nil, fmt.Errorf("external variable %q is not declared", name)
		}
		value, err := normalizeExternalValue(raw)
		if err != nil {
			return nil, fmt.Errorf("external variable %q: %w", name, err)
		}
		values[name] = value
	}
	return values, nil
}

func declaredExternalVariables(program *CompiledProgram) map[string]bool {
	declared := make(map[string]bool)
	if program == nil {
		return declared
	}
	for _, rule := range program.Rules {
		for name := range rule.ExternalSlots {
			declared[name] = true
		}
	}
	return declared
}

func normalizeExternalValue(value any) (externalValue, error) {
	switch v := value.(type) {
	case bool:
		if v {
			return externalValue{valueType: ValueTypeInt, intVal: 1}, nil
		}
		return externalValue{valueType: ValueTypeInt, intVal: 0}, nil
	case int:
		return externalValue{valueType: ValueTypeInt, intVal: int64(v)}, nil
	case int8:
		return externalValue{valueType: ValueTypeInt, intVal: int64(v)}, nil
	case int16:
		return externalValue{valueType: ValueTypeInt, intVal: int64(v)}, nil
	case int32:
		return externalValue{valueType: ValueTypeInt, intVal: int64(v)}, nil
	case int64:
		return externalValue{valueType: ValueTypeInt, intVal: v}, nil
	case uint:
		return normalizeExternalUint(uint64(v))
	case uint8:
		return normalizeExternalUint(uint64(v))
	case uint16:
		return normalizeExternalUint(uint64(v))
	case uint32:
		return normalizeExternalUint(uint64(v))
	case uint64:
		return normalizeExternalUint(v)
	case float32:
		return externalValue{valueType: ValueTypeDouble, doubleVal: float64(v)}, nil
	case float64:
		return externalValue{valueType: ValueTypeDouble, doubleVal: v}, nil
	case string:
		return externalValue{valueType: ValueTypeString, stringVal: v}, nil
	default:
		return externalValue{}, fmt.Errorf("unsupported value type %T", value)
	}
}

func normalizeExternalUint(value uint64) (externalValue, error) {
	if value > math.MaxInt64 {
		return externalValue{}, fmt.Errorf("unsigned integer %d exceeds int64 range", value)
	}
	return externalValue{valueType: ValueTypeInt, intVal: int64(value)}, nil
}

func cloneExternalValues(values map[string]externalValue) map[string]externalValue {
	if len(values) == 0 {
		return nil
	}
	cloned := make(map[string]externalValue, len(values))
	for name, value := range values {
		cloned[name] = value
	}
	return cloned
}
