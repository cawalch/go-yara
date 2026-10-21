package compiler

import (
	"context"
	"slices"
	"sort"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/regex"
)

const (
	minPrefilterAtomLength      = 2
	maxPrefilterAtomLength      = 8
	maxRegexByteSetSize         = 96
	maxSparseRegexByteSetValues = 8
	// A few non-text atoms with the same sparse root can share one fast
	// byte-search pass without paying the general automaton crossover cost.
	minSparseSharedNonTextEntries = 2
	// Below this crossover, the existing per-pattern SIMD byte searches are
	// cheaper than adding more root transitions to the global automaton.
	minSharedNonTextEntries = 32
	// Fixed class-only regexes cannot use the literal automaton. Once several
	// are present, one byte-dispatch pass is cheaper than rescanning the input
	// independently for every pattern.
	minSharedFixedRegexEntries = 4
	// Keep suffix-derived candidate ranges narrow. Wider ranges are better
	// served by the existing byte-set or VM paths than by probing every offset.
	maxLeadingGapAtomOffsetWidth = 64
)

type prefilterAtom struct {
	data   []byte
	offset int
	score  int
}

type regexPrefilterAtom struct {
	data        []byte
	minOffset   int
	maxOffset   int
	score       int
	asciiNoCase bool
}

type regexAlternativeDedupKey struct {
	data        string
	minOffset   int
	maxOffset   int
	asciiNoCase bool
}

type regexByteSetPrefilter struct {
	set       regex.ByteSet
	minOffset int
	maxOffset int
	count     int
}

type prefilterDedupKey struct {
	cacheKey      string
	atomData      string
	atomMinOffset int
	atomMaxOffset int
	kind          StringKind
	wide          bool
	atomNoCase    bool
}

type nonTextCacheKey struct {
	kind     StringKind
	cacheKey string
}

type fixedRegexDispatchEntry struct {
	pattern    RegexPattern
	modifiers  []ast.StringModifier
	cacheIndex int
	atomOffset int
	wide       bool
}

type fixedRegexDispatch struct {
	buckets      [256][]int
	entries      []fixedRegexDispatchEntry
	cacheIndices []int
	cacheOrder   []fixedRegexCacheOrder
}

type fixedRegexCacheOrder struct {
	cacheIndex int
	wideLength int
}

func sortedPatternIDs[V any](patterns map[string]V) []string {
	ids := make([]string, 0, len(patterns))
	for id := range patterns {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// prefilterStringClass tells the reject path what, if anything, it must probe
// for one of a rule's strings.
type prefilterStringClass uint8

const (
	// prefilterStringUnresolved marks a string whose kind or pattern could not be
	// resolved at compile time. The reject path cannot reason about the rule and
	// reports rulePrefilterUnknown, exactly as the map-lookup version did when a
	// lookup missed.
	prefilterStringUnresolved prefilterStringClass = iota
	// prefilterStringText is a text string, always represented in the shared
	// automaton, so the reject path has nothing extra to check.
	prefilterStringText
	// prefilterStringNonText is a regex or hex string whose candidate spans live
	// in the scanner's non-text cache at cacheIndex.
	prefilterStringNonText
	// prefilterStringDead is an unreferenced or dead string omitted from compilation.
	prefilterStringDead
)

// prefilterStringInfo is one string's resolved reject-path data.
type prefilterStringInfo struct {
	class      prefilterStringClass
	cacheIndex int
}

// buildPrefilterStrings resolves each of a rule's strings to the class and cache
// index the reject path needs.
//
// This is pure precomputation of compile-time-constant data. rulePrefilterStatus
// previously re-resolved it on every scan through the string-keyed StringKinds,
// RegexPatterns and HexPatterns maps, costing two string hashes per string per
// rule per event — which dominated the reject path on realistic rulesets.
//
// Must run after cache indices are assigned, since it captures cacheIndex.
func buildPrefilterStrings(rule *CompiledRule) {
	infos := make([]prefilterStringInfo, len(rule.IndexToStringID))
	for i, identifier := range rule.IndexToStringID {
		infos[i] = resolvePrefilterString(rule, identifier)
	}
	rule.prefilterStrings = infos
}

// resolvePrefilterString resolves one string to the class and cache index the
// reject path needs, reporting prefilterStringUnresolved when the string's kind
// or pattern is missing or unrecognised. Each of those cases made the previous
// map-lookup implementation return rulePrefilterUnknown for the whole rule, and
// still does.
func resolvePrefilterString(rule *CompiledRule, identifier string) prefilterStringInfo {
	if rule.IsStringDead(identifier) {
		return prefilterStringInfo{class: prefilterStringDead}
	}
	unresolved := prefilterStringInfo{class: prefilterStringUnresolved}

	kind, exists := rule.StringKinds[identifier]
	if !exists {
		return unresolved
	}
	switch kind {
	case StringKindText:
		return prefilterStringInfo{class: prefilterStringText}
	case StringKindRegex:
		pattern, ok := rule.RegexPatterns[identifier]
		if !ok {
			return unresolved
		}
		return prefilterStringInfo{class: prefilterStringNonText, cacheIndex: pattern.cacheIndex}
	case StringKindHex:
		pattern, ok := rule.HexPatterns[identifier]
		if !ok || pattern == nil {
			return unresolved
		}
		return prefilterStringInfo{class: prefilterStringNonText, cacheIndex: pattern.cacheIndex}
	default:
		return unresolved
	}
}

func assignNonTextCacheIndices(rules []*CompiledRule) int {
	indices := make(map[nonTextCacheKey]int)
	nextIndex := 0
	for _, rule := range rules {
		if rule.IsDead {
			continue
		}
		for _, strID := range sortedPatternIDs(rule.RegexPatterns) {
			if rule.IsStringDead(strID) {
				continue
			}
			pattern := rule.RegexPatterns[strID]
			pattern.cacheIndex = -1
			if pattern.cacheKey != "" {
				key := nonTextCacheKey{kind: StringKindRegex, cacheKey: pattern.cacheKey}
				index, exists := indices[key]
				if !exists {
					index = nextIndex
					nextIndex++
					indices[key] = index
				}
				pattern.cacheIndex = index
			}
			rule.RegexPatterns[strID] = pattern
		}
		for _, strID := range sortedPatternIDs(rule.HexPatterns) {
			if rule.IsStringDead(strID) {
				continue
			}
			pattern := rule.HexPatterns[strID]
			if pattern == nil {
				continue
			}
			pattern.cacheIndex = -1
			if pattern.cacheKey == "" {
				continue
			}
			key := nonTextCacheKey{kind: StringKindHex, cacheKey: pattern.cacheKey}
			index, exists := indices[key]
			if !exists {
				index = nextIndex
				nextIndex++
				indices[key] = index
			}
			pattern.cacheIndex = index
		}
	}
	// Every cacheIndex is final at this point, so the reject path's per-string
	// table can be resolved once here. Both the fresh-compile and deserialize
	// paths route through this function, so neither needs its own call.
	for _, rule := range rules {
		buildPrefilterStrings(rule)
	}
	return nextIndex
}

func buildFixedRegexDispatch(rules []*CompiledRule) *fixedRegexDispatch {
	entries := make([]fixedRegexDispatchEntry, 0)
	seen := make(map[prefilterDedupKey]struct{})
	for _, rule := range rules {
		if rule.IsDead {
			continue
		}
		for _, strID := range sortedPatternIDs(rule.RegexPatterns) {
			if rule.IsStringDead(strID) {
				continue
			}
			pattern := rule.RegexPatterns[strID]
			if len(pattern.fixedByteSets) == 0 ||
				len(pattern.prefix) >= minPrefilterAtomLength ||
				len(pattern.atom) >= minPrefilterAtomLength ||
				pattern.byteSetCount == 0 ||
				pattern.byteSetMinOffset != pattern.byteSetMaxOffset ||
				pattern.cacheIndex < 0 {
				continue
			}

			modifiers := rule.StringModifiers[strID]
			hasWide := hasModifier(modifiers, ast.StringModifierWide)
			hasASCII := hasModifier(modifiers, ast.StringModifierASCII)
			encodings := []bool{false}
			switch {
			case hasWide && hasASCII:
				encodings = []bool{true, false}
			case hasWide:
				encodings = []bool{true}
			}

			for _, wide := range encodings {
				key := prefilterDedupKey{kind: StringKindRegex, cacheKey: pattern.cacheKey, wide: wide}
				if _, exists := seen[key]; exists {
					continue
				}
				seen[key] = struct{}{}
				atomOffset := pattern.byteSetMinOffset
				if wide {
					atomOffset *= 2
				}
				entries = append(entries, fixedRegexDispatchEntry{
					pattern:    pattern,
					modifiers:  modifiers,
					cacheIndex: pattern.cacheIndex,
					atomOffset: atomOffset,
					wide:       wide,
				})
			}
		}
	}
	if len(entries) < minSharedFixedRegexEntries {
		return nil
	}

	dispatch := &fixedRegexDispatch{entries: entries}
	cacheSeen := make(map[int]struct{}, len(entries))
	cacheEntryCounts := make(map[int]int, len(entries))
	for entryIndex, entry := range entries {
		for value := 0; value < 256; value++ {
			if entry.pattern.byteSet.Contains(byte(value)) {
				dispatch.buckets[value] = append(dispatch.buckets[value], entryIndex)
			}
		}
		if _, exists := cacheSeen[entry.cacheIndex]; !exists {
			cacheSeen[entry.cacheIndex] = struct{}{}
			dispatch.cacheIndices = append(dispatch.cacheIndices, entry.cacheIndex)
		}
		cacheEntryCounts[entry.cacheIndex]++
	}
	for _, entry := range entries {
		if !entry.wide || cacheEntryCounts[entry.cacheIndex] < 2 {
			continue
		}
		dispatch.cacheOrder = append(dispatch.cacheOrder, fixedRegexCacheOrder{
			cacheIndex: entry.cacheIndex,
			wideLength: len(entry.pattern.fixedByteSets) * 2,
		})
	}
	return dispatch
}

func (s *Scanner) resetPrefilterCandidates(size int) {
	if cap(s.prefilterCandidates) < size {
		s.prefilterCandidates = make([][]int, size)
		s.touchedPrefilterCandidates = s.touchedPrefilterCandidates[:0]
		return
	}
	for _, index := range s.touchedPrefilterCandidates {
		if index >= 0 && index < len(s.prefilterCandidates) {
			s.prefilterCandidates[index] = s.prefilterCandidates[index][:0]
		}
	}
	s.touchedPrefilterCandidates = s.touchedPrefilterCandidates[:0]
	s.prefilterCandidates = s.prefilterCandidates[:size]
}

func (s *Scanner) populateNonTextPrefilterCache(
	ctx context.Context,
	data []byte,
	cache *nonTextMatchCache,
) error {
	if s.program.nonTextCacheSize == 0 || len(s.touchedPrefilterCandidates) == 0 {
		return ctx.Err()
	}
	if s.matchCtx != nil {
		s.matchCtx.maxMatchSpan = s.maxMatchSpan
	}
	slices.Sort(s.touchedPrefilterCandidates)
	for touchedIndex := 0; touchedIndex < len(s.touchedPrefilterCandidates); {
		if err := ctx.Err(); err != nil {
			return err
		}
		lookupIdx := s.touchedPrefilterCandidates[touchedIndex]
		if lookupIdx < 0 || lookupIdx >= len(s.program.sharedLookup) {
			touchedIndex++
			continue
		}
		entry := s.program.sharedLookup[lookupIdx]
		if entry.Kind == StringKindText || entry.CacheIndex < 0 || entry.CacheIndex >= len(cache.matches) {
			touchedIndex++
			continue
		}
		if entry.RuleIndex < 0 || entry.RuleIndex >= len(s.program.Rules) {
			touchedIndex++
			continue
		}
		//nolint:nestif // a touched alternative must expand and deduplicate its complete atom cover
		if entry.Kind == StringKindRegex && entry.alternativeAtom {
			lookupGroupStart := lookupIdx
			for lookupGroupStart > 0 {
				previous := s.program.sharedLookup[lookupGroupStart-1]
				if !previous.alternativeAtom || previous.Kind != StringKindRegex ||
					previous.CacheIndex != entry.CacheIndex || previous.IsWide != entry.IsWide {
					break
				}
				lookupGroupStart--
			}
			groupEnd := lookupIdx + 1
			for groupEnd < len(s.program.sharedLookup) {
				next := s.program.sharedLookup[groupEnd]
				if !next.alternativeAtom ||
					next.Kind != StringKindRegex ||
					next.CacheIndex != entry.CacheIndex ||
					next.IsWide != entry.IsWide {
					break
				}
				groupEnd++
			}

			groupEntry := s.program.sharedLookup[lookupGroupStart]
			rule := s.program.Rules[groupEntry.RuleIndex]
			if groupEntry.StringIdx < 0 || groupEntry.StringIdx >= len(rule.IndexToStringID) {
				touchedIndex++
				continue
			}
			if s.canSkipSharedNonTextEntry(groupEntry, rule, data) {
				cache.set(entry.CacheIndex, nil)
				for touchedIndex < len(s.touchedPrefilterCandidates) &&
					s.touchedPrefilterCandidates[touchedIndex] < groupEnd {
					touchedIndex++
				}
				continue
			}
			strID := rule.IndexToStringID[groupEntry.StringIdx]
			dst := cache.matches[entry.CacheIndex]
			matchGroupStart := len(dst)
			for candidateIndex := lookupGroupStart; candidateIndex < groupEnd; candidateIndex++ {
				candidateEntry := s.program.sharedLookup[candidateIndex]
				candidates := s.prefilterCandidates[candidateIndex]
				if len(candidates) > 0 {
					dst = appendRegexPrefilterMatches(
						dst,
						rule,
						strID,
						candidateEntry,
						data,
						candidates,
						ctx.Done(),
						s.matchCtx,
					)
				}
			}
			group := sortAndDedupeMatchSpans(dst[matchGroupStart:])
			dst = dst[:matchGroupStart+len(group)]
			cache.set(entry.CacheIndex, dst)
			if len(dst) > 0 {
				s.sharedNonTextMatched = true
				s.markNonTextCacheRules(entry.CacheIndex)
			}
			for touchedIndex < len(s.touchedPrefilterCandidates) &&
				s.touchedPrefilterCandidates[touchedIndex] < groupEnd {
				touchedIndex++
			}
			continue
		}

		rule := s.program.Rules[entry.RuleIndex]
		if entry.StringIdx < 0 || entry.StringIdx >= len(rule.IndexToStringID) {
			touchedIndex++
			continue
		}
		if s.canSkipSharedNonTextEntry(entry, rule, data) {
			cache.set(entry.CacheIndex, nil)
			touchedIndex++
			continue
		}
		strID := rule.IndexToStringID[entry.StringIdx]
		candidates := s.prefilterCandidates[lookupIdx]

		switch entry.Kind {
		case StringKindRegex:
			dst := cache.matches[entry.CacheIndex]
			if len(candidates) > 0 {
				dst = appendRegexPrefilterMatches(dst, rule, strID, entry, data, candidates, ctx.Done(), s.matchCtx)
			}
			cache.set(entry.CacheIndex, dst)
		case StringKindHex:
			dst := cache.matches[entry.CacheIndex]
			if len(candidates) > 0 {
				dst = appendHexPrefilterMatches(dst, rule, strID, entry, data, candidates, ctx.Done(), &s.hexScratch)
			}
			cache.set(entry.CacheIndex, dst)
		}
		if len(cache.matches[entry.CacheIndex]) > 0 {
			s.sharedNonTextMatched = true
			s.markNonTextCacheRules(entry.CacheIndex)
		}
		touchedIndex++
	}
	return ctx.Err()
}

func (s *Scanner) canSkipSharedNonTextEntry(entry sharedAutomatonEntry, rule *CompiledRule, data []byte) bool {
	return !s.prefilterDisabled &&
		s.skipUnmatchedNonText &&
		entry.singleRuleCache &&
		s.hookMask&(hookBitTelemetry|hookBitRuleProfile) == 0 &&
		s.ruleRejectedBeforeNonText(rule, data)
}

func sortAndDedupeMatchSpans(matches []matchSpan) []matchSpan {
	slices.SortFunc(matches, func(left, right matchSpan) int {
		switch {
		case left.Offset < right.Offset:
			return -1
		case left.Offset > right.Offset:
			return 1
		case left.Length < right.Length:
			return -1
		case left.Length > right.Length:
			return 1
		default:
			return 0
		}
	})
	if len(matches) < 2 {
		return matches
	}
	unique := 1
	for _, candidate := range matches[1:] {
		if candidate.Offset == matches[unique-1].Offset {
			continue
		}
		matches[unique] = candidate
		unique++
	}
	return matches[:unique]
}

//nolint:revive // argument-limit: hot-path helper keeps candidate verification direct
func appendRegexPrefilterMatches(
	dst []matchSpan,
	rule *CompiledRule,
	strID string,
	entry sharedAutomatonEntry,
	data []byte,
	candidates []int,
	done <-chan struct{},
	matchCtx *MatchContext,
) []matchSpan {
	pattern, ok := rule.RegexPatterns[strID]
	if !ok || len(pattern.Code) == 0 {
		return dst
	}
	flags := pattern.Flags &^ regex.FlagsWide
	if entry.IsWide {
		flags |= regex.FlagsWide
	}
	// An atom after an unbounded prefix cannot identify candidate starts, but
	// its absence still proves the regex cannot match. If it is present, keep
	// correctness by delegating to the existing exact matcher.
	if entry.AtomMaxOffset < 0 {
		return appendRegexFallbackMatches(dst, rule, strID, pattern, data, flags, entry.IsWide, done, matchCtx)
	}
	limit := max(1024, len(data)/4)
	modifiers := rule.StringModifiers[strID]
	hasFixedByteSet := !entry.IsWide && pattern.byteSetCount > 0 &&
		pattern.byteSetMinOffset >= 0 && pattern.byteSetMinOffset == pattern.byteSetMaxOffset
	maxMatchSpan := 0
	if matchCtx != nil {
		maxMatchSpan = matchCtx.maxMatchSpan
	}
	var bs *regex.VMBatch

	verifyCandidateStart := func(start int) {
		if pattern.anchored && start != 0 {
			return
		}
		if hasFixedByteSet {
			checkPos := start + pattern.byteSetMinOffset
			if checkPos >= len(data) || !pattern.byteSet.Contains(data[checkPos]) {
				return
			}
		}
		if bs == nil {
			bs = newRegexMatchBatch(matchCtx, pattern)
		}
		scanData := data
		if maxMatchSpan > 0 && start < len(data) {
			scanData = data[:min(len(data), start+maxMatchSpan)]
		}
		matched, startOff, endOff := execRegexMatchAt(bs, pattern, scanData, flags, entry.IsWide, start, done)
		if !matched {
			return
		}
		absStart := start + startOff
		absEnd := start + endOff
		if absEnd < absStart {
			return
		}
		match := Match{Pattern: strID, Offset: int64(absStart), Length: absEnd - absStart}
		if matchPassesModifiers(data, match, modifiers, entry.IsWide) {
			dst = append(dst, matchSpan{Offset: match.Offset, Length: match.Length})
		}
	}

	if entry.AtomOffset == entry.AtomMaxOffset && len(candidates) <= limit {
		lastStart := -1
		for index, atomStart := range candidates {
			if scanCanceledAt(done, index) {
				return dst
			}
			start := atomStart - entry.AtomOffset
			if start < 0 || start > len(data) || start <= lastStart {
				continue
			}
			lastStart = start
			verifyCandidateStart(start)
		}
		return dst
	}

	var startsBuf [64]int
	starts, handled := collectRegexCandidateStartsInto(
		startsBuf[:0],
		candidates,
		entry.AtomOffset,
		entry.AtomMaxOffset,
		entry.IsWide,
		len(data),
		limit,
	)
	if !handled {
		return appendRegexFallbackMatches(dst, rule, strID, pattern, data, flags, entry.IsWide, done, matchCtx)
	}
	for index, start := range starts {
		if scanCanceledAt(done, index) {
			return dst
		}
		verifyCandidateStart(start)
	}
	return dst
}

//nolint:revive // argument-limit: rare fallback keeps hot-path state explicit
func appendRegexFallbackMatches(
	dst []matchSpan,
	rule *CompiledRule,
	strID string,
	pattern RegexPattern,
	data []byte,
	flags regex.Flags,
	isWide bool,
	done <-chan struct{},
	matchCtx *MatchContext,
) []matchSpan {
	ctx := matchContextPool.Get().(*MatchContext)
	ctx.compact = true
	ctx.Reset(data)
	ctx.cancelDone = done
	if matchCtx != nil {
		ctx.maxMatchSpan = matchCtx.maxMatchSpan
	}
	addRegexMatches(ctx, strID, pattern, data, rule.StringModifiers[strID], flags, isWide)
	dst = append(dst, ctx.spans[strID]...)
	ctx.Release()
	return dst
}

//nolint:revive // argument-limit: hot-path helper keeps candidate verification direct
func appendHexPrefilterMatches(
	dst []matchSpan,
	rule *CompiledRule,
	strID string,
	entry sharedAutomatonEntry,
	data []byte,
	candidates []int,
	done <-chan struct{},
	scratch *hexMatchScratch,
) []matchSpan {
	pattern := rule.HexPatterns[strID]
	if pattern == nil {
		return dst
	}
	if scratch == nil {
		scratch = &hexMatchScratch{}
	}
	linear := isLinearHexPattern(pattern.Tokens)
	lastStart := -1

	for index, atomStart := range candidates {
		if scanCanceledAt(done, index) {
			return dst
		}
		start := atomStart - entry.AtomOffset
		if start < 0 || start >= len(data) || start == lastStart {
			continue
		}
		lastStart = start

		if linear {
			end, ok := matchLinearHexPattern(pattern.Tokens, data, start, nil)
			if !ok || end <= start {
				continue
			}
			match := Match{Pattern: strID, Offset: int64(start), Length: end - start}
			if matchPassesModifiers(data, match, rule.StringModifiers[strID], false) {
				dst = append(dst, matchSpan{Offset: match.Offset, Length: match.Length})
			}
			continue
		}

		scratch.matchEach(pattern.Tokens, data, start, nil, func(end int) bool {
			if end <= start {
				return true
			}
			match := Match{Pattern: strID, Offset: int64(start), Length: end - start}
			if matchPassesModifiers(data, match, rule.StringModifiers[strID], false) {
				dst = append(dst, matchSpan{Offset: match.Offset, Length: match.Length})
			}
			return true
		})
	}
	return dst
}
