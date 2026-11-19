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
	data      []byte
	offset    int
	maxOffset int
	score     int
}

type regexPrefilterAtom struct {
	data        []byte
	minOffset   int
	maxOffset   int
	maxSuffix   int
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
	preferWide bool
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
	buildLocalNonTextEntries(rule)
}

func buildLocalNonTextEntries(rule *CompiledRule) {
	if len(rule.RegexPatterns) > 0 {
		regexes := make([]localRegexEntry, 0, len(rule.RegexPatterns))
		for _, id := range sortedPatternIDs(rule.RegexPatterns) {
			slot, ok := rule.StringIDToIndex[id]
			if !ok {
				slot = -1
			}
			modifiers := rule.StringModifiers[id]
			regexes = append(regexes, localRegexEntry{
				id:           id,
				slot:         slot,
				pattern:      rule.RegexPatterns[id],
				modifiers:    modifiers,
				wideAndASCII: hasModifier(modifiers, ast.StringModifierWide) && hasModifier(modifiers, ast.StringModifierASCII),
			})
		}
		rule.localRegexes = regexes
	}
	if len(rule.HexPatterns) > 0 {
		hexes := make([]localHexEntry, 0, len(rule.HexPatterns))
		for _, id := range sortedPatternIDs(rule.HexPatterns) {
			slot, ok := rule.StringIDToIndex[id]
			if !ok {
				slot = -1
			}
			hexes = append(hexes, localHexEntry{
				id:        id,
				slot:      slot,
				pattern:   rule.HexPatterns[id],
				modifiers: rule.StringModifiers[id],
			})
		}
		rule.localHexes = hexes
	}
	rule.localNonTextBuilt = true
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
			if pattern.verification != nil || len(pattern.fixedByteSets) == 0 ||
				len(pattern.prefix) >= minPrefilterAtomLength ||
				len(pattern.atom) >= minPrefilterAtomLength ||
				pattern.byteSetCount == 0 ||
				pattern.byteSetMinOffset != pattern.byteSetMaxOffset ||
				pattern.cacheIndex < 0 {
				continue
			}

			modifiers := rule.StringModifiers[strID]
			encodings, count := regexEncodingOrder(pattern.Flags, hasModifier(modifiers, ast.StringModifierWide), hasModifier(modifiers, ast.StringModifierASCII))

			for _, wide := range encodings[:count] {
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
		for value := range 256 {
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
		encodings, _ := regexEncodingOrder(entry.pattern.Flags, true, true)
		dispatch.cacheOrder = append(dispatch.cacheOrder, fixedRegexCacheOrder{
			cacheIndex: entry.cacheIndex,
			wideLength: len(entry.pattern.fixedByteSets) * 2,
			preferWide: encodings[0],
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
		if entry.combined != nil {
			s.populateCombinedRegex(ctx, data, cache, entry.combined, s.prefilterCandidates[lookupIdx])
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

		var candidates []int
		if lookupIdx < len(s.prefilterCandidates) {
			candidates = s.prefilterCandidates[lookupIdx]
		}
		if len(candidates) > 0 {
			if entry.hexDisc != nil {
				s.verifyHexFanoutDiscriminated(ctx, entry, data, candidates, cache)
			} else {
				s.verifySharedNonTextEntry(ctx, entry, data, candidates, cache)
				for _, extra := range entry.fanout {
					s.verifySharedNonTextEntry(ctx, extra, data, candidates, cache)
				}
			}
		}
		touchedIndex++
	}
	return ctx.Err()
}

//nolint:revive // argument-limit: hot-path helper avoids struct allocation
func (s *Scanner) verifySharedNonTextEntry(
	ctx context.Context,
	entry sharedAutomatonEntry,
	data []byte,
	candidates []int,
	cache *nonTextMatchCache,
) {
	rule := s.program.Rules[entry.RuleIndex]
	if entry.StringIdx < 0 || entry.StringIdx >= len(rule.IndexToStringID) {
		return
	}
	if s.canSkipSharedNonTextEntry(entry, rule, data) {
		cache.set(entry.CacheIndex, nil)
		return
	}
	strID := rule.IndexToStringID[entry.StringIdx]

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
}

func (s *Scanner) canSkipSharedNonTextEntry(entry sharedAutomatonEntry, rule *CompiledRule, data []byte) bool {
	return !s.prefilterDisabled &&
		s.skipUnmatchedNonText &&
		entry.singleRuleCache &&
		s.hookMask&(hookBitTelemetry|hookBitRuleProfile|hookBitPatternProfile) == 0 &&
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
	maxMatchSpan := 0
	if matchCtx != nil {
		maxMatchSpan = matchCtx.maxMatchSpan
	}
	if entry.AtomMaxOffset < 0 || (pattern.verification != nil && needsBoundedRegexVerification(&pattern, data, maxMatchSpan)) {
		return appendRegexFallbackMatches(dst, rule, strID, pattern, data, flags, entry.IsWide, done, matchCtx)
	}
	limit := max(1024, len(data)/4)
	verifier := regexPrefilterVerifier{
		strID:           strID,
		modifiers:       rule.StringModifiers[strID],
		data:            data,
		flags:           flags,
		isWide:          entry.IsWide,
		hasFixedByteSet: !entry.IsWide && pattern.byteSetCount > 0 && pattern.byteSetMinOffset >= 0 && pattern.byteSetMinOffset == pattern.byteSetMaxOffset,
		maxMatchSpan:    maxMatchSpan,
		done:            done,
		matchCtx:        matchCtx,
	}

	atomMinOffset, atomMaxOffset := pattern.atomMinOffset, pattern.atomMaxOffset
	if entry.IsWide {
		atomMinOffset *= 2
		if atomMaxOffset >= 0 {
			atomMaxOffset *= 2
		}
	}
	checkAtomValid := entry.AtomOffset == atomMinOffset && entry.AtomMaxOffset == atomMaxOffset

	if entry.AtomOffset == entry.AtomMaxOffset && len(candidates) <= limit {
		lastStart := -1
		for index, atomStart := range candidates {
			if scanCanceledAt(done, index) {
				return dst
			}
			if checkAtomValid && !pattern.hasValidAtomOccurrence(data, atomStart, entry.IsWide) {
				continue
			}
			start := atomStart - entry.AtomOffset
			if start < 0 || start > len(data) || start <= lastStart {
				continue
			}
			lastStart = start
			dst, verifier.bs = verifier.verifyStart(dst, &pattern, start)
		}
		return dst
	}

	if checkAtomValid {
		validCandidates := candidates[:0]
		for _, atomStart := range candidates {
			if _, ok := pattern.atomOccurrenceValid(data, atomStart, entry.IsWide); ok {
				validCandidates = append(validCandidates, atomStart)
			}
		}
		candidates = validCandidates
	}

	if !entry.IsWide {
		handled, canceled := verifySortedCandidateStarts(
			candidates,
			entry.AtomOffset,
			entry.AtomMaxOffset,
			len(data),
			limit,
			done,
			func(start int) {
				dst, verifier.bs = verifier.verifyStart(dst, &pattern, start)
			},
		)
		if canceled {
			return dst
		}
		if handled {
			return dst
		}
	}

	var startsBuf [64]int
	startsIn := startsBuf[:0]
	if matchCtx != nil && cap(matchCtx.regexCandidates) > 0 {
		startsIn = matchCtx.regexCandidates[:0]
	}
	starts, handled := collectRegexCandidateStartsInto(
		startsIn,
		candidates,
		entry.AtomOffset,
		entry.AtomMaxOffset,
		entry.IsWide,
		len(data),
		limit,
	)
	if matchCtx != nil && starts != nil {
		matchCtx.retainRegexCandidates(starts)
	}
	if !handled {
		return appendRegexFallbackMatches(dst, rule, strID, pattern, data, flags, entry.IsWide, done, matchCtx)
	}
	for index, start := range starts {
		if scanCanceledAt(done, index) {
			return dst
		}
		dst, verifier.bs = verifier.verifyStart(dst, &pattern, start)
	}
	return dst
}

type regexPrefilterVerifier struct {
	strID           string
	modifiers       []ast.StringModifier
	data            []byte
	flags           regex.Flags
	isWide          bool
	hasFixedByteSet bool
	maxMatchSpan    int
	done            <-chan struct{}
	matchCtx        *MatchContext
	bs              *regex.VMBatch
}

func (pattern *RegexPattern) hasValidAtomOccurrence(data []byte, atomStart int, isWide bool) bool {
	_, ok := pattern.atomOccurrenceValid(data, atomStart, isWide)
	return ok
}

func (v regexPrefilterVerifier) verifyStart(dst []matchSpan, pattern *RegexPattern, start int) ([]matchSpan, *regex.VMBatch) {
	if pattern.anchored && start != 0 {
		return dst, v.bs
	}
	if !pattern.startMatchesFirstByte(v.data, start, v.isWide) {
		return dst, v.bs
	}
	if v.hasFixedByteSet {
		checkPos := start + pattern.byteSetMinOffset
		if checkPos >= len(v.data) || !pattern.byteSet.Contains(v.data[checkPos]) {
			return dst, v.bs
		}
	}
	if len(pattern.fixedByteSets) > 0 {
		endOff, matched := fixedRegexMatchAt(pattern.fixedByteSets, v.data, v.isWide, start)
		if !matched {
			return dst, v.bs
		}
		match := Match{Pattern: v.strID, Offset: int64(start), Length: endOff}
		if matchPassesModifiers(v.data, match, v.modifiers, v.isWide) {
			dst = append(dst, matchSpan{Offset: match.Offset, Length: match.Length})
		}
		return dst, v.bs
	}
	bs := v.bs
	if bs == nil {
		bs = newRegexMatchBatch(v.matchCtx, pattern)
	}
	scanData, relStart, windowStart := boundedRegexWindow(v.data, start, pattern, v.isWide, v.maxMatchSpan)
	matched, startOff, endOff := execRegexMatchAt(bs, pattern, scanData, v.flags, v.isWide, relStart, v.done)
	if !matched {
		if v.matchCtx != nil && bs.BudgetExceeded() {
			v.matchCtx.verificationBudgetRejects++
		}
		return dst, bs
	}
	absStart := windowStart + relStart + startOff
	absEnd := windowStart + relStart + endOff
	if absEnd < absStart {
		return dst, bs
	}
	match := Match{Pattern: v.strID, Offset: int64(absStart), Length: absEnd - absStart}
	if matchPassesModifiers(v.data, match, v.modifiers, v.isWide) {
		dst = append(dst, matchSpan{Offset: match.Offset, Length: match.Length})
	}
	return dst, bs
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
	ctx.Reset(data)
	ctx.cancelDone = done
	if matchCtx != nil {
		ctx.maxMatchSpan = matchCtx.maxMatchSpan
	}
	addRegexMatches(ctx, strID, pattern, data, rule.StringModifiers[strID], flags, isWide)
	dst = append(dst, ctx.spansFor(strID)...)
	if matchCtx != nil {
		matchCtx.verificationBudgetRejects += ctx.verificationBudgetRejects
	}
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
	if pattern.scanMetadata != nil {
		scratch.prepareHexMetadata(pattern.Tokens, pattern.scanMetadata)
	} else {
		scratch.prepareHex(pattern.Tokens)
	}
	var xorKey *byte
	if len(pattern.XorKeys) == 1 {
		xorKey = &pattern.XorKeys[0]
	}
	linear := scratch.planPrefix == len(pattern.Tokens)
	lastStart := -1

	var firstByte byte
	var hasFirstByte bool
	if len(pattern.Tokens) > 0 {
		firstByte, hasFirstByte = definiteHexByte(pattern.Tokens[0], xorKey)
	}
	verifyCandidateStart := func(start int) {
		if hasFirstByte && (start >= len(data) || data[start] != firstByte) {
			return
		}
		if linear {
			end, ok := matchLinearHexPattern(pattern.Tokens, data, start, xorKey)
			if !ok || end <= start {
				return
			}
			match := Match{Pattern: strID, Offset: int64(start), Length: end - start}
			if matchPassesModifiers(data, match, rule.StringModifiers[strID], false) {
				dst = append(dst, matchSpan{Offset: match.Offset, Length: match.Length})
			}
			return
		}

		scratch.matchEach(pattern.Tokens, data, start, xorKey, func(end int) bool {
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

	limit := max(1024, len(data)/4)
	if entry.AtomMaxOffset >= 0 {
		var adj [4]hexAtomAdjCheck
		if nAdj := collectHexAtomAdjacentChecks(pattern.Tokens, entry.AtomOffset, entry.AtomMaxOffset, xorKey, &adj); nAdj > 0 {
			candidates = filterHexCandidatesByAdjacent(scratch.candidateStarts[:0], candidates, data, adj[:nAdj])
			scratch.candidateStarts = candidates[:0]
			if len(candidates) == 0 {
				return dst
			}
		}
	}
	if entry.AtomOffset == entry.AtomMaxOffset && len(candidates) <= limit {
		for index, atomStart := range candidates {
			if scanCanceledAt(done, index) {
				return dst
			}
			start := atomStart - entry.AtomOffset
			if start < 0 || start >= len(data) || start == lastStart {
				continue
			}
			lastStart = start
			verifyCandidateStart(start)
		}
		return dst
	}

	if entry.AtomMaxOffset >= 0 {
		if verifyHexRangeCandidates(candidates, entry, len(data), limit, done, verifyCandidateStart) {
			return dst
		}
	}

	findPreparedHexMatchesEach(pattern, data, done, scratch, func(m Match) bool {
		m.Pattern = strID
		if matchPassesModifiers(data, m, rule.StringModifiers[strID], false) {
			dst = append(dst, matchSpan{Offset: m.Offset, Length: m.Length})
		}
		return true
	})
	return dst
}

//nolint:revive // argument-limit: hot-path helper avoids closure allocation
func verifyHexRangeCandidates(
	candidates []int,
	entry sharedAutomatonEntry,
	dataLen, limit int,
	done <-chan struct{},
	verifyCandidateStart func(int),
) bool {
	handled, canceled := verifySortedCandidateStarts(
		candidates,
		entry.AtomOffset,
		entry.AtomMaxOffset,
		dataLen,
		limit,
		done,
		verifyCandidateStart,
	)
	if canceled || handled {
		return true
	}
	var startsBuf [64]int
	starts, collectHandled := collectRegexCandidateStartsInto(
		startsBuf[:0],
		candidates,
		entry.AtomOffset,
		entry.AtomMaxOffset,
		false,
		dataLen,
		limit,
	)
	if !collectHandled {
		return false
	}
	for index, start := range starts {
		if scanCanceledAt(done, index) {
			return true
		}
		verifyCandidateStart(start)
	}
	return true
}

type hexAtomAdjCheck struct {
	relOffset int
	want      byte
}

//nolint:revive // argument-limit: hot-path helper avoids struct allocation
func collectHexAtomAdjacentChecks(
	tokens []HexPatternToken,
	atomOffset, atomMaxOffset int,
	xorKey *byte,
	out *[4]hexAtomAdjCheck,
) int {
	if atomMaxOffset < 0 {
		return 0
	}
	currMin, currMax := 0, 0
	runStartTok := 0
	runMin, runMax := 0, 0
	flushRun := func(runEndTok int) int {
		if runEndTok <= runStartTok {
			return 0
		}
		offsetInRun := atomOffset - runMin
		runLen := runEndTok - runStartTok
		if offsetInRun < 0 || offsetInRun >= runLen || atomMaxOffset-runMax != offsetInRun {
			return 0
		}
		n := 0
		for i := runStartTok; i < runEndTok && n < len(out); i++ {
			if i-runStartTok == offsetInRun {
				continue
			}
			if b, ok := definiteHexByte(tokens[i], xorKey); ok {
				out[n] = hexAtomAdjCheck{relOffset: (i - runStartTok) - offsetInRun, want: b}
				n++
			}
		}
		return n
	}
	for i, tok := range tokens {
		switch tok.Kind {
		case HexTokenByte, HexTokenMasked, HexTokenWildcard:
			currMin++
			if currMax >= 0 {
				currMax++
			}
		default:
			if n := flushRun(i); n > 0 {
				return n
			}
			switch tok.Kind {
			case HexTokenJump:
				if tok.Min > 0 {
					currMin += tok.Min
				}
				if tok.Max < 0 {
					currMax = -1
				} else if currMax >= 0 {
					currMax += tok.Max
				}
			case HexTokenAlt:
				return 0
			}
			runStartTok = i + 1
			runMin, runMax = currMin, currMax
		}
	}
	return flushRun(len(tokens))
}

//nolint:revive // argument-limit: hot-path helper avoids struct allocation
func filterHexCandidatesByAdjacent(dst, candidates []int, data []byte, checks []hexAtomAdjCheck) []int {
	out := dst[:0]
	for _, atomStart := range candidates {
		ok := true
		for _, c := range checks {
			pos := atomStart + c.relOffset
			if pos < 0 || pos >= len(data) || data[pos] != c.want {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, atomStart)
		}
	}
	return out
}

type hexFanoutDiscriminator struct {
	relOffset int
	buckets   [256][]int
	wildcard  []int
}

func buildHexFanoutDiscriminators(rules []*CompiledRule, lookup []sharedAutomatonEntry) {
	for i := range lookup {
		entry := &lookup[i]
		if entry.Kind != StringKindHex || len(entry.fanout) < 8 {
			continue
		}
		entry.hexDisc = buildHexFanoutDiscriminator(rules, *entry)
	}
}

func buildHexFanoutDiscriminator(rules []*CompiledRule, leader sharedAutomatonEntry) *hexFanoutDiscriminator {
	groupSize := 1 + len(leader.fanout)
	allChecks := make([][4]hexAtomAdjCheck, groupSize)
	allCounts := make([]int, groupSize)
	offsetStats := make(map[int][256]bool)
	offsetHits := make(map[int]int)

	for idx := range groupSize {
		e := leader
		if idx > 0 {
			e = leader.fanout[idx-1]
		}
		if e.RuleIndex < 0 || e.RuleIndex >= len(rules) {
			continue
		}
		rule := rules[e.RuleIndex]
		if e.StringIdx < 0 || e.StringIdx >= len(rule.IndexToStringID) {
			continue
		}
		pat := rule.HexPatterns[rule.IndexToStringID[e.StringIdx]]
		if pat == nil || len(pat.XorKeys) > 1 {
			continue
		}
		var xorKey *byte
		if len(pat.XorKeys) == 1 {
			xorKey = &pat.XorKeys[0]
		}
		n := collectHexAtomAdjacentChecks(pat.Tokens, e.AtomOffset, e.AtomMaxOffset, xorKey, &allChecks[idx])
		allCounts[idx] = n
		for j := range n {
			c := allChecks[idx][j]
			seen := offsetStats[c.relOffset]
			seen[c.want] = true
			offsetStats[c.relOffset] = seen
			offsetHits[c.relOffset]++
		}
	}

	bestOffset := 0
	bestScore := -1
	bestDistinct := 0
	for relOffset, hits := range offsetHits {
		if hits < groupSize/2 {
			continue
		}
		distinct := 0
		for _, ok := range offsetStats[relOffset] {
			if ok {
				distinct++
			}
		}
		if distinct < 2 {
			continue
		}
		score := distinct*1024 + hits
		if score > bestScore {
			bestScore = score
			bestOffset = relOffset
			bestDistinct = distinct
		}
	}
	if bestScore < 0 || bestDistinct < 2 {
		return nil
	}

	disc := &hexFanoutDiscriminator{relOffset: bestOffset}
	for idx := range groupSize {
		matched := false
		for j := range allCounts[idx] {
			if allChecks[idx][j].relOffset == bestOffset {
				b := allChecks[idx][j].want
				disc.buckets[b] = append(disc.buckets[b], idx)
				matched = true
				break
			}
		}
		if !matched {
			disc.wildcard = append(disc.wildcard, idx)
		}
	}
	return disc
}

//nolint:revive // argument-limit: hot-path helper avoids struct allocation
func (s *Scanner) verifyHexFanoutDiscriminated(
	ctx context.Context,
	leader sharedAutomatonEntry,
	data []byte,
	candidates []int,
	cache *nonTextMatchCache,
) {
	disc := leader.hexDisc
	groupSize := 1 + len(leader.fanout)
	if cap(s.hexScratch.fanoutCandidates) < groupSize {
		s.hexScratch.fanoutCandidates = make([][]int, groupSize)
	} else {
		s.hexScratch.fanoutCandidates = s.hexScratch.fanoutCandidates[:groupSize]
	}
	fanout := s.hexScratch.fanoutCandidates
	touched := s.hexScratch.fanoutTouched[:0]

	relOffset := disc.relOffset
	for _, atomStart := range candidates {
		pos := atomStart + relOffset
		if pos < 0 || pos >= len(data) {
			continue
		}
		targets := disc.buckets[data[pos]]
		for _, target := range targets {
			if len(fanout[target]) == 0 {
				touched = append(touched, target)
			}
			fanout[target] = append(fanout[target], atomStart)
		}
	}

	for _, target := range touched {
		entry := leader
		if target > 0 {
			entry = leader.fanout[target-1]
		}
		s.verifySharedNonTextEntry(ctx, entry, data, fanout[target], cache)
		fanout[target] = fanout[target][:0]
	}
	s.hexScratch.fanoutTouched = touched[:0]

	for _, target := range disc.wildcard {
		entry := leader
		if target > 0 {
			entry = leader.fanout[target-1]
		}
		s.verifySharedNonTextEntry(ctx, entry, data, candidates, cache)
	}
}
