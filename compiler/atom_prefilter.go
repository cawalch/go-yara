package compiler

import (
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
	data      []byte
	minOffset int
	maxOffset int
	score     int
}

type regexAlternativeDedupKey struct {
	data      string
	minOffset int
	maxOffset int
}

type regexByteSetPrefilter struct {
	set       regex.ByteSet
	minOffset int
	maxOffset int
	count     int
}

type prefilterDedupKey struct {
	kind     StringKind
	cacheKey string
	wide     bool
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

func assignNonTextCacheIndices(rules []*CompiledRule) int {
	indices := make(map[nonTextCacheKey]int)
	nextIndex := 0
	for _, rule := range rules {
		for _, strID := range sortedPatternIDs(rule.RegexPatterns) {
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
	return nextIndex
}

func buildFixedRegexDispatch(rules []*CompiledRule) *fixedRegexDispatch {
	entries := make([]fixedRegexDispatchEntry, 0)
	seen := make(map[prefilterDedupKey]struct{})
	for _, rule := range rules {
		for _, strID := range sortedPatternIDs(rule.RegexPatterns) {
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

// selectLiteralAtom chooses a bounded, high-information window from a literal
// prefix. Later windows win ties because generated rule families commonly
// share their leading bytes and vary near the end of the prefix.
func selectLiteralAtom(literal []byte) (prefilterAtom, bool) {
	if len(literal) < minPrefilterAtomLength {
		return prefilterAtom{}, false
	}
	width := min(len(literal), maxPrefilterAtomLength)
	best := prefilterAtom{score: -1}
	for offset := 0; offset+width <= len(literal); offset++ {
		data := literal[offset : offset+width]
		score := prefilterAtomScore(data)
		if score >= best.score {
			best = prefilterAtom{data: data, offset: offset, score: score}
		}
	}
	return best, true
}

func selectMandatoryRegexAtom(atoms []regex.LiteralAtom) (regexPrefilterAtom, bool) {
	return selectRegexAtom(atoms, false)
}

func selectBoundedMandatoryRegexAtom(atoms []regex.LiteralAtom) (regexPrefilterAtom, bool) {
	return selectRegexAtom(atoms, true)
}

func selectRegexAtom(atoms []regex.LiteralAtom, boundedOnly bool) (regexPrefilterAtom, bool) {
	best := regexPrefilterAtom{score: -1}
	for _, candidate := range atoms {
		if boundedOnly && candidate.MaxOffset < 0 {
			continue
		}
		atom, ok := selectLiteralAtom(candidate.Data)
		if !ok {
			continue
		}
		minOffset := candidate.MinOffset + atom.offset
		maxOffset := candidate.MaxOffset
		if maxOffset >= 0 {
			maxOffset += atom.offset
		}
		candidateAtom := regexPrefilterAtom{
			data:      atom.data,
			minOffset: minOffset,
			maxOffset: maxOffset,
			score:     atom.score,
		}
		if betterRegexPrefilterAtom(candidateAtom, best) {
			best = candidateAtom
		}
	}
	return best, len(best.data) >= minPrefilterAtomLength
}

// selectAlternativeRegexAtoms keeps one mandatory atom for every cover group.
// Bounded atoms are preferred, but an unbounded atom can still prove its branch
// cannot match when the atom is absent. The set is all-or-nothing: omitting a
// group would make the candidate scan unsound and could hide a valid match.
func selectAlternativeRegexAtoms(alternatives [][]regex.LiteralAtom) ([]regexPrefilterAtom, bool) {
	if len(alternatives) < 2 {
		return nil, false
	}
	atoms := make([]regexPrefilterAtom, 0, len(alternatives))
	seen := make(map[regexAlternativeDedupKey]struct{}, len(alternatives))
	for _, alternative := range alternatives {
		atom, ok := selectBoundedMandatoryRegexAtom(alternative)
		if !ok {
			atom, ok = selectMandatoryRegexAtom(alternative)
		}
		if !ok {
			return nil, false
		}
		key := regexAlternativeDedupKey{
			data:      string(atom.data),
			minOffset: atom.minOffset,
			maxOffset: atom.maxOffset,
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		atoms = append(atoms, atom)
	}
	return atoms, len(atoms) > 0
}

func selectLeadingGapRegexPlan(plan regex.LeadingByteGapPlan) (*regexLeadingGapPlan, bool) {
	if len(plan.AtomGroups) == 0 || plan.GapSet.Count() > maxRegexByteSetSize {
		return nil, false
	}
	atoms := make([]regexPrefilterAtom, 0, len(plan.AtomGroups))
	seen := make(map[regexAlternativeDedupKey]struct{}, len(plan.AtomGroups))
	for _, group := range plan.AtomGroups {
		atom, ok := selectBoundedMandatoryRegexAtom(group)
		if !ok {
			return nil, false
		}
		if atom.maxOffset-atom.minOffset > maxLeadingGapAtomOffsetWidth {
			return nil, false
		}
		key := regexAlternativeDedupKey{data: string(atom.data), minOffset: atom.minOffset, maxOffset: atom.maxOffset}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		atoms = append(atoms, atom)
	}
	if len(atoms) == 0 {
		return nil, false
	}
	return &regexLeadingGapPlan{
		leadingSet: plan.LeadingSet,
		gapSet:     plan.GapSet,
		gapMin:     plan.GapMin,
		gapMax:     plan.GapMax,
		atoms:      atoms,
	}, true
}

func cloneLeadingGapRegexPlan(plan *regexLeadingGapPlan) *regexLeadingGapPlan {
	if plan == nil {
		return nil
	}
	return &regexLeadingGapPlan{
		leadingSet: plan.leadingSet,
		gapSet:     plan.gapSet,
		gapMin:     plan.gapMin,
		gapMax:     plan.gapMax,
		atoms:      cloneRegexPrefilterAtoms(plan.atoms),
	}
}

func cloneRegexPrefilterAtoms(atoms []regexPrefilterAtom) []regexPrefilterAtom {
	if len(atoms) == 0 {
		return nil
	}
	cloned := make([]regexPrefilterAtom, len(atoms))
	for index, atom := range atoms {
		cloned[index] = atom
		cloned[index].data = append([]byte(nil), atom.data...)
	}
	return cloned
}

func widenRegexPrefilterAtoms(atoms []regexPrefilterAtom) []regexPrefilterAtom {
	if len(atoms) == 0 {
		return nil
	}
	wide := make([]regexPrefilterAtom, len(atoms))
	for index, atom := range atoms {
		wide[index] = atom
		wide[index].data = widenRegexPrefix(atom.data)
		wide[index].minOffset *= 2
		if wide[index].maxOffset >= 0 {
			wide[index].maxOffset *= 2
		}
	}
	return wide
}

func betterRegexPrefilterAtom(candidate, current regexPrefilterAtom) bool {
	if len(candidate.data) != len(current.data) {
		return len(candidate.data) > len(current.data)
	}
	candidateBounded := candidate.maxOffset >= 0
	currentBounded := current.maxOffset >= 0
	if candidateBounded != currentBounded {
		return candidateBounded
	}
	if candidate.score != current.score {
		return candidate.score > current.score
	}
	if candidateBounded {
		candidateWidth := candidate.maxOffset - candidate.minOffset
		currentWidth := current.maxOffset - current.minOffset
		if candidateWidth != currentWidth {
			return candidateWidth < currentWidth
		}
	}
	return true
}

func selectMandatoryRegexByteSetAtom(atoms []regex.ByteSetAtom, flags regex.Flags) (regexByteSetPrefilter, bool) {
	var best regexByteSetPrefilter
	found := false
	for _, atom := range atoms {
		set := atom.Set
		if flags&regex.FlagsNoCase != 0 {
			set = set.ASCIIFolded()
		}
		count := set.Count()
		if count == 0 || count > maxRegexByteSetSize {
			continue
		}
		candidate := regexByteSetPrefilter{
			set:       set,
			minOffset: atom.MinOffset,
			maxOffset: atom.MaxOffset,
			count:     count,
		}
		if !found || betterRegexByteSetPrefilter(candidate, best) {
			best = candidate
			found = true
		}
	}
	return best, found
}

func betterRegexByteSetPrefilter(candidate, current regexByteSetPrefilter) bool {
	candidateBounded := candidate.maxOffset >= 0
	currentBounded := current.maxOffset >= 0
	if candidateBounded != currentBounded {
		return candidateBounded
	}
	if candidate.count != current.count {
		return candidate.count < current.count
	}
	if candidateBounded {
		candidateWidth := candidate.maxOffset - candidate.minOffset
		currentWidth := current.maxOffset - current.minOffset
		if candidateWidth != currentWidth {
			return candidateWidth < currentWidth
		}
	}
	return true
}

func selectSharedRegexAtom(pattern RegexPattern) (regexPrefilterAtom, bool) {
	if atom, ok := selectLiteralAtom(pattern.prefix); ok {
		return regexPrefilterAtom{
			data:      atom.data,
			minOffset: atom.offset,
			maxOffset: atom.offset,
			score:     atom.score,
		}, true
	}
	if len(pattern.atom) < minPrefilterAtomLength {
		return regexPrefilterAtom{}, false
	}
	return regexPrefilterAtom{
		data:      pattern.atom,
		minOffset: pattern.atomMinOffset,
		maxOffset: pattern.atomMaxOffset,
		score:     prefilterAtomScore(pattern.atom),
	}, true
}

func prefilterAtomScore(atom []byte) int {
	score := 0
	var seen [256]bool
	for _, b := range atom {
		switch {
		case b == 0 || b >= 0x80:
			score += 6
		case b >= '0' && b <= '9':
			score += 3
		case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z':
			score += 2
		default:
			score += 4
		}
		if !seen[b] {
			score++
			seen[b] = true
		}
	}
	return score
}

// selectHexAtom chooses the best literal run whose byte offset from the start
// is statically known. Variable jumps and alternatives end the safe region;
// patterns without a useful atom remain on the existing matcher path.
func selectHexAtom(tokens []HexPatternToken) (prefilterAtom, bool) {
	best := prefilterAtom{score: -1}
	fixedOffset := 0
	runOffset := 0
	var run []byte

	considerRun := func() {
		atom, ok := selectLiteralAtom(run)
		if ok {
			atom.offset += runOffset
			if len(atom.data) > len(best.data) || (len(atom.data) == len(best.data) && atom.score >= best.score) {
				best = atom
			}
		}
		run = nil
	}

	for _, token := range tokens {
		exact := token.Kind == HexTokenByte && !token.Negated
		if token.Kind == HexTokenMasked && token.Mask == 0xFF && !token.Negated {
			exact = true
		}
		if exact {
			if len(run) == 0 {
				runOffset = fixedOffset
			}
			run = append(run, token.Value)
			fixedOffset++
			continue
		}

		considerRun()
		switch token.Kind {
		case HexTokenByte, HexTokenMasked, HexTokenWildcard:
			fixedOffset++
		case HexTokenJump:
			if token.Min < 0 || token.Min != token.Max {
				return best, len(best.data) >= minPrefilterAtomLength
			}
			fixedOffset += token.Min
		case HexTokenAlt:
			return best, len(best.data) >= minPrefilterAtomLength
		}
	}
	considerRun()
	return best, len(best.data) >= minPrefilterAtomLength
}

func (s *Scanner) resetPrefilterCandidates(size int) {
	if cap(s.prefilterCandidates) < size {
		s.prefilterCandidates = make([][]int, size)
		return
	}
	s.prefilterCandidates = s.prefilterCandidates[:size]
	for idx := range s.prefilterCandidates {
		s.prefilterCandidates[idx] = s.prefilterCandidates[idx][:0]
	}
}

func (s *Scanner) populateNonTextPrefilterCache(data []byte, cache *nonTextMatchCache) {
	for lookupIdx, entry := range s.program.SharedLookup {
		if entry.Kind == StringKindText || entry.CacheIndex < 0 || entry.CacheIndex >= len(cache.matches) {
			continue
		}
		if entry.RuleIndex < 0 || entry.RuleIndex >= len(s.program.Rules) {
			continue
		}
		rule := s.program.Rules[entry.RuleIndex]
		if entry.StringIdx < 0 || entry.StringIdx >= len(rule.IndexToStringID) {
			continue
		}
		strID := rule.IndexToStringID[entry.StringIdx]
		candidates := s.prefilterCandidates[lookupIdx]

		switch entry.Kind {
		case StringKindRegex:
			dst := cache.matches[entry.CacheIndex]
			if len(candidates) > 0 {
				dst = appendRegexPrefilterMatches(dst, rule, strID, entry, data, candidates)
			}
			cache.set(entry.CacheIndex, dst)
		case StringKindHex:
			dst := cache.matches[entry.CacheIndex]
			if len(candidates) > 0 {
				dst = appendHexPrefilterMatches(dst, rule, strID, entry, data, candidates)
			}
			cache.set(entry.CacheIndex, dst)
		}
	}
}

//nolint:revive // argument-limit: hot-path helper keeps candidate verification direct
func appendRegexPrefilterMatches(
	dst []matchSpan,
	rule *CompiledRule,
	strID string,
	entry SharedAutomatonEntry,
	data []byte,
	candidates []int,
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
		return appendRegexFallbackMatches(dst, rule, strID, pattern, data, flags, entry.IsWide)
	}
	limit := max(1024, len(data)/4)
	starts, handled := collectRegexCandidateStarts(
		candidates,
		entry.AtomOffset,
		entry.AtomMaxOffset,
		entry.IsWide,
		len(data),
		limit,
	)
	if !handled {
		return appendRegexFallbackMatches(dst, rule, strID, pattern, data, flags, entry.IsWide)
	}
	if len(starts) == 0 {
		return dst
	}
	bs, release := newRegexMatchBatch(pattern)
	defer releaseRegexMatchBatch(release)
	for _, start := range starts {
		if pattern.anchored && start != 0 {
			continue
		}
		matched, startOff, endOff := execRegexMatchAt(bs, pattern, data, flags, entry.IsWide, start)
		if !matched {
			continue
		}
		absStart := start + startOff
		absEnd := start + endOff
		if absEnd < absStart {
			continue
		}
		match := Match{Pattern: strID, Offset: int64(absStart), Length: absEnd - absStart}
		if matchPassesModifiers(data, match, rule.StringModifiers[strID], entry.IsWide) {
			dst = append(dst, matchSpan{Offset: match.Offset, Length: match.Length})
		}
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
) []matchSpan {
	ctx := matchContextPool.Get().(*MatchContext)
	ctx.compact = true
	ctx.Reset(data)
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
	entry SharedAutomatonEntry,
	data []byte,
	candidates []int,
) []matchSpan {
	pattern := rule.HexPatterns[strID]
	if pattern == nil {
		return dst
	}
	linear := isLinearHexPattern(pattern.Tokens)
	var scratch hexMatchScratch
	lastStart := -1

	for _, atomStart := range candidates {
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

		for _, end := range scratch.match(pattern.Tokens, data, start, nil) {
			if end <= start {
				continue
			}
			match := Match{Pattern: strID, Offset: int64(start), Length: end - start}
			if matchPassesModifiers(data, match, rule.StringModifiers[strID], false) {
				dst = append(dst, matchSpan{Offset: match.Offset, Length: match.Length})
			}
		}
	}
	return dst
}
