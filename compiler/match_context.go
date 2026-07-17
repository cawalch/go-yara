package compiler

import (
	"bytes"
	"sort"
	"sync"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/regex"
)

var matchContextPool = sync.Pool{
	New: func() any {
		return &MatchContext{
			Matches: make(map[string][]Match),
		}
	},
}

// BuildMatchContext scans data for all patterns in the rule and returns a populated match context.
func BuildMatchContext(rule *CompiledRule, data []byte) *MatchContext {
	ctx := matchContextPool.Get().(*MatchContext)
	PopulateMatchContext(ctx, rule, data)
	return ctx
}

// PopulateMatchContext populates an existing match context (reused) with matches from data
func PopulateMatchContext(ctx *MatchContext, rule *CompiledRule, data []byte) {
	ctx.Reset(data)

	if rule == nil {
		return
	}

	if len(data) == 0 {
		for id, regexInfo := range rule.RegexPatterns {
			modifiers := rule.StringModifiers[id]
			addRegexMatchesWithModifiers(ctx, id, regexInfo, data, modifiers)
		}
		return
	}

	if rule.Automaton != nil {
		for match := range rule.Automaton.SearchIter(data) {
			acceptAutomatonMatch(ctx, rule, data, match)
		}
	}

	for id, regexInfo := range rule.RegexPatterns {
		modifiers := rule.StringModifiers[id]
		addRegexMatchesWithModifiers(ctx, id, regexInfo, data, modifiers)
	}

	for id, pattern := range rule.HexPatterns {
		for _, m := range FindHexMatches(pattern, data) {
			m.Pattern = id
			if matchPassesModifiers(data, m, rule.StringModifiers[id], false) {
				ctx.AddMatch(m)
			}
		}
	}
}

// Reset clears the match context for reuse
func (ctx *MatchContext) Reset(data []byte) {
	ctx.Data = data
	clear(ctx.Matches)
	ctx.FileSize = int64(len(data))
	ctx.EntryPoint = 0
}

// Release returns the match context to the pool
func (ctx *MatchContext) Release() {
	// Clear data reference effectively to allow GC
	ctx.Data = nil
	matchContextPool.Put(ctx)
}

//nolint:revive // argument-limit: API surface function; reducing params would require struct indirection
func addRegexMatches(ctx *MatchContext, id string, regexInfo RegexPattern, data []byte, modifiers []ast.StringModifier, flags regex.Flags, isWide bool) {
	addRegexMatchesCached(ctx, id, regexInfo, data, modifiers, flags, isWide, nil)
}

//nolint:revive // argument-limit: hot path avoids allocating an options struct
func addRegexMatchesCached(
	ctx *MatchContext,
	id string,
	regexInfo RegexPattern,
	data []byte,
	modifiers []ast.StringModifier,
	flags regex.Flags,
	isWide bool,
	byteSetCache *regexByteSetCandidateCache,
) {
	if len(regexInfo.Code) == 0 {
		return
	}

	if regexInfo.anchored {
		bs, release := newRegexMatchBatch(regexInfo)
		defer releaseRegexMatchBatch(release)
		addRegexMatchAt(ctx, id, regexInfo, data, modifiers, flags, isWide, bs, 0)
		return
	}

	prefix := regexInfo.prefix
	if isWide {
		prefix = regexInfo.widePrefix
	}
	if len(prefix) >= minPrefilterAtomLength || len(regexInfo.atom) == 0 {
		if len(prefix) > 0 {
			addRegexMatchesFromPrefix(ctx, id, regexInfo, data, modifiers, flags, isWide, prefix)
			return
		}
	}

	atom := regexInfo.atom
	if isWide {
		atom = regexInfo.wideAtom
	}
	atomRequiresLinearFallback := false
	if len(atom) > 0 {
		starts, handled := regexAtomCandidateStarts(data, atom, regexInfo, flags, isWide)
		if handled {
			if len(starts) == 0 {
				return
			}
			bs, release := newRegexMatchBatch(regexInfo)
			defer releaseRegexMatchBatch(release)
			for _, start := range starts {
				addRegexMatchAt(ctx, id, regexInfo, data, modifiers, flags, isWide, bs, start)
			}
			return
		}
		atomRequiresLinearFallback = true
	}
	alternativeAtoms := regexInfo.alternativeAtoms
	if isWide {
		alternativeAtoms = regexInfo.wideAlternativeAtoms
	}
	if len(alternativeAtoms) > 0 {
		addRegexMatchesFromAlternatives(ctx, id, regexInfo, data, modifiers, flags, isWide, alternativeAtoms)
		return
	}
	useByteSet := regexInfo.byteSetCount > 0 &&
		(!atomRequiresLinearFallback || regexInfo.byteSetMaxOffset >= 0)
	if useByteSet {
		search := regexByteSetSearch{
			data:    data,
			pattern: regexInfo,
			wide:    isWide,
			cache:   byteSetCache,
			useSparseValues: !regexInfo.byteSetContiguous &&
				shouldUseSparseRegexByteSetSearch(data, regexInfo.byteSetValues, isWide),
		}
		plan, handled := search.candidatePlan()
		if handled {
			if plan.count == 0 {
				return
			}
			bs, release := newRegexMatchBatch(regexInfo)
			defer releaseRegexMatchBatch(release)
			candidates := search.candidateIterator(plan)
			for start, ok := candidates.next(); ok; start, ok = candidates.next() {
				addRegexMatchAt(ctx, id, regexInfo, data, modifiers, flags, isWide, bs, start)
			}
			return
		}
	}

	bs, release := newRegexMatchBatch(regexInfo)
	defer releaseRegexMatchBatch(release)
	addRegexMatchesLinear(ctx, id, regexInfo, data, modifiers, flags, isWide, bs)
}

type regexAlternativeCursor struct {
	atom         regexPrefilterAtom
	searcher     regexLiteralSearcher
	searchFrom   int
	start        int
	rangeEnd     int
	pendingStart int
	pendingEnd   int
	hasPending   bool
}

func (cursor *regexAlternativeCursor) advance() {
	if cursor.start >= 0 && cursor.start < cursor.rangeEnd {
		cursor.start++
		return
	}

	start, end, ok := cursor.nextRange()
	if !ok {
		cursor.start = -1
		return
	}
	for {
		nextStart, nextEnd, found := cursor.nextAtomRange()
		if !found {
			break
		}
		if nextStart > end+1 {
			cursor.pendingStart = nextStart
			cursor.pendingEnd = nextEnd
			cursor.hasPending = true
			break
		}
		end = max(end, nextEnd)
	}
	cursor.start = start
	cursor.rangeEnd = end
}

func (cursor *regexAlternativeCursor) nextRange() (int, int, bool) {
	if cursor.hasPending {
		cursor.hasPending = false
		return cursor.pendingStart, cursor.pendingEnd, true
	}
	return cursor.nextAtomRange()
}

func (cursor *regexAlternativeCursor) nextAtomRange() (int, int, bool) {
	for cursor.searchFrom <= len(cursor.searcher.data) {
		occurrence := cursor.searcher.index(cursor.searchFrom)
		if occurrence < 0 {
			return 0, 0, false
		}
		cursor.searchFrom = occurrence + 1
		start := max(0, occurrence-cursor.atom.maxOffset)
		end := min(len(cursor.searcher.data), occurrence-cursor.atom.minOffset)
		if start <= end {
			return start, end, true
		}
	}
	return 0, 0, false
}

//nolint:revive // argument-limit: hot path avoids allocating an options struct
func addRegexMatchesFromAlternatives(
	ctx *MatchContext,
	id string,
	regexInfo RegexPattern,
	data []byte,
	modifiers []ast.StringModifier,
	flags regex.Flags,
	isWide bool,
	atoms []regexPrefilterAtom,
) {
	var inline [8]regexAlternativeCursor
	var cursors []regexAlternativeCursor
	if len(atoms) <= len(inline) {
		cursors = inline[:len(atoms)]
	} else {
		cursors = make([]regexAlternativeCursor, len(atoms))
	}
	for index, atom := range atoms {
		cursors[index].atom = atom
		cursors[index].searcher = newRegexLiteralSearcher(data, atom.data, flags)
		cursors[index].start = -1
		cursors[index].advance()
	}

	bs, release := newRegexMatchBatch(regexInfo)
	defer releaseRegexMatchBatch(release)
	for {
		candidate := -1
		for index := range cursors {
			start := cursors[index].start
			if start >= 0 && (candidate < 0 || start < candidate) {
				candidate = start
			}
		}
		if candidate < 0 {
			return
		}

		addRegexMatchAt(ctx, id, regexInfo, data, modifiers, flags, isWide, bs, candidate)
		for index := range cursors {
			if cursors[index].start == candidate {
				cursors[index].advance()
			}
		}
	}
}

//nolint:revive // argument-limit: hot path avoids allocating an options struct
func addRegexMatchesFromPrefix(
	ctx *MatchContext,
	id string,
	regexInfo RegexPattern,
	data []byte,
	modifiers []ast.StringModifier,
	flags regex.Flags,
	isWide bool,
	prefix []byte,
) {
	searcher := newRegexLiteralSearcher(data, prefix, flags)
	candidate := searcher.index(0)
	if candidate < 0 {
		return
	}
	bs, release := newRegexMatchBatch(regexInfo)
	defer releaseRegexMatchBatch(release)
	for candidate >= 0 {
		addRegexMatchAt(ctx, id, regexInfo, data, modifiers, flags, isWide, bs, candidate)
		searchFrom := candidate + 1
		if searchFrom > len(data) {
			return
		}
		candidate = searcher.index(searchFrom)
	}
}

//nolint:revive // argument-limit: hot path avoids allocating an options struct
func addRegexMatchesLinear(
	ctx *MatchContext,
	id string,
	regexInfo RegexPattern,
	data []byte,
	modifiers []ast.StringModifier,
	flags regex.Flags,
	isWide bool,
	bs *regex.VMBatch,
) {
	for pos := 0; pos <= len(data); pos++ {
		addRegexMatchAt(ctx, id, regexInfo, data, modifiers, flags, isWide, bs, pos)
	}
}

//nolint:revive // argument-limit: hot path avoids allocating an options struct
func addRegexMatchAt(
	ctx *MatchContext,
	id string,
	regexInfo RegexPattern,
	data []byte,
	modifiers []ast.StringModifier,
	flags regex.Flags,
	isWide bool,
	bs *regex.VMBatch,
	start int,
) {
	matched, startOffset, endOffset := execRegexMatchAt(bs, regexInfo, data, flags, isWide, start)
	if !matched {
		return
	}
	absStart := start + startOffset
	absEnd := start + endOffset
	if absEnd < absStart {
		return
	}
	match := Match{Pattern: id, Offset: int64(absStart), Length: absEnd - absStart}
	if matchPassesModifiers(data, match, modifiers, isWide) {
		ctx.AddMatch(match)
	}
}

func newRegexMatchBatch(pattern RegexPattern) (*regex.VMBatch, func()) {
	if len(pattern.fixedByteSets) > 0 {
		return nil, nil
	}
	return regex.NewVMBatch(len(pattern.Code))
}

func releaseRegexMatchBatch(release func()) {
	if release != nil {
		release()
	}
}

//nolint:revive // argument-limit: exact and VM paths share one hot verifier
func execRegexMatchAt(
	bs *regex.VMBatch,
	pattern RegexPattern,
	data []byte,
	flags regex.Flags,
	isWide bool,
	start int,
) (matched bool, startOffset, endOffset int) {
	if len(pattern.fixedByteSets) > 0 {
		length, ok := fixedRegexMatchAt(pattern.fixedByteSets, data, isWide, start)
		if !ok {
			return false, -1, -1
		}
		return true, 0, length
	}
	return regex.ExecMatchBatch(bs, pattern.Code, data, flags, start)
}

//nolint:revive // argument-limit: fixed-width hot path avoids options indirection
func fixedRegexMatchAt(sets []regex.ByteSet, data []byte, wide bool, start int) (int, bool) {
	step := 1
	if wide {
		step = 2
	}
	length := len(sets) * step
	if start < 0 || start > len(data)-length {
		return 0, false
	}
	for index, set := range sets {
		position := start + index*step
		if !set.Contains(data[position]) || wide && data[position+1] != 0 {
			return 0, false
		}
	}
	return length, true
}

//nolint:revive // argument-limit: hot path avoids allocating an options struct
func regexAtomCandidateStarts(
	data, atom []byte,
	pattern RegexPattern,
	flags regex.Flags,
	isWide bool,
) ([]int, bool) {
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
	for searchFrom := first + 1; searchFrom <= len(data); {
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
	maxOffset := pattern.atomMaxOffset
	if isWide {
		minOffset *= 2
		maxOffset *= 2
	}
	return collectRegexCandidateStarts(atomStarts, minOffset, maxOffset, isWide, len(data), limit)
}

type regexByteSetSearch struct {
	data            []byte
	pattern         RegexPattern
	wide            bool
	cache           *regexByteSetCandidateCache
	useSparseValues bool
}

func shouldUseSparseRegexByteSetSearch(data, values []byte, wide bool) bool {
	if wide || len(values) == 0 || len(data) < 64 {
		return false
	}
	sample := data[:min(len(data), 512)]
	matches := 0
	for _, value := range sample {
		for _, candidate := range values {
			if value == candidate {
				matches++
				if matches >= 8 {
					return false
				}
				break
			}
		}
	}
	return true
}

type regexByteSetCacheKey struct {
	set  regex.ByteSet
	wide bool
}

const maxCachedRegexByteSetPositions = 64

type regexByteSetCacheEntry struct {
	positions []int
	ready     bool
	complete  bool
}

type regexByteSetCandidateCache struct {
	entries map[regexByteSetCacheKey]*regexByteSetCacheEntry
}

func (cache *regexByteSetCandidateCache) reset() {
	for _, entry := range cache.entries {
		entry.positions = entry.positions[:0]
		entry.ready = false
		entry.complete = false
	}
}

func (search regexByteSetSearch) cacheEntry() *regexByteSetCacheEntry {
	if search.cache == nil {
		return nil
	}
	if search.cache.entries == nil {
		search.cache.entries = make(map[regexByteSetCacheKey]*regexByteSetCacheEntry)
	}
	key := regexByteSetCacheKey{set: search.pattern.byteSet, wide: search.wide}
	entry := search.cache.entries[key]
	if entry == nil {
		entry = &regexByteSetCacheEntry{}
		search.cache.entries[key] = entry
	}
	return entry
}

type regexByteSetCandidatePlan struct {
	positions []int
	useCached bool
	count     int
}

func (search regexByteSetSearch) candidatePlan() (regexByteSetCandidatePlan, bool) {
	entry := search.cacheEntry()
	if search.pattern.byteSetMaxOffset < 0 {
		return search.unboundedCandidatePlan(entry)
	}
	limit := max(1024, len(search.data)/4)
	if entry != nil && entry.ready && entry.complete {
		return search.planCachedPositions(entry.positions, limit)
	}
	return search.planScannedPositions(entry, limit)
}

func (search regexByteSetSearch) unboundedCandidatePlan(entry *regexByteSetCacheEntry) (regexByteSetCandidatePlan, bool) {
	if entry != nil && entry.ready && entry.complete {
		return regexByteSetCandidatePlan{positions: entry.positions, useCached: true}, len(entry.positions) == 0
	}
	if search.index(0) >= 0 {
		if entry != nil {
			entry.positions = entry.positions[:0]
			entry.ready = true
			entry.complete = false
		}
		return regexByteSetCandidatePlan{}, false
	}
	if entry != nil {
		entry.positions = entry.positions[:0]
		entry.ready = true
		entry.complete = true
	}
	return regexByteSetCandidatePlan{useCached: entry != nil}, true
}

func (search regexByteSetSearch) planCachedPositions(positions []int, limit int) (regexByteSetCandidatePlan, bool) {
	counter := newRegexCandidateStartCounter(search, limit)
	for _, position := range positions {
		if !counter.add(position) {
			return regexByteSetCandidatePlan{}, false
		}
	}
	return regexByteSetCandidatePlan{positions: positions, useCached: true, count: counter.count}, true
}

func (search regexByteSetSearch) planScannedPositions(entry *regexByteSetCacheEntry, limit int) (regexByteSetCandidatePlan, bool) {
	counter := newRegexCandidateStartCounter(search, limit)
	collect := entry != nil && !entry.ready
	complete := collect
	if collect {
		entry.positions = entry.positions[:0]
	}

	for searchFrom := 0; searchFrom <= len(search.data); {
		position := search.index(searchFrom)
		if position < 0 {
			break
		}
		if collect {
			if len(entry.positions) < maxCachedRegexByteSetPositions {
				entry.positions = append(entry.positions, position)
			} else {
				entry.positions = entry.positions[:0]
				complete = false
				collect = false
			}
		}
		if !counter.add(position) {
			search.finishCacheEntry(entry, false)
			return regexByteSetCandidatePlan{}, false
		}
		searchFrom = position + 1
	}

	search.finishCacheEntry(entry, complete)
	plan := regexByteSetCandidatePlan{count: counter.count}
	if entry != nil && entry.complete {
		plan.positions = entry.positions
		plan.useCached = true
	}
	return plan, true
}

func (search regexByteSetSearch) finishCacheEntry(entry *regexByteSetCacheEntry, complete bool) {
	if entry == nil || entry.ready {
		return
	}
	entry.ready = true
	entry.complete = complete
	if !complete {
		entry.positions = entry.positions[:0]
	}
}

type regexCandidateStartCounter struct {
	ranges regexCandidateStartRanges
	count  int
	limit  int
}

type regexCandidateStartRanges struct {
	minOffset  int
	maxOffset  int
	dataLength int
	step       int
	wide       bool
	covered    [2]int
}

func newRegexCandidateStartCounter(search regexByteSetSearch, limit int) regexCandidateStartCounter {
	return regexCandidateStartCounter{ranges: newRegexCandidateStartRanges(search), limit: limit}
}

func newRegexCandidateStartRanges(search regexByteSetSearch) regexCandidateStartRanges {
	minOffset := search.pattern.byteSetMinOffset
	maxOffset := search.pattern.byteSetMaxOffset
	step := 1
	covered := [2]int{-1, -1}
	if search.wide {
		minOffset *= 2
		maxOffset *= 2
		step = 2
		covered = [2]int{-2, -1}
	}
	return regexCandidateStartRanges{
		minOffset:  minOffset,
		maxOffset:  maxOffset,
		dataLength: len(search.data),
		step:       step,
		wide:       search.wide,
		covered:    covered,
	}
}

func (counter *regexCandidateStartCounter) add(position int) bool {
	first, last, ok := counter.ranges.next(position)
	if !ok {
		return true
	}
	added := (last-first)/counter.ranges.step + 1
	counter.count += added
	return counter.count <= counter.limit
}

func (ranges *regexCandidateStartRanges) next(position int) (int, int, bool) {
	first := max(0, position-ranges.maxOffset)
	last := min(ranges.dataLength, position-ranges.minOffset)
	lane := 0
	if ranges.wide {
		lane = position & 1
		if first&1 != lane {
			first++
		}
	}
	first = max(first, ranges.covered[lane]+ranges.step)
	if first > last {
		return 0, 0, false
	}
	count := (last-first)/ranges.step + 1
	last = first + (count-1)*ranges.step
	ranges.covered[lane] = last
	return first, last, true
}

type regexByteSetPositionIterator struct {
	search    regexByteSetSearch
	positions []int
	useCached bool
	index     int
	searchPos int
}

func (iterator *regexByteSetPositionIterator) next() (int, bool) {
	if iterator.useCached {
		if iterator.index >= len(iterator.positions) {
			return 0, false
		}
		position := iterator.positions[iterator.index]
		iterator.index++
		return position, true
	}
	position := iterator.search.index(iterator.searchPos)
	if position < 0 {
		return 0, false
	}
	iterator.searchPos = position + 1
	return position, true
}

type regexByteSetCandidateIterator struct {
	positions regexByteSetPositionIterator
	ranges    regexCandidateStartRanges
	current   int
	last      int
}

func (search regexByteSetSearch) candidateIterator(plan regexByteSetCandidatePlan) regexByteSetCandidateIterator {
	return regexByteSetCandidateIterator{
		positions: regexByteSetPositionIterator{
			search:    search,
			positions: plan.positions,
			useCached: plan.useCached,
		},
		ranges:  newRegexCandidateStartRanges(search),
		current: 1,
	}
}

func (iterator *regexByteSetCandidateIterator) next() (int, bool) {
	for {
		if iterator.current <= iterator.last {
			start := iterator.current
			iterator.current += iterator.ranges.step
			return start, true
		}
		position, ok := iterator.positions.next()
		if !ok {
			return 0, false
		}
		first, last, ok := iterator.ranges.next(position)
		if !ok {
			continue
		}
		iterator.last = last
		iterator.current = first + iterator.ranges.step
		return first, true
	}
}

//nolint:revive // argument-limit: shared by local and Aho-Corasick candidate paths
func collectRegexCandidateStarts(
	atomStarts []int,
	minOffset, maxOffset int,
	isWide bool,
	dataLength, limit int,
) ([]int, bool) {
	step := 1
	if isWide {
		step = 2
	}
	starts := make([]int, 0, min(limit, len(atomStarts)*2))
	for _, atomStart := range atomStarts {
		first := max(0, atomStart-maxOffset)
		last := min(dataLength, atomStart-minOffset)
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
			starts = append(starts, start)
		}
	}
	if len(starts) < 2 {
		return starts, true
	}

	sort.Ints(starts)
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

func widenRegexPrefix(prefix []byte) []byte {
	if len(prefix) == 0 {
		return nil
	}
	wide := make([]byte, len(prefix)*2)
	for i, b := range prefix {
		wide[i*2] = b
	}
	return wide
}

//nolint:revive // argument-limit: byte-search hot path avoids options indirection
func indexRegexLiteral(data []byte, pos int, literal []byte, flags regex.Flags, isWide bool) int {
	if isWide {
		flags |= regex.FlagsWide
	} else {
		flags &^= regex.FlagsWide
	}
	searcher := newRegexLiteralSearcher(data, literal, flags)
	return searcher.index(pos)
}

type regexLiteralSearcher struct {
	data    []byte
	literal []byte
	noCase  bool
	wide    bool
	anchor  int
	cursor  asciiFoldByteCursor
}

// newRegexLiteralSearcher chooses a data-sensitive anchor once for all
// occurrences of one literal in a scan. Reusing the plan is important for
// match-heavy inputs, where resampling for every returned match is expensive.
func newRegexLiteralSearcher(data, literal []byte, flags regex.Flags) regexLiteralSearcher {
	searcher := regexLiteralSearcher{
		data:    data,
		literal: literal,
		noCase:  flags&regex.FlagsNoCase != 0,
		wide:    flags&regex.FlagsWide != 0,
	}
	if searcher.noCase && len(literal) > 0 {
		searcher.anchor = selectRegexLiteralSearchAnchor(data, literal, searcher.wide)
		searcher.cursor = newASCIIFoldByteCursor(literal[searcher.anchor])
	}
	return searcher
}

func (searcher *regexLiteralSearcher) index(pos int) int {
	data := searcher.data
	literal := searcher.literal
	if len(literal) == 0 || pos < 0 || pos > len(data) {
		return -1
	}
	if !searcher.noCase {
		idx := bytes.Index(data[pos:], literal)
		if idx < 0 {
			return -1
		}
		return pos + idx
	}

	last := len(data) - len(literal)
	anchor := searcher.anchor
	searchFrom := pos + anchor
	searchLimit := last + anchor + 1
	for searchFrom < searchLimit {
		occurrence := searcher.cursor.next(data[:searchLimit], searchFrom)
		if occurrence < 0 {
			return -1
		}
		candidate := occurrence - anchor
		if equalRegexPrefixFold(data[candidate:candidate+len(literal)], literal, searcher.wide) {
			return candidate
		}
		searchFrom = occurrence + 1
	}
	return -1
}

func (search regexByteSetSearch) index(pos int) int {
	if search.pattern.byteSetContiguous {
		return search.indexContiguous(pos)
	}
	return search.indexGeneral(pos)
}

func (search regexByteSetSearch) indexContiguous(pos int) int {
	start := max(0, pos)
	if search.pattern.byteSetLower == search.pattern.byteSetUpper && !search.wide {
		return indexRegexByte(search.data, start, search.pattern.byteSetLower)
	}
	data := search.data
	lower := search.pattern.byteSetLower
	width := search.pattern.byteSetUpper - lower
	wide := search.wide
	last := len(data) - 1
	if wide {
		last--
	}
	for candidate := start; candidate <= last; candidate++ {
		inRange := data[candidate]-lower <= width
		if inRange && (!wide || data[candidate+1] == 0) {
			return candidate
		}
	}
	return -1
}

func indexRegexByte(data []byte, pos int, value byte) int {
	index := bytes.IndexByte(data[pos:], value)
	if index < 0 {
		return -1
	}
	return pos + index
}

func (search regexByteSetSearch) indexGeneral(pos int) int {
	if search.useSparseValues {
		return indexSparseRegexByteSet(search.data, pos, search.pattern.byteSetValues)
	}
	data := search.data
	set := search.pattern.byteSet
	wide := search.wide
	last := len(data) - 1
	if wide {
		last--
	}
	for candidate := max(0, pos); candidate <= last; candidate++ {
		member := set.Contains(data[candidate])
		if member && (!wide || data[candidate+1] == 0) {
			return candidate
		}
	}
	return -1
}

func indexSparseRegexByteSet(data []byte, from int, values []byte) int {
	const chunkSize = 4096
	from = max(0, from)
	for from < len(data) {
		end := min(len(data), from+chunkSize)
		chunk := data[from:end]
		best := -1
		for _, value := range values {
			position := bytes.IndexByte(chunk, value)
			if position >= 0 && (best < 0 || position < best) {
				best = position
			}
		}
		if best >= 0 {
			return from + best
		}
		from = end
	}
	return -1
}

const maxRegexLiteralAnchorCandidates = 8

// selectRegexLiteralSearchAnchor samples the input and chooses the least
// frequent byte from the literal for the case-folded byte cursor.
func selectRegexLiteralSearchAnchor(data, literal []byte, wide bool) int {
	step := 1
	if wide {
		step = 2
	}

	var offsets [maxRegexLiteralAnchorCandidates]int
	var folded [maxRegexLiteralAnchorCandidates]byte
	candidateCount := 0
	for offset := 0; offset < len(literal) && candidateCount < len(offsets); offset += step {
		value := toLowerTable[literal[offset]]
		duplicate := false
		for index := 0; index < candidateCount; index++ {
			if folded[index] == value {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		offsets[candidateCount] = offset
		folded[candidateCount] = value
		candidateCount++
	}
	if candidateCount < 2 || len(data) < 64 {
		return 0
	}

	var counts [maxRegexLiteralAnchorCandidates]uint16
	sample := data[:min(len(data), 512)]
	for _, value := range sample {
		value = toLowerTable[value]
		for index := 0; index < candidateCount; index++ {
			if value == folded[index] {
				counts[index]++
			}
		}
	}

	best := 0
	for index := 1; index < candidateCount; index++ {
		if counts[index] < counts[best] ||
			counts[index] == counts[best] && prefilterAtomScore(literal[offsets[index]:offsets[index]+1]) >
				prefilterAtomScore(literal[offsets[best]:offsets[best]+1]) {
			best = index
		}
	}
	return offsets[best]
}

type asciiFoldByteCursor struct {
	values    [2]byte
	positions [2]int
	count     int
	lastFrom  int
}

const (
	asciiFoldCursorExhausted  = -1
	asciiFoldCursorUnsearched = -2
)

func newASCIIFoldByteCursor(want byte) asciiFoldByteCursor {
	other := flipASCIICase(want)
	cursor := asciiFoldByteCursor{
		values:    [2]byte{want, other},
		positions: [2]int{asciiFoldCursorUnsearched, asciiFoldCursorUnsearched},
		count:     1,
		lastFrom:  -1,
	}
	if other != want {
		cursor.count = 2
	}
	return cursor
}

func (cursor *asciiFoldByteCursor) next(data []byte, from int) int {
	if from < cursor.lastFrom {
		cursor.positions = [2]int{asciiFoldCursorUnsearched, asciiFoldCursorUnsearched}
	}
	cursor.lastFrom = from
	best := -1
	for index := 0; index < cursor.count; index++ {
		position := cursor.positions[index]
		if position == asciiFoldCursorExhausted {
			continue
		}
		if position < from {
			relative := bytes.IndexByte(data[from:], cursor.values[index])
			if relative < 0 {
				cursor.positions[index] = asciiFoldCursorExhausted
				continue
			}
			position = from + relative
			cursor.positions[index] = position
		}
		if best < 0 || position < best {
			best = position
		}
	}
	return best
}

func indexASCIIFoldByte(data []byte, want byte) int {
	other := flipASCIICase(want)
	for index, value := range data {
		if value == want || value == other {
			return index
		}
	}
	return -1
}

func equalRegexPrefixFold(data, prefix []byte, wide bool) bool {
	step := 1
	if wide {
		step = 2
	}
	for i := 0; i < len(prefix); i += step {
		if data[i] != prefix[i] && data[i] != flipASCIICase(prefix[i]) {
			return false
		}
		if wide && data[i+1] != 0 {
			return false
		}
	}
	return true
}

//nolint:revive // argument-limit: API surface
func addRegexMatchesWithModifiers(ctx *MatchContext, id string, regexInfo RegexPattern, data []byte, modifiers []ast.StringModifier) {
	addRegexMatchesWithModifiersCached(ctx, id, regexInfo, data, modifiers, nil)
}

//nolint:revive // argument-limit: hot path avoids allocating an options struct
func addRegexMatchesWithModifiersCached(
	ctx *MatchContext,
	id string,
	regexInfo RegexPattern,
	data []byte,
	modifiers []ast.StringModifier,
	byteSetCache *regexByteSetCandidateCache,
) {
	hasWide := hasModifier(modifiers, ast.StringModifierWide)
	hasASCII := hasModifier(modifiers, ast.StringModifierASCII)
	baseFlags := regexInfo.Flags

	switch {
	case hasWide && hasASCII:
		addRegexMatchesCached(ctx, id, regexInfo, data, modifiers, baseFlags|regex.FlagsWide, true, byteSetCache)
		addRegexMatchesCached(ctx, id, regexInfo, data, modifiers, baseFlags&^regex.FlagsWide, false, byteSetCache)
	case hasWide:
		addRegexMatchesCached(ctx, id, regexInfo, data, modifiers, baseFlags|regex.FlagsWide, true, byteSetCache)
	default:
		addRegexMatchesCached(ctx, id, regexInfo, data, modifiers, baseFlags&^regex.FlagsWide, false, byteSetCache)
	}
}

// verifyTextMatch confirms the data region at m.Offset matches the stored
// pattern exactly (case-sensitive strings) or case-insensitively (nocase
// strings). The Aho-Corasick automaton is a candidate finder: for nocase
// strings it registers both ASCII cases of each letter, which means a
// case-sensitive string sharing a trie state could fire on the wrong case.
// This re-check rejects those false candidates. For legitimate candidates the
// check is a no-op. For nocase we lowercase both sides: plain nocase patterns
// are already lowercased, but xor+nocase applies xor after lowercasing so the
// stored variant bytes may be uppercase. Wide strings are handled
// transparently because they are byte-interleaved with 0x00 (unaffected by
// case folding).
//
// acceptAutomatonMatch verifies and records a single Aho-Corasick candidate.
// The automaton is a candidate finder: for nocase strings it registers both
// ASCII cases of each letter, so a case-sensitive string sharing a trie state
// can fire on the wrong case. verifyTextMatch rejects those false candidates;
// matchPassesModifiers then applies remaining modifiers (e.g. fullword).
//
//nolint:revive // argument-limit: internal helper
func acceptAutomatonMatch(ctx *MatchContext, rule *CompiledRule, data []byte, match ACMatch) {
	if rule.StringKinds != nil && rule.StringKinds[match.StringID] != StringKindText {
		return
	}
	length := 0
	isWide := false
	isNocase := false
	var pattern []byte
	if match.StringIndex >= 0 && match.StringIndex < len(rule.Automaton.Strings) {
		info := rule.Automaton.Strings[match.StringIndex]
		length = info.Length
		isWide = (info.Flags & regex.FlagsWide) != 0
		isNocase = (info.Flags & regex.FlagsNoCase) != 0
		pattern = info.Data
	}
	m := Match{
		Pattern: match.StringID,
		Offset:  int64(match.Backtrack),
		Length:  length,
	}
	if !verifyTextMatch(data, m, pattern, isNocase) {
		return
	}
	if matchPassesModifiers(data, m, rule.StringModifiers[match.StringID], isWide) {
		ctx.AddMatch(m)
	}
}

//nolint:revive // argument-limit: internal helper
func verifyTextMatch(data []byte, m Match, pattern []byte, noCase bool) bool {
	if len(pattern) == 0 || m.Length != len(pattern) {
		return false
	}
	offset := int(m.Offset)
	if offset < 0 || offset+m.Length > len(data) {
		return false
	}
	if noCase {
		for i := 0; i < m.Length; i++ {
			if toLowerTable[data[offset+i]] != toLowerTable[pattern[i]] {
				return false
			}
		}
		return true
	}
	for i := 0; i < m.Length; i++ {
		if data[offset+i] != pattern[i] {
			return false
		}
	}
	return true
}

//nolint:revive // argument-limit: internal helper
func matchPassesModifiers(data []byte, m Match, modifiers []ast.StringModifier, isWide bool) bool {
	if len(modifiers) == 0 {
		return true
	}
	if !hasModifier(modifiers, ast.StringModifierFullword) {
		return true
	}
	return isFullwordMatch(data, int(m.Offset), m.Length, isWide)
}

func hasModifier(modifiers []ast.StringModifier, mod ast.StringModifierType) bool {
	for _, m := range modifiers {
		if m.Type == mod {
			return true
		}
	}
	return false
}

//nolint:revive // argument-limit: internal helper
func isFullwordMatch(data []byte, offset, length int, isWide bool) bool {
	if offset < 0 || length <= 0 {
		return false
	}
	if !isWide {
		if offset > 0 && isWordChar(data[offset-1]) {
			return false
		}
		end := offset + length
		if end < len(data) && isWordChar(data[end]) {
			return false
		}
		return true
	}

	if offset >= 2 && isWideWordChar(data, offset-2) {
		return false
	}
	end := offset + length
	if end+1 < len(data) && isWideWordChar(data, end) {
		return false
	}
	return true
}

func isWordChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

func isWideWordChar(data []byte, pos int) bool {
	if pos < 0 || pos+1 >= len(data) {
		return false
	}
	if data[pos+1] != 0x00 {
		return false
	}
	return isWordChar(data[pos])
}
