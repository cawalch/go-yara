package compiler

import (
	"bytes"
	"slices"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/regex"
)

//nolint:revive // argument-limit: API surface function; reducing params would require struct indirection
func addRegexMatches(ctx *MatchContext, id string, regexInfo RegexPattern, data []byte, modifiers []ast.StringModifier, flags regex.Flags, isWide bool) {
	if needsBoundedRegexVerification(regexInfo, data, ctx.maxMatchSpan) {
		addBoundedRegexVerifications(ctx, id, regexInfo, data, modifiers)
		return
	}
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
	// Libyara only verifies candidates that start inside a nonempty buffer.
	if len(regexInfo.Code) == 0 || len(data) == 0 {
		return
	}
	if scanCanceled(ctx.cancelDone) {
		return
	}

	if regexInfo.anchored {
		bs := newRegexMatchBatch(ctx, regexInfo)
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
	//nolint:nestif // candidate verification keeps cancellation local to hot loops
	if len(atom) > 0 {
		starts, handled := regexAtomCandidateStarts(data, atom, regexInfo, flags, isWide, ctx.cancelDone)
		if handled {
			if len(starts) == 0 {
				return
			}
			bs := newRegexMatchBatch(ctx, regexInfo)
			for index, start := range starts {
				if scanCanceledAt(ctx.cancelDone, index) {
					return
				}
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
	useByteSet := regexInfo.byteSetCount > 0 &&
		(!atomRequiresLinearFallback || regexInfo.byteSetMaxOffset >= 0)
	useSparseByteSet := useByteSet && !regexInfo.byteSetContiguous &&
		shouldUseSparseRegexByteSetSearch(data, regexInfo.byteSetValues, isWide)
	if len(alternativeAtoms) > 0 {
		if !hasUnboundedRegexAlternative(alternativeAtoms) {
			addRegexMatchesFromAlternatives(ctx, id, regexInfo, data, modifiers, flags, isWide, alternativeAtoms)
			return
		}
		// A sparse leading byte set is cheaper to scan directly than probing every
		// unbounded literal. For dense sets, absent literals avoid that linear scan.
		if !useSparseByteSet && !unboundedRegexAlternativePresent(data, alternativeAtoms, flags, ctx.cancelDone) {
			addRegexMatchesFromAlternatives(ctx, id, regexInfo, data, modifiers, flags, isWide, alternativeAtoms)
			return
		}
	}
	//nolint:nestif // candidate verification keeps cancellation local to hot loops
	if !isWide && regexInfo.leadingGap != nil && !useSparseByteSet {
		starts, handled := leadingGapRegexCandidateStarts(data, regexInfo.leadingGap, flags, ctx.cancelDone)
		if handled {
			if len(starts) == 0 {
				return
			}
			bs := newRegexMatchBatch(ctx, regexInfo)
			for index, start := range starts {
				if scanCanceledAt(ctx.cancelDone, index) {
					return
				}
				addRegexMatchAt(ctx, id, regexInfo, data, modifiers, flags, isWide, bs, start)
			}
			return
		}
	}
	//nolint:nestif // candidate verification keeps cancellation local to hot loops
	if useByteSet {
		search := regexByteSetSearch{
			data:            data,
			pattern:         regexInfo,
			wide:            isWide,
			cache:           byteSetCache,
			useSparseValues: useSparseByteSet,
			done:            ctx.cancelDone,
		}
		plan, handled := search.candidatePlan()
		if handled {
			if plan.count == 0 {
				return
			}
			bs := newRegexMatchBatch(ctx, regexInfo)
			candidates := search.candidateIterator(plan)
			for index, start, ok := 0, 0, false; ; index++ {
				start, ok = candidates.next()
				if !ok {
					return
				}
				if scanCanceledAt(ctx.cancelDone, index) {
					return
				}
				addRegexMatchAt(ctx, id, regexInfo, data, modifiers, flags, isWide, bs, start)
			}
		}
	}

	bs := newRegexMatchBatch(ctx, regexInfo)
	addRegexMatchesLinear(ctx, id, regexInfo, data, modifiers, flags, isWide, bs)
}

//nolint:revive // cancellation signal stays explicit in the candidate hot path
func leadingGapRegexCandidateStarts(
	data []byte,
	plan *regexLeadingGapPlan,
	flags regex.Flags,
	done <-chan struct{},
) ([]int, bool) {
	if plan == nil || len(plan.atoms) == 0 {
		return nil, false
	}
	limit := max(1024, len(data)/4)
	starts := make([]int, 0, min(limit, 64))
	checkpoint := 0
	for _, atom := range plan.atoms {
		searcher := newRegexLiteralSearcher(data, atom.data, flags)
		for occurrence := searcher.index(0); occurrence >= 0; occurrence = searcher.index(occurrence + 1) {
			if scanCanceledAt(done, checkpoint) {
				return nil, true
			}
			checkpoint++
			for offset := atom.minOffset; offset <= atom.maxOffset; offset++ {
				suffixStart := occurrence - offset
				if suffixStart < 1 || suffixStart > len(data) {
					continue
				}
				maxGap := suffixStart - 1
				if plan.gapMax >= 0 {
					maxGap = min(maxGap, plan.gapMax)
				}
				for gapLength := 0; gapLength <= maxGap; gapLength++ {
					if scanCanceledAt(done, checkpoint) {
						return nil, true
					}
					checkpoint++
					leadingPosition := suffixStart - gapLength - 1
					if gapLength >= plan.gapMin && plan.leadingSet.Contains(data[leadingPosition]) {
						if len(starts) >= limit {
							return nil, false
						}
						starts = append(starts, leadingPosition)
					}
					if gapLength == maxGap || !plan.gapSet.Contains(data[leadingPosition]) {
						break
					}
				}
			}
			if occurrence == len(data) {
				break
			}
		}
	}
	if len(starts) < 2 {
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

func hasUnboundedRegexAlternative(atoms []regexPrefilterAtom) bool {
	for _, atom := range atoms {
		if atom.maxOffset < 0 {
			return true
		}
	}
	return false
}

//nolint:revive // cancellation signal stays explicit in the candidate hot path
func unboundedRegexAlternativePresent(
	data []byte,
	atoms []regexPrefilterAtom,
	flags regex.Flags,
	done <-chan struct{},
) bool {
	for index, atom := range atoms {
		if scanCanceledAt(done, index) {
			return false
		}
		if atom.maxOffset >= 0 {
			continue
		}
		searchFlags := flags
		if atom.asciiNoCase {
			searchFlags |= regex.FlagsNoCase
		}
		searcher := newRegexLiteralSearcher(data, atom.data, searchFlags)
		if searcher.index(0) >= 0 {
			return true
		}
	}
	return false
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
	boundedCount := 0
	for _, atom := range atoms {
		if atom.maxOffset >= 0 {
			boundedCount++
		}
	}
	if boundedCount == 0 {
		return
	}
	var inline [8]regexAlternativeCursor
	var cursors []regexAlternativeCursor
	if boundedCount <= len(inline) {
		cursors = inline[:boundedCount]
	} else {
		cursors = make([]regexAlternativeCursor, boundedCount)
	}
	cursorIndex := 0
	for _, atom := range atoms {
		if atom.maxOffset < 0 {
			continue
		}
		index := cursorIndex
		cursorIndex++
		cursors[index].atom = atom
		searchFlags := flags
		if atom.asciiNoCase {
			searchFlags |= regex.FlagsNoCase
		}
		cursors[index].searcher = newRegexLiteralSearcher(data, atom.data, searchFlags)
		cursors[index].start = -1
		cursors[index].advance()
	}

	bs := newRegexMatchBatch(ctx, regexInfo)
	checkpoint := 0
	for {
		if scanCanceledAt(ctx.cancelDone, checkpoint) {
			return
		}
		checkpoint++
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
	bs := newRegexMatchBatch(ctx, regexInfo)
	for checkpoint := 0; candidate >= 0; checkpoint++ {
		if scanCanceledAt(ctx.cancelDone, checkpoint) {
			return
		}
		addRegexMatchAt(ctx, id, regexInfo, data, modifiers, flags, isWide, bs, candidate)
		// Fast scan can stop only after the context accepts an occurrence;
		// a streaming ownership filter may reject earlier candidates.
		if ctx.maxMatchesPerPattern > 0 && ctx.matchCount(id) >= ctx.maxMatchesPerPattern {
			return
		}
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
	for pos := 0; pos < len(data); pos++ {
		if scanCanceledAt(ctx.cancelDone, pos) {
			return
		}
		addRegexMatchAt(ctx, id, regexInfo, data, modifiers, flags, isWide, bs, pos)
	}
}

const (
	regexWindowMarginASCII = 16
	regexWindowMarginWide  = 32
)

//nolint:nestif,revive // argument-limit,nestif: window calculation keeps matching parameters explicit
func boundedRegexWindow(
	data []byte,
	start int,
	pattern RegexPattern,
	isWide bool,
	maxMatchSpan int,
) ([]byte, int, int) {
	dataLen := len(data)
	if dataLen == 0 || start >= dataLen {
		return data, start, 0
	}

	margin := regexWindowMarginASCII
	if isWide {
		margin = regexWindowMarginWide
	}

	windowStart := max(0, start-margin)
	if isWide && (start-windowStart)&1 != 0 {
		windowStart--
	}
	if windowStart < 0 {
		windowStart = 0
	}

	windowEnd := dataLen
	if maxMatchSpan > 0 {
		spanEnd := start + maxMatchSpan
		if spanEnd < windowEnd {
			windowEnd = spanEnd
		}
	}

	if pattern.atomMaxOffset >= 0 && pattern.atomMaxSuffix >= 0 {
		maxOffset := pattern.atomMaxOffset
		atomLen := len(pattern.atom)
		if isWide {
			maxOffset *= 2
			atomLen = len(pattern.wideAtom)
		}
		maxSuffix := pattern.atomMaxSuffix
		if isWide {
			maxSuffix *= 2
		}
		tightEnd := start + maxOffset + atomLen + maxSuffix + margin
		if tightEnd < windowEnd {
			windowEnd = tightEnd
		}
	} else if pattern.maxLength >= 0 {
		maxLen := pattern.maxLength
		if isWide {
			maxLen *= 2
		}
		tightEnd := start + maxLen + margin
		if tightEnd < windowEnd {
			windowEnd = tightEnd
		}
	}

	if windowEnd > dataLen {
		windowEnd = dataLen
	}
	if windowEnd < windowStart {
		windowEnd = windowStart
	}

	return data[windowStart:windowEnd], start - windowStart, windowStart
}

func (pattern RegexPattern) startMatchesFirstByte(data []byte, start int, isWide bool) bool {
	if !pattern.hasFirstByteSet {
		return true
	}
	if isWide {
		return start < len(data) && pattern.firstByteSet.Contains(data[start]) && start+1 < len(data) && data[start+1] == 0
	}
	return start < len(data) && pattern.firstByteSet.Contains(data[start])
}

//nolint:revive // argument-limit: prefix verification keeps hot-path arguments explicit
func matchExactPrefix(data []byte, atomStart int, prefix []byte, noCase bool) bool {
	if len(prefix) == 0 {
		return true
	}
	if atomStart < len(prefix) {
		return false
	}
	if noCase {
		return bytes.EqualFold(data[atomStart-len(prefix):atomStart], prefix)
	}
	return bytes.Equal(data[atomStart-len(prefix):atomStart], prefix)
}

//nolint:revive // argument-limit: backward scanning avoids allocating a scan parameter struct
func countBackwardMatches(data []byte, from, step int, set regex.ByteSet, maxCount int) int {
	count := 0
	for pos := from; pos >= 0; pos -= step {
		if step == 2 && data[pos+1] != 0 {
			break
		}
		if !set.Contains(data[pos]) {
			break
		}
		count++
		if maxCount >= 0 && count >= maxCount {
			break
		}
	}
	return count
}

func (pattern RegexPattern) atomOccurrenceValidASCII(data []byte, atomStart int, noCase bool) (int, bool) {
	if !matchExactPrefix(data, atomStart, pattern.exactPrefixSuffix, noCase) {
		return 0, false
	}
	if pattern.hasPrecedingByteSet && pattern.atomMinOffset > 0 {
		if atomStart < 1 || !pattern.precedingByteSet.Contains(data[atomStart-1]) {
			return 0, false
		}
	}
	effMaxOffset := pattern.atomMaxOffset
	if pattern.hasPrefixRepeat {
		from := atomStart - len(pattern.exactPrefixSuffix) - 1
		count := countBackwardMatches(data, from, 1, pattern.prefixRepeatClass, pattern.prefixRepeatMax)
		if count < pattern.prefixRepeatMin {
			return 0, false
		}
		if pattern.prefixRepeatMax >= 0 && count < pattern.prefixRepeatMax {
			effMaxOffset = max(pattern.atomMinOffset, pattern.atomMaxOffset-(pattern.prefixRepeatMax-count))
		}
	}
	return effMaxOffset, true
}

func (pattern RegexPattern) atomOccurrenceValidWide(data []byte, atomStart int, noCase bool) (int, bool) {
	if !matchExactPrefix(data, atomStart, pattern.wideExactPrefix, noCase) {
		return 0, false
	}
	if pattern.hasPrecedingByteSet && pattern.atomMinOffset > 0 {
		if atomStart < 2 || data[atomStart-1] != 0 || !pattern.precedingByteSet.Contains(data[atomStart-2]) {
			return 0, false
		}
	}
	effMaxOffset := pattern.atomMaxOffset * 2
	if pattern.hasPrefixRepeat {
		from := atomStart - len(pattern.wideExactPrefix) - 2
		count := countBackwardMatches(data, from, 2, pattern.prefixRepeatClass, pattern.prefixRepeatMax)
		if count < pattern.prefixRepeatMin {
			return 0, false
		}
		if pattern.prefixRepeatMax >= 0 && count < pattern.prefixRepeatMax {
			effMaxOffset = max(pattern.atomMinOffset*2, pattern.atomMaxOffset*2-(pattern.prefixRepeatMax-count)*2)
		}
	}
	return effMaxOffset, true
}

func (pattern RegexPattern) atomOccurrenceValid(data []byte, atomStart int, isWide bool) (int, bool) {
	noCase := pattern.atomASCIINoCase || pattern.Flags&regex.FlagsNoCase != 0
	if isWide {
		return pattern.atomOccurrenceValidWide(data, atomStart, noCase)
	}
	return pattern.atomOccurrenceValidASCII(data, atomStart, noCase)
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
	if !regexInfo.startMatchesFirstByte(data, start, isWide) {
		return
	}
	// Endpoint-filtered patterns are nonempty. Reject their left boundary
	// before running the VM; a later endpoint cannot make it valid.
	if flags&regex.FlagsFullwordEnd != 0 && !isFullwordStart(data, start, isWide) {
		return
	}
	maxMatchSpan := 0
	if ctx != nil {
		maxMatchSpan = ctx.maxMatchSpan
	}
	scanData, relStart, windowStart := boundedRegexWindow(data, start, regexInfo, isWide, maxMatchSpan)
	matched, startOffset, endOffset := execRegexMatchAt(bs, regexInfo, scanData, flags, isWide, relStart, ctx.cancelDone)
	if !matched {
		return
	}
	absStart := windowStart + relStart + startOffset
	absEnd := windowStart + relStart + endOffset
	if absEnd < absStart {
		return
	}
	match := Match{Pattern: id, Offset: int64(absStart), Length: absEnd - absStart}
	if matchPassesModifiers(data, match, modifiers, isWide && flags&regexASCIIWordBoundary == 0) {
		ctx.AddMatch(match)
	}
}

func newRegexMatchBatch(ctx *MatchContext, pattern RegexPattern) *regex.VMBatch {
	if len(pattern.fixedByteSets) > 0 {
		return nil
	}
	return ctx.acquireRegexBatch(len(pattern.Code))
}

//nolint:revive // cancellation signal accompanies the exact verifier arguments
func execRegexMatchAt(bs *regex.VMBatch, pattern RegexPattern, data []byte, flags regex.Flags, isWide bool, start int, done <-chan struct{}) (matched bool, startOffset, endOffset int) {
	if scanCanceled(done) {
		return false, -1, -1
	}

	if pattern.verification != nil && pattern.verification.ForwardOnly && len(data)-start > regexVerificationDistance {
		ends, err := regex.ExecVerifyBatchWithCancel(bs, pattern.verification.Atoms[0].Forward, data, flags, start, regexVerificationDistance, done)
		if err != nil || len(ends) == 0 {
			return false, -1, -1
		}
		return true, 0, ends[0] - start
	}
	if pattern.boundedAlternation != nil {
		return execBoundedAlternation(bs, pattern.boundedAlternation, data, flags, start, done)
	}
	if len(pattern.fixedByteSets) > 0 {
		length, ok := fixedRegexMatchAt(pattern.fixedByteSets, data, isWide, start)
		if !ok {
			return false, -1, -1
		}
		return true, 0, length
	}
	// Retain higher-priority continuations after a shorter branch accepts.
	// This VM-only flag must not change the pattern's encoding preference.
	if flags&regexForwardPriority != 0 {
		flags |= regex.FlagsGreedy
	}
	matched, startOffset, endOffset, _ = regex.ExecMatchBatchWithCancel(bs, pattern.Code, data, flags, start, done)
	return
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

	starts := make([]int, 0, min(limit, len(atomStarts)*2))
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

	if len(starts) < 2 {
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
