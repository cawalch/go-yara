package compiler

import (
	"sort"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/regex"
)

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
		if !useSparseByteSet && !unboundedRegexAlternativePresent(data, alternativeAtoms, flags) {
			addRegexMatchesFromAlternatives(ctx, id, regexInfo, data, modifiers, flags, isWide, alternativeAtoms)
			return
		}
	}
	if !isWide && regexInfo.leadingGap != nil && !useSparseByteSet {
		starts, handled := leadingGapRegexCandidateStarts(data, regexInfo.leadingGap, flags)
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
	}
	if useByteSet {
		search := regexByteSetSearch{
			data:            data,
			pattern:         regexInfo,
			wide:            isWide,
			cache:           byteSetCache,
			useSparseValues: useSparseByteSet,
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

func leadingGapRegexCandidateStarts(data []byte, plan *regexLeadingGapPlan, flags regex.Flags) ([]int, bool) {
	if plan == nil || len(plan.atoms) == 0 {
		return nil, false
	}
	limit := max(1024, len(data)/4)
	starts := make([]int, 0, min(limit, 64))
	for _, atom := range plan.atoms {
		searcher := newRegexLiteralSearcher(data, atom.data, flags)
		for occurrence := searcher.index(0); occurrence >= 0; occurrence = searcher.index(occurrence + 1) {
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

func unboundedRegexAlternativePresent(data []byte, atoms []regexPrefilterAtom, flags regex.Flags) bool {
	for _, atom := range atoms {
		if atom.maxOffset >= 0 {
			continue
		}
		searcher := newRegexLiteralSearcher(data, atom.data, flags)
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
