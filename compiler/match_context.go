package compiler

import (
	"cmp"
	"slices"
	"sync"

	"github.com/cawalch/go-yara/regex"
)

var matchContextPool = sync.Pool{
	New: func() any {
		return &MatchContext{
			Matches:     make(map[string][]Match),
			spans:       make(map[string][]matchSpan),
			spanBuffers: make(map[string][]matchSpan),
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
	defer func() {
		ctx.normalizeMatches()
		ctx.materializePublicMatches()
	}()

	if rule == nil {
		return
	}

	if len(rule.fixedOffsets) != 0 {
		defer ctx.filterFixedOffsets(rule.fixedOffsets, 0)
	}

	if len(data) == 0 {
		for id, regexInfo := range rule.RegexPatterns {
			modifiers := rule.StringModifiers[id]
			addRegexMatchesWithModifiers(ctx, id, regexInfo, data, modifiers)
		}
		return
	}

	if rule.automaton != nil {
		for match := range rule.automaton.SearchIter(data) {
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

func (ctx *MatchContext) normalizeMatches() {
	if ctx.slotRule != nil {
		for _, slot := range ctx.touchedSlots {
			if slot >= 0 && slot < len(ctx.spansByIndex) && len(ctx.spansByIndex[slot]) > 0 {
				ctx.spansByIndex[slot] = sortAndDedupeMatchSpans(ctx.spansByIndex[slot])
			}
		}
		return
	}
	for id, spans := range ctx.spans {
		ctx.spans[id] = sortAndDedupeMatchSpans(spans)
	}
}

func (ctx *MatchContext) materializePublicMatches() {
	if !ctx.hasSpans() {
		return
	}
	if ctx.Matches == nil {
		ctx.Matches = make(map[string][]Match)
	}
	ctx.forEachSpanSlice(func(id string, spans []matchSpan) {
		ms := make([]Match, len(spans))
		for i, sp := range spans {
			ms[i] = Match{
				Pattern: id,
				Offset:  sp.Offset,
				Length:  sp.Length,
			}
		}
		ctx.Matches[id] = ms
	})
}

// normalizeRegexEncodingMatches resolves ASCII/wide collisions before general
// normalization. Producers append the preferred encoding first; retain that
// occurrence even if the other encoding has a shorter (or longer) span.
func (ctx *MatchContext) normalizeRegexEncodingMatches(id string) {
	if ctx.slotRule != nil {
		if slot, ok := ctx.slotRule.StringIDToIndex[id]; ok && slot >= 0 && slot < len(ctx.spansByIndex) {
			if spans := ctx.spansByIndex[slot]; len(spans) > 1 {
				slices.SortStableFunc(spans, func(a, b matchSpan) int { return cmp.Compare(a.Offset, b.Offset) })
				ctx.spansByIndex[slot] = slices.CompactFunc(spans, func(a, b matchSpan) bool { return a.Offset == b.Offset })
			}
		}
		return
	}
	if spans := ctx.spans[id]; len(spans) > 1 {
		slices.SortStableFunc(spans, func(a, b matchSpan) int { return cmp.Compare(a.Offset, b.Offset) })
		ctx.spans[id] = slices.CompactFunc(spans, func(a, b matchSpan) bool { return a.Offset == b.Offset })
	}
}

// ResetForRule clears the match context and binds dense integer span storage
// to rule.IndexToStringID so scanning avoids string-map hashing.
func (ctx *MatchContext) ResetForRule(rule *CompiledRule, data []byte) {
	ctx.Reset(data)
	if rule == nil || len(rule.IndexToStringID) == 0 {
		return
	}
	n := len(rule.IndexToStringID)
	if cap(ctx.spansByIndex) < n {
		ctx.spansByIndex = make([][]matchSpan, n)
	} else {
		ctx.spansByIndex = ctx.spansByIndex[:n]
	}
	ctx.slotRule = rule
}

// Reset clears the match context for reuse
func (ctx *MatchContext) Reset(data []byte) {
	ctx.matchFilter = nil
	ctx.moduleCache = nil
	ctx.assertionResults = nil
	ctx.externalValues = nil
	ctx.Data = data
	ctx.Blocks = nil
	ctx.cancelDone = nil
	ctx.resetCompactStorage()
	ctx.FileSize = int64(len(data))
	ctx.EntryPoint = 0
	ctx.HasEntryPoint = false
	ctx.entryPointChecked = false
	ctx.verificationBudgetRejects = 0
}

func (ctx *MatchContext) resetCompactStorage() {
	for _, slot := range ctx.touchedSlots {
		if slot >= 0 && slot < len(ctx.spansByIndex) {
			ctx.spansByIndex[slot] = ctx.spansByIndex[slot][:0]
		}
	}
	ctx.touchedSlots = ctx.touchedSlots[:0]
	ctx.slotRule = nil
	if len(ctx.spans) > 0 {
		if ctx.spanBuffers == nil {
			ctx.spanBuffers = make(map[string][]matchSpan, len(ctx.spans))
		}
		for id, spans := range ctx.spans {
			if cap(spans) > cap(ctx.spanBuffers[id]) {
				ctx.spanBuffers[id] = spans[:0]
			}
		}
		clear(ctx.spans)
	}
	if len(ctx.Matches) > 0 {
		clear(ctx.Matches)
	}
}

func (ctx *MatchContext) acquireRegexBatch(codeLen int) *regex.VMBatch {
	if ctx == nil {
		b := &regex.VMBatch{}
		b.Prepare(codeLen)
		return b
	}
	ctx.regexBatch.Prepare(codeLen)
	return &ctx.regexBatch
}

// Release returns the match context to the pool
func (ctx *MatchContext) Release() {
	ctx.regexBatch.Release()
	ctx.resetForPool()
	matchContextPool.Put(ctx)
}

func (ctx *MatchContext) resetForPool() {
	for _, slot := range ctx.touchedSlots {
		if slot >= 0 && slot < len(ctx.spansByIndex) {
			ctx.spansByIndex[slot] = ctx.spansByIndex[slot][:0]
		}
	}
	ctx.touchedSlots = ctx.touchedSlots[:0]
	clear(ctx.Matches)
	clear(ctx.spans)
	clear(ctx.spanBuffers)
	*ctx = MatchContext{
		Matches:      ctx.Matches,
		spansByIndex: ctx.spansByIndex,
		touchedSlots: ctx.touchedSlots,
		spans:        ctx.spans,
		spanBuffers:  ctx.spanBuffers,
	}
}
