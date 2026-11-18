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
	for id, spans := range ctx.spans {
		ctx.spans[id] = sortAndDedupeMatchSpans(spans)
	}
}

func (ctx *MatchContext) materializePublicMatches() {
	if len(ctx.spans) == 0 {
		return
	}
	if ctx.Matches == nil {
		ctx.Matches = make(map[string][]Match, len(ctx.spans))
	}
	for id, spans := range ctx.spans {
		ms := make([]Match, len(spans))
		for i, sp := range spans {
			ms[i] = Match{
				Pattern: id,
				Offset:  sp.Offset,
				Length:  sp.Length,
			}
		}
		ctx.Matches[id] = ms
	}
}

// normalizeRegexEncodingMatches resolves ASCII/wide collisions before general
// normalization. Producers append the preferred encoding first; retain that
// occurrence even if the other encoding has a shorter (or longer) span.
func (ctx *MatchContext) normalizeRegexEncodingMatches(id string) {
	if spans := ctx.spans[id]; len(spans) > 1 {
		slices.SortStableFunc(spans, func(a, b matchSpan) int { return cmp.Compare(a.Offset, b.Offset) })
		ctx.spans[id] = slices.CompactFunc(spans, func(a, b matchSpan) bool { return a.Offset == b.Offset })
	}
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
	if ctx.spanBuffers == nil {
		ctx.spanBuffers = make(map[string][]matchSpan, len(ctx.spans))
	}
	for id, spans := range ctx.spans {
		if cap(spans) > cap(ctx.spanBuffers[id]) {
			ctx.spanBuffers[id] = spans[:0]
		}
	}
	clear(ctx.spans)
	clear(ctx.Matches)
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
	clear(ctx.Matches)
	clear(ctx.spans)
	clear(ctx.spanBuffers)
	*ctx = MatchContext{
		Matches:     ctx.Matches,
		spans:       ctx.spans,
		spanBuffers: ctx.spanBuffers,
	}
}
