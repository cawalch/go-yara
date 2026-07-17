package compiler

import "sync"

var matchContextPool = sync.Pool{
	New: func() any {
		return &MatchContext{
			Matches:      make(map[string][]Match),
			matchBuffers: make(map[string][]Match),
			spans:        make(map[string][]matchSpan),
			spanBuffers:  make(map[string][]matchSpan),
		}
	},
}

// BuildMatchContext scans data for all patterns in the rule and returns a populated match context.
func BuildMatchContext(rule *CompiledRule, data []byte) *MatchContext {
	ctx := matchContextPool.Get().(*MatchContext)
	ctx.compact = false
	PopulateMatchContext(ctx, rule, data)
	return ctx
}

// PopulateMatchContext populates an existing match context (reused) with matches from data
func PopulateMatchContext(ctx *MatchContext, rule *CompiledRule, data []byte) {
	ctx.compact = false
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
	ctx.Blocks = nil
	if ctx.compact {
		ctx.resetCompactStorage()
	} else {
		ctx.resetPublicStorage()
	}
	ctx.FileSize = int64(len(data))
	ctx.EntryPoint = 0
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

func (ctx *MatchContext) resetPublicStorage() {
	if ctx.matchBuffers == nil {
		ctx.matchBuffers = make(map[string][]Match, len(ctx.Matches))
	}
	for id, matches := range ctx.Matches {
		if cap(matches) > cap(ctx.matchBuffers[id]) {
			ctx.matchBuffers[id] = matches[:0]
		}
	}
	clear(ctx.Matches)
	clear(ctx.spans)
}

// Release returns the match context to the pool
func (ctx *MatchContext) Release() {
	// Clear data reference effectively to allow GC
	ctx.Data = nil
	ctx.Blocks = nil
	ctx.compact = false
	ctx.maxMatchesPerPattern = 0
	matchContextPool.Put(ctx)
}
