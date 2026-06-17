package compiler

import (
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
	if len(regexInfo.Code) == 0 {
		return
	}

	// Use batched VM state to avoid sync.Pool Get/Put overhead
	// when calling runAtMatch thousands of times in this loop.
	bs, release := regex.NewVMBatch(len(regexInfo.Code))
	defer release()

	pos := 0
	for pos <= len(data) {
		matched, start, end := regex.ExecMatchBatch(bs, regexInfo.Code, data, flags, pos)
		if !matched {
			pos++
			continue
		}

		absStart := pos + start
		absEnd := pos + end

		// Handle invalid range
		if absEnd < absStart {
			pos = absStart + 1
			continue
		}

		m := Match{
			Pattern: id,
			Offset:  int64(absStart),
			Length:  absEnd - absStart,
		}
		if matchPassesModifiers(data, m, modifiers, isWide) {
			ctx.AddMatch(m)
		}

		// Advance position past the current match start to find overlapping/subsequent matches
		pos = absStart + 1
	}
}

//nolint:revive // argument-limit: API surface
func addRegexMatchesWithModifiers(ctx *MatchContext, id string, regexInfo RegexPattern, data []byte, modifiers []ast.StringModifier) {
	hasWide := hasModifier(modifiers, ast.StringModifierWide)
	hasASCII := hasModifier(modifiers, ast.StringModifierASCII)
	baseFlags := regexInfo.Flags

	switch {
	case hasWide && hasASCII:
		addRegexMatches(ctx, id, regexInfo, data, modifiers, baseFlags|regex.FlagsWide, true)
		addRegexMatches(ctx, id, regexInfo, data, modifiers, baseFlags&^regex.FlagsWide, false)
	case hasWide:
		addRegexMatches(ctx, id, regexInfo, data, modifiers, baseFlags|regex.FlagsWide, true)
	default:
		addRegexMatches(ctx, id, regexInfo, data, modifiers, baseFlags&^regex.FlagsWide, false)
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
