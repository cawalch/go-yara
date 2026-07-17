package compiler

import (
	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/regex"
)

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
func acceptAutomatonMatch(ctx *MatchContext, rule *CompiledRule, data []byte, match ACMatch) bool {
	if rule.StringKinds != nil && rule.StringKinds[match.StringID] != StringKindText {
		return false
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
		return false
	}
	if matchPassesModifiers(data, m, rule.StringModifiers[match.StringID], isWide) {
		ctx.AddMatch(m)
		return true
	}
	return false
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
