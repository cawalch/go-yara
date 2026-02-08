package compiler

import (
	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/regex"
)

// BuildMatchContext scans data for all patterns in the rule and returns a populated match context.
func BuildMatchContext(rule *CompiledRule, data []byte) *MatchContext {
	ctx := &MatchContext{
		Data:     data,
		Matches:  make(map[string][]Match),
		FileSize: int64(len(data)),
	}

	if rule == nil {
		return ctx
	}

	if len(data) == 0 {
		for id, regexInfo := range rule.RegexPatterns {
			addRegexMatches(ctx, id, regexInfo, data, rule.StringModifiers[id])
		}
		return ctx
	}

	if rule.Automaton != nil {
		for _, match := range rule.Automaton.Search(data) {
			if rule.StringKinds != nil && rule.StringKinds[match.StringID] != StringKindText {
				continue
			}
			length := 0
			if match.StringIndex >= 0 && match.StringIndex < len(rule.Automaton.Strings) {
				length = rule.Automaton.Strings[match.StringIndex].Length
			}
			m := Match{
				Pattern: match.StringID,
				Offset:  int64(match.Backtrack),
				Length:  length,
			}
			if matchPassesModifiers(data, m, rule.StringModifiers[match.StringID]) {
				ctx.AddMatch(m)
			}
		}
	}

	for id, regexInfo := range rule.RegexPatterns {
		addRegexMatches(ctx, id, regexInfo, data, rule.StringModifiers[id])
	}

	for id, pattern := range rule.HexPatterns {
		for _, m := range FindHexMatches(pattern, data) {
			m.Pattern = id
			if matchPassesModifiers(data, m, rule.StringModifiers[id]) {
				ctx.AddMatch(m)
			}
		}
	}

	return ctx
}

func addRegexMatches(ctx *MatchContext, id string, regexInfo RegexPattern, data []byte, modifiers []ast.StringModifier) {
	if len(regexInfo.Code) == 0 {
		return
	}
	flags := regexInfo.Flags | regex.FlagsScan
	pos := 0
	for pos <= len(data) {
		matched, start, end := regex.ExecMatch(regexInfo.Code, data[pos:], flags)
		if !matched {
			return
		}
		absStart := pos + start
		absEnd := pos + end
		if absEnd < absStart {
			return
		}
		m := Match{
			Pattern: id,
			Offset:  int64(absStart),
			Length:  absEnd - absStart,
		}
		if matchPassesModifiers(data, m, modifiers) {
			ctx.AddMatch(m)
		}
		pos = absStart + 1
	}
}

func matchPassesModifiers(data []byte, m Match, modifiers []ast.StringModifier) bool {
	if len(modifiers) == 0 {
		return true
	}
	if !hasModifier(modifiers, ast.StringModifierFullword) {
		return true
	}
	isWide := hasModifier(modifiers, ast.StringModifierWide) || hasModifier(modifiers, ast.StringModifierBase64Wide)
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
