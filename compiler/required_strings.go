package compiler

import (
	"slices"
	"strings"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/regex"
	"github.com/cawalch/go-yara/token"
)

type stringPresenceBounds struct {
	required   []string
	forbidden  []string
	sufficient []string
}

// deriveStringPresenceBounds accepts only pure string-presence Boolean conditions.
// Skipping other expressions preserves runtime errors and evaluation order.
func deriveStringPresenceBounds(expr ast.Expression, patterns []*ast.String, anonymousStrings []string) ([]string, []string) {
	if len(patterns) < 2 {
		return nil, nil
	}
	bounds, safe := stringPresence(expr, patterns, anonymousStrings)
	if !safe {
		return nil, nil
	}
	var required, forbidden []string
	if len(bounds.required) > 0 {
		slices.Sort(bounds.required)
		required = slices.Compact(bounds.required)
	}
	if len(bounds.forbidden) > 0 {
		slices.Sort(bounds.forbidden)
		forbidden = slices.Compact(bounds.forbidden)
	}
	return required, forbidden
}

func stringPresence(expr ast.Expression, patterns []*ast.String, anonymousStrings []string) (stringPresenceBounds, bool) {
	switch e := expr.(type) {
	case *ast.Identifier:
		if strings.HasPrefix(e.Name, "$") && !strings.Contains(e.Name, "*") && e.Name != "$" {
			return stringPresenceBounds{
				required:   []string{e.Name},
				sufficient: []string{e.Name},
			}, true
		}
		return stringPresenceBounds{}, false
	case *ast.Literal:
		return stringPresenceBounds{}, e.Type == token.TRUE || e.Type == token.FALSE
	case *ast.BinaryOp:
		return binaryStringPresence(e, patterns, anonymousStrings)
	case *ast.UnaryOp:
		if e.Op != token.NOT {
			return stringPresenceBounds{}, false
		}
		inner, safe := stringPresence(e.Right, patterns, anonymousStrings)
		if !safe {
			return stringPresenceBounds{}, false
		}
		return stringPresenceBounds{
			forbidden:  inner.sufficient,
			sufficient: inner.forbidden,
		}, true
	case *ast.OfExpression:
		return ofExpressionStringPresence(e, patterns, anonymousStrings)
	default:
		return stringPresenceBounds{}, false
	}
}

func binaryStringPresence(e *ast.BinaryOp, patterns []*ast.String, anonymousStrings []string) (stringPresenceBounds, bool) {
	if e.Op != token.AND && e.Op != token.OR {
		return stringPresenceBounds{}, false
	}
	left, leftSafe := stringPresence(e.Left, patterns, anonymousStrings)
	right, rightSafe := stringPresence(e.Right, patterns, anonymousStrings)
	if !leftSafe || !rightSafe {
		return stringPresenceBounds{}, false
	}
	if e.Op == token.AND {
		return stringPresenceBounds{
			required:   append(left.required, right.required...),
			forbidden:  append(left.forbidden, right.forbidden...),
			sufficient: intersectStrings(left.sufficient, right.sufficient),
		}, true
	}
	return stringPresenceBounds{
		required:   intersectStrings(left.required, right.required),
		forbidden:  intersectStrings(left.forbidden, right.forbidden),
		sufficient: append(left.sufficient, right.sufficient...),
	}, true
}

func ofExpressionStringPresence(e *ast.OfExpression, patterns []*ast.String, anonymousStrings []string) (stringPresenceBounds, bool) {
	if e.InRange != nil || e.AtOffset != nil {
		return stringPresenceBounds{}, false
	}
	count, ok := e.Count.(*ast.Identifier)
	if !ok {
		return stringPresenceBounds{}, false
	}
	ids, safe := requiredStringSet(e.Strings, patterns, anonymousStrings)
	if !safe || len(ids) == 0 {
		return stringPresenceBounds{}, safe
	}
	switch count.Name {
	case QuantifierAll:
		var suff []string
		if len(ids) == 1 {
			suff = slices.Clone(ids)
		}
		return stringPresenceBounds{
			required:   ids,
			sufficient: suff,
		}, true
	case QuantifierAny:
		var req []string
		if len(ids) == 1 {
			req = slices.Clone(ids)
		}
		return stringPresenceBounds{
			required:   req,
			sufficient: ids,
		}, true
	case QuantifierNone:
		return stringPresenceBounds{
			forbidden: ids,
		}, true
	default:
		return stringPresenceBounds{}, false
	}
}

func intersectStrings(left, right []string) []string {
	if len(left) == 0 || len(right) == 0 {
		return nil
	}
	var result []string
	for _, id := range left {
		if slices.Contains(right, id) {
			result = append(result, id)
		}
	}
	return result
}

func requiredStringSet(expr ast.Expression, patterns []*ast.String, anonymousStrings []string) ([]string, bool) {
	switch e := expr.(type) {
	case *ast.Identifier:
		var result []string
		if e.Name == "$" {
			result = slices.Clone(anonymousStrings)
		} else {
			for _, pattern := range patterns {
				if e.Name == "them" || e.Name == pattern.Identifier ||
					(strings.HasPrefix(e.Name, "$") && strings.HasSuffix(e.Name, "*") && strings.HasPrefix(pattern.Identifier, strings.TrimSuffix(e.Name, "*"))) {
					result = append(result, pattern.Identifier)
				}
			}
		}
		slices.Sort(result)
		return slices.Compact(result), true
	case *ast.StringTuple:
		var result []string
		for _, element := range e.Elements {
			ids, ok := requiredStringSet(element, patterns, anonymousStrings)
			if !ok {
				return nil, false
			}
			result = append(result, ids...)
		}
		slices.Sort(result)
		return slices.Compact(result), true
	case *ast.BinaryOp:
		if e.Op != token.COMMA {
			return nil, false
		}
		left, ok := requiredStringSet(e.Left, patterns, anonymousStrings)
		if !ok {
			return nil, false
		}
		right, ok := requiredStringSet(e.Right, patterns, anonymousStrings)
		if !ok {
			return nil, false
		}
		result := slices.Concat(left, right)
		slices.Sort(result)
		return slices.Compact(result), true
	default:
		return nil, false
	}
}

func requiredStringIndex(rule *CompiledRule, id string) (int, bool) {
	if len(rule.IndexToStringID) == 1 && rule.IndexToStringID[0] == id {
		return 0, true
	}
	index, ok := rule.StringIDToIndex[id]
	return index, ok
}

func (s *Scanner) missingRequiredString(rule *CompiledRule) bool {
	// Dense candidates fall back to normal evaluation after bounded gate work.
	budget := 128
	for _, id := range rule.requiredStrings {
		if budget == 0 {
			return false
		}
		budget--
		index, ok := requiredStringIndex(rule, id)
		if !ok {
			continue
		}
		info := rule.prefilterStrings[index]
		switch info.class {
		case prefilterStringText:
			found := false
			for _, match := range s.globalMatches[rule.Index] {
				if budget == 0 {
					return false
				}
				budget--
				if int(match.ruleStringIdx) == index {
					found = true
					break
				}
			}
			if !found {
				return true
			}
		case prefilterStringNonText:
			matches, ready := s.getNonTextMatches(&s.nonTextCache, info.cacheIndex, true)
			if ready && len(matches) == 0 {
				return true
			}
		}
	}
	return false
}

func (s *Scanner) hasForbiddenStringMatch(rule *CompiledRule, usesharedAutomaton bool) bool {
	for _, id := range rule.forbiddenStrings {
		if len(s.matchCtx.spansFor(id)) > 0 {
			return true
		}
		index, ok := rule.StringIDToIndex[id]
		if !ok {
			continue
		}
		if index >= 0 && index < len(rule.prefilterStrings) {
			info := rule.prefilterStrings[index]
			if info.class == prefilterStringNonText {
				matches, ready := s.getNonTextMatches(&s.nonTextCache, info.cacheIndex, usesharedAutomaton)
				if ready && len(matches) > 0 {
					return true
				}
			}
		}
	}
	return false
}

func (s *Scanner) ruleRejectedBeforeNonText(rule *CompiledRule, data []byte) bool {
	if rule == nil || rule.Index < 0 || rule.Index >= len(s.globalMatches) {
		return false
	}
	entries := s.globalMatches[rule.Index]
	budget := 128
	for _, id := range rule.requiredStrings {
		if budget == 0 {
			return false
		}
		budget--
		index, ok := requiredStringIndex(rule, id)
		if !ok || index < 0 || index >= len(rule.prefilterStrings) {
			continue
		}
		info := rule.prefilterStrings[index]
		switch info.class {
		case prefilterStringText:
			found := false
			for _, match := range entries {
				if budget == 0 {
					return false
				}
				budget--
				if int(match.ruleStringIdx) == index {
					found = true
					break
				}
			}
			if !found {
				return true
			}
		case prefilterStringNonText:
			if matches, ready := s.nonTextCache.get(info.cacheIndex); ready && len(matches) == 0 {
				return true
			}
		}
	}
	if len(rule.forbiddenStrings) == 0 || len(entries) == 0 {
		return false
	}
	for _, id := range rule.forbiddenStrings {
		strIdx, ok := rule.StringIDToIndex[id]
		if !ok {
			continue
		}
		for _, e := range entries {
			if budget == 0 {
				return false
			}
			budget--
			if int(e.ruleStringIdx) != strIdx {
				continue
			}
			if s.hookMask&hookBitPatternProfile == 0 {
				return true
			}
			info := s.program.sharedAutomaton.strings[e.sharedString]
			m := Match{Pattern: id, Offset: e.offset, Length: info.Length}
			if verifyTextMatch(data, m, info.Data, (info.Flags&regex.FlagsNoCase) != 0) &&
				matchPassesModifiers(data, m, rule.StringModifiers[id], (info.Flags&regex.FlagsWide) != 0) {
				return true
			}
		}
	}
	return false
}
