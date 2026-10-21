package compiler

import (
	"slices"
	"strings"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

type stringPresenceBounds struct {
	required   []string
	forbidden  []string
	sufficient []string
}

// deriveStringPresenceBounds accepts only pure string-presence Boolean conditions.
// Skipping other expressions preserves runtime errors and evaluation order.
func deriveStringPresenceBounds(expr ast.Expression, patterns []*ast.String) ([]string, []string) {
	if len(patterns) < 2 {
		return nil, nil
	}
	bounds, safe := stringPresence(expr, patterns)
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

func stringPresence(expr ast.Expression, patterns []*ast.String) (stringPresenceBounds, bool) {
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
		return binaryStringPresence(e, patterns)
	case *ast.UnaryOp:
		if e.Op != token.NOT {
			return stringPresenceBounds{}, false
		}
		inner, safe := stringPresence(e.Right, patterns)
		if !safe {
			return stringPresenceBounds{}, false
		}
		return stringPresenceBounds{
			forbidden:  inner.sufficient,
			sufficient: inner.forbidden,
		}, true
	case *ast.OfExpression:
		return ofExpressionStringPresence(e, patterns)
	default:
		return stringPresenceBounds{}, false
	}
}

func binaryStringPresence(e *ast.BinaryOp, patterns []*ast.String) (stringPresenceBounds, bool) {
	if e.Op != token.AND && e.Op != token.OR {
		return stringPresenceBounds{}, false
	}
	left, leftSafe := stringPresence(e.Left, patterns)
	right, rightSafe := stringPresence(e.Right, patterns)
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

func ofExpressionStringPresence(e *ast.OfExpression, patterns []*ast.String) (stringPresenceBounds, bool) {
	if e.InRange != nil || e.AtOffset != nil {
		return stringPresenceBounds{}, false
	}
	count, ok := e.Count.(*ast.Identifier)
	if !ok {
		return stringPresenceBounds{}, false
	}
	ids, safe := requiredStringSet(e.Strings, patterns)
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

func requiredStringSet(expr ast.Expression, patterns []*ast.String) ([]string, bool) {
	switch e := expr.(type) {
	case *ast.Identifier:
		var result []string
		for _, pattern := range patterns {
			if e.Name == "them" || e.Name == pattern.Identifier || strings.HasSuffix(e.Name, "*") && strings.HasPrefix(pattern.Identifier, strings.TrimSuffix(e.Name, "*")) {
				result = append(result, pattern.Identifier)
			}
		}
		return result, true
	case *ast.StringTuple:
		var result []string
		for _, element := range e.Elements {
			ids, ok := requiredStringSet(element, patterns)
			if !ok {
				return nil, false
			}
			result = append(result, ids...)
		}
		return result, true
	default:
		return nil, false
	}
}

func (s *Scanner) missingRequiredString(rule *CompiledRule) bool {
	// Dense candidates fall back to normal evaluation after bounded gate work.
	budget := 128
	for _, id := range rule.requiredStrings {
		if budget == 0 {
			return false
		}
		budget--
		index, ok := rule.StringIDToIndex[id]
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
				if match.strID == id {
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
		if len(s.matchCtx.spans[id]) > 0 {
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
		index, ok := rule.StringIDToIndex[id]
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
				if match.strID == id {
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
		for _, e := range entries {
			if budget == 0 {
				return false
			}
			budget--
			if e.strID != id {
				continue
			}
			m := Match{Pattern: id, Offset: e.span.Offset, Length: e.span.Length}
			if verifyTextMatch(data, m, e.pattern, e.isNocase) &&
				matchPassesModifiers(data, m, rule.StringModifiers[id], e.isWide) {
				return true
			}
		}
	}
	return false
}
