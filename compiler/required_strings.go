package compiler

import (
	"slices"
	"strings"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

// deriveRequiredStrings accepts only pure string-presence Boolean conditions.
// Skipping other expressions preserves runtime errors and evaluation order.
func deriveRequiredStrings(expr ast.Expression, patterns []*ast.String) []string {
	if len(patterns) < 2 {
		return nil
	}
	required, safe := requiredStringPresence(expr, patterns)
	if !safe {
		return nil
	}
	slices.Sort(required)
	return slices.Compact(required)
}

func requiredStringPresence(expr ast.Expression, patterns []*ast.String) ([]string, bool) {
	switch e := expr.(type) {
	case *ast.Identifier:
		if strings.HasPrefix(e.Name, "$") && !strings.Contains(e.Name, "*") && e.Name != "$" {
			return []string{e.Name}, true
		}
		return nil, false
	case *ast.Literal:
		return nil, e.Type == token.TRUE || e.Type == token.FALSE
	case *ast.BinaryOp:
		if e.Op != token.AND && e.Op != token.OR {
			return nil, false
		}
		left, leftSafe := requiredStringPresence(e.Left, patterns)
		right, rightSafe := requiredStringPresence(e.Right, patterns)
		if !leftSafe || !rightSafe {
			return nil, false
		}
		if e.Op == token.AND {
			return append(left, right...), true
		}
		result := left[:0]
		for _, id := range left {
			if slices.Contains(right, id) {
				result = append(result, id)
			}
		}
		return result, true
	case *ast.OfExpression:
		count, ok := e.Count.(*ast.Identifier)
		if !ok || count.Name != QuantifierAll || e.InRange != nil || e.AtOffset != nil {
			return nil, false
		}
		return requiredStringSet(e.Strings, patterns)
	default:
		return nil, false
	}
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
