package compiler

import (
	"math/bits"
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

type stringPresenceMaskBounds struct {
	required   uint64
	forbidden  uint64
	sufficient uint64
}

const (
	maskUnsafe uint8 = iota
	maskSafe
	maskFallback
)

// deriveStringPresenceBounds accepts only pure string-presence Boolean conditions.
// Skipping other expressions preserves runtime errors and evaluation order.
func deriveStringPresenceBounds(expr ast.Expression, patterns []*ast.String) ([]string, []string) {
	if len(patterns) < 2 {
		return nil, nil
	}
	if len(patterns) <= 64 {
		bounds, status := stringPresenceMask(expr, patterns)
		switch status {
		case maskUnsafe:
			return nil, nil
		case maskSafe:
			return maskToSortedNames(bounds.required, patterns), maskToSortedNames(bounds.forbidden, patterns)
		}
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

func maskToSortedNames(mask uint64, patterns []*ast.String) []string {
	if mask == 0 {
		return nil
	}
	names := make([]string, 0, bits.OnesCount64(mask))
	for mask != 0 {
		idx := bits.TrailingZeros64(mask)
		names = append(names, patterns[idx].Identifier)
		mask &= mask - 1
	}
	slices.Sort(names)
	return slices.Compact(names)
}

func stringPresenceMask(expr ast.Expression, patterns []*ast.String) (stringPresenceMaskBounds, uint8) {
	switch e := expr.(type) {
	case *ast.Identifier:
		if strings.HasPrefix(e.Name, "$") && !strings.Contains(e.Name, "*") && e.Name != "$" {
			for i, pattern := range patterns {
				if pattern.Identifier == e.Name {
					bit := uint64(1) << i
					return stringPresenceMaskBounds{required: bit, sufficient: bit}, maskSafe
				}
			}
			return stringPresenceMaskBounds{}, maskFallback
		}
		return stringPresenceMaskBounds{}, maskUnsafe
	case *ast.Literal:
		if e.Type == token.TRUE || e.Type == token.FALSE {
			return stringPresenceMaskBounds{}, maskSafe
		}
		return stringPresenceMaskBounds{}, maskUnsafe
	case *ast.BinaryOp:
		return binaryStringPresenceMask(e, patterns)
	case *ast.UnaryOp:
		if e.Op != token.NOT {
			return stringPresenceMaskBounds{}, maskUnsafe
		}
		inner, status := stringPresenceMask(e.Right, patterns)
		if status != maskSafe {
			return stringPresenceMaskBounds{}, status
		}
		return stringPresenceMaskBounds{
			forbidden:  inner.sufficient,
			sufficient: inner.forbidden,
		}, maskSafe
	case *ast.OfExpression:
		return ofExpressionStringPresenceMask(e, patterns)
	default:
		return stringPresenceMaskBounds{}, maskUnsafe
	}
}

func binaryStringPresenceMask(e *ast.BinaryOp, patterns []*ast.String) (stringPresenceMaskBounds, uint8) {
	if e.Op != token.AND && e.Op != token.OR {
		return stringPresenceMaskBounds{}, maskUnsafe
	}
	left, leftStatus := stringPresenceMask(e.Left, patterns)
	if leftStatus != maskSafe {
		return stringPresenceMaskBounds{}, leftStatus
	}
	right, rightStatus := stringPresenceMask(e.Right, patterns)
	if rightStatus != maskSafe {
		return stringPresenceMaskBounds{}, rightStatus
	}
	if e.Op == token.AND {
		return stringPresenceMaskBounds{
			required:   left.required | right.required,
			forbidden:  left.forbidden | right.forbidden,
			sufficient: left.sufficient & right.sufficient,
		}, maskSafe
	}
	return stringPresenceMaskBounds{
		required:   left.required & right.required,
		forbidden:  left.forbidden & right.forbidden,
		sufficient: left.sufficient | right.sufficient,
	}, maskSafe
}

func ofExpressionStringPresenceMask(e *ast.OfExpression, patterns []*ast.String) (stringPresenceMaskBounds, uint8) {
	if e.InRange != nil || e.AtOffset != nil {
		return stringPresenceMaskBounds{}, maskUnsafe
	}
	count, ok := e.Count.(*ast.Identifier)
	if !ok {
		return stringPresenceMaskBounds{}, maskUnsafe
	}
	ids, safe := requiredStringSetMask(e.Strings, patterns)
	if !safe {
		return stringPresenceMaskBounds{}, maskUnsafe
	}
	if ids == 0 {
		return stringPresenceMaskBounds{}, maskSafe
	}
	switch count.Name {
	case QuantifierAll:
		var suff uint64
		if bits.OnesCount64(ids) == 1 {
			suff = ids
		}
		return stringPresenceMaskBounds{required: ids, sufficient: suff}, maskSafe
	case QuantifierAny:
		var req uint64
		if bits.OnesCount64(ids) == 1 {
			req = ids
		}
		return stringPresenceMaskBounds{required: req, sufficient: ids}, maskSafe
	case QuantifierNone:
		return stringPresenceMaskBounds{forbidden: ids}, maskSafe
	default:
		return stringPresenceMaskBounds{}, maskUnsafe
	}
}

func requiredStringSetMask(expr ast.Expression, patterns []*ast.String) (uint64, bool) {
	switch e := expr.(type) {
	case *ast.Identifier:
		var mask uint64
		for i, pattern := range patterns {
			if e.Name == "them" || e.Name == pattern.Identifier || strings.HasSuffix(e.Name, "*") && strings.HasPrefix(pattern.Identifier, strings.TrimSuffix(e.Name, "*")) {
				mask |= uint64(1) << i
			}
		}
		return mask, true
	case *ast.StringTuple:
		var mask uint64
		for _, element := range e.Elements {
			elemMask, ok := requiredStringSetMask(element, patterns)
			if !ok {
				return 0, false
			}
			mask |= elemMask
		}
		return mask, true
	default:
		return 0, false
	}
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
