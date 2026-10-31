package compiler

import (
	"slices"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/regex"
	"github.com/cawalch/go-yara/token"
)

// Derive before constant folding: even unreachable occurrence observations
// disable libyara's fixed-offset optimization for that string.
func deriveFixedOffsets(rule *ast.Rule) map[string]int64 {
	if ruleDeclaresEvidence(rule) {
		return nil
	}
	refs := newConditionStringReferences()
	refs.fixedOffsets = make(map[string]int64)
	for _, str := range rule.Strings {
		refs.fixedStrings = append(refs.fixedStrings, str.Identifier)
	}
	collectConditionStringReferences(rule.Condition, refs)
	for _, str := range rule.Strings {
		encoded := slices.ContainsFunc(str.Modifiers, func(modifier ast.StringModifier) bool {
			return modifier.Type == ast.StringModifierBase64 || modifier.Type == ast.StringModifierBase64Wide
		})
		if encoded || isStringReferenced(str.Identifier, str.Identifier == "$", refs) {
			delete(refs.fixedOffsets, str.Identifier)
		}
	}
	if len(refs.fixedOffsets) == 0 {
		return nil
	}
	return refs.fixedOffsets
}

func collectFixedOffsetReference(expr *ast.BinaryOp, refs *conditionStringReferences) bool {
	if expr.Op != token.AT {
		return false
	}
	id, ok := expr.Left.(*ast.Identifier)
	if !ok || id.Quantifier != "" {
		return false
	}
	offset, constant := evaluateConstantInt(FoldConstants(expr.Right))
	if !constant {
		return false
	}
	ids := []string{id.Name}
	if id.Name == "$" {
		// libyara updates every declaration for an anonymous loop reference,
		// even when the loop's string set contains only a subset of them.
		ids = refs.fixedStrings
	}
	for _, name := range ids {
		if previous, exists := refs.fixedOffsets[name]; exists && previous != offset {
			refs.exact[name] = struct{}{}
		}
		refs.fixedOffsets[name] = offset
	}
	return true
}

// Filter owned per-rule scratch storage, never shared automaton/cache results.
// base converts reader windows and memory blocks to absolute scan offsets.
func (ctx *MatchContext) filterFixedOffsets(offsets map[string]int64, base int64) {
	for id, offset := range offsets {
		if spans, ok := ctx.spans[id]; ok {
			spans = slices.DeleteFunc(spans, func(span matchSpan) bool {
				return offset < base || span.Offset != offset-base
			})
			if len(spans) == 0 {
				delete(ctx.spans, id)
			} else {
				ctx.spans[id] = spans
			}
		}
		if matches, ok := ctx.Matches[id]; ok {
			matches = slices.DeleteFunc(matches, func(match Match) bool {
				return offset < base || match.Offset != offset-base
			})
			if len(matches) == 0 {
				delete(ctx.Matches, id)
			} else {
				ctx.Matches[id] = matches
			}
		}
	}
}

// Match libyara's literal AST extraction, not fixed-width matching. In
// particular, regex groups/classes/repetitions still use regex semantics.
func (result *stringCompilationResult) isFixedOffsetLiteral() bool {
	switch result.kind {
	case StringKindText:
		return true
	case StringKindRegex:
		if result.parsedAST == nil || result.parsedAST.Root == nil {
			return false
		}
		root := result.parsedAST.Root
		return root.Kind == regex.NodeLiteral || (root.Kind == regex.NodeConcat && len(root.Children) > 0 &&
			!slices.ContainsFunc(root.Children, func(child *regex.Node) bool { return child.Kind != regex.NodeLiteral }))
	case StringKindHex:
		return result.hexPattern != nil && fixedOffsetHexLiteral(result.hexPattern.Tokens)
	default:
		return false
	}
}

func fixedOffsetHexLiteral(tokens []HexPatternToken) bool {
	if len(tokens) == 0 {
		return false
	}
	for _, token := range tokens {
		if token.Negated {
			return false
		}
		switch token.Kind {
		case HexTokenByte:
		case HexTokenAlt:
			if len(token.Alternatives) != 1 || !fixedOffsetHexLiteral(token.Alternatives[0]) {
				return false
			}
		default:
			return false
		}
	}
	return true
}
