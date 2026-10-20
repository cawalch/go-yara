package compiler

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

func (cc *conditionCompiler) compileOfExpression(ofExpr *ast.OfExpression) error {
	var opcode Opcode

	// Special case: "#a in (min..max) of ($a*)" — count-in-range with string set.
	// We handle this before the general flow to avoid emitting OpOf which would
	// consume the setIndex we need for OpOfFoundIn.
	if _, ok := ofExpr.Count.(*ast.StringCount); ok && ofExpr.InRange != nil {
		// #a in (min..max) of ($str*)
		// Resolve the string set and emit OpCountInOf.
		// Stack: [setIndex, min, max] → OpCountInOf counts matched strings in set, checks if count is within [min, max].
		setIndex, pos := cc.resolveStringSetIndex(ofExpr.Strings)
		cc.emitter.EmitPush(uint64(setIndex), pos.Line, pos.Column)
		if err := cc.compileExpression(ofExpr.InRange); err != nil {
			return err
		}
		cc.emitter.EmitOpcode(OpCountInOf, ofExpr.Pos.Line, ofExpr.Pos.Column)
		return nil
	}

	// Check if the count is a percent expression ("N % of")
	if percentExpr, ok := ofExpr.Count.(*ast.PercentExpression); ok {
		if err := cc.compileExpression(percentExpr.Value); err != nil {
			return fmt.Errorf("compiling percent expression: %w", err)
		}
		opcode = OpOfPercent
	} else {
		if err := cc.compileCountExpression(ofExpr.Count); err != nil {
			return fmt.Errorf("compiling count expression in of-expression: %w", err)
		}
		opcode = OpOf
	}

	if err := cc.compileStringsExpression(ofExpr.Strings); err != nil {
		return fmt.Errorf("compiling strings expression in of-expression: %w", err)
	}

	// Compile optional constraint and adjust opcode
	isPercent := isPercentOpcode(opcode)
	if ofExpr.InRange != nil {
		opcode = cc.compileInRangeConstraint(ofExpr.InRange, ofExpr.Pos, opcode, isPercent)
	} else if ofExpr.AtOffset != nil {
		opcode = cc.compileAtOffsetConstraint(ofExpr.AtOffset, ofExpr.Pos, opcode, isPercent)
	}

	cc.emitter.EmitOpcode(opcode, ofExpr.Pos.Line, ofExpr.Pos.Column)
	return nil
}

func isPercentOpcode(op Opcode) bool {
	return op == OpOfPercent || op == OpOfPercentIn || op == OpOfPercentAt
}

//nolint:revive // argument-limit: internal helper
func (cc *conditionCompiler) compileInRangeConstraint(
	expr ast.Expression,
	_ token.Position,
	baseOpcode Opcode,
	isPercent bool,
) Opcode {
	rangeOp, ok := expr.(*ast.BinaryOp)
	if !ok || rangeOp.Op != token.DOT {
		return baseOpcode // fallback; error will be caught elsewhere
	}
	if err := cc.compileExpression(rangeOp.Left); err != nil {
		return baseOpcode
	}
	if err := cc.compileExpression(rangeOp.Right); err != nil {
		return baseOpcode
	}
	if isPercent {
		return OpOfPercentIn
	}
	return OpOfFoundIn
}

//nolint:revive // argument-limit: internal helper
func (cc *conditionCompiler) compileAtOffsetConstraint(
	expr ast.Expression,
	_ token.Position,
	baseOpcode Opcode,
	isPercent bool,
) Opcode {
	if err := cc.compileExpression(expr); err != nil {
		return baseOpcode
	}
	if isPercent {
		return OpOfPercentAt
	}
	return OpOfFoundAt
}

func (cc *conditionCompiler) compileCountExpression(countExpr ast.Expression) error {
	if ident, ok := countExpr.(*ast.Identifier); ok {
		switch ident.Name {
		case QuantifierAny:
			cc.emitter.EmitPush(1, ident.Pos.Line, ident.Pos.Column)
			return nil
		case QuantifierAll:
			cc.emitter.EmitPush(0xFFFFFFFF, ident.Pos.Line, ident.Pos.Column)
			return nil
		case QuantifierNone:
			cc.emitter.EmitPush(0, ident.Pos.Line, ident.Pos.Column)
			return nil
		}
	}
	return cc.compileExpression(countExpr)
}

func (cc *conditionCompiler) compileStringsExpression(stringsExpr ast.Expression) error {
	if ident, ok := stringsExpr.(*ast.Identifier); ok {
		switch {
		case ident.Name == "them":
			cc.emitter.EmitPush(stringSetAll, ident.Pos.Line, ident.Pos.Column)
			return nil
		case ident.Name == "$":
			cc.emitter.EmitPush(stringSetAnonymous, ident.Pos.Line, ident.Pos.Column)
			return nil
		case cc.isRuleReference(ident.Name):
			return cc.compileRuleReference(ident.Name, ident.Pos.Line, ident.Pos.Column)
		case cc.isStringSetIdentifier(ident.Name):
			ids, err := cc.expandStringSetIdentifier(ident.Name)
			if err != nil {
				return err
			}
			index := cc.internStringSet(ids)
			cc.emitter.EmitPush(uint64(index), ident.Pos.Line, ident.Pos.Column)
			return nil
		}
	}
	if binOp, ok := stringsExpr.(*ast.BinaryOp); ok && binOp.Op == token.COMMA {
		ids, err := cc.collectStringSetFromComma(binOp)
		if err != nil {
			return err
		}
		index := cc.internStringSet(ids)
		cc.emitter.EmitPush(uint64(index), binOp.Pos.Line, binOp.Pos.Column)
		return nil
	}
	return cc.compileExpression(stringsExpr)
}

// resolveStringSetIndex resolves a string set expression to its interned index and position.
// It does NOT emit any bytecode — just returns the index for the caller to use.
func (cc *conditionCompiler) resolveStringSetIndex(stringsExpr ast.Expression) (int, token.Position) {
	if ident, ok := stringsExpr.(*ast.Identifier); ok {
		switch ident.Name {
		case "them", "all":
			return cc.internStringSet(cc.allStringIdentifiers()), ident.Pos
		case "$":
			return cc.internStringSet(cc.anonymousStringIdentifiers()), ident.Pos
		default:
			if cc.isStringSetIdentifier(ident.Name) {
				ids, err := cc.expandStringSetIdentifier(ident.Name)
				if err != nil {
					ids = []string{ident.Name}
				}
				return cc.internStringSet(ids), ident.Pos
			}
		}
	}
	if binOp, ok := stringsExpr.(*ast.BinaryOp); ok && binOp.Op == token.COMMA {
		ids, err := cc.collectStringSetFromComma(binOp)
		if err != nil {
			return 0, binOp.Pos
		}
		return cc.internStringSet(ids), binOp.Pos
	}
	return 0, token.Position{}
}

func (cc *conditionCompiler) isStringSetIdentifier(name string) bool {
	if name == "$" {
		return true
	}
	if strings.HasSuffix(name, "*") {
		return strings.HasPrefix(name, "$")
	}
	_, exists := cc.stringOffsets[name]
	if exists {
		return true
	}
	_, exists = cc.stringOffsets["$"+name]
	return exists
}

func (cc *conditionCompiler) expandStringSetIdentifier(name string) ([]string, error) {
	if name == "$" {
		return cc.anonymousStringIdentifiers(), nil
	}
	if before, ok := strings.CutSuffix(name, "*"); ok {
		prefix := before
		return cc.matchingStringIdentifiers(prefix), nil
	}
	if _, ok := cc.stringOffsets[name]; ok {
		return []string{name}, nil
	}
	if _, ok := cc.stringOffsets["$"+name]; ok {
		return []string{"$" + name}, nil
	}
	return nil, fmt.Errorf("undefined string identifier: %s", name)
}

func (cc *conditionCompiler) matchingStringIdentifiers(prefix string) []string {
	matches := make([]string, 0)
	for ident := range cc.stringOffsets {
		if strings.HasPrefix(ident, prefix) {
			matches = append(matches, ident)
		}
	}
	sort.Strings(matches)
	return matches
}

func (cc *conditionCompiler) allStringIdentifiers() []string {
	ids := make([]string, 0, len(cc.stringOffsets))
	for ident := range cc.stringOffsets {
		ids = append(ids, ident)
	}
	sort.Strings(ids)
	return ids
}

func (cc *conditionCompiler) anonymousStringIdentifiers() []string {
	if len(cc.anonymousStrings) == 0 {
		return nil
	}
	ids := make([]string, len(cc.anonymousStrings))
	copy(ids, cc.anonymousStrings)
	sort.Strings(ids)
	return ids
}

func (cc *conditionCompiler) collectStringSetFromComma(expr *ast.BinaryOp) ([]string, error) {
	leftIDs, err := cc.collectStringSet(expr.Left)
	if err != nil {
		return nil, err
	}
	rightIDs, err := cc.collectStringSet(expr.Right)
	if err != nil {
		return nil, err
	}
	leftIDs = append(leftIDs, rightIDs...)
	return cc.uniqueSortedStrings(leftIDs), nil
}

func (cc *conditionCompiler) collectStringSet(expr ast.Expression) ([]string, error) {
	switch e := expr.(type) {
	case *ast.Identifier:
		return cc.expandStringSetIdentifier(e.Name)
	case *ast.StringTuple:
		var ids []string
		for _, elem := range e.Elements {
			sub, err := cc.collectStringSet(elem)
			if err != nil {
				return nil, err
			}
			ids = append(ids, sub...)
		}
		return cc.uniqueSortedStrings(ids), nil
	case *ast.BinaryOp:
		if e.Op == token.COMMA {
			return cc.collectStringSetFromComma(e)
		}
	}
	return nil, errors.New("unsupported string set expression")
}

func (cc *conditionCompiler) uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	sort.Strings(values)
	out := make([]string, 0, len(values))
	var last string
	for i, v := range values {
		if i == 0 || v != last {
			out = append(out, v)
			last = v
		}
	}
	return out
}

func (cc *conditionCompiler) internStringSet(ids []string) int {
	normalized := cc.uniqueSortedStrings(append([]string(nil), ids...))
	key := strings.Join(normalized, "\x00")
	if idx, ok := cc.stringSetIndex[key]; ok {
		return idx
	}
	idx := len(cc.stringSets)
	cc.stringSets = append(cc.stringSets, normalized)
	cc.stringSetIndex[key] = idx
	return idx
}
