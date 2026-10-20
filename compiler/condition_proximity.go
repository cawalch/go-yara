package compiler

import (
	"fmt"
	"math"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

type proximityPlan struct {
	strA    string
	strB    string
	minDist int64
	maxDist int64
}

func (cc *conditionCompiler) compileProximity(plan *proximityPlan, pos token.Position) error {
	offsetA, existsA := cc.findStringOffset(plan.strA)
	if !existsA {
		return fmt.Errorf("undefined string identifier: %s", plan.strA)
	}
	offsetB, existsB := cc.findStringOffset(plan.strB)
	if !existsB {
		return fmt.Errorf("undefined string identifier: %s", plan.strB)
	}

	cc.emitStringIdentifier(offsetA, plan.strA, pos.Line, pos.Column)
	cc.emitStringIdentifier(offsetB, plan.strB, pos.Line, pos.Column)
	cc.emitter.EmitPush(uint64(plan.minDist), pos.Line, pos.Column) // #nosec G115 -- preserve signed integer bits
	cc.emitter.EmitPush(uint64(plan.maxDist), pos.Line, pos.Column) // #nosec G115 -- preserve signed integer bits
	cc.emitter.EmitOpcode(OpProximity, pos.Line, pos.Column)
	return nil
}

func (cc *conditionCompiler) tryParseProximityLoop(forLoop *ast.ForLoop) (*proximityPlan, bool) {
	if forLoop.Quantifier != "any" || len(forLoop.Variables) != 1 {
		return nil, false
	}
	varOuter := forLoop.Variables[0]
	strOuter, ok := extractRangeStringCount(forLoop.Range)
	if !ok {
		return nil, false
	}

	innerLoop, ok := forLoop.Condition.(*ast.ForLoop)
	if !ok || innerLoop.Quantifier != "any" || len(innerLoop.Variables) != 1 {
		return nil, false
	}
	varInner := innerLoop.Variables[0]
	strInner, ok := extractRangeStringCount(innerLoop.Range)
	if !ok {
		return nil, false
	}

	if strOuter == "" || strInner == "" || varOuter == "" || varInner == "" || varOuter == varInner {
		return nil, false
	}

	clauses := flattenAndClauses(innerLoop.Condition)
	if len(clauses) == 0 {
		return nil, false
	}

	// Try Orientation 1: strA = strOuter, varA = varOuter, strB = strInner, varB = varInner
	b1 := proximityBinding{strA: strOuter, varA: varOuter, strB: strInner, varB: varInner}
	if minDist, maxDist, ok := tryEvaluateClauses(clauses, b1); ok {
		return &proximityPlan{
			strA:    strOuter,
			strB:    strInner,
			minDist: minDist,
			maxDist: maxDist,
		}, true
	}

	// Try Orientation 2: strA = strInner, varA = varInner, strB = strOuter, varB = varOuter
	b2 := proximityBinding{strA: strInner, varA: varInner, strB: strOuter, varB: varOuter}
	if minDist, maxDist, ok := tryEvaluateClauses(clauses, b2); ok {
		return &proximityPlan{
			strA:    strInner,
			strB:    strOuter,
			minDist: minDist,
			maxDist: maxDist,
		}, true
	}

	return nil, false
}

type proximityBinding struct {
	strA string
	varA string
	strB string
	varB string
}

func extractRangeStringCount(rangeExpr ast.Expression) (string, bool) {
	bin, ok := rangeExpr.(*ast.BinaryOp)
	if !ok || bin.Op != token.DOT {
		return "", false
	}
	startLit, ok := bin.Left.(*ast.Literal)
	if !ok {
		return "", false
	}
	val, err := globalLiteralInt(startLit)
	if err != nil || val != 1 {
		return "", false
	}
	strCount, ok := bin.Right.(*ast.StringCount)
	if !ok || strCount.Index != nil {
		return "", false
	}
	id, ok := strCount.String.(*ast.Identifier)
	if !ok {
		return "", false
	}
	return normalizeStringIdent(id.Name), true
}

func flattenAndClauses(expr ast.Expression) []ast.Expression {
	if bin, ok := expr.(*ast.BinaryOp); ok && bin.Op == token.AND {
		left := flattenAndClauses(bin.Left)
		right := flattenAndClauses(bin.Right)
		return append(left, right...)
	}
	return []ast.Expression{expr}
}

func isOffsetOf(expr ast.Expression, targetStr, targetVar string) bool {
	offset, ok := expr.(*ast.StringOffset)
	if !ok || offset.Index == nil {
		return false
	}
	id, ok := offset.String.(*ast.Identifier)
	if !ok {
		return false
	}
	idx, ok := offset.Index.(*ast.Identifier)
	if !ok {
		return false
	}
	return normalizeStringIdent(id.Name) == targetStr && idx.Name == targetVar
}

func normalizeStringIdent(name string) string {
	if len(name) > 0 && name[0] != '$' {
		return "$" + name
	}
	return name
}

func tryEvaluateClauses(clauses []ast.Expression, b proximityBinding) (minDist, maxDist int64, ok bool) {
	minDist = math.MinInt64
	maxDist = math.MaxInt64

	for _, clause := range clauses {
		bin, ok := clause.(*ast.BinaryOp)
		if !ok {
			return 0, 0, false
		}
		if newMin, newMax, matched, valid := evaluateDiffClause(bin, b, minDist, maxDist); matched {
			if !valid {
				return 0, 0, false
			}
			minDist, maxDist = newMin, newMax
			continue
		}
		if newMin, newMax, matched, valid := evaluateOffsetClause(bin, b, minDist, maxDist); matched {
			if !valid {
				return 0, 0, false
			}
			minDist, maxDist = newMin, newMax
			continue
		}
		return 0, 0, false
	}

	return minDist, maxDist, true
}

func parseDiffExpr(expr ast.Expression, b proximityBinding) bool {
	diffBin, isDiff := expr.(*ast.BinaryOp)
	return isDiff && diffBin.Op == token.MINUS &&
		isOffsetOf(diffBin.Left, b.strB, b.varB) &&
		isOffsetOf(diffBin.Right, b.strA, b.varA)
}

//nolint:revive // argument-limit: internal helper requires (op, k, minDist, maxDist)
func applyDiffOp(op token.Type, k, minDist, maxDist int64) (newMin, newMax int64, ok bool) {
	switch op {
	case token.LT:
		return minDist, min(maxDist, k-1), true
	case token.LE:
		return minDist, min(maxDist, k), true
	case token.GT:
		return max(minDist, k+1), maxDist, true
	case token.GE:
		return max(minDist, k), maxDist, true
	case token.EQ:
		return max(minDist, k), min(maxDist, k), true
	default:
		return minDist, maxDist, false
	}
}

//nolint:revive // argument-limit: internal helper requires (op, k, minDist, maxDist)
func applyDiffOpSwapped(op token.Type, k, minDist, maxDist int64) (newMin, newMax int64, ok bool) {
	switch op {
	case token.LT: // k < diff <=> diff > k
		return max(minDist, k+1), maxDist, true
	case token.LE: // k <= diff <=> diff >= k
		return max(minDist, k), maxDist, true
	case token.GT: // k > diff <=> diff < k
		return minDist, min(maxDist, k-1), true
	case token.GE: // k >= diff <=> diff <= k
		return minDist, min(maxDist, k), true
	case token.EQ:
		return max(minDist, k), min(maxDist, k), true
	default:
		return minDist, maxDist, false
	}
}

//nolint:revive // argument-limit: internal helper requires (bin, b, minDist, maxDist)
func evaluateDiffClause(bin *ast.BinaryOp, b proximityBinding, minDist, maxDist int64) (newMin, newMax int64, matched, ok bool) {
	if parseDiffExpr(bin.Left, b) {
		lit, isLit := bin.Right.(*ast.Literal)
		if !isLit {
			return minDist, maxDist, true, false
		}
		k, err := globalLiteralInt(lit)
		if err != nil {
			return minDist, maxDist, true, false
		}
		newMin, newMax, opOk := applyDiffOp(bin.Op, k, minDist, maxDist)
		return newMin, newMax, true, opOk
	}

	if parseDiffExpr(bin.Right, b) {
		lit, isLit := bin.Left.(*ast.Literal)
		if !isLit {
			return minDist, maxDist, true, false
		}
		k, err := globalLiteralInt(lit)
		if err != nil {
			return minDist, maxDist, true, false
		}
		newMin, newMax, opOk := applyDiffOpSwapped(bin.Op, k, minDist, maxDist)
		return newMin, newMax, true, opOk
	}

	return minDist, maxDist, false, false
}

//nolint:revive // argument-limit: internal helper requires (bin, b, minDist, maxDist)
func evaluateOffsetClause(bin *ast.BinaryOp, b proximityBinding, minDist, maxDist int64) (newMin, newMax int64, matched, ok bool) {
	if isOffsetOf(bin.Left, b.strB, b.varB) && isOffsetOf(bin.Right, b.strA, b.varA) {
		switch bin.Op {
		case token.GT:
			return max(minDist, 1), maxDist, true, true
		case token.GE:
			return max(minDist, 0), maxDist, true, true
		case token.LT:
			return minDist, min(maxDist, -1), true, true
		case token.LE:
			return minDist, min(maxDist, 0), true, true
		case token.EQ:
			return max(minDist, 0), min(maxDist, 0), true, true
		default:
			return minDist, maxDist, true, false
		}
	}

	if isOffsetOf(bin.Left, b.strA, b.varA) && isOffsetOf(bin.Right, b.strB, b.varB) {
		switch bin.Op {
		case token.LT: // a < b <=> b > a
			return max(minDist, 1), maxDist, true, true
		case token.LE: // a <= b <=> b >= a
			return max(minDist, 0), maxDist, true, true
		case token.GT: // a > b <=> b < a
			return minDist, min(maxDist, -1), true, true
		case token.GE: // a >= b <=> b <= a
			return minDist, min(maxDist, 0), true, true
		case token.EQ:
			return max(minDist, 0), min(maxDist, 0), true, true
		default:
			return minDist, maxDist, true, false
		}
	}

	return minDist, maxDist, false, false
}
