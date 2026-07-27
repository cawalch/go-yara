package compiler

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

type noStringTruth uint8

const (
	noStringFalse noStringTruth = 1 << iota
	noStringTrue
	noStringUnknown = noStringFalse | noStringTrue
)

// conditionRequiresStringMatch reports whether expr is guaranteed to be false
// when none of the rule's strings match. The analysis is intentionally
// conservative: an expression that cannot be proven false remains eligible for
// normal evaluation.
func conditionRequiresStringMatch(expr ast.Expression) bool {
	return truthWithoutStringMatches(expr)&noStringTrue == 0 &&
		evaluationSafeWithoutStringMatches(expr)
}

func evaluationSafeWithoutStringMatches(expr ast.Expression) bool {
	switch e := expr.(type) {
	case *ast.Literal, *ast.Identifier:
		return true
	case *ast.StringCount:
		return staticStringOccurrenceIndex(e.Index)
	case *ast.StringOffset:
		return staticStringOccurrenceIndex(e.Index)
	case *ast.StringLength:
		return staticStringOccurrenceIndex(e.Index)
	case *ast.UnaryOp:
		return e.Op == token.NOT && evaluationSafeWithoutStringMatches(e.Right)
	case *ast.BinaryOp:
		leftSafe := evaluationSafeWithoutStringMatches(e.Left)
		if !leftSafe {
			return false
		}
		leftTruth := truthWithoutStringMatches(e.Left)
		switch e.Op {
		case token.AND:
			if leftTruth&noStringTrue == 0 {
				return true
			}
			return evaluationSafeWithoutStringMatches(e.Right)
		case token.OR:
			if leftTruth&noStringFalse == 0 {
				return true
			}
			return evaluationSafeWithoutStringMatches(e.Right)
		case token.AT, token.IN:
			return staticStringConstraint(e.Op, e.Right)
		default:
			_, leftOK := integerWithoutStringMatches(e.Left)
			_, rightOK := integerWithoutStringMatches(e.Right)
			return leftOK && rightOK
		}
	case *ast.OfExpression:
		return isRuleStringSet(e.Strings) &&
			ofTruthWithoutStringMatches(e) != noStringUnknown
	case *ast.PercentExpression:
		_, ok := integerWithoutStringMatches(e.Value)
		return ok
	default:
		// Function calls and loops can return runtime errors. Keep evaluating
		// them unless an enclosing short-circuit proves they are unreachable.
		return false
	}
}

func truthWithoutStringMatches(expr ast.Expression) noStringTruth {
	switch e := expr.(type) {
	case nil:
		return noStringUnknown
	case *ast.Literal:
		return literalExpressionTruth(e)
	case *ast.Identifier:
		if strings.HasPrefix(e.Name, "$") {
			return noStringFalse
		}
		return noStringUnknown
	case *ast.StringCount:
		if !staticStringOccurrenceIndex(e.Index) {
			return noStringUnknown
		}
		return noStringFalse
	case *ast.StringOffset:
		if staticStringOccurrenceIndex(e.Index) {
			return noStringFalse
		}
		return noStringUnknown
	case *ast.StringLength:
		if staticStringOccurrenceIndex(e.Index) {
			return noStringFalse
		}
		return noStringUnknown
	case *ast.BinaryOp:
		return binaryTruthWithoutStringMatches(e)
	case *ast.UnaryOp:
		if e.Op != token.NOT {
			return noStringUnknown
		}
		return invertTruth(truthWithoutStringMatches(e.Right))
	case *ast.OfExpression:
		return ofTruthWithoutStringMatches(e)
	case *ast.PercentExpression:
		return truthWithoutStringMatches(e.Value)
	default:
		return noStringUnknown
	}
}

func literalExpressionTruth(literal *ast.Literal) noStringTruth {
	switch literal.Type {
	case token.TRUE:
		return noStringTrue
	case token.FALSE:
		return noStringFalse
	case token.IntegerLit, token.HexIntegerLit, token.OctalIntegerLit:
		value, err := strconv.ParseInt(fmt.Sprint(literal.Value), 0, 64)
		if err != nil {
			return noStringUnknown
		}
		return scalarTruth(value)
	case token.FloatLit:
		value, err := strconv.ParseFloat(fmt.Sprint(literal.Value), 64)
		if err != nil {
			return noStringUnknown
		}
		return scalarTruth(value)
	case token.StringLit:
		return scalarTruth(fmt.Sprint(literal.Value))
	default:
		return noStringUnknown
	}
}

func scalarTruth(value any) noStringTruth {
	switch typed := value.(type) {
	case bool:
		if typed {
			return noStringTrue
		}
		return noStringFalse
	case int:
		if typed != 0 {
			return noStringTrue
		}
		return noStringFalse
	case int64:
		if typed != 0 {
			return noStringTrue
		}
		return noStringFalse
	case float64:
		if typed != 0 {
			return noStringTrue
		}
		return noStringFalse
	case string:
		if typed != "" {
			return noStringTrue
		}
		return noStringFalse
	default:
		return noStringUnknown
	}
}

func binaryTruthWithoutStringMatches(expr *ast.BinaryOp) noStringTruth {
	left := truthWithoutStringMatches(expr.Left)
	right := truthWithoutStringMatches(expr.Right)
	switch expr.Op {
	case token.AND:
		var result noStringTruth
		if left&noStringTrue != 0 && right&noStringTrue != 0 {
			result |= noStringTrue
		}
		if left&noStringFalse != 0 || right&noStringFalse != 0 {
			result |= noStringFalse
		}
		return result
	case token.OR:
		var result noStringTruth
		if left&noStringTrue != 0 || right&noStringTrue != 0 {
			result |= noStringTrue
		}
		if left&noStringFalse != 0 && right&noStringFalse != 0 {
			result |= noStringFalse
		}
		return result
	case token.AT, token.IN:
		if isStringPresenceExpression(expr.Left) && staticStringConstraint(expr.Op, expr.Right) {
			return noStringFalse
		}
		return noStringUnknown
	}

	leftInt, leftOK := integerWithoutStringMatches(expr.Left)
	rightInt, rightOK := integerWithoutStringMatches(expr.Right)
	if !leftOK || !rightOK {
		return noStringUnknown
	}
	var value bool
	switch expr.Op {
	case token.EQ:
		value = leftInt == rightInt
	case token.NEQ:
		value = leftInt != rightInt
	case token.LT:
		value = leftInt < rightInt
	case token.LE:
		value = leftInt <= rightInt
	case token.GT:
		value = leftInt > rightInt
	case token.GE:
		value = leftInt >= rightInt
	default:
		integer, ok := integerWithoutStringMatches(expr)
		if !ok {
			return noStringUnknown
		}
		return scalarTruth(integer)
	}
	return scalarTruth(value)
}

func integerWithoutStringMatches(expr ast.Expression) (int64, bool) {
	switch e := expr.(type) {
	case *ast.Literal:
		switch e.Type {
		case token.IntegerLit, token.HexIntegerLit, token.OctalIntegerLit:
			value, err := strconv.ParseInt(fmt.Sprint(e.Value), 0, 64)
			return value, err == nil
		case token.TRUE:
			return 1, true
		case token.FALSE:
			return 0, true
		}
	case *ast.StringCount:
		if !staticStringOccurrenceIndex(e.Index) {
			return 0, false
		}
		return 0, true
	case *ast.PercentExpression:
		return integerWithoutStringMatches(e.Value)
	case *ast.UnaryOp:
		value, ok := integerWithoutStringMatches(e.Right)
		if !ok {
			return 0, false
		}
		switch e.Op {
		case token.MINUS:
			return -value, true
		case token.BitwiseNot:
			return ^value, true
		}
	case *ast.BinaryOp:
		left, leftOK := integerWithoutStringMatches(e.Left)
		right, rightOK := integerWithoutStringMatches(e.Right)
		if !leftOK || !rightOK {
			return 0, false
		}
		switch e.Op {
		case token.PLUS:
			return left + right, true
		case token.MINUS:
			return left - right, true
		case token.MULTIPLY:
			return left * right, true
		case token.IntDivide:
			if right != 0 {
				return left / right, true
			}
		case token.MODULO:
			if right != 0 {
				return left % right, true
			}
		case token.BitwiseAnd:
			return left & right, true
		case token.BitwiseOr:
			return left | right, true
		case token.BitwiseXor:
			return left ^ right, true
		case token.LeftShift:
			if right >= 0 && right < 64 {
				return left << uint64(right), true
			}
		case token.RightShift:
			if right >= 0 && right < 64 {
				return left >> uint64(right), true
			}
		}
	}
	return 0, false
}

func invertTruth(value noStringTruth) noStringTruth {
	var result noStringTruth
	if value&noStringFalse != 0 {
		result |= noStringTrue
	}
	if value&noStringTrue != 0 {
		result |= noStringFalse
	}
	return result
}

func isStringPresenceExpression(expr ast.Expression) bool {
	identifier, ok := expr.(*ast.Identifier)
	return ok && strings.HasPrefix(identifier.Name, "$")
}

func ofTruthWithoutStringMatches(expr *ast.OfExpression) noStringTruth {
	// This is the count-in-range form rather than a normal quantifier. Zero
	// may fall inside its dynamic range, so it is not safe to reject.
	if _, countInRange := expr.Count.(*ast.StringCount); countInRange && expr.InRange != nil {
		return noStringUnknown
	}
	if expr.InRange != nil && !staticStringConstraint(token.IN, expr.InRange) {
		return noStringUnknown
	}
	if expr.AtOffset != nil && !staticStringConstraint(token.AT, expr.AtOffset) {
		return noStringUnknown
	}

	switch count := expr.Count.(type) {
	case *ast.Identifier:
		switch count.Name {
		case QuantifierAny:
			return noStringFalse
		case QuantifierNone:
			return noStringTrue
		case QuantifierAll:
			if stringSetStaticallyNonEmpty(expr.Strings) {
				return noStringFalse
			}
			return noStringUnknown
		}
	case *ast.PercentExpression:
		percent, ok := integerWithoutStringMatches(count.Value)
		if !ok {
			return noStringUnknown
		}
		if percent <= 0 {
			return noStringTrue
		}
		if stringSetStaticallyNonEmpty(expr.Strings) {
			return noStringFalse
		}
		return noStringUnknown
	}

	count, ok := integerWithoutStringMatches(expr.Count)
	if !ok {
		return noStringUnknown
	}
	if count <= 0 {
		return noStringTrue
	}
	return noStringFalse
}

func isRuleStringSet(expr ast.Expression) bool {
	switch e := expr.(type) {
	case *ast.Identifier:
		return e.Name == "them" || strings.HasPrefix(e.Name, "$")
	case *ast.StringTuple:
		for _, element := range e.Elements {
			if !isStringPresenceExpression(element) {
				return false
			}
		}
		return true
	case *ast.BinaryOp:
		return e.Op == token.COMMA && isRuleStringSet(e.Left) && isRuleStringSet(e.Right)
	default:
		return false
	}
}

func stringSetStaticallyNonEmpty(expr ast.Expression) bool {
	switch e := expr.(type) {
	case *ast.Identifier:
		if e.Name == "them" {
			return true
		}
		return e.Name != "$" && strings.HasPrefix(e.Name, "$") && !strings.HasSuffix(e.Name, "*")
	case *ast.StringTuple:
		return len(e.Elements) > 0
	case *ast.BinaryOp:
		return e.Op == token.COMMA && (stringSetStaticallyNonEmpty(e.Left) || stringSetStaticallyNonEmpty(e.Right))
	default:
		return false
	}
}

func staticStringOccurrenceIndex(index ast.Expression) bool {
	if index == nil {
		return true
	}
	_, ok := integerWithoutStringMatches(index)
	return ok
}

func staticStringConstraint(operator token.Type, expr ast.Expression) bool {
	if operator == token.AT {
		_, ok := integerWithoutStringMatches(expr)
		return ok
	}
	rangeExpr, ok := expr.(*ast.BinaryOp)
	if !ok || rangeExpr.Op != token.DOT {
		return false
	}
	_, leftOK := integerWithoutStringMatches(rangeExpr.Left)
	_, rightOK := integerWithoutStringMatches(rangeExpr.Right)
	return leftOK && rightOK
}
