package semantic

import (
	"math"
	"strconv"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/internal/int64ops"
	"github.com/cawalch/go-yara/token"
)

// validateConstantIntegerBinaryOp reports compile-time integer overflow,
// division by zero, and negative shift counts on constant expressions.
func (v *Validator) validateConstantIntegerBinaryOp(binOp *ast.BinaryOp) *Error {
	rhs, rhsOK := evalConstantInt(binOp.Right)
	if (binOp.Op == token.DIVIDE || binOp.Op == token.IntDivide || binOp.Op == token.MODULO) && rhsOK && rhs == 0 {
		return &Error{
			Code:     ErrCodeDivisionByZero,
			Message:  "division by zero",
			Position: binOp.Position(),
			Rule:     v.currentRule,
		}
	}

	lhs, lhsOK := evalConstantInt(binOp.Left)
	if !lhsOK || !rhsOK {
		return nil
	}

	switch binOp.Op {
	case token.PLUS:
		if _, ok := int64ops.Add(lhs, rhs); !ok {
			return v.integerOverflowError(binOp.Position())
		}
	case token.MINUS:
		if _, ok := int64ops.Sub(lhs, rhs); !ok {
			return v.integerOverflowError(binOp.Position())
		}
	case token.MULTIPLY:
		if _, ok := int64ops.Mul(lhs, rhs); !ok {
			return v.integerOverflowError(binOp.Position())
		}
	case token.DIVIDE, token.IntDivide:
		if _, status := int64ops.Div(lhs, rhs); status == int64ops.DivOverflow {
			return v.integerOverflowError(binOp.Position())
		}
	case token.LeftShift, token.RightShift:
		if rhs < 0 {
			return &Error{
				Code:     ErrCodeInvalidOperation,
				Message:  "negative shift count",
				Position: binOp.Position(),
				Rule:     v.currentRule,
			}
		}
	}
	return nil
}

func (v *Validator) integerOverflowError(pos token.Position) *Error {
	return &Error{
		Code:     ErrCodeIntegerOverflow,
		Message:  "integer overflow",
		Position: pos,
		Rule:     v.currentRule,
	}
}

func evalConstantInt(expr ast.Expression) (int64, bool) {
	switch e := expr.(type) {
	case *ast.Literal:
		return constantLiteralInt(e)
	case *ast.UnaryOp:
		if e.Op == token.MINUS {
			if lit, ok := e.Right.(*ast.Literal); ok && lit.Type == token.IntegerLit {
				if text, ok := lit.Value.(string); ok && text == "9223372036854775808" {
					return math.MinInt64, true
				}
			}
		}
		val, ok := evalConstantInt(e.Right)
		if !ok {
			return 0, false
		}
		switch e.Op {
		case token.PLUS:
			return val, true
		case token.MINUS:
			return -val, true
		case token.BitwiseNot:
			return ^val, true
		default:
			return 0, false
		}
	case *ast.BinaryOp:
		lhs, okL := evalConstantInt(e.Left)
		rhs, okR := evalConstantInt(e.Right)
		if !okL || !okR {
			return 0, false
		}
		return evalConstantBinaryInt(e.Op, lhs, rhs)
	default:
		return 0, false
	}
}

func constantLiteralInt(lit *ast.Literal) (int64, bool) {
	switch lit.Type {
	case token.IntegerLit, token.HexIntegerLit, token.OctalIntegerLit, token.SizeLit:
	default:
		return 0, false
	}
	switch v := lit.Value.(type) {
	case int:
		return int64(v), true
	case int8:
		return int64(v), true
	case int16:
		return int64(v), true
	case int32:
		return int64(v), true
	case int64:
		return v, true
	case uint64:
		if v <= math.MaxInt64 {
			return int64(v), true
		}
		return int64(v-math.MaxInt64-1) - math.MaxInt64 - 1, true //checkednarrow:ignore bounded within [0, math.MaxInt64]
	case string:
		if lit.Type == token.SizeLit {
			val, err := int64ops.ParseSizeLiteral(v)
			return val, err == nil
		}
		if v == "" {
			return 0, false
		}
		if val, err := int64ops.ParseIntLiteral(v); err == nil {
			return val, true
		}
		if val, err := strconv.ParseInt(v, 0, 64); err == nil {
			return val, true
		}
		return 0, false
	default:
		return 0, false
	}
}

func evalConstantBinaryInt(op token.Type, lhs, rhs int64) (int64, bool) {
	switch op {
	case token.PLUS:
		return int64ops.Add(lhs, rhs)
	case token.MINUS:
		return int64ops.Sub(lhs, rhs)
	case token.MULTIPLY:
		return int64ops.Mul(lhs, rhs)
	case token.DIVIDE, token.IntDivide:
		val, status := int64ops.Div(lhs, rhs)
		return val, status == int64ops.DivOK
	case token.MODULO:
		val, status := int64ops.Mod(lhs, rhs)
		return val, status == int64ops.DivOK
	case token.BitwiseAnd:
		return lhs & rhs, true
	case token.BitwiseOr:
		return lhs | rhs, true
	case token.BitwiseXor:
		return lhs ^ rhs, true
	case token.LeftShift:
		return int64ops.ShiftLeft(lhs, rhs)
	case token.RightShift:
		return int64ops.ShiftRight(lhs, rhs)
	default:
		return 0, false
	}
}
