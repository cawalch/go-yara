package compiler

import (
	"strings"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

// FoldConstants recursively evaluates compile-time constant operations on AST expressions.
// It simplifies boolean logic (e.g. true or X -> true, false and X -> false),
// integer literal comparisons (e.g. 1 == 2 -> false), arithmetic on integer literals,
// string comparisons, and unary operations on constants.
func FoldConstants(expr ast.Expression) ast.Expression {
	if expr == nil {
		return nil
	}

	switch e := expr.(type) {
	case *ast.Literal:
		return e
	case *ast.Identifier:
		return e
	case *ast.UnaryOp:
		return foldUnaryOp(e)
	case *ast.BinaryOp:
		return foldBinaryOp(e)
	case *ast.OfExpression:
		return foldOfExpression(e)
	case *ast.ForLoop:
		return foldForLoop(e)
	case *ast.FunctionCall:
		return foldFunctionCall(e)
	case *ast.StringLength:
		e.Index = FoldConstants(e.Index)
		return e
	case *ast.StringOffset:
		e.Index = FoldConstants(e.Index)
		return e
	case *ast.StringCount:
		e.Index = FoldConstants(e.Index)
		return e
	case *ast.LengthOf:
		e.Target = FoldConstants(e.Target)
		return e
	case *ast.PercentExpression:
		e.Value = FoldConstants(e.Value)
		return e
	case *ast.StringTuple:
		for i := range e.Elements {
			e.Elements[i] = FoldConstants(e.Elements[i])
		}
		return e
	default:
		return expr
	}
}

func foldUnaryOp(u *ast.UnaryOp) ast.Expression {
	right := FoldConstants(u.Right)

	switch u.Op {
	case token.NOT:
		if isConstantTrue(right) {
			return boolLiteral(false, u.Pos)
		}
		if isConstantFalse(right) {
			return boolLiteral(true, u.Pos)
		}
	case token.BitwiseNot:
		if val, ok := evaluateConstantInt(right); ok {
			return intLiteral(^val, u.Pos)
		}
	case token.MINUS:
		if val, ok := evaluateConstantInt(right); ok {
			return intLiteral(-val, u.Pos)
		}
		if val, ok := evaluateConstantFloat(right); ok {
			return floatLiteral(-val, u.Pos)
		}
	case token.DEFINED:
		if isConstant(right) {
			return boolLiteral(true, u.Pos)
		}
	}

	u.Right = right
	return u
}

func foldBinaryOp(b *ast.BinaryOp) ast.Expression {
	left := FoldConstants(b.Left)
	right := FoldConstants(b.Right)

	switch b.Op {
	case token.AND:
		return foldLogicalAnd(b, left, right)
	case token.OR:
		return foldLogicalOr(b, left, right)
	case token.EQ, token.NEQ, token.LT, token.LE, token.GT, token.GE:
		if folded, ok := foldComparison(b, left, right); ok {
			return folded
		}
	case token.CONTAINS, token.ICONTAINS, token.STARTSWITH, token.ISTARTSWITH, token.ENDSWITH, token.IENDSWITH, token.IEQUALS:
		if folded, ok := foldStringOp(b, left, right); ok {
			return folded
		}
	case token.PLUS, token.MINUS, token.MULTIPLY, token.DIVIDE, token.MODULO,
		token.BitwiseAnd, token.BitwiseOr, token.BitwiseXor, token.LeftShift, token.RightShift:
		if folded, ok := foldIntegerArithmetic(b, left, right); ok {
			return folded
		}
	}

	b.Left = left
	b.Right = right
	return b
}

func foldLogicalAnd(b *ast.BinaryOp, left, right ast.Expression) ast.Expression {
	if isConstantFalse(left) || isConstantFalse(right) {
		return boolLiteral(false, b.Pos)
	}
	if isConstantTrue(left) {
		return right
	}
	if isConstantTrue(right) {
		return left
	}
	return &ast.BinaryOp{Pos: b.Pos, Left: left, Op: token.AND, Right: right}
}

func foldLogicalOr(b *ast.BinaryOp, left, right ast.Expression) ast.Expression {
	if isConstantTrue(left) || isConstantTrue(right) {
		return boolLiteral(true, b.Pos)
	}
	if isConstantFalse(left) {
		return right
	}
	if isConstantFalse(right) {
		return left
	}
	return &ast.BinaryOp{Pos: b.Pos, Left: left, Op: token.OR, Right: right}
}

func foldComparison(b *ast.BinaryOp, left, right ast.Expression) (ast.Expression, bool) {
	op := b.Op
	pos := b.Pos
	if valL, okL := evaluateConstantInt(left); okL {
		if valR, okR := evaluateConstantInt(right); okR {
			switch op {
			case token.EQ:
				return boolLiteral(valL == valR, pos), true
			case token.NEQ:
				return boolLiteral(valL != valR, pos), true
			case token.LT:
				return boolLiteral(valL < valR, pos), true
			case token.LE:
				return boolLiteral(valL <= valR, pos), true
			case token.GT:
				return boolLiteral(valL > valR, pos), true
			case token.GE:
				return boolLiteral(valL >= valR, pos), true
			}
		}
	}

	if valL, okL := evaluateConstantFloat(left); okL {
		if valR, okR := evaluateConstantFloat(right); okR {
			switch op {
			case token.EQ:
				return boolLiteral(valL == valR, pos), true
			case token.NEQ:
				return boolLiteral(valL != valR, pos), true
			case token.LT:
				return boolLiteral(valL < valR, pos), true
			case token.LE:
				return boolLiteral(valL <= valR, pos), true
			case token.GT:
				return boolLiteral(valL > valR, pos), true
			case token.GE:
				return boolLiteral(valL >= valR, pos), true
			}
		}
	}

	if bL, okL := evaluateConstantBool(left); okL {
		if bR, okR := evaluateConstantBool(right); okR {
			switch op {
			case token.EQ:
				return boolLiteral(bL == bR, pos), true
			case token.NEQ:
				return boolLiteral(bL != bR, pos), true
			}
		}
	}

	if sL, okL := evaluateConstantString(left); okL {
		if sR, okR := evaluateConstantString(right); okR {
			switch op {
			case token.EQ:
				return boolLiteral(sL == sR, pos), true
			case token.NEQ:
				return boolLiteral(sL != sR, pos), true
			}
		}
	}

	return nil, false
}

func foldStringOp(b *ast.BinaryOp, left, right ast.Expression) (ast.Expression, bool) {
	op := b.Op
	pos := b.Pos
	sL, okL := evaluateConstantString(left)
	sR, okR := evaluateConstantString(right)
	if !okL || !okR {
		return nil, false
	}

	switch op {
	case token.CONTAINS:
		return boolLiteral(strings.Contains(sL, sR), pos), true
	case token.ICONTAINS:
		return boolLiteral(strings.Contains(strings.ToLower(sL), strings.ToLower(sR)), pos), true
	case token.STARTSWITH:
		return boolLiteral(strings.HasPrefix(sL, sR), pos), true
	case token.ISTARTSWITH:
		return boolLiteral(strings.HasPrefix(strings.ToLower(sL), strings.ToLower(sR)), pos), true
	case token.ENDSWITH:
		return boolLiteral(strings.HasSuffix(sL, sR), pos), true
	case token.IENDSWITH:
		return boolLiteral(strings.HasSuffix(strings.ToLower(sL), strings.ToLower(sR)), pos), true
	case token.IEQUALS:
		return boolLiteral(strings.EqualFold(sL, sR), pos), true
	default:
		return nil, false
	}
}

func foldIntegerArithmetic(b *ast.BinaryOp, left, right ast.Expression) (ast.Expression, bool) {
	op := b.Op
	pos := b.Pos
	valL, okL := evaluateConstantInt(left)
	valR, okR := evaluateConstantInt(right)
	if !okL || !okR {
		return nil, false
	}

	switch op {
	case token.PLUS:
		return intLiteral(valL+valR, pos), true
	case token.MINUS:
		return intLiteral(valL-valR, pos), true
	case token.MULTIPLY:
		return intLiteral(valL*valR, pos), true
	case token.DIVIDE:
		if valR != 0 {
			return intLiteral(valL/valR, pos), true
		}
	case token.MODULO:
		if valR != 0 {
			return intLiteral(valL%valR, pos), true
		}
	case token.BitwiseAnd:
		return intLiteral(valL&valR, pos), true
	case token.BitwiseOr:
		return intLiteral(valL|valR, pos), true
	case token.BitwiseXor:
		return intLiteral(valL^valR, pos), true
	case token.LeftShift:
		if valR >= 0 && valR < 64 {
			return intLiteral(valL<<valR, pos), true
		}
	case token.RightShift:
		if valR >= 0 && valR < 64 {
			return intLiteral(valL>>valR, pos), true
		}
	}
	return nil, false
}

func foldOfExpression(o *ast.OfExpression) ast.Expression {
	o.Count = FoldConstants(o.Count)
	o.Strings = FoldConstants(o.Strings)
	o.InRange = FoldConstants(o.InRange)
	o.AtOffset = FoldConstants(o.AtOffset)
	return o
}

func foldForLoop(f *ast.ForLoop) ast.Expression {
	f.Range = FoldConstants(f.Range)
	f.Condition = FoldConstants(f.Condition)
	f.InRange = FoldConstants(f.InRange)
	f.AtOffset = FoldConstants(f.AtOffset)
	return f
}

func foldFunctionCall(f *ast.FunctionCall) ast.Expression {
	for i := range f.Args {
		f.Args[i] = FoldConstants(f.Args[i])
	}
	if f.Function == "defined" && len(f.Args) == 1 {
		if isConstant(f.Args[0]) {
			return boolLiteral(true, f.Pos)
		}
	}
	return f
}

func isConstantTrue(expr ast.Expression) bool {
	if lit, ok := expr.(*ast.Literal); ok {
		return lit.Type == token.TRUE
	}
	return false
}

func isConstantFalse(expr ast.Expression) bool {
	if lit, ok := expr.(*ast.Literal); ok {
		return lit.Type == token.FALSE
	}
	return false
}

func isConstant(expr ast.Expression) bool {
	if lit, ok := expr.(*ast.Literal); ok {
		switch lit.Type {
		case token.TRUE, token.FALSE, token.IntegerLit, token.HexIntegerLit,
			token.OctalIntegerLit, token.FloatLit, token.StringLit, token.SizeLit:
			return true
		}
	}
	return false
}

func isConditionStaticallyFalse(expr ast.Expression) bool {
	if expr == nil {
		return false
	}
	folded := FoldConstants(expr)
	return isConstantFalse(folded)
}

func evaluateConstantInt(expr ast.Expression) (int64, bool) {
	lit, ok := expr.(*ast.Literal)
	if !ok {
		return 0, false
	}
	switch lit.Type {
	case token.IntegerLit, token.HexIntegerLit, token.OctalIntegerLit, token.SizeLit:
		val, err := globalLiteralInt(lit)
		if err == nil {
			return val, true
		}
	}
	return 0, false
}

func evaluateConstantBool(expr ast.Expression) (bool, bool) {
	lit, ok := expr.(*ast.Literal)
	if !ok {
		return false, false
	}
	if lit.Type == token.TRUE {
		return true, true
	}
	if lit.Type == token.FALSE {
		return false, true
	}
	return false, false
}

func evaluateConstantFloat(expr ast.Expression) (float64, bool) {
	lit, ok := expr.(*ast.Literal)
	if !ok {
		return 0, false
	}
	if lit.Type == token.FloatLit {
		val, err := globalLiteralFloat(lit)
		if err == nil {
			return val, true
		}
	}
	return 0, false
}

func evaluateConstantString(expr ast.Expression) (string, bool) {
	lit, ok := expr.(*ast.Literal)
	if !ok {
		return "", false
	}
	if lit.Type == token.StringLit {
		if s, ok := lit.Value.(string); ok {
			return s, true
		}
	}
	return "", false
}

func boolLiteral(val bool, pos token.Position) *ast.Literal {
	t := token.FALSE
	if val {
		t = token.TRUE
	}
	return &ast.Literal{
		Pos:   pos,
		Type:  t,
		Value: val,
	}
}

func intLiteral(val int64, pos token.Position) *ast.Literal {
	return &ast.Literal{
		Pos:   pos,
		Type:  token.IntegerLit,
		Value: val,
	}
}

func floatLiteral(val float64, pos token.Position) *ast.Literal {
	return &ast.Literal{
		Pos:   pos,
		Type:  token.FloatLit,
		Value: val,
	}
}
