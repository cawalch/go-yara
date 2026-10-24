package compiler

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

// conditionAssertion is an immutable operand-pool entry. Keeping full-width
// constants here avoids narrowing offsets and thresholds in fused bytecode.
type conditionAssertion struct {
	Opcode     Opcode
	Comparison Opcode
	Offset     int64
	Value      int64
	String     string
}

func assertionInteger(expr ast.Expression) (int64, bool) {
	literal, ok := expr.(*ast.Literal)
	if !ok {
		return 0, false
	}
	switch literal.Type {
	case token.IntegerLit, token.HexIntegerLit, token.OctalIntegerLit:
		value, err := globalLiteralInt(literal)
		return value, err == nil
	case token.SizeLit:
		text, ok := literal.Value.(string)
		if !ok {
			return 0, false
		}
		value, err := parseSizeLiteral(text)
		return value, err == nil
	default:
		return 0, false
	}
}

func assertionComparison(op token.Type) (Opcode, bool) {
	switch op {
	case token.EQ:
		return OpIntEq, true
	case token.NEQ:
		return OpIntNeq, true
	case token.LT:
		return OpIntLt, true
	case token.LE:
		return OpIntLe, true
	case token.GT:
		return OpIntGt, true
	case token.GE:
		return OpIntGe, true
	default:
		return 0, false
	}
}

func reverseAssertionComparison(op Opcode) Opcode {
	switch op {
	case OpIntLt:
		return OpIntGt
	case OpIntGt:
		return OpIntLt
	case OpIntLe:
		return OpIntGe
	case OpIntGe:
		return OpIntLe
	}
	return op
}

func assertionFromExpression(expr ast.Expression) (conditionAssertion, bool) {
	bin, ok := expr.(*ast.BinaryOp)
	if !ok {
		return conditionAssertion{}, false
	}
	if bin.Op == token.AT {
		id, ok := bin.Left.(*ast.Identifier)
		offset, constant := assertionInteger(bin.Right)
		if !ok || !constant || id.Name == "$" || !strings.HasPrefix(id.Name, "$") || id.Quantifier != "" {
			return conditionAssertion{}, false
		}
		return conditionAssertion{Opcode: OpAssertStringAt, Offset: offset, String: id.Name}, true
	}
	comparison, ok := assertionComparison(bin.Op)
	if !ok {
		return conditionAssertion{}, false
	}
	left, right := bin.Left, bin.Right
	value, constant := assertionInteger(right)
	if !constant {
		value, constant = assertionInteger(left)
		if !constant {
			return conditionAssertion{}, false
		}
		left = right
		comparison = reverseAssertionComparison(comparison)
	}
	assertion := conditionAssertion{Comparison: comparison, Value: value}
	switch expr := left.(type) {
	case *ast.Literal:
		if expr.Type != token.FILESIZE {
			return conditionAssertion{}, false
		}
		assertion.Opcode = OpAssertFilesize
	case *ast.StringCount:
		id, ok := expr.String.(*ast.Identifier)
		if !ok || expr.Index != nil || id.Name == "$" || id.Quantifier != "" {
			return conditionAssertion{}, false
		}
		assertion.Opcode, assertion.String = OpAssertStringCount, "$"+strings.TrimPrefix(id.Name, "$")
	case *ast.FunctionCall:
		if comparison != OpIntEq || len(expr.Args) != 1 {
			return conditionAssertion{}, false
		}
		switch expr.Function {
		case "uint16":
			assertion.Opcode = OpAssertUint16Eq
		case "uint32":
			assertion.Opcode = OpAssertUint32Eq
		default:
			return conditionAssertion{}, false
		}
		offset, ok := assertionInteger(expr.Args[0])
		if !ok {
			return conditionAssertion{}, false
		}
		assertion.Offset = offset
	default:
		return conditionAssertion{}, false
	}
	return assertion, true
}

func (cc *conditionCompiler) compileAssertion(bin *ast.BinaryOp) bool {
	if cc.disableAssertions {
		return false
	}
	assertion, ok := assertionFromExpression(bin)
	if !ok {
		return false
	}
	if assertion.String != "" {
		if _, exists := cc.findStringOffset(assertion.String); !exists {
			return false
		}
	}
	index := slices.Index(cc.assertions, assertion)
	if index < 0 {
		index = len(cc.assertions)
		cc.assertions = append(cc.assertions, assertion)
	}
	cc.emitter.EmitOpcodeWithOperand(assertion.Opcode, Operand{Type: OperandImmediate32, Value: uint64(index)}, bin.Pos.Line, bin.Pos.Column)
	return true
}

// Only hoist filesize guards in conditions whose other operations cannot
// produce errors or invoke callbacks. Mandatory integer reads are already
// checked by the existing header constraints. Optional reads, loops, arithmetic,
// and module calls stay in the interpreter to preserve observable failures.
func assertionPruningSafe(expr ast.Expression, headers []HeaderConstraint) bool {
	if assertion, ok := assertionFromExpression(expr); ok {
		if assertion.Opcode != OpAssertUint16Eq && assertion.Opcode != OpAssertUint32Eq {
			return true
		}
		constraint, ok := headerConstraintFromExpression(expr)
		return ok && slices.Contains(headers, constraint)
	}
	switch expr := expr.(type) {
	case *ast.BinaryOp:
		return (expr.Op == token.AND || expr.Op == token.OR) && assertionPruningSafe(expr.Left, headers) && assertionPruningSafe(expr.Right, headers)
	case *ast.UnaryOp:
		return expr.Op == token.NOT && assertionPruningSafe(expr.Right, headers)
	case *ast.Literal:
		return expr.Type == token.TRUE || expr.Type == token.FALSE
	case *ast.Identifier:
		return strings.HasPrefix(expr.Name, "$") && expr.Quantifier == ""
	default:
		return false
	}
}

func mandatoryAssertionIndices(expr ast.Expression, assertions []conditionAssertion) []int {
	if !assertionPruningSafe(expr, deriveHeaderConstraints(expr)) {
		return nil
	}
	var indices []int
	var visit func(ast.Expression)
	visit = func(expr ast.Expression) {
		if assertion, ok := assertionFromExpression(expr); ok && assertion.Opcode == OpAssertFilesize {
			if index := slices.Index(assertions, assertion); index >= 0 && !slices.Contains(indices, index) {
				indices = append(indices, index)
			}
			return
		}
		if bin, ok := expr.(*ast.BinaryOp); ok && bin.Op == token.AND {
			visit(bin.Left)
			visit(bin.Right)
		}
	}
	visit(expr)
	return indices
}

func (assertion conditionAssertion) validate() error {
	switch assertion.Opcode {
	case OpAssertUint16Eq, OpAssertUint32Eq:
		if assertion.Comparison != OpIntEq || assertion.String != "" {
			return errors.New("invalid integer assertion")
		}
	case OpAssertFilesize, OpAssertStringCount:
		if assertion.Comparison < OpIntEq || assertion.Comparison > OpIntGe {
			return errors.New("invalid assertion comparison")
		}
		if assertion.Opcode == OpAssertFilesize && assertion.String != "" {
			return errors.New("invalid filesize assertion")
		}
	case OpAssertStringAt:
	default:
		return fmt.Errorf("invalid assertion opcode %d", assertion.Opcode)
	}
	if (assertion.Opcode == OpAssertStringAt || assertion.Opcode == OpAssertStringCount) && (!strings.HasPrefix(assertion.String, "$") || assertion.String == "$") {
		return errors.New("invalid assertion string identifier")
	}
	return nil
}
