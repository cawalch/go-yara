package compiler

import (
	"strings"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

func externalAssertion(expr ast.Expression, names, locals map[string]int) (conditionAssertion, bool) {
	bin, ok := expr.(*ast.BinaryOp)
	if !ok {
		return conditionAssertion{}, false
	}
	comparison, ok := assertionComparison(bin.Op)
	if !ok {
		return conditionAssertion{}, false
	}
	left, right := bin.Left, bin.Right
	reversed := false
	id, ok := left.(*ast.Identifier)
	if !ok {
		left, right = right, left
		reversed = true
		id, ok = left.(*ast.Identifier)
		comparison = reverseAssertionComparison(comparison)
	}
	if !ok {
		return conditionAssertion{}, false
	}
	if _, exists := names[id.Name]; !exists {
		return conditionAssertion{}, false
	}
	if _, shadowed := locals[id.Name]; shadowed {
		return conditionAssertion{}, false
	}
	literal, ok := right.(*ast.Literal)
	if !ok {
		return conditionAssertion{}, false
	}
	assertion := conditionAssertion{Opcode: OpAssertExternal, External: id.Name, Comparison: comparison, ExternalRight: reversed}
	if value, integer := assertionInteger(literal); integer {
		assertion.ExternalType = ValueTypeInt
		assertion.Value = value
		return assertion, true
	}
	switch literal.Type {
	case token.TRUE, token.FALSE:
		assertion.ExternalType = ValueTypeInt
		if literal.Type == token.TRUE {
			assertion.Value = 1
		}
	case token.StringLit:
		assertion.ExternalType = ValueTypeString
		assertion.Text, ok = literal.Value.(string)
		if !ok {
			return conditionAssertion{}, false
		}

	default:
		return conditionAssertion{}, false
	}
	return assertion, true
}

func evaluateExternalAssertion(assertion *conditionAssertion, values map[string]externalValue) assertionResult {
	value, exists := values[assertion.External]
	if !exists {
		return assertionUndefined
	}
	matched := false
	switch assertion.ExternalType {
	case ValueTypeInt:
		if value.valueType != ValueTypeInt {
			return assertionTypeMismatch
		}
		matched = compareAssertion(value.intVal, assertion.Value, assertion.Comparison)
	case ValueTypeString:
		if value.valueType != ValueTypeString {
			return assertionTypeMismatch
		}
		matched = compareAssertion(int64(strings.Compare(value.stringVal, assertion.Text)), 0, assertion.Comparison)

	}
	if matched {
		return assertionTrue
	}
	return assertionFalse
}

func (i *Interpreter) externalAssertionError(assertion *conditionAssertion) error {
	value := i.matchContext.externalValues[assertion.External]
	if assertion.ExternalType == ValueTypeString {
		return &InterpreterError{Type: ErrorTypeMismatch, Message: "string comparison operation requires string operands"}
	}

	// Preserve the dynamic integer comparison's exact type-error behavior.
	left, right := value.toInterpreterValue(i), Value{Type: ValueTypeInt, IntVal: assertion.Value}
	if assertion.ExternalRight {
		left, right = right, left
	}
	_, err := i.compareValues(left, right, assertion.Comparison)
	return err
}
