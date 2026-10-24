package compiler

import (
	"context"
	"errors"
	"slices"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

// A fixed dataflow program evaluates a complete boolean condition without
// interpreter operand-stack traffic. Inputs always precede their consumers.
type assertionInstruction struct {
	Op                     Opcode
	Left, Right, Assertion int
}

func (cc *conditionCompiler) assertionForExpression(expr ast.Expression) (conditionAssertion, bool) {
	if assertion, ok := assertionFromExpression(expr); ok {
		return assertion, true
	}
	return externalAssertion(expr, cc.externalVariables, cc.variableMap)
}

func (cc *conditionCompiler) internAssertion(assertion conditionAssertion) int {
	index := slices.Index(cc.assertions, assertion)
	if index < 0 {
		index = len(cc.assertions)
		cc.assertions = append(cc.assertions, assertion)
	}
	return index
}

func (cc *conditionCompiler) compileAssertionProgram(expr ast.Expression) bool {
	if cc.disableAssertions {
		return false
	}
	original := len(cc.assertions)
	var nodes []assertionInstruction
	var build func(ast.Expression) (int, bool)
	build = func(expr ast.Expression) (int, bool) {
		node := assertionInstruction{Left: -1, Right: -1, Assertion: -1}
		if assertion, ok := cc.assertionForExpression(expr); ok {
			node.Op = assertion.Opcode
			node.Assertion = cc.internAssertion(assertion)
			nodes = append(nodes, node)
			return len(nodes) - 1, true
		}
		switch e := expr.(type) {
		case *ast.BinaryOp:
			if e.Op != token.AND && e.Op != token.OR {
				return 0, false
			}
			node.Op = OpAnd
			if e.Op == token.OR {
				node.Op = OpOr
			}
			var ok bool
			node.Left, ok = build(e.Left)
			if !ok {
				return 0, false
			}
			node.Right, ok = build(e.Right)
			if !ok {
				return 0, false
			}
		case *ast.UnaryOp:
			if e.Op != token.NOT {
				return 0, false
			}
			node.Op = OpNot
			var ok bool
			node.Left, ok = build(e.Right)
			if !ok {
				return 0, false
			}
		default:
			return 0, false
		}
		nodes = append(nodes, node)
		return len(nodes) - 1, true
	}
	if _, ok := build(expr); !ok {
		cc.assertions = cc.assertions[:original]
		return false
	}
	cc.assertionProgram = nodes
	cc.emitter.EmitOpcode(OpEvalAssertions, expr.Position().Line, expr.Position().Column)
	return true
}

func validateAssertionProgram(nodes []assertionInstruction, assertions []conditionAssertion) error {
	for index, node := range nodes {
		switch node.Op {
		case OpAnd, OpOr:
			if node.Right < 0 || node.Right >= index {
				return errors.New("invalid assertion right register")
			}
			fallthrough
		case OpNot:
			if node.Left < 0 || node.Left >= index {
				return errors.New("invalid assertion left register")
			}
		default:
			if node.Assertion < 0 || node.Assertion >= len(assertions) || assertions[node.Assertion].Opcode != node.Op {
				return errors.New("invalid assertion program leaf")
			}
		}
	}
	return nil
}

func (i *Interpreter) executeEvalAssertions() error {
	rule := i.currentCompiledRule
	if rule == nil || len(rule.assertionProgram) == 0 {
		return &InterpreterError{Type: ErrorInvalidBytecode, Opcode: OpEvalAssertions, Message: "missing assertion program"}
	}
	// Prepared programs are validated once. Check register bounds here as well,
	// since the low-level interpreter also accepts caller-provided bytecode.
	nodes := rule.assertionProgram
	if cap(i.assertionRegisters) < len(nodes) {
		i.assertionRegisters = make([]assertionResult, len(nodes))
	}
	registers := i.assertionRegisters[:len(nodes)]
	i.assertionRegisters = registers
	for index, node := range nodes {
		if i.matchContext != nil && index%64 == 0 {
			select {
			case <-i.matchContext.cancelDone:
				return context.Canceled
			default:
			}
		}
		result := assertionFalse
		switch node.Op {
		case OpAnd, OpOr, OpNot:
			if node.Left < 0 || node.Left >= index || (node.Op != OpNot && (node.Right < 0 || node.Right >= index)) {
				return &InterpreterError{Type: ErrorInvalidBytecode, Opcode: OpEvalAssertions, Message: "invalid assertion register"}
			}
			left := registers[node.Left]
			switch node.Op {
			case OpAnd:
				if left == assertionTrue && registers[node.Right] == assertionTrue {
					result = assertionTrue
				}
			case OpOr:
				if left == assertionTrue || registers[node.Right] == assertionTrue {
					result = assertionTrue
				}
			case OpNot:
				if left == assertionUndefined {
					result = assertionUndefined
				} else if left != assertionTrue {
					result = assertionTrue
				}
			}
		default:
			if node.Assertion < 0 || node.Assertion >= len(rule.assertions) || rule.assertions[node.Assertion].Opcode != node.Op {
				return &InterpreterError{Type: ErrorInvalidBytecode, Opcode: OpEvalAssertions, Message: "invalid assertion leaf"}
			}
			var err error
			result, err = i.evaluateAssertion(node.Assertion)
			if err != nil {
				return err
			}
		}
		registers[index] = result
	}
	i.directCondition = true
	i.directResult = registers[len(nodes)-1]
	return nil
}
