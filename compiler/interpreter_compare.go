package compiler

import "fmt"

// executeTypedComparison performs a typed comparison for the given opcode.
func (i *Interpreter) executeTypedComparison(opcode Opcode) error {
	if err := i.validateStackUnderflowN(opcode, 2); err != nil {
		return err
	}

	b := i.stack[len(i.stack)-1]
	a := i.stack[len(i.stack)-2]
	i.stack = i.stack[:len(i.stack)-2]

	result, err := i.compareValues(a, b, opcode)
	if err != nil {
		return err
	}

	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(result)})
}

// compareValues dispatches to integer or double comparison based on operand type.
func (i *Interpreter) compareValues(a, b Value, opcode Opcode) (bool, error) {
	switch a.Type {
	case ValueTypeInt:
		return i.compareIntegers(a, b, opcode)
	case ValueTypeDouble:
		return i.compareDoubles(a, b, opcode)
	default:
		return false, &InterpreterError{Type: ErrorTypeMismatch, Message: "numeric operands required"}
	}
}

// compareIntegers compares two integer values.
func (i *Interpreter) compareIntegers(a, b Value, opcode Opcode) (bool, error) {
	if b.Type != ValueTypeInt {
		return false, &InterpreterError{Type: ErrorTypeMismatch, Message: "integer operands required"}
	}

	switch opcode {
	case OpIntEq, OpDblEq:
		return a.IntVal == b.IntVal, nil
	case OpIntNeq, OpDblNeq:
		return a.IntVal != b.IntVal, nil
	case OpIntLt, OpDblLt:
		return a.IntVal < b.IntVal, nil
	case OpIntLe, OpDblLe:
		return a.IntVal <= b.IntVal, nil
	case OpIntGt, OpDblGt:
		return a.IntVal > b.IntVal, nil
	case OpIntGe, OpDblGe:
		return a.IntVal >= b.IntVal, nil
	default:
		return false, &InterpreterError{Type: ErrorUnsupportedOpcode, Message: "invalid comparison opcode"}
	}
}

// compareDoubles compares two double values.
func (i *Interpreter) compareDoubles(a, b Value, opcode Opcode) (bool, error) {
	if b.Type != ValueTypeDouble {
		return false, &InterpreterError{Type: ErrorTypeMismatch, Message: "double operands required"}
	}

	switch opcode {
	case OpIntEq, OpDblEq:
		return a.DoubleVal == b.DoubleVal, nil
	case OpIntNeq, OpDblNeq:
		return a.DoubleVal != b.DoubleVal, nil
	case OpIntLt, OpDblLt:
		return a.DoubleVal < b.DoubleVal, nil
	case OpIntLe, OpDblLe:
		return a.DoubleVal <= b.DoubleVal, nil
	case OpIntGt, OpDblGt:
		return a.DoubleVal > b.DoubleVal, nil
	case OpIntGe, OpDblGe:
		return a.DoubleVal >= b.DoubleVal, nil
	default:
		return false, &InterpreterError{Type: ErrorUnsupportedOpcode, Message: "invalid comparison opcode"}
	}
}

// executeStringComparison performs a string comparison with the given predicate.
func (i *Interpreter) executeStringComparison(comparison func(string, string) bool) error {
	a, b, err := i.popTwo()
	if err != nil {
		return err
	}

	if a.Type != ValueTypeString || b.Type != ValueTypeString {
		return &InterpreterError{
			Type:    ErrorTypeMismatch,
			Message: "string comparison operation requires string operands",
		}
	}

	result := int64(0)
	if comparison(i.getString(a), i.getString(b)) {
		result = 1
	}

	return i.push(Value{Type: ValueTypeInt, IntVal: result})
}

// --- Individual comparison handlers ---

func (i *Interpreter) executeIntEq() error  { return i.executeTypedComparison(OpIntEq) }
func (i *Interpreter) executeIntNeq() error { return i.executeTypedComparison(OpIntNeq) }
func (i *Interpreter) executeIntLt() error  { return i.executeTypedComparison(OpIntLt) }
func (i *Interpreter) executeIntGt() error  { return i.executeTypedComparison(OpIntGt) }
func (i *Interpreter) executeIntLe() error  { return i.executeTypedComparison(OpIntLe) }
func (i *Interpreter) executeIntGe() error  { return i.executeTypedComparison(OpIntGe) }

func (i *Interpreter) executeDblEq() error  { return i.executeTypedComparison(OpDblEq) }
func (i *Interpreter) executeDblNeq() error { return i.executeTypedComparison(OpDblNeq) }
func (i *Interpreter) executeDblLt() error  { return i.executeTypedComparison(OpDblLt) }
func (i *Interpreter) executeDblGt() error  { return i.executeTypedComparison(OpDblGt) }
func (i *Interpreter) executeDblLe() error  { return i.executeTypedComparison(OpDblLe) }
func (i *Interpreter) executeDblGe() error  { return i.executeTypedComparison(OpDblGe) }

func (i *Interpreter) executeStrEq() error  { return i.executeStringComparison(func(a, b string) bool { return a == b }) }
func (i *Interpreter) executeStrNeq() error { return i.executeStringComparison(func(a, b string) bool { return a != b }) }
func (i *Interpreter) executeStrLt() error  { return i.executeStringComparison(func(a, b string) bool { return a < b }) }
func (i *Interpreter) executeStrGt() error  { return i.executeStringComparison(func(a, b string) bool { return a > b }) }
func (i *Interpreter) executeStrLe() error  { return i.executeStringComparison(func(a, b string) bool { return a <= b }) }
func (i *Interpreter) executeStrGe() error  { return i.executeStringComparison(func(a, b string) bool { return a >= b }) }

// executeIntToDouble handles OpIntToDbl opcode.
func (i *Interpreter) executeIntToDouble() error {
	if err := i.validateStackUnderflow(OpIntToDbl); err != nil {
		return err
	}

	v := i.stack[len(i.stack)-1]
	if v.Type == ValueTypeInt {
		i.stack[len(i.stack)-1] = Value{Type: ValueTypeDouble, DoubleVal: float64(v.IntVal)}
		return nil
	}

	return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpIntToDbl, Message: "integer operand required"}
}

// executeStringToBool handles OpStrToBool opcode.
func (i *Interpreter) executeStringToBool() error {
	if err := i.validateStackUnderflow(OpStrToBool); err != nil {
		return err
	}

	v := i.stack[len(i.stack)-1]
	if v.Type == ValueTypeString {
		result := i.getString(v) != ""
		i.stack[len(i.stack)-1] = Value{Type: ValueTypeInt, IntVal: boolToInt(result)}
		return nil
	}

	return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpStrToBool, Message: "string operand required"}
}

// executePushRuleOperation handles OpPushRule opcode.
func (i *Interpreter) executePushRuleOperation() error {
	if err := i.validateBytecodeBounds(OpPushRule, 1); err != nil {
		return err
	}
	ruleIdx := int(i.bytecode[i.ip])
	i.ip++
	if ruleIdx >= len(i.compiledRules) {
		return &InterpreterError{Type: ErrorInvalidBytecode, Opcode: OpPushRule, Message: fmt.Sprintf("rule index %d out of range", ruleIdx)}
	}
	ruleName := i.compiledRules[ruleIdx].Name
	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(i.ruleResults[ruleName])})
}

// executeInitRuleOperation handles OpInitRule opcode.
func (i *Interpreter) executeInitRuleOperation() error {
	if err := i.validateBytecodeBounds(OpInitRule, 1); err != nil {
		return err
	}
	ruleIdx := int(i.bytecode[i.ip])
	i.ip++
	if ruleIdx >= len(i.compiledRules) {
		return &InterpreterError{Type: ErrorInvalidBytecode, Opcode: OpInitRule, Message: fmt.Sprintf("rule index %d out of range", ruleIdx)}
	}
	i.currentRule = i.compiledRules[ruleIdx].Name
	return i.push(Value{Type: ValueTypeInt, IntVal: 1})
}

// executeMatchRuleOperation handles OpMatchRule opcode.
func (i *Interpreter) executeMatchRuleOperation() error {
	if err := i.validateStackUnderflow(OpMatchRule); err != nil {
		return err
	}
	condition := i.stack[len(i.stack)-1]
	i.stack = i.stack[:len(i.stack)-1]
	if i.currentRule == "" {
		return &InterpreterError{Type: ErrorRuntime, Opcode: OpMatchRule, Message: "no current rule context"}
	}
	i.ruleResults[i.currentRule] = i.isTruthy(condition)
	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(i.ruleResults[i.currentRule])})
}
