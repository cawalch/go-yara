package compiler

// executeBitwiseAnd handles OpBitwiseAnd opcode.
func (i *Interpreter) executeBitwiseAnd() error {
	return i.executeBinaryOp(func(a, b int64) int64 { return a & b })
}

// executeBitwiseOr handles OpBitwiseOr opcode.
func (i *Interpreter) executeBitwiseOr() error {
	return i.executeBinaryOp(func(a, b int64) int64 { return a | b })
}

// executeBitwiseXor handles OpBitwiseXor opcode.
func (i *Interpreter) executeBitwiseXor() error {
	return i.executeBinaryOp(func(a, b int64) int64 { return a ^ b })
}

// executeBitwiseNot handles OpBitwiseNot opcode.
func (i *Interpreter) executeBitwiseNot() error {
	if err := i.validateStackUnderflow(OpBitwiseNot); err != nil {
		return err
	}

	v := i.stack[len(i.stack)-1]
	switch v.Type {
	case ValueTypeInt:
		i.stack[len(i.stack)-1] = Value{Type: ValueTypeInt, IntVal: ^v.IntVal}
	case ValueTypeUndefined:
		i.stack[len(i.stack)-1] = Value{Type: ValueTypeUndefined}
	default:
		i.stack[len(i.stack)-1] = Value{Type: ValueTypeUndefined}
	}
	return nil
}

// executeShiftLeft handles OpShl opcode.
func (i *Interpreter) executeShiftLeft() error {
	return i.executeBinaryOp(func(a, b int64) int64 {
		if b < 0 {
			return a << 0
		}
		if b > 63 {
			b = 63
		}
		return a << uint64(b) // #nosec G115 - safe conversion with bounds check above
	})
}

// executeShiftRight handles OpShr opcode.
func (i *Interpreter) executeShiftRight() error {
	return i.executeBinaryOp(func(a, b int64) int64 {
		if b < 0 {
			return a >> 0
		}
		if b > 63 {
			b = 63
		}
		return a >> uint64(b) // #nosec G115 - safe conversion with bounds check above
	})
}

// --- Individual integer arithmetic handlers ---

func (i *Interpreter) executeIntAdd() error {
	return i.executeBinaryOp(func(a, b int64) int64 { return a + b })
}

func (i *Interpreter) executeIntSub() error {
	return i.executeBinaryOp(func(a, b int64) int64 { return a - b })
}

func (i *Interpreter) executeIntMul() error {
	return i.executeBinaryOp(func(a, b int64) int64 { return a * b })
}

func (i *Interpreter) executeIntDiv() error {
	a, b, err := i.popTwo()
	if err != nil {
		return err
	}
	if a.Type == ValueTypeUndefined || b.Type == ValueTypeUndefined {
		return i.push(Value{Type: ValueTypeUndefined})
	}
	if a.Type != ValueTypeInt || b.Type != ValueTypeInt {
		return i.handleNonIntegerOperands(a, b, "integer-only operation requires integer operands")
	}
	if b.IntVal == 0 {
		return i.push(Value{Type: ValueTypeUndefined})
	}
	return i.push(Value{Type: ValueTypeInt, IntVal: a.IntVal / b.IntVal})
}

func (i *Interpreter) executeMod() error {
	a, b, err := i.popTwo()
	if err != nil {
		return err
	}
	if a.Type == ValueTypeUndefined || b.Type == ValueTypeUndefined {
		return i.push(Value{Type: ValueTypeUndefined})
	}
	if a.Type != ValueTypeInt || b.Type != ValueTypeInt {
		return i.handleNonIntegerOperands(a, b, "integer-only operation requires integer operands")
	}
	if b.IntVal == 0 {
		return i.push(Value{Type: ValueTypeUndefined})
	}
	return i.push(Value{Type: ValueTypeInt, IntVal: a.IntVal % b.IntVal})
}

func (i *Interpreter) executeIntMinus() error {
	if err := i.validateStackUnderflow(OpIntMinus); err != nil {
		return err
	}
	v := i.stack[len(i.stack)-1]
	if v.Type == ValueTypeUndefined {
		return nil
	}
	if v.Type != ValueTypeInt {
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpIntMinus, Message: "integer operand required"}
	}
	i.stack[len(i.stack)-1] = Value{Type: ValueTypeInt, IntVal: -v.IntVal}
	return nil
}

// --- Individual double arithmetic handlers ---

func (i *Interpreter) executeDblAdd() error {
	return i.executeDoubleOp(func(a, b float64) float64 { return a + b })
}

func (i *Interpreter) executeDblSub() error {
	return i.executeDoubleOp(func(a, b float64) float64 { return a - b })
}

func (i *Interpreter) executeDblMul() error {
	return i.executeDoubleOp(func(a, b float64) float64 { return a * b })
}

func (i *Interpreter) executeDblDiv() error {
	a, b, err := i.popTwo()
	if err != nil {
		return err
	}
	if a.Type == ValueTypeUndefined || b.Type == ValueTypeUndefined {
		return i.push(Value{Type: ValueTypeUndefined})
	}
	if a.Type != ValueTypeDouble || b.Type != ValueTypeDouble {
		return i.push(Value{Type: ValueTypeUndefined})
	}
	if b.DoubleVal == 0.0 {
		return i.push(Value{Type: ValueTypeUndefined})
	}
	return i.push(Value{Type: ValueTypeDouble, DoubleVal: a.DoubleVal / b.DoubleVal})
}

func (i *Interpreter) executeDblMinus() error {
	if err := i.validateStackUnderflow(OpDblMinus); err != nil {
		return err
	}
	v := i.stack[len(i.stack)-1]
	if v.Type == ValueTypeUndefined {
		return nil
	}
	if v.Type != ValueTypeDouble {
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpDblMinus, Message: "double operand required"}
	}
	i.stack[len(i.stack)-1] = Value{Type: ValueTypeDouble, DoubleVal: -v.DoubleVal}
	return nil
}
