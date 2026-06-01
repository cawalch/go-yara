package compiler

// executeBitwiseAnd handles OpBitwiseAnd opcode.
func (i *Interpreter) executeBitwiseAnd() error {
	return i.executeBinaryOp(func(a, b int64) int64 { return a & b }, nil)
}

// executeBitwiseOr handles OpBitwiseOr opcode.
func (i *Interpreter) executeBitwiseOr() error {
	return i.executeBinaryOp(func(a, b int64) int64 { return a | b }, nil)
}

// executeBitwiseXor handles OpBitwiseXor opcode.
func (i *Interpreter) executeBitwiseXor() error {
	return i.executeBinaryOp(func(a, b int64) int64 { return a ^ b }, nil)
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
	}, nil)
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
	}, nil)
}

// --- Individual integer arithmetic handlers ---

func (i *Interpreter) executeIntAdd() error {
	return i.executeBinaryOp(func(a, b int64) int64 { return a + b }, nil)
}

func (i *Interpreter) executeIntSub() error {
	return i.executeBinaryOp(func(a, b int64) int64 { return a - b }, nil)
}

func (i *Interpreter) executeIntMul() error {
	return i.executeBinaryOp(func(a, b int64) int64 { return a * b }, nil)
}

func (i *Interpreter) executeIntDiv() error {
	return i.executeBinaryOpWithCheck(func(a, b int64) (int64, error) {
		if b == 0 {
			return 0, &InterpreterError{Type: ErrorDivisionByZero, Opcode: OpIntDiv, Message: "division by zero"}
		}
		return a / b, nil
	}, nil)
}

func (i *Interpreter) executeMod() error {
	return i.executeBinaryOpWithCheck(func(a, b int64) (int64, error) {
		if b == 0 {
			return 0, &InterpreterError{Type: ErrorDivisionByZero, Opcode: OpMod, Message: "modulo by zero"}
		}
		return a % b, nil
	}, nil)
}

func (i *Interpreter) executeIntMinus() error {
	if err := i.validateStackUnderflow(OpIntMinus); err != nil {
		return err
	}
	v := i.stack[len(i.stack)-1]
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
	return i.executeDoubleOp(func(a, b float64) float64 { return a / b })
}

func (i *Interpreter) executeDblMinus() error {
	if err := i.validateStackUnderflow(OpDblMinus); err != nil {
		return err
	}
	v := i.stack[len(i.stack)-1]
	if v.Type != ValueTypeDouble {
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpDblMinus, Message: "double operand required"}
	}
	i.stack[len(i.stack)-1] = Value{Type: ValueTypeDouble, DoubleVal: -v.DoubleVal}
	return nil
}
