package compiler

import "fmt"

// executeNop is a no-op instruction.
func (i *Interpreter) executeNop() error {
	return nil
}

// executeHalt stops the interpreter loop.
func (i *Interpreter) executeHalt() error {
	i.stopped = true
	return nil
}

// executeAndOperation handles AND logical operation.
func (i *Interpreter) executeAndOperation() error {
	return i.executeBinaryOp(func(a, b int64) int64 {
		result := a != 0 && b != 0
		if result {
			return 1
		}
		return 0
	}, nil)
}

// executeOrOperation handles OR logical operation.
func (i *Interpreter) executeOrOperation() error {
	return i.executeBinaryOp(func(a, b int64) int64 {
		result := a != 0 || b != 0
		if result {
			return 1
		}
		return 0
	}, nil)
}

// executeNotOperation handles NOT logical operation.
func (i *Interpreter) executeNotOperation() error {
	if err := i.validateStackUnderflow(OpNot); err != nil {
		return err
	}
	v := i.stack[len(i.stack)-1]
	result := i.isTruthy(v)
	i.stack[len(i.stack)-1] = Value{Type: ValueTypeInt, IntVal: boolToInt(!result)}
	return nil
}

// executeDefinedOperation handles DEFINED logical operation.
func (i *Interpreter) executeDefinedOperation() error {
	if err := i.validateStackUnderflow(OpDefined); err != nil {
		return err
	}
	v := i.stack[len(i.stack)-1]
	defined := v.Type != ValueTypeUndefined
	i.stack[len(i.stack)-1] = Value{Type: ValueTypeInt, IntVal: boolToInt(defined)}
	return nil
}

// executeJz jumps if the top-of-stack value is falsy (does not pop).
func (i *Interpreter) executeJz() error {
	return i.executeConditionalJump(OpJz)
}

// executeJzP jumps if the top-of-stack value is falsy (pops first).
func (i *Interpreter) executeJzP() error {
	return i.executeConditionalJump(OpJzP)
}

// executeJtrue jumps if the top-of-stack value is truthy (does not pop).
func (i *Interpreter) executeJtrue() error {
	return i.executeConditionalJump(OpJtrue)
}

// executeJfalse jumps if the top-of-stack value is falsy (does not pop).
func (i *Interpreter) executeJfalse() error {
	return i.executeConditionalJump(OpJfalse)
}

// executeConditionalJump handles jump operations with common logic.
func (i *Interpreter) executeConditionalJump(opcode Opcode) error {
	if err := i.validateStackUnderflow(opcode); err != nil {
		return err
	}

	condition := i.stack[len(i.stack)-1]

	if opcode == OpJzP {
		i.stack = i.stack[:len(i.stack)-1]
	}

	// Read the 4-byte relative jump offset operand
	if err := i.validateBytecodeBounds(opcode, 4); err != nil {
		return err
	}
	relativeOffset := int32(i.bytecode[i.ip]) | int32(i.bytecode[i.ip+1])<<8 |
		int32(i.bytecode[i.ip+2])<<16 | int32(i.bytecode[i.ip+3])<<24

	var shouldJump bool
	switch opcode {
	case OpJz, OpJzP:
		shouldJump = !i.isTruthy(condition)
	case OpJtrue:
		shouldJump = i.isTruthy(condition)
	case OpJfalse:
		shouldJump = !i.isTruthy(condition)
	}

	if shouldJump {
		// Jump to the target: the emitter computed the relative offset from the END
		// of the jump instruction (after the 4-byte operand). So the target is:
		// (ip + 4) + relativeOffset, where ip points to the start of the operand
		target := i.ip + 4 + int(relativeOffset)
		if target < 0 || target > len(i.bytecode) {
			return &InterpreterError{Type: ErrorInvalidBytecode, Opcode: opcode,
				Message: fmt.Sprintf("jump target out of bounds: %d (bytecode len: %d)", target, len(i.bytecode))}
		}
		i.ip = target
	} else {
		// Skip past the 4-byte operand
		i.ip += 4
	}
	return nil
}

// executeEntrypoint pushes the file entry point onto the stack.
func (i *Interpreter) executeEntrypoint() error {
	if i.matchContext != nil {
		return i.push(Value{Type: ValueTypeInt, IntVal: i.matchContext.EntryPoint})
	}
	return i.push(Value{Type: ValueTypeInt, IntVal: 0})
}

// executeFilesize pushes the file size onto the stack.
func (i *Interpreter) executeFilesize() error {
	if i.matchContext != nil {
		return i.push(Value{Type: ValueTypeInt, IntVal: i.matchContext.FileSize})
	}
	return i.push(Value{Type: ValueTypeInt, IntVal: 0})
}
