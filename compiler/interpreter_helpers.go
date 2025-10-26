// Package compiler provides helper methods for the YARA interpreter.
package compiler

import (
	"encoding/binary"
)

// InterpreterError represents an interpreter execution error
type InterpreterError struct {
	Type    InterpreterErrorType
	Opcode  Opcode
	Message string
}

// InterpreterErrorType represents the type of interpreter error
type InterpreterErrorType int

const (
	// ErrorUnsupportedOpcode indicates an unknown opcode
	ErrorUnsupportedOpcode InterpreterErrorType = iota
	// ErrorDivisionByZero indicates division by zero
	ErrorDivisionByZero
	// ErrorStackUnderflow indicates stack underflow
	ErrorStackUnderflow
	// ErrorStackOverflow indicates stack overflow
	ErrorStackOverflow
	// ErrorInvalidMemoryAccess indicates invalid memory access
	ErrorInvalidMemoryAccess
	// ErrorUnimplemented indicates unimplemented functionality
	ErrorUnimplemented
	// ErrorTypeMismatch indicates type mismatch in operations
	ErrorTypeMismatch
)

func (e *InterpreterError) Error() string {
	return e.Message
}

// push pushes a value onto the stack with overflow checking
func (i *Interpreter) push(value Value) error {
	const maxStackDepth = 1024 // Configurable stack limit

	if len(i.stack) >= maxStackDepth {
		return &InterpreterError{
			Type:    ErrorStackOverflow,
			Message: "stack overflow: maximum stack depth exceeded",
		}
	}

	i.stack = append(i.stack, value)
	return nil
}

// pop pops a value from the stack with underflow checking
func (i *Interpreter) pop() (Value, error) {
	if len(i.stack) == 0 {
		return Value{Type: ValueTypeUndefined}, &InterpreterError{
			Type:    ErrorStackUnderflow,
			Message: "stack underflow: cannot pop from empty stack",
		}
	}

	value := i.stack[len(i.stack)-1]
	i.stack = i.stack[:len(i.stack)-1]
	return value, nil
}

// popTwo pops two values from the stack (b, a order for binary operations)
func (i *Interpreter) popTwo() (a, b Value, err error) {
	if len(i.stack) < 2 {
		return Value{}, Value{}, &InterpreterError{
			Type:    ErrorStackUnderflow,
			Message: "stack underflow: need at least 2 values for binary operation",
		}
	}

	b = i.stack[len(i.stack)-1]
	i.stack = i.stack[:len(i.stack)-1]

	a = i.stack[len(i.stack)-1]
	i.stack = i.stack[:len(i.stack)-1]

	return a, b, nil
}

// executeBinaryOp executes a binary integer operation
func (i *Interpreter) executeBinaryOp(operation func(int64, int64) int64) error {
	a, b, err := i.popTwo()
	if err != nil {
		return err
	}

	if a.Type != ValueTypeInt || b.Type != ValueTypeInt {
		return &InterpreterError{
			Type:    ErrorTypeMismatch,
			Message: "binary integer operation requires integer operands",
		}
	}

	result := operation(a.IntVal, b.IntVal)
	return i.push(Value{Type: ValueTypeInt, IntVal: result})
}

// executeBinaryOpWithCheck executes a binary integer operation with error checking
func (i *Interpreter) executeBinaryOpWithCheck(operation func(int64, int64) (int64, error)) error {
	a, b, err := i.popTwo()
	if err != nil {
		return err
	}

	if a.Type != ValueTypeInt || b.Type != ValueTypeInt {
		return &InterpreterError{
			Type:    ErrorTypeMismatch,
			Message: "binary integer operation requires integer operands",
		}
	}

	result, err := operation(a.IntVal, b.IntVal)
	if err != nil {
		return err
	}

	return i.push(Value{Type: ValueTypeInt, IntVal: result})
}

// executeDoubleOp executes a binary double operation
func (i *Interpreter) executeDoubleOp(operation func(float64, float64) float64) error {
	a, b, err := i.popTwo()
	if err != nil {
		return err
	}

	if a.Type != ValueTypeDouble || b.Type != ValueTypeDouble {
		return &InterpreterError{
			Type:    ErrorTypeMismatch,
			Message: "binary double operation requires double operands",
		}
	}

	result := operation(a.DoubleVal, b.DoubleVal)
	return i.push(Value{Type: ValueTypeDouble, DoubleVal: result})
}

// executeDoubleOpWithCheck executes a binary double operation with error checking
func (i *Interpreter) executeDoubleOpWithCheck(operation func(float64, float64) (float64, error)) error {
	a, b, err := i.popTwo()
	if err != nil {
		return err
	}

	if a.Type != ValueTypeDouble || b.Type != ValueTypeDouble {
		return &InterpreterError{
			Type:    ErrorTypeMismatch,
			Message: "binary double operation requires double operands",
		}
	}

	result, err := operation(a.DoubleVal, b.DoubleVal)
	if err != nil {
		return err
	}

	return i.push(Value{Type: ValueTypeDouble, DoubleVal: result})
}

// executeComparisonOp executes a comparison operation on integers
func (i *Interpreter) executeComparisonOp(operation func(int64, int64) int64) error {
	a, b, err := i.popTwo()
	if err != nil {
		return err
	}

	if a.Type != ValueTypeInt || b.Type != ValueTypeInt {
		return &InterpreterError{
			Type:    ErrorTypeMismatch,
			Message: "integer comparison operation requires integer operands",
		}
	}

	result := operation(a.IntVal, b.IntVal)
	return i.push(Value{Type: ValueTypeInt, IntVal: result})
}

// executeDoubleComparisonOp executes a comparison operation on doubles
func (i *Interpreter) executeDoubleComparisonOp(operation func(float64, float64) int64) error {
	a, b, err := i.popTwo()
	if err != nil {
		return err
	}

	if a.Type != ValueTypeDouble || b.Type != ValueTypeDouble {
		return &InterpreterError{
			Type:    ErrorTypeMismatch,
			Message: "double comparison operation requires double operands",
		}
	}

	result := operation(a.DoubleVal, b.DoubleVal)
	return i.push(Value{Type: ValueTypeInt, IntVal: result})
}

// executeStringComparisonOp executes a comparison operation on strings
func (i *Interpreter) executeStringComparisonOp(operation func(string, string) int64) error {
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

	result := operation(a.StringVal, b.StringVal)
	return i.push(Value{Type: ValueTypeInt, IntVal: result})
}

// executeConditionalJump executes a conditional jump
func (i *Interpreter) executeConditionalJump(shouldJump func(int64) bool) error {
	condition, err := i.pop()
	if err != nil {
		return err
	}

	var conditionValue int64
	switch condition.Type {
	case ValueTypeInt:
		conditionValue = condition.IntVal
	case ValueTypeDouble:
		conditionValue = int64(condition.DoubleVal)
		if condition.DoubleVal != 0 && conditionValue == 0 {
			conditionValue = 1 // Handle non-zero doubles that cast to zero
		}
	case ValueTypeString:
		conditionValue = 1
		if condition.StringVal == "" {
			conditionValue = 0
		}
	default:
		conditionValue = 0
	}

	if shouldJump(conditionValue) {
		// Read jump offset (little-endian 32-bit)
		if i.ip+4 > len(i.bytecode) {
			return &InterpreterError{
				Type:    ErrorInvalidMemoryAccess,
				Message: "jump offset extends beyond bytecode",
			}
		}

		offset := int32(binary.LittleEndian.Uint32(i.bytecode[i.ip:]))
		i.ip += 4
		i.ip += int(offset)
	} else {
		// Skip the jump offset
		i.ip += 4
	}

	return nil
}

// executeUnaryOp executes a unary integer operation using functional patterns
// nolint:dupl // Different type handling from executeUnaryDoubleOp
func (i *Interpreter) executeUnaryOp(operation func(int64) int64) error {
	if len(i.stack) == 0 {
		return &InterpreterError{
			Type:    ErrorStackUnderflow,
			Message: "stack underflow: cannot pop for unary operation",
		}
	}

	// Pop operand from stack
	operand := i.stack[len(i.stack)-1]
	i.stack = i.stack[:len(i.stack)-1]

	// Type validation for integer operations
	if operand.Type != ValueTypeInt {
		return &InterpreterError{
			Type:    ErrorTypeMismatch,
			Message: "unary integer operation requires integer operand",
		}
	}

	// Apply operation and push result
	result := operation(operand.IntVal)
	return i.push(Value{Type: ValueTypeInt, IntVal: result})
}

// executeUnaryDoubleOp executes a unary double operation using functional patterns
// nolint:dupl // Different type handling from executeUnaryOp
func (i *Interpreter) executeUnaryDoubleOp(operation func(float64) float64) error {
	if len(i.stack) == 0 {
		return &InterpreterError{
			Type:    ErrorStackUnderflow,
			Message: "stack underflow: cannot pop for unary operation",
		}
	}

	// Pop operand from stack for double operation
	operand := i.stack[len(i.stack)-1]
	i.stack = i.stack[:len(i.stack)-1]

	// Type validation for double operations
	if operand.Type != ValueTypeDouble {
		return &InterpreterError{
			Type:    ErrorTypeMismatch,
			Message: "unary double operation requires double operand",
		}
	}

	// Apply operation and push result
	result := operation(operand.DoubleVal)
	return i.push(Value{Type: ValueTypeDouble, DoubleVal: result})
}
