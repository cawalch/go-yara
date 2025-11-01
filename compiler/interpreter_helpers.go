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

// numericOperationConfig holds configuration for executing numeric operations
type numericOperationConfig struct {
	IntOp       func(int64, int64) int64
	FloatOp     func(float64, float64) float64
	FloatOp64   func(float64, float64) int64 // For comparison operations
	ResultType  ValueType
	IsComparison bool
	ErrorMsg    string
}

// executeNumericOperation executes numeric operations with automatic type promotion
func (i *Interpreter) executeNumericOperation(config numericOperationConfig) error {
	a, b, err := i.popTwo()
	if err != nil {
		return err
	}

	// Handle mixed-type operations with automatic type promotion
	switch a.Type {
	case ValueTypeInt:
		switch b.Type {
		case ValueTypeInt:
			// int op int = resultType
			result := config.IntOp(a.IntVal, b.IntVal)
			return i.push(Value{Type: config.ResultType, IntVal: result})

		case ValueTypeDouble:
			// int op double = resultType (promote int to double)
			if config.IsComparison {
				result := config.FloatOp64(float64(a.IntVal), b.DoubleVal)
				return i.push(Value{Type: config.ResultType, IntVal: result})
			}
			result := config.FloatOp(float64(a.IntVal), b.DoubleVal)
			return i.push(Value{Type: config.ResultType, DoubleVal: result})

		default:
			return &InterpreterError{
				Type:    ErrorTypeMismatch,
				Message: config.ErrorMsg,
			}
		}

	case ValueTypeDouble:
		switch b.Type {
		case ValueTypeInt:
			// double op int = resultType (promote int to double)
			if config.IsComparison {
				result := config.FloatOp64(a.DoubleVal, float64(b.IntVal))
				return i.push(Value{Type: config.ResultType, IntVal: result})
			}
			result := config.FloatOp(a.DoubleVal, float64(b.IntVal))
			return i.push(Value{Type: config.ResultType, DoubleVal: result})

		case ValueTypeDouble:
			// double op double = resultType
			if config.IsComparison {
				result := config.FloatOp64(a.DoubleVal, b.DoubleVal)
				return i.push(Value{Type: config.ResultType, IntVal: result})
			}
			result := config.FloatOp(a.DoubleVal, b.DoubleVal)
			return i.push(Value{Type: config.ResultType, DoubleVal: result})

		default:
			return &InterpreterError{
				Type:    ErrorTypeMismatch,
				Message: config.ErrorMsg,
			}
		}

	default:
		return &InterpreterError{
			Type:    ErrorTypeMismatch,
			Message: config.ErrorMsg,
		}
	}
}

// executeBinaryOp executes a binary operation with automatic type promotion for mixed int/float operations
func (i *Interpreter) executeBinaryOp(intOp func(int64, int64) int64, floatOp func(float64, float64) float64) error {
	config := numericOperationConfig{
		IntOp:      intOp,
		FloatOp:    floatOp,
		ResultType: ValueTypeInt,
		ErrorMsg:   "binary operation requires numeric operands",
	}
	return i.executeNumericOperation(config)
}

// executeBinaryOpLegacy executes a binary integer operation (backwards compatibility)
func (i *Interpreter) executeBinaryOpLegacy(operation func(int64, int64) int64) error {
	return i.executeBinaryOp(operation, func(a, b float64) float64 {
		// This shouldn't be called in legacy mode, but provide fallback
		return float64(operation(int64(a), int64(b)))
	})
}

// executeBinaryOpWithCheckLegacy executes a binary integer operation with error checking (backwards compatibility)
func (i *Interpreter) executeBinaryOpWithCheckLegacy(operation func(int64, int64) (int64, error)) error {
	return i.executeBinaryOpWithCheck(operation, func(a, b float64) (float64, error) {
		// This shouldn't be called in legacy mode, but provide fallback
		result, err := operation(int64(a), int64(b))
		return float64(result), err
	})
}

// executeBinaryOpWithCheck executes a binary operation with error checking and automatic type promotion
func (i *Interpreter) executeBinaryOpWithCheck(intOp func(int64, int64) (int64, error), floatOp func(float64, float64) (float64, error)) error {
	a, b, err := i.popTwo()
	if err != nil {
		return err
	}

	return i.executeTypedBinaryOp(a, b, binaryOps{intOp: intOp, floatOp: floatOp})
}

// binaryOps represents binary operation functions for different types
type binaryOps struct {
	intOp  func(int64, int64) (int64, error)
	floatOp func(float64, float64) (float64, error)
}

// executeTypedBinaryOp executes a binary operation based on operand types
func (i *Interpreter) executeTypedBinaryOp(a, b Value, ops binaryOps) error {
	switch a.Type {
	case ValueTypeInt:
		return i.executeIntBinaryOp(a, b, ops)

	case ValueTypeDouble:
		return i.executeDoubleBinaryOp(a, b, ops)

	default:
		return i.createTypeMismatchError("binary operation requires numeric operands")
	}
}

// executeIntBinaryOp handles operations where the first operand is an integer
func (i *Interpreter) executeIntBinaryOp(a, b Value, ops binaryOps) error {
	switch b.Type {
	case ValueTypeInt:
		result, err := ops.intOp(a.IntVal, b.IntVal)
		if err != nil {
			return err
		}
		return i.push(Value{Type: ValueTypeInt, IntVal: result})

	case ValueTypeDouble:
		// int + double = double (promote int to double)
		result, err := ops.floatOp(float64(a.IntVal), b.DoubleVal)
		if err != nil {
			return err
		}
		return i.push(Value{Type: ValueTypeDouble, DoubleVal: result})

	default:
		return i.createTypeMismatchError("binary operation requires numeric operands")
	}
}

// executeDoubleBinaryOp handles operations where the first operand is a double
func (i *Interpreter) executeDoubleBinaryOp(a, b Value, ops binaryOps) error {
	switch b.Type {
	case ValueTypeInt:
		// double + int = double (promote int to double)
		result, err := ops.floatOp(a.DoubleVal, float64(b.IntVal))
		if err != nil {
			return err
		}
		return i.push(Value{Type: ValueTypeDouble, DoubleVal: result})

	case ValueTypeDouble:
		result, err := ops.floatOp(a.DoubleVal, b.DoubleVal)
		if err != nil {
			return err
		}
		return i.push(Value{Type: ValueTypeDouble, DoubleVal: result})

	default:
		return i.createTypeMismatchError("binary operation requires numeric operands")
	}
}

// createTypeMismatchError creates a type mismatch error
func (i *Interpreter) createTypeMismatchError(message string) error {
	return &InterpreterError{
		Type:    ErrorTypeMismatch,
		Message: message,
	}
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

// executeComparisonOp executes a comparison operation with automatic type promotion for mixed int/float operations
func (i *Interpreter) executeComparisonOp(intOp func(int64, int64) int64, floatOp func(float64, float64) int64) error {
	config := numericOperationConfig{
		IntOp:       intOp,
		FloatOp64:   floatOp,
		ResultType:  ValueTypeInt,
		IsComparison: true,
		ErrorMsg:    "comparison operation requires numeric operands",
	}
	return i.executeNumericOperation(config)
}

// executeComparisonOpLegacy executes a comparison operation on integers (backwards compatibility)
func (i *Interpreter) executeComparisonOpLegacy(operation func(int64, int64) int64) error {
	return i.executeComparisonOp(operation, func(a, b float64) int64 {
		// This shouldn't be called in legacy mode, but provide fallback
		return operation(int64(a), int64(b))
	})
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

// executeUnaryOp executes a unary numeric operation with automatic type handling
func (i *Interpreter) executeUnaryOp(intOp func(int64) int64, floatOp func(float64) float64) error {
	if len(i.stack) == 0 {
		return &InterpreterError{
			Type:    ErrorStackUnderflow,
			Message: "stack underflow: cannot pop for unary operation",
		}
	}

	// Pop operand from stack
	operand := i.stack[len(i.stack)-1]
	i.stack = i.stack[:len(i.stack)-1]

	// Handle different types with automatic type promotion
	switch operand.Type {
	case ValueTypeInt:
		// Apply integer operation and push result
		result := intOp(operand.IntVal)
		return i.push(Value{Type: ValueTypeInt, IntVal: result})

	case ValueTypeDouble:
		// Apply double operation and push result
		result := floatOp(operand.DoubleVal)
		return i.push(Value{Type: ValueTypeDouble, DoubleVal: result})

	default:
		return &InterpreterError{
			Type:    ErrorTypeMismatch,
			Message: "unary operation requires numeric operand",
		}
	}
}

// executeUnaryOpLegacy executes a unary integer operation (backwards compatibility)
func (i *Interpreter) executeUnaryOpLegacy(operation func(int64) int64) error {
	return i.executeUnaryOp(operation, func(a float64) float64 {
		return float64(operation(int64(a)))
	})
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
