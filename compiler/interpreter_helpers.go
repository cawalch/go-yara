package compiler

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
	// ErrorInvalidBytecode indicates invalid bytecode format
	ErrorInvalidBytecode
	// ErrorRuntime indicates runtime execution errors
	ErrorRuntime
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

func (i *Interpreter) executeBinaryOp(operation func(int64, int64) int64) error {
	a, b, err := i.popTwo()
	if err != nil {
		return err
	}
	if a.Type != ValueTypeInt || b.Type != ValueTypeInt {
		return i.handleNonIntegerOperands(a, b, "binary operation requires numeric operands")
	}
	return i.push(Value{Type: ValueTypeInt, IntVal: operation(a.IntVal, b.IntVal)})
}

func (i *Interpreter) executeBinaryOpWithCheck(operation func(int64, int64) (int64, error)) error {
	a, b, err := i.popTwo()
	if err != nil {
		return err
	}
	if a.Type != ValueTypeInt || b.Type != ValueTypeInt {
		return i.handleNonIntegerOperands(a, b, "integer-only operation requires integer operands")
	}
	result, err := operation(a.IntVal, b.IntVal)
	if err != nil {
		return err
	}
	return i.push(Value{Type: ValueTypeInt, IntVal: result})
}

func (i *Interpreter) handleNonIntegerOperands(a, b Value, message string) error {
	if (a.Type == ValueTypeInt || a.Type == ValueTypeDouble) &&
		(b.Type == ValueTypeInt || b.Type == ValueTypeDouble) {
		return &InterpreterError{Type: ErrorTypeMismatch, Message: message}
	}
	return i.push(Value{Type: ValueTypeUndefined})
}

// executeDoubleOp executes a binary double operation
func (i *Interpreter) executeDoubleOp(operation func(float64, float64) float64) error {
	a, b, err := i.popTwo()
	if err != nil {
		return err
	}

	// Handle undefined values - any operation with undefined results in undefined
	if a.Type == ValueTypeUndefined || b.Type == ValueTypeUndefined {
		return i.push(Value{Type: ValueTypeUndefined})
	}

	if a.Type != ValueTypeDouble || b.Type != ValueTypeDouble {
		return i.push(Value{Type: ValueTypeUndefined})
	}

	result := operation(a.DoubleVal, b.DoubleVal)
	return i.push(Value{Type: ValueTypeDouble, DoubleVal: result})
}
