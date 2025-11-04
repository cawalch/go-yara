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

// numericOperationConfig holds configuration for executing numeric operations
type numericOperationConfig struct {
	IntOp        func(int64, int64) int64
	FloatOp      func(float64, float64) float64
	FloatOp64    func(float64, float64) int64 // For comparison operations
	ResultType   ValueType
	IsComparison bool
	ErrorMsg     string
}

// executeNumericOperation executes numeric operations with automatic type promotion
func (i *Interpreter) executeNumericOperation(config numericOperationConfig) error {
	a, b, err := i.popTwo()
	if err != nil {
		return err
	}

	// Handle undefined values - any operation with undefined results in undefined
	if a.Type == ValueTypeUndefined || b.Type == ValueTypeUndefined {
		return i.push(Value{Type: ValueTypeUndefined})
	}

	// Dispatch based on operand types
	return i.executeTypedOperation(a, b, config)
}

// executeTypedOperation handles the actual operation based on operand types
func (i *Interpreter) executeTypedOperation(a, b Value, config numericOperationConfig) error {
	switch a.Type {
	case ValueTypeInt:
		return i.executeIntOperation(a, b, config)
	case ValueTypeDouble:
		return i.executeDoubleOperation(a, b, config)
	default:
		return i.push(Value{Type: ValueTypeUndefined})
	}
}

// executeIntOperation handles operations where first operand is an integer
func (i *Interpreter) executeIntOperation(a, b Value, config numericOperationConfig) error {
	switch b.Type {
	case ValueTypeInt:
		result := config.IntOp(a.IntVal, b.IntVal)
		return i.push(Value{Type: config.ResultType, IntVal: result})

	case ValueTypeDouble:
		return i.executeIntDoubleOperation(a, b, config)

	default:
		return i.push(Value{Type: ValueTypeUndefined})
	}
}

// executeDoubleOperation handles operations where first operand is a double
func (i *Interpreter) executeDoubleOperation(a, b Value, config numericOperationConfig) error {
	switch b.Type {
	case ValueTypeInt:
		return i.executeDoubleIntOperation(a, b, config)

	case ValueTypeDouble:
		var result Value
		if config.IsComparison {
			result = Value{Type: config.ResultType, IntVal: config.FloatOp64(a.DoubleVal, b.DoubleVal)}
		} else {
			result = Value{Type: config.ResultType, DoubleVal: config.FloatOp(a.DoubleVal, b.DoubleVal)}
		}
		return i.push(result)

	default:
		return i.push(Value{Type: ValueTypeUndefined})
	}
}

// executeIntDoubleOperation handles int op double operations
func (i *Interpreter) executeIntDoubleOperation(a, b Value, config numericOperationConfig) error {
	if config.IsComparison {
		result := config.FloatOp64(float64(a.IntVal), b.DoubleVal)
		return i.push(Value{Type: config.ResultType, IntVal: result})
	}
	result := config.FloatOp(float64(a.IntVal), b.DoubleVal)
	return i.push(Value{Type: config.ResultType, DoubleVal: result})
}

// executeDoubleIntOperation handles double op int operations
func (i *Interpreter) executeDoubleIntOperation(a, b Value, config numericOperationConfig) error {
	if config.IsComparison {
		result := config.FloatOp64(a.DoubleVal, float64(b.IntVal))
		return i.push(Value{Type: config.ResultType, IntVal: result})
	}
	result := config.FloatOp(a.DoubleVal, float64(b.IntVal))
	return i.push(Value{Type: config.ResultType, DoubleVal: result})
}

// executeBinaryOp executes a binary operation with automatic type promotion for mixed int/float operations
func (i *Interpreter) executeBinaryOp(intOp func(int64, int64) int64, _ func(float64, float64) float64) error {
	config := numericOperationConfig{
		IntOp:      intOp,
		FloatOp64:  nil, // Not used for integer-only operations
		ResultType: ValueTypeInt,
		ErrorMsg:   "binary operation requires numeric operands",
	}
	return i.executeNumericOperation(config)
}

// executeBinaryOpWithCheck executes a binary operation with error checking and automatic type promotion
func (i *Interpreter) executeBinaryOpWithCheck(intOp func(int64, int64) (int64, error), _ func(float64, float64) (float64, error)) error {
	a, b, err := i.popTwo()
	if err != nil {
		return err
	}

	return i.executeTypedBinaryOp(a, b, binaryOps{intOp: intOp, floatOp: nil})
}

// binaryOps represents binary operation functions for different types
type binaryOps struct {
	intOp   func(int64, int64) (int64, error)
	floatOp func(float64, float64) (float64, error)
}

// executeTypedBinaryOp executes a binary operation based on operand types
func (i *Interpreter) executeTypedBinaryOp(a, b Value, ops binaryOps) error {
	// Handle undefined values - any operation with undefined results in undefined
	if a.Type == ValueTypeUndefined || b.Type == ValueTypeUndefined {
		return i.push(Value{Type: ValueTypeUndefined})
	}

	switch a.Type {
	case ValueTypeInt:
		return i.executeIntBinaryOp(a, b, ops)

	case ValueTypeDouble:
		return i.executeDoubleBinaryOp(a, b, ops)

	default:
		return i.push(Value{Type: ValueTypeUndefined})
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
		return i.push(Value{Type: ValueTypeUndefined})
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
		return i.push(Value{Type: ValueTypeUndefined})
	}
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
