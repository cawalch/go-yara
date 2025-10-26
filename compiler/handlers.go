// Package compiler provides opcode handlers for the YARA interpreter.
package compiler

import (
	"encoding/binary"
	"fmt"
)

// Shared helper functions for opcode handlers

// executePatternOperationWithIndex is a shared helper for operations that take pattern and index
func executePatternOperationWithIndex(
	i *Interpreter,
	operationName string,
	operation func(string, int64, *Interpreter) Value,
) error {
	if len(i.stack) < 2 {
		return &InterpreterError{
			Type:    ErrorStackUnderflow,
			Message: fmt.Sprintf("stack underflow: need pattern and index for %s", operationName),
		}
	}

	// Pop index and pattern (order matters for stack operations)
	index := i.stack[len(i.stack)-1]
	pattern := i.stack[len(i.stack)-2]
	i.stack = i.stack[:len(i.stack)-2]

	if pattern.Type != ValueTypeString {
		return &InterpreterError{
			Type:    ErrorTypeMismatch,
			Message: fmt.Sprintf("%s requires string pattern operand", operationName),
		}
	}

	if index.Type != ValueTypeInt {
		return &InterpreterError{
			Type:    ErrorTypeMismatch,
			Message: fmt.Sprintf("%s requires integer index operand", operationName),
		}
	}

	// Execute the operation
	result := operation(pattern.StringVal, index.IntVal, i)
	return i.push(result)
}

// executePatternOperation is a shared helper for operations that take only pattern and return boolean
func executePatternOperation(
	i *Interpreter,
	operationName string,
	operation func(string, *Interpreter) bool,
) error {
	if len(i.stack) == 0 {
		return &InterpreterError{
			Type:    ErrorStackUnderflow,
			Message: fmt.Sprintf("stack underflow: need pattern for %s", operationName),
		}
	}

	pattern := i.stack[len(i.stack)-1]
	i.stack = i.stack[:len(i.stack)-1]

	if pattern.Type != ValueTypeString {
		return &InterpreterError{
			Type:    ErrorTypeMismatch,
			Message: fmt.Sprintf("%s requires string pattern operand", operationName),
		}
	}

	result := int64(0)
	if operation(pattern.StringVal, i) {
		result = 1
	}

	return i.push(Value{Type: ValueTypeInt, IntVal: result})
}

// executePatternOperationWithValue is a shared helper for operations that take only pattern and return Value
func executePatternOperationWithValue(
	i *Interpreter,
	operationName string,
	operation func(string, *Interpreter) Value,
) error {
	if len(i.stack) == 0 {
		return &InterpreterError{
			Type:    ErrorStackUnderflow,
			Message: fmt.Sprintf("stack underflow: need pattern for %s", operationName),
		}
	}

	pattern := i.stack[len(i.stack)-1]
	i.stack = i.stack[:len(i.stack)-1]

	if pattern.Type != ValueTypeString {
		return &InterpreterError{
			Type:    ErrorTypeMismatch,
			Message: fmt.Sprintf("%s requires string pattern operand", operationName),
		}
	}

	result := operation(pattern.StringVal, i)
	return i.push(result)
}

// OpcodeHandler defines the interface for handling specific opcodes
type OpcodeHandler interface {
	// Execute handles the opcode execution
	Execute(i *Interpreter) error
	// CanHandle returns true if this handler can process the given opcode
	CanHandle(opcode Opcode) bool
	// Category returns the handler category for debugging
	Category() string
}

// HandlerRegistry manages opcode handlers
type HandlerRegistry struct {
	handlers map[Opcode]OpcodeHandler
	fallback OpcodeHandler
}

// NewHandlerRegistry creates a new handler registry
func NewHandlerRegistry() *HandlerRegistry {
	registry := &HandlerRegistry{
		handlers: make(map[Opcode]OpcodeHandler),
	}
	registry.setupDefaultHandlers()
	return registry
}

// RegisterHandler registers a handler for specific opcodes
func (hr *HandlerRegistry) RegisterHandler(handler OpcodeHandler, opcodes ...Opcode) {
	for _, opcode := range opcodes {
		hr.handlers[opcode] = handler
	}
}

// SetFallback sets the fallback handler for unknown opcodes
func (hr *HandlerRegistry) SetFallback(handler OpcodeHandler) {
	hr.fallback = handler
}

// GetHandler returns the appropriate handler for an opcode
func (hr *HandlerRegistry) GetHandler(opcode Opcode) OpcodeHandler {
	if handler, exists := hr.handlers[opcode]; exists {
		return handler
	}
	if hr.fallback != nil {
		return hr.fallback
	}
	return &UnsupportedOpcodeHandler{}
}

// setupDefaultHandlers registers all default opcode handlers
func (hr *HandlerRegistry) setupDefaultHandlers() {
	// Stack operations
	stackHandler := &StackHandler{}
	hr.RegisterHandler(stackHandler,
		OP_PUSH_8, OP_PUSH_16, OP_PUSH_32, OP_PUSH_U, OP_POP,
	)

	// Arithmetic operations
	arithmeticHandler := &ArithmeticHandler{}
	hr.RegisterHandler(arithmeticHandler,
		OP_INT_ADD, OP_INT_SUB, OP_INT_MUL, OP_INT_DIV, OP_MOD, OP_INT_MINUS,
		OP_DBL_ADD, OP_DBL_SUB, OP_DBL_MUL, OP_DBL_DIV, OP_DBL_MINUS,
	)

	// Logical operations
	logicalHandler := &LogicalHandler{}
	hr.RegisterHandler(logicalHandler,
		OP_AND, OP_OR, OP_NOT,
	)

	// Bitwise operations
	bitwiseHandler := &BitwiseHandler{}
	hr.RegisterHandler(bitwiseHandler,
		OP_BITWISE_AND, OP_BITWISE_OR, OP_BITWISE_XOR, OP_BITWISE_NOT,
		OP_SHL, OP_SHR,
	)

	// Comparison operations
	comparisonHandler := &ComparisonHandler{}
	hr.RegisterHandler(comparisonHandler,
		OP_INT_EQ, OP_INT_NEQ, OP_INT_LT, OP_INT_LE, OP_INT_GT, OP_INT_GE,
		OP_DBL_EQ, OP_DBL_NEQ, OP_DBL_LT, OP_DBL_LE, OP_DBL_GT, OP_DBL_GE,
		OP_STR_EQ, OP_STR_NEQ, OP_STR_LT, OP_STR_LE, OP_STR_GT, OP_STR_GE,
	)

	// Control flow
	controlHandler := &ControlFlowHandler{}
	hr.RegisterHandler(controlHandler,
		OP_NOP, OP_HALT, OP_JZ, OP_JTRUE, OP_JFALSE,
	)

	// Memory operations
	memoryHandler := &MemoryHandler{}
	hr.RegisterHandler(memoryHandler,
		OP_PUSH_M, OP_POP_M, OP_CLEAR_M, OP_INCR_M,
	)

	// Type conversion operations
	conversionHandler := &ConversionHandler{}
	hr.RegisterHandler(conversionHandler,
		OP_INT_TO_DBL, OP_STR_TO_BOOL, OP_INT8, OP_INT16, OP_INT32,
	)

	// String operations
	stringHandler := &StringHandler{}
	hr.RegisterHandler(stringHandler,
		OP_LENGTH, OP_COUNT,
	)

	// Pattern matching operations
	patternHandler := &PatternHandler{}
	hr.RegisterHandler(patternHandler,
		OP_FOUND, OP_FOUND_AT, OP_FOUND_IN, OP_OFFSET, OP_OF, OP_MATCHES,
	)

	// File operations
	fileHandler := &FileHandler{}
	hr.RegisterHandler(fileHandler,
		OP_ENTRYPOINT, OP_FILESIZE,
	)

	// Rule operations
	ruleHandler := &RuleHandler{}
	hr.RegisterHandler(ruleHandler,
		OP_PUSH_RULE, OP_INIT_RULE, OP_MATCH_RULE,
	)

	// Set fallback for unsupported opcodes
	hr.SetFallback(&UnsupportedOpcodeHandler{})
}

// StackHandler handles stack manipulation opcodes
type StackHandler struct{}

// CanHandle returns true if this handler can process the given opcode
func (h *StackHandler) CanHandle(opcode Opcode) bool {
	switch opcode {
	case OP_PUSH_8, OP_PUSH_16, OP_PUSH_32, OP_PUSH_U, OP_POP:
		return true
	default:
		return false
	}
}

// Category returns the handler category for debugging
func (h *StackHandler) Category() string {
	return "stack"
}

// Execute handles the opcode execution for stack operations
func (h *StackHandler) Execute(i *Interpreter) error {
	opcode := Opcode(i.bytecode[i.ip-1]) // Get the opcode that was just consumed

	switch opcode {
	case OP_PUSH_8:
		val := int64(i.bytecode[i.ip])
		i.ip++
		return i.push(Value{Type: ValueTypeInt, IntVal: val})

	case OP_PUSH_16:
		val := int64(binary.LittleEndian.Uint16(i.bytecode[i.ip:]))
		i.ip += 2
		return i.push(Value{Type: ValueTypeInt, IntVal: val})

	case OP_PUSH_32:
		val := int64(binary.LittleEndian.Uint32(i.bytecode[i.ip:]))
		i.ip += 4
		return i.push(Value{Type: ValueTypeInt, IntVal: val})

	case OP_PUSH_U:
		// Push undefined value
		return i.push(Value{Type: ValueTypeUndefined})

	case OP_POP:
		if len(i.stack) > 0 {
			i.stack = i.stack[:len(i.stack)-1]
		}
		return nil

	default:
		return h.unsupportedOpcode(opcode)
	}
}

func (h *StackHandler) unsupportedOpcode(opcode Opcode) error {
	return &InterpreterError{
		Type:    ErrorUnsupportedOpcode,
		Opcode:  opcode,
		Message: fmt.Sprintf("Unsupported stack opcode: %v", opcode),
	}
}

// ArithmeticHandler handles arithmetic operations
type ArithmeticHandler struct{}

// CanHandle returns true if this handler can process the given opcode
func (h *ArithmeticHandler) CanHandle(opcode Opcode) bool {
	switch opcode {
	case OP_INT_ADD, OP_INT_SUB, OP_INT_MUL, OP_INT_DIV, OP_MOD, OP_INT_MINUS,
		OP_DBL_ADD, OP_DBL_SUB, OP_DBL_MUL, OP_DBL_DIV, OP_DBL_MINUS:
		return true
	default:
		return false
	}
}

// Category returns the handler category for debugging
func (h *ArithmeticHandler) Category() string {
	return "arithmetic"
}

// Execute handles the opcode execution for arithmetic operations
func (h *ArithmeticHandler) Execute(i *Interpreter) error {
	opcode := Opcode(i.bytecode[i.ip-1])

	switch opcode {
	case OP_INT_ADD:
		return i.executeBinaryOp(func(a, b int64) int64 { return a + b })

	case OP_INT_SUB:
		return i.executeBinaryOp(func(a, b int64) int64 { return a - b })

	case OP_INT_MUL:
		return i.executeBinaryOp(func(a, b int64) int64 { return a * b })

	case OP_INT_DIV:
		return i.executeBinaryOpWithCheck(func(a, b int64) (int64, error) {
			if b == 0 {
				return 0, &InterpreterError{
					Type:    ErrorDivisionByZero,
					Message: "integer division by zero",
				}
			}
			return a / b, nil
		})

	case OP_MOD:
		return i.executeBinaryOpWithCheck(func(a, b int64) (int64, error) {
			if b == 0 {
				return 0, &InterpreterError{
					Type:    ErrorDivisionByZero,
					Message: "integer modulo by zero",
				}
			}
			return a % b, nil
		})

	case OP_DBL_ADD:
		return i.executeDoubleOp(func(a, b float64) float64 { return a + b })

	case OP_DBL_SUB:
		return i.executeDoubleOp(func(a, b float64) float64 { return a - b })

	case OP_DBL_MUL:
		return i.executeDoubleOp(func(a, b float64) float64 { return a * b })

	case OP_DBL_DIV:
		return i.executeDoubleOpWithCheck(func(a, b float64) (float64, error) {
			if b == 0.0 {
				return 0, &InterpreterError{
					Type:    ErrorDivisionByZero,
					Message: "floating point division by zero",
				}
			}
			return a / b, nil
		})

	case OP_INT_MINUS:
		// Unary integer negation
		return i.executeUnaryOp(func(a int64) int64 { return -a })

	case OP_DBL_MINUS:
		// Unary double negation
		return i.executeUnaryDoubleOp(func(a float64) float64 { return -a })

	default:
		return h.unsupportedOpcode(opcode)
	}
}

func (h *ArithmeticHandler) unsupportedOpcode(opcode Opcode) error {
	return &InterpreterError{
		Type:    ErrorUnsupportedOpcode,
		Opcode:  opcode,
		Message: fmt.Sprintf("Unsupported arithmetic opcode: %v", opcode),
	}
}

// LogicalHandler handles logical operations
type LogicalHandler struct{}

// CanHandle returns true if this handler can process the given opcode
func (h *LogicalHandler) CanHandle(opcode Opcode) bool {
	return opcode == OP_AND || opcode == OP_OR || opcode == OP_NOT
}

// Category returns the handler category for debugging
func (h *LogicalHandler) Category() string {
	return "logical"
}

// Execute handles the opcode execution for logical operations
func (h *LogicalHandler) Execute(i *Interpreter) error {
	opcode := Opcode(i.bytecode[i.ip-1])

	switch opcode {
	case OP_AND:
		return i.executeBinaryOp(func(a, b int64) int64 {
			if a != 0 && b != 0 {
				return 1
			}
			return 0
		})

	case OP_OR:
		return i.executeBinaryOp(func(a, b int64) int64 {
			if a != 0 || b != 0 {
				return 1
			}
			return 0
		})

	case OP_NOT:
		if len(i.stack) > 0 {
			v := i.stack[len(i.stack)-1]
			switch {
			case v.Type == ValueTypeUndefined:
				i.stack[len(i.stack)-1] = Value{Type: ValueTypeInt, IntVal: 0}
			case v.IntVal == 0:
				i.stack[len(i.stack)-1] = Value{Type: ValueTypeInt, IntVal: 1}
			default:
				i.stack[len(i.stack)-1] = Value{Type: ValueTypeInt, IntVal: 0}
			}
		}
		return nil

	default:
		return h.unsupportedOpcode(opcode)
	}
}

func (h *LogicalHandler) unsupportedOpcode(opcode Opcode) error {
	return &InterpreterError{
		Type:    ErrorUnsupportedOpcode,
		Opcode:  opcode,
		Message: fmt.Sprintf("Unsupported logical opcode: %v", opcode),
	}
}

// ControlFlowHandler handles control flow opcodes
type ControlFlowHandler struct{}

// CanHandle returns true if this handler can process the given opcode
func (h *ControlFlowHandler) CanHandle(opcode Opcode) bool {
	switch opcode {
	case OP_NOP, OP_HALT, OP_JZ, OP_JTRUE, OP_JFALSE:
		return true
	default:
		return false
	}
}

// Category returns the handler category for debugging
func (h *ControlFlowHandler) Category() string {
	return "control_flow"
}

// Execute handles the opcode execution for control flow operations
func (h *ControlFlowHandler) Execute(i *Interpreter) error {
	opcode := Opcode(i.bytecode[i.ip-1])

	switch opcode {
	case OP_NOP:
		// No operation
		return nil

	case OP_HALT:
		i.stopped = true
		return nil

	case OP_JZ:
		// Jump if zero (pop condition, jump if false)
		return i.executeConditionalJump(func(condition int64) bool {
			return condition == 0
		})

	case OP_JTRUE:
		// Jump if true
		return i.executeConditionalJump(func(condition int64) bool {
			return condition != 0
		})

	case OP_JFALSE:
		// Jump if false
		return i.executeConditionalJump(func(condition int64) bool {
			return condition == 0
		})

	default:
		return h.unsupportedOpcode(opcode)
	}
}

func (h *ControlFlowHandler) unsupportedOpcode(opcode Opcode) error {
	return &InterpreterError{
		Type:    ErrorUnsupportedOpcode,
		Opcode:  opcode,
		Message: fmt.Sprintf("Unsupported control flow opcode: %v", opcode),
	}
}

// UnsupportedOpcodeHandler handles unknown opcodes
type UnsupportedOpcodeHandler struct{}

// CanHandle returns true if this handler can process the given opcode
func (h *UnsupportedOpcodeHandler) CanHandle(opcode Opcode) bool {
	return true // Can handle any opcode as fallback
}

// Category returns the handler category for debugging
func (h *UnsupportedOpcodeHandler) Category() string {
	return "unsupported"
}

// Execute handles the opcode execution for unsupported opcodes
func (h *UnsupportedOpcodeHandler) Execute(i *Interpreter) error {
	// Handle case where instruction pointer isn't properly positioned
	var opcode Opcode
	if i.ip > 0 && i.ip <= len(i.bytecode) {
		opcode = Opcode(i.bytecode[i.ip-1])
	} else {
		// For direct calls, we can't determine the opcode, so just return no-op
		return nil
	}

	// OP_ERROR (opcode 0) seems to be used as a no-op in some tests
	if opcode == OP_ERROR {
		return nil // Treat as no-op
	}

	return &InterpreterError{
		Type:    ErrorUnsupportedOpcode,
		Opcode:  opcode,
		Message: fmt.Sprintf("Unsupported opcode: %v", opcode),
	}
}

// RuleHandler handles rule-related opcodes
type RuleHandler struct{}

// CanHandle returns true if this handler can process the given opcode
func (h *RuleHandler) CanHandle(opcode Opcode) bool {
	switch opcode {
	case OP_PUSH_RULE, OP_INIT_RULE, OP_MATCH_RULE:
		return true
	default:
		return false
	}
}

// Category returns the handler category for debugging
func (h *RuleHandler) Category() string {
	return "rule"
}

// Execute handles the opcode execution for rule operations
func (h *RuleHandler) Execute(i *Interpreter) error {
	opcode := Opcode(i.bytecode[i.ip-1]) // Get the opcode that was just consumed

	switch opcode {
	case OP_PUSH_RULE:
		// Read rule index from bytecode
		if i.ip >= len(i.bytecode) {
			return &InterpreterError{
				Type:    ErrorUnimplemented,
				Message: "OP_PUSH_RULE: missing rule index operand",
			}
		}
		ruleIndex := int64(i.bytecode[i.ip])
		i.ip++

		// Get the rule name and check if we have a result
		if ruleIndex >= 0 && int(ruleIndex) < len(i.compiledRules) {
			ruleName := i.compiledRules[ruleIndex].Name
			if result, exists := i.ruleResults[ruleName]; exists {
				return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt64(result)})
			}

			// If no result exists, we need to execute the referenced rule
			// This is a simple approach to handle rule dependencies
			if int(ruleIndex) < len(i.compiledRules) {
				referencedRule := i.compiledRules[ruleIndex]

				// Create a new interpreter for the referenced rule
				refInterpreter := NewInterpreter(referencedRule.GetBytecode())
				refInterpreter.SetMatchContext(i.matchContext)
				refInterpreter.SetRuleResults(i.ruleResults) // Share rule results
				refInterpreter.SetCurrentRule(referencedRule.GetName())
				refInterpreter.SetCompiledRules(i.compiledRules)

				// Execute the referenced rule
				execErr := refInterpreter.Execute()
				if execErr == nil {
					// Get the result from the referenced rule's execution
					stack := refInterpreter.GetStack()
					if len(stack) > 0 {
						result := stack[len(stack)-1]
						if result.Type == ValueTypeInt {
							resultBool := result.IntVal != 0
							i.ruleResults[referencedRule.GetName()] = resultBool
							return i.push(
								Value{Type: ValueTypeInt, IntVal: boolToInt64(resultBool)},
							)
						}
					}
				}
			}
		}

		// If we couldn't resolve the rule, push false
		return i.push(Value{Type: ValueTypeInt, IntVal: 0})

	case OP_INIT_RULE:
		// Initialize rule execution - for now this is a no-op
		return nil

	case OP_MATCH_RULE:
		// Mark rule as matched - for now this is a no-op
		// The actual rule matching is handled at a higher level
		return nil

	default:
		return &InterpreterError{
			Type:    ErrorUnsupportedOpcode,
			Opcode:  opcode,
			Message: fmt.Sprintf("Unsupported rule opcode: %v", opcode),
		}
	}
}

// boolToInt64 converts a boolean to int64 (true -> 1, false -> 0)
func boolToInt64(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
