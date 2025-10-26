// Package compiler provides additional opcode handlers for the YARA interpreter.
package compiler

import (
	"fmt"
)

// BitwiseHandler handles bitwise operations
type BitwiseHandler struct{}

// CanHandle returns true if this handler can process the given opcode
func (h *BitwiseHandler) CanHandle(opcode Opcode) bool {
	switch opcode {
	case OP_BITWISE_AND, OP_BITWISE_OR, OP_BITWISE_XOR, OP_BITWISE_NOT,
		OP_SHL, OP_SHR:
		return true
	default:
		return false
	}
}

// Category returns the handler category for debugging
func (h *BitwiseHandler) Category() string {
	return "bitwise"
}

// Execute handles the opcode execution for bitwise operations
func (h *BitwiseHandler) Execute(i *Interpreter) error {
	opcode := Opcode(i.bytecode[i.ip-1])

	switch opcode {
	case OP_BITWISE_AND:
		return i.executeBinaryOp(func(a, b int64) int64 { return a & b })

	case OP_BITWISE_OR:
		return i.executeBinaryOp(func(a, b int64) int64 { return a | b })

	case OP_BITWISE_XOR:
		return i.executeBinaryOp(func(a, b int64) int64 { return a ^ b })

	case OP_BITWISE_NOT:
		if len(i.stack) > 0 {
			v := i.stack[len(i.stack)-1]
			if v.Type == ValueTypeInt {
				i.stack[len(i.stack)-1] = Value{Type: ValueTypeInt, IntVal: ^v.IntVal}
			}
		}
		return nil

	case OP_SHL:
		return i.executeBinaryOp(func(a, b int64) int64 { return a << uint64(b) })

	case OP_SHR:
		return i.executeBinaryOp(func(a, b int64) int64 { return a >> uint64(b) })

	default:
		return h.unsupportedOpcode(opcode)
	}
}

func (h *BitwiseHandler) unsupportedOpcode(opcode Opcode) error {
	return &InterpreterError{
		Type:    ErrorUnsupportedOpcode,
		Opcode:  opcode,
		Message: fmt.Sprintf("Unsupported bitwise opcode: %v", opcode),
	}
}

// ComparisonHandler handles comparison operations
type ComparisonHandler struct{}

// CanHandle returns true if this handler can process the given opcode
func (h *ComparisonHandler) CanHandle(opcode Opcode) bool {
	switch opcode {
	case OP_INT_EQ, OP_INT_NEQ, OP_INT_LT, OP_INT_LE, OP_INT_GT, OP_INT_GE,
		OP_DBL_EQ, OP_DBL_NEQ, OP_DBL_LT, OP_DBL_LE, OP_DBL_GT, OP_DBL_GE,
		OP_STR_EQ, OP_STR_NEQ, OP_STR_LT, OP_STR_LE, OP_STR_GT, OP_STR_GE:
		return true
	default:
		return false
	}
}

// Category returns the handler category for debugging
func (h *ComparisonHandler) Category() string {
	return "comparison"
}

// Execute handles the opcode execution for comparison operations
func (h *ComparisonHandler) Execute(i *Interpreter) error {
	opcode := Opcode(i.bytecode[i.ip-1])

	switch opcode {
	case OP_INT_EQ:
		return i.executeComparisonOp(func(a, b int64) int64 {
			if a == b {
				return 1
			}
			return 0
		})

	case OP_INT_NEQ:
		return i.executeComparisonOp(func(a, b int64) int64 {
			if a != b {
				return 1
			}
			return 0
		})

	case OP_INT_LT:
		return i.executeComparisonOp(func(a, b int64) int64 {
			if a < b {
				return 1
			}
			return 0
		})

	case OP_INT_LE:
		return i.executeComparisonOp(func(a, b int64) int64 {
			if a <= b {
				return 1
			}
			return 0
		})

	case OP_INT_GT:
		return i.executeComparisonOp(func(a, b int64) int64 {
			if a > b {
				return 1
			}
			return 0
		})

	case OP_INT_GE:
		return i.executeComparisonOp(func(a, b int64) int64 {
			if a >= b {
				return 1
			}
			return 0
		})

	case OP_DBL_EQ:
		return i.executeDoubleComparisonOp(func(a, b float64) int64 {
			if a == b {
				return 1
			}
			return 0
		})

	case OP_DBL_NEQ:
		return i.executeDoubleComparisonOp(func(a, b float64) int64 {
			if a != b {
				return 1
			}
			return 0
		})

	case OP_DBL_LT:
		return i.executeDoubleComparisonOp(func(a, b float64) int64 {
			if a < b {
				return 1
			}
			return 0
		})

	case OP_DBL_LE:
		return i.executeDoubleComparisonOp(func(a, b float64) int64 {
			if a <= b {
				return 1
			}
			return 0
		})

	case OP_DBL_GT:
		return i.executeDoubleComparisonOp(func(a, b float64) int64 {
			if a > b {
				return 1
			}
			return 0
		})

	case OP_DBL_GE:
		return i.executeDoubleComparisonOp(func(a, b float64) int64 {
			if a >= b {
				return 1
			}
			return 0
		})

	case OP_STR_EQ:
		return i.executeStringComparisonOp(func(a, b string) int64 {
			if a == b {
				return 1
			}
			return 0
		})

	case OP_STR_NEQ:
		return i.executeStringComparisonOp(func(a, b string) int64 {
			if a != b {
				return 1
			}
			return 0
		})

	case OP_STR_LT:
		return i.executeStringComparisonOp(func(a, b string) int64 {
			if a < b {
				return 1
			}
			return 0
		})

	case OP_STR_LE:
		return i.executeStringComparisonOp(func(a, b string) int64 {
			if a <= b {
				return 1
			}
			return 0
		})

	case OP_STR_GT:
		return i.executeStringComparisonOp(func(a, b string) int64 {
			if a > b {
				return 1
			}
			return 0
		})

	case OP_STR_GE:
		return i.executeStringComparisonOp(func(a, b string) int64 {
			if a >= b {
				return 1
			}
			return 0
		})

	default:
		return h.unsupportedOpcode(opcode)
	}
}

func (h *ComparisonHandler) unsupportedOpcode(opcode Opcode) error {
	return &InterpreterError{
		Type:    ErrorUnsupportedOpcode,
		Opcode:  opcode,
		Message: fmt.Sprintf("Unsupported comparison opcode: %v", opcode),
	}
}

// MemoryHandler handles memory operations
type MemoryHandler struct{}

// CanHandle returns true if this handler can process the given opcode
func (h *MemoryHandler) CanHandle(opcode Opcode) bool {
	return opcode == OP_PUSH_M || opcode == OP_POP_M || opcode == OP_CLEAR_M || opcode == OP_INCR_M
}

// Category returns the handler category for debugging
func (h *MemoryHandler) Category() string {
	return "memory"
}

// Execute handles the opcode execution for memory operations
func (h *MemoryHandler) Execute(i *Interpreter) error {
	opcode := Opcode(i.bytecode[i.ip-1])

	switch opcode {
	case OP_PUSH_M:
		// Push from memory slot
		if i.ip < len(i.bytecode) {
			slot := int(i.bytecode[i.ip])
			i.ip++
			if slot >= 0 && slot < len(i.memory) {
				return i.push(i.memory[slot])
			}
		}
		return nil

	case OP_POP_M:
		// Pop to memory slot
		if i.ip < len(i.bytecode) && len(i.stack) > 0 {
			slot := int(i.bytecode[i.ip])
			i.ip++
			value, err := i.pop()
			if err != nil {
				return err
			}
			if slot >= 0 && slot < len(i.memory) {
				i.memory[slot] = value
			}
		}
		return nil

	case OP_CLEAR_M:
		// Clear memory slot
		if i.ip < len(i.bytecode) {
			slot := int(i.bytecode[i.ip])
			i.ip++
			if slot >= 0 && slot < len(i.memory) {
				i.memory[slot] = Value{Type: ValueTypeUndefined}
			}
		}
		return nil

	case OP_INCR_M:
		// Increment memory slot (does not push result)
		if i.ip < len(i.bytecode) {
			slot := int(i.bytecode[i.ip])
			i.ip++
			if slot >= 0 && slot < len(i.memory) {
				val := i.memory[slot]
				if val.Type == ValueTypeInt {
					i.memory[slot] = Value{
						Type:   ValueTypeInt,
						IntVal: val.IntVal + 1,
					}
				} else {
					// Initialize undefined values to 0, then increment
					i.memory[slot] = Value{
						Type:   ValueTypeInt,
						IntVal: 1,
					}
				}
			}
		}
		return nil

	default:
		return h.unsupportedOpcode(opcode)
	}
}

func (h *MemoryHandler) unsupportedOpcode(opcode Opcode) error {
	return &InterpreterError{
		Type:    ErrorUnsupportedOpcode,
		Opcode:  opcode,
		Message: fmt.Sprintf("Unsupported memory opcode: %v", opcode),
	}
}

// ConversionHandler handles type conversion operations
type ConversionHandler struct{}

// CanHandle returns true if this handler can process the given opcode
func (h *ConversionHandler) CanHandle(opcode Opcode) bool {
	switch opcode {
	case OP_INT_TO_DBL, OP_STR_TO_BOOL,
		OP_INT8, OP_INT16, OP_INT32:
		return true
	default:
		return false
	}
}

// Category returns the handler category for debugging
func (h *ConversionHandler) Category() string {
	return "conversion"
}

// Execute handles the opcode execution for type conversion operations
func (h *ConversionHandler) Execute(i *Interpreter) error {
	opcode := Opcode(i.bytecode[i.ip-1])

	switch opcode {
	case OP_INT_TO_DBL:
		if len(i.stack) > 0 {
			v := i.stack[len(i.stack)-1]
			if v.Type == ValueTypeInt {
				i.stack[len(i.stack)-1] = Value{
					Type:      ValueTypeDouble,
					DoubleVal: float64(v.IntVal),
				}
			}
		}
		return nil

	case OP_STR_TO_BOOL:
		if len(i.stack) > 0 {
			v := i.stack[len(i.stack)-1]
			if v.Type == ValueTypeString {
				result := int64(0)
				if v.StringVal != "" {
					result = 1
				}
				i.stack[len(i.stack)-1] = Value{
					Type:   ValueTypeInt,
					IntVal: result,
				}
			}
		}
		return nil

	case OP_INT8:
		if len(i.stack) > 0 {
			v := i.stack[len(i.stack)-1]
			if v.Type == ValueTypeInt {
				// Convert to 8-bit signed integer
				val := int8(v.IntVal)
				i.stack[len(i.stack)-1] = Value{
					Type:   ValueTypeInt,
					IntVal: int64(val),
				}
			}
		}
		return nil

	case OP_INT16:
		if len(i.stack) > 0 {
			v := i.stack[len(i.stack)-1]
			if v.Type == ValueTypeInt {
				// Convert to 16-bit signed integer
				val := int16(v.IntVal)
				i.stack[len(i.stack)-1] = Value{
					Type:   ValueTypeInt,
					IntVal: int64(val),
				}
			}
		}
		return nil

	case OP_INT32:
		if len(i.stack) > 0 {
			v := i.stack[len(i.stack)-1]
			if v.Type == ValueTypeInt {
				// Convert to 32-bit signed integer
				val := int32(v.IntVal)
				i.stack[len(i.stack)-1] = Value{
					Type:   ValueTypeInt,
					IntVal: int64(val),
				}
			}
		}
		return nil

	default:
		return h.unsupportedOpcode(opcode)
	}
}

func (h *ConversionHandler) unsupportedOpcode(opcode Opcode) error {
	return &InterpreterError{
		Type:    ErrorUnsupportedOpcode,
		Opcode:  opcode,
		Message: fmt.Sprintf("Unsupported conversion opcode: %v", opcode),
	}
}

// StringHandler handles string operations
type StringHandler struct{}

// CanHandle returns true if this handler can process the given opcode
func (h *StringHandler) CanHandle(opcode Opcode) bool {
	return opcode == OP_LENGTH || opcode == OP_COUNT
}

// Category returns the handler category for debugging
func (h *StringHandler) Category() string {
	return "string"
}

// executeWithOpcode executes the string operation with the given opcode
// This method is used when executeOpcode is called directly (e.g., in tests)
func (h *StringHandler) executeWithOpcode(i *Interpreter, opcode Opcode) error {
	switch opcode {
	case OP_LENGTH:
		// OP_LENGTH in YARA gets the length of a pattern match at a specific index
		// Stack layout: [pattern_string, index] -> [length]
		return h.executeLengthOperation(i)

	case OP_COUNT:
		// OP_COUNT gets the number of matches for a pattern
		// Stack layout: [pattern_string] -> [count]
		return h.executeCountOperation(i)

	default:
		return h.unsupportedOpcode(opcode)
	}
}

// Execute handles the opcode execution for string operations
func (h *StringHandler) Execute(i *Interpreter) error {
	// Normal execution flow - read opcode from bytecode
	opcode := Opcode(i.bytecode[i.ip-1])
	return h.executeWithOpcode(i, opcode)
}

// executeLengthOperation gets the length of a pattern match at a specific index
// Stack layout: [pattern_string, index] -> [length]
func (h *StringHandler) executeLengthOperation(i *Interpreter) error {
	return h.executePatternOperationWithIndex(i, "length operation", h.getMatchLength)
}

// getMatchLength gets the length of a pattern match at a specific index
func (h *StringHandler) getMatchLength(pattern string, index int64, i *Interpreter) Value {
	if i.matchContext == nil {
		return Value{Type: ValueTypeUndefined}
	}

	matches, exists := i.matchContext.Matches[pattern]
	if !exists || int(index) > len(matches) || index <= 0 {
		return Value{Type: ValueTypeUndefined}
	}

	// Convert 1-based index to 0-based array access
	match := matches[index-1]
	return Value{Type: ValueTypeInt, IntVal: int64(match.Length)}
}

// executeCountOperation gets the number of matches for a pattern
// Stack layout: [pattern_string] -> [count]
func (h *StringHandler) executeCountOperation(i *Interpreter) error {
	return h.executePatternOperation(i, "count operation", func(pattern string, i *Interpreter) Value {
		count := h.countMatches(pattern, i)
		return Value{Type: ValueTypeInt, IntVal: int64(count)}
	})
}

// countMatches counts the number of matches for a pattern
func (h *StringHandler) countMatches(pattern string, i *Interpreter) int {
	if i.matchContext == nil {
		return 0
	}

	matches, exists := i.matchContext.Matches[pattern]
	if !exists {
		return 0
	}

	return len(matches)
}

// executePatternOperationWithIndex uses the shared helper for operations that take pattern and index
func (h *StringHandler) executePatternOperationWithIndex(i *Interpreter, operationName string, operation func(string, int64, *Interpreter) Value) error {
	return executePatternOperationWithIndex(i, operationName, operation)
}

// executePatternOperation uses the shared helper for operations that take only pattern and return Value
func (h *StringHandler) executePatternOperation(i *Interpreter, operationName string, operation func(string, *Interpreter) Value) error {
	return executePatternOperationWithValue(i, operationName, operation)
}

func (h *StringHandler) unsupportedOpcode(opcode Opcode) error {
	return &InterpreterError{
		Type:    ErrorUnsupportedOpcode,
		Opcode:  opcode,
		Message: fmt.Sprintf("Unsupported string opcode: %v", opcode),
	}
}

// PatternHandler handles pattern matching operations
type PatternHandler struct{}

// CanHandle returns true if this handler can process the given opcode
func (h *PatternHandler) CanHandle(opcode Opcode) bool {
	return opcode == OP_FOUND || opcode == OP_FOUND_AT || opcode == OP_FOUND_IN || opcode == OP_OFFSET || opcode == OP_OF || opcode == OP_MATCHES
}

// Category returns the handler category for debugging
func (h *PatternHandler) Category() string {
	return "pattern"
}

// executeWithOpcode executes the pattern operation with the given opcode
// This method is used when executeOpcode is called directly (e.g., in tests)
func (h *PatternHandler) executeWithOpcode(i *Interpreter, opcode Opcode) error {
	switch opcode {
	case OP_OFFSET:
		// OP_OFFSET: Get offset of pattern match at given index
		// Stack layout before: [pattern_string, index]
		// Stack layout after:  [offset]
		return h.executeOffsetOperation(i)

	case OP_FOUND:
		// OP_FOUND: Check if pattern exists (returns 0 or 1)
		return h.executeFoundOperation(i)

	case OP_FOUND_AT:
		// OP_FOUND_AT: Check if pattern exists at specific offset
		return h.executeFoundAtOperation(i)

	case OP_FOUND_IN:
		// OP_FOUND_IN: Check if pattern exists in range
		return h.executeFoundInOperation(i)

	case OP_OF:
		// OP_OF: Count matches (pattern quantifier)
		return h.executeOfOperation(i)

	case OP_MATCHES:
		// OP_MATCHES: Check if pattern matches (alias for OP_FOUND)
		return h.executeFoundOperation(i)

	default:
		return h.unsupportedOpcode(opcode)
	}
}

// Execute handles the opcode execution for pattern matching operations
func (h *PatternHandler) Execute(i *Interpreter) error {
	// Normal execution flow - read opcode from bytecode
	opcode := Opcode(i.bytecode[i.ip-1])
	return h.executeWithOpcode(i, opcode)
}

// FileHandler handles file operations
type FileHandler struct{}

// CanHandle returns true if this handler can process the given opcode
func (h *FileHandler) CanHandle(opcode Opcode) bool {
	return opcode == OP_ENTRYPOINT || opcode == OP_FILESIZE
}

// Category returns the handler category for debugging
func (h *FileHandler) Category() string {
	return "file"
}

// Execute handles the opcode execution for file operations
func (h *FileHandler) Execute(i *Interpreter) error {
	opcode := Opcode(i.bytecode[i.ip-1])

	switch opcode {
	case OP_ENTRYPOINT:
		if i.matchContext != nil {
			return i.push(Value{
				Type:   ValueTypeInt,
				IntVal: i.matchContext.EntryPoint,
			})
		} else {
			return i.push(Value{Type: ValueTypeInt, IntVal: 0})
		}

	case OP_FILESIZE:
		if i.matchContext != nil {
			return i.push(Value{
				Type:   ValueTypeInt,
				IntVal: i.matchContext.FileSize,
			})
		} else {
			return i.push(Value{Type: ValueTypeInt, IntVal: 0})
		}

	default:
		return h.unsupportedOpcode(opcode)
	}
}

func (h *FileHandler) unsupportedOpcode(opcode Opcode) error {
	return &InterpreterError{
		Type:    ErrorUnsupportedOpcode,
		Opcode:  opcode,
		Message: fmt.Sprintf("Unsupported file opcode: %v", opcode),
	}
}

// executeOffsetOperation gets the offset of a pattern match at a specific index
// Stack layout: [pattern_string, index] -> [offset]
func (h *PatternHandler) executeOffsetOperation(i *Interpreter) error {
	return h.executePatternOperationWithIndex(i, "offset operation", h.getMatchOffset)
}

// executeFoundOperation checks if a pattern has any matches
// Stack layout: [pattern_string] -> [0 or 1]
func (h *PatternHandler) executeFoundOperation(i *Interpreter) error {
	if len(i.stack) == 0 {
		return &InterpreterError{
			Type:    ErrorStackUnderflow,
			Message: "stack underflow: need pattern for found operation",
		}
	}

	pattern := i.stack[len(i.stack)-1]
	i.stack = i.stack[:len(i.stack)-1]

	if pattern.Type != ValueTypeString {
		return &InterpreterError{
			Type:    ErrorTypeMismatch,
			Message: "found operation requires string pattern operand",
		}
	}

	// Check if pattern has any matches
	hasMatches := h.hasMatches(pattern.StringVal, i)
	result := int64(0)
	if hasMatches {
		result = 1
	}

	return i.push(Value{Type: ValueTypeInt, IntVal: result})
}

// executeFoundAtOperation checks if a pattern exists at a specific offset
// Stack layout: [pattern_string, offset] -> [0 or 1]
func (h *PatternHandler) executeFoundAtOperation(i *Interpreter) error {
	if len(i.stack) < 2 {
		return &InterpreterError{
			Type:    ErrorStackUnderflow,
			Message: "stack underflow: need pattern and offset for found-at operation",
		}
	}

	offset := i.stack[len(i.stack)-1]
	pattern := i.stack[len(i.stack)-2]
	i.stack = i.stack[:len(i.stack)-2]

	if pattern.Type != ValueTypeString {
		return &InterpreterError{
			Type:    ErrorTypeMismatch,
			Message: "found-at operation requires string pattern operand",
		}
	}

	if offset.Type != ValueTypeInt {
		return &InterpreterError{
			Type:    ErrorTypeMismatch,
			Message: "found-at operation requires integer offset operand",
		}
	}

	// Check if pattern has match at specific offset
	hasMatchAt := h.hasMatchAt(pattern.StringVal, offset.IntVal, i)
	result := int64(0)
	if hasMatchAt {
		result = 1
	}

	return i.push(Value{Type: ValueTypeInt, IntVal: result})
}

// executeFoundInOperation checks if pattern exists in a range
// Stack layout: [pattern_string, start_offset, end_offset] -> [0 or 1]
func (h *PatternHandler) executeFoundInOperation(i *Interpreter) error {
	if len(i.stack) < 3 {
		return &InterpreterError{
			Type:    ErrorStackUnderflow,
			Message: "stack underflow: need pattern, start, and end for found-in operation",
		}
	}

	endOffset := i.stack[len(i.stack)-1]
	startOffset := i.stack[len(i.stack)-2]
	pattern := i.stack[len(i.stack)-3]
	i.stack = i.stack[:len(i.stack)-3]

	if pattern.Type != ValueTypeString {
		return &InterpreterError{
			Type:    ErrorTypeMismatch,
			Message: "found-in operation requires string pattern operand",
		}
	}

	// Check if pattern has match in range
	hasMatchInRange := h.hasMatchInRange(pattern.StringVal, startOffset.IntVal, endOffset.IntVal, i)
	result := int64(0)
	if hasMatchInRange {
		result = 1
	}

	return i.push(Value{Type: ValueTypeInt, IntVal: result})
}

// executeOfOperation counts matches with error handling
// Stack layout: [pattern_string] -> [count]
func (h *PatternHandler) executeOfOperation(i *Interpreter) error {
	return h.executePatternOperation(i, "of operation", func(pattern string, i *Interpreter) bool {
		count := h.countMatches(pattern, i)
		return count > 0
	})
}

// Helper methods using functional patterns with interpreter context
func (h *PatternHandler) getMatchOffset(pattern string, index int64, i *Interpreter) Value {
	if i.matchContext == nil {
		return Value{Type: ValueTypeUndefined}
	}

	matches, exists := i.matchContext.Matches[pattern]
	if !exists || int(index) > len(matches) || index <= 0 {
		return Value{Type: ValueTypeUndefined}
	}

	// Convert 1-based index to 0-based array access
	match := matches[index-1]
	return Value{Type: ValueTypeInt, IntVal: match.Offset}
}

func (h *PatternHandler) hasMatches(pattern string, i *Interpreter) bool {
	if i.matchContext == nil {
		return false
	}

	matches, exists := i.matchContext.Matches[pattern]
	return exists && len(matches) > 0
}

func (h *PatternHandler) hasMatchAt(pattern string, offset int64, i *Interpreter) bool {
	if i.matchContext == nil {
		return false
	}

	matches, exists := i.matchContext.Matches[pattern]
	if !exists {
		return false
	}

	for _, match := range matches {
		if match.Offset == offset {
			return true
		}
	}
	return false
}

func (h *PatternHandler) hasMatchInRange(pattern string, startOffset, endOffset int64, i *Interpreter) bool {
	if i.matchContext == nil {
		return false
	}

	matches, exists := i.matchContext.Matches[pattern]
	if !exists {
		return false
	}

	for _, match := range matches {
		if match.Offset >= startOffset && match.Offset < endOffset {
			return true
		}
	}
	return false
}

func (h *PatternHandler) countMatches(pattern string, i *Interpreter) int {
	if i.matchContext == nil {
		return 0
	}

	matches, exists := i.matchContext.Matches[pattern]
	if !exists {
		return 0
	}

	return len(matches)
}

// executePatternOperationWithIndex uses the shared helper for operations that take pattern and index
func (h *PatternHandler) executePatternOperationWithIndex(i *Interpreter, operationName string, operation func(string, int64, *Interpreter) Value) error {
	return executePatternOperationWithIndex(i, operationName, operation)
}

// executePatternOperation uses the shared helper for operations that take only pattern
func (h *PatternHandler) executePatternOperation(i *Interpreter, operationName string, operation func(string, *Interpreter) bool) error {
	return executePatternOperation(i, operationName, operation)
}

func (h *PatternHandler) unsupportedOpcode(opcode Opcode) error {
	return &InterpreterError{
		Type:    ErrorUnsupportedOpcode,
		Opcode:  opcode,
		Message: fmt.Sprintf("Unsupported pattern opcode: %v", opcode),
	}
}
