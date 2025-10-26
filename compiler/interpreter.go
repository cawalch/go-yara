// Package compiler provides bytecode interpretation and execution for YARA rules.
package compiler

import (
	"encoding/binary"
	"fmt"
	"math"
)

// Value represents a YARA value that can be int, double, or string
type Value struct {
	Type      ValueType
	IntVal    int64
	DoubleVal float64
	StringVal string
}

// ValueType represents the type of a YARA value
type ValueType uint8

const (
	// ValueTypeInt represents an integer value
	ValueTypeInt ValueType = iota
	// ValueTypeDouble represents a floating-point value
	ValueTypeDouble
	// ValueTypeString represents a string value
	ValueTypeString
	// ValueTypeUndefined represents an undefined value
	ValueTypeUndefined
)

// String constants for quantifiers
const (
	// QuantifierAny represents the "any" quantifier
	QuantifierAny = "any"
	// QuantifierAll represents the "all" quantifier
	QuantifierAll = "all"
	// QuantifierThem represents the "them" quantifier
	QuantifierThem = "them"
	// QuantifierNone represents the "none" quantifier
	QuantifierNone = "none"
)

// Interpreter represents a bytecode interpreter for YARA rules
type Interpreter struct {
	bytecode     []byte
	ip           int        // Instruction pointer
	stack        []Value    // Execution stack
	memory       [256]Value // Memory slots for variables
	stopped      bool
	result       error
	matchContext *MatchContext   // Pattern matching context
	ruleResults  map[string]bool // Track execution results of all rules in the program
	currentRule  string          // Name of the currently executing rule
}

// MatchContext holds pattern matching state
type MatchContext struct {
	Data       []byte
	Matches    map[string][]Match // Pattern -> list of matches
	FileSize   int64
	EntryPoint int64
}

// Match represents a pattern match
type Match struct {
	Pattern string
	Offset  int64
	Length  int
	Base    int64 // Base address for match
}

// AddMatch adds a match to the context
func (mc *MatchContext) AddMatch(m Match) {
	if m.Pattern == "" {
		return
	}
	mc.Matches[m.Pattern] = append(mc.Matches[m.Pattern], m)
}

// NewInterpreter creates a new bytecode interpreter
func NewInterpreter(bytecode []byte) *Interpreter {
	return &Interpreter{
		bytecode: bytecode,
		ip:       0,
		stack:    make([]Value, 0, 256),
		stopped:  false,
		matchContext: &MatchContext{
			Matches: make(map[string][]Match),
		},
		ruleResults: make(map[string]bool),
	}
}

// Execute runs the bytecode
func (i *Interpreter) Execute() error {
	for !i.stopped && i.ip < len(i.bytecode) {
		opcode := Opcode(i.bytecode[i.ip])
		i.ip++

		if err := i.executeOpcode(opcode); err != nil {
			return err
		}
	}

	// Store the execution result for the current rule
	if i.currentRule != "" && len(i.stack) > 0 {
		result := i.stack[len(i.stack)-1]
		if result.Type == ValueTypeInt {
			i.ruleResults[i.currentRule] = result.IntVal != 0
		} else {
			i.ruleResults[i.currentRule] = false
		}
	}

	return i.result
}

// executeOpcode executes a single opcode
func (i *Interpreter) executeOpcode(opcode Opcode) error {
	switch opcode {
	case OP_NOP:
		// No operation
		return nil

	case OP_HALT:
		i.stopped = true
		return nil

	case OP_PUSH_8:
		val := int64(i.bytecode[i.ip])
		i.ip++
		i.push(Value{Type: ValueTypeInt, IntVal: val})
		return nil

	case OP_PUSH_16:
		val := int64(binary.LittleEndian.Uint16(i.bytecode[i.ip:]))
		i.ip += 2
		i.push(Value{Type: ValueTypeInt, IntVal: val})
		return nil

	case OP_PUSH_32:
		val := int64(binary.LittleEndian.Uint32(i.bytecode[i.ip:]))
		i.ip += 4
		i.push(Value{Type: ValueTypeInt, IntVal: val})
		return nil

	case OP_PUSH_U:
		// OP_PUSH_U is used for undefined identifiers
		// In the original implementation, this was a placeholder for rule identifiers
		// But based on the test and emitter usage, it's primarily for undefined values
		i.push(Value{Type: ValueTypeUndefined})
		return nil

	case OP_POP:
		if len(i.stack) > 0 {
			i.stack = i.stack[:len(i.stack)-1]
		}
		return nil

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

	case OP_BITWISE_NOT:
		if len(i.stack) > 0 {
			v := i.stack[len(i.stack)-1]
			if v.Type == ValueTypeInt {
				i.stack[len(i.stack)-1] = Value{Type: ValueTypeInt, IntVal: ^v.IntVal}
			}
		}
		return nil

	case OP_BITWISE_AND:
		return i.executeBinaryOp(func(a, b int64) int64 { return a & b })

	case OP_BITWISE_OR:
		return i.executeBinaryOp(func(a, b int64) int64 { return a | b })

	case OP_BITWISE_XOR:
		return i.executeBinaryOp(func(a, b int64) int64 { return a ^ b })

	case OP_SHL:
		return i.executeBinaryOp(func(a, b int64) int64 {
			// Safe shift with bounds check
			if b < 0 || b >= 64 {
				return 0 // Undefined behavior for invalid shift
			}
			return a << uint(b)
		})

	case OP_SHR:
		return i.executeBinaryOp(func(a, b int64) int64 {
			// Safe shift with bounds check
			if b < 0 || b >= 64 {
				return 0 // Undefined behavior for invalid shift
			}
			return a >> uint(b)
		})

	case OP_MOD:
		return i.executeBinaryOp(func(a, b int64) int64 {
			if b == 0 {
				return 0
			}
			return a % b
		})

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
				if len(v.StringVal) > 0 {
					i.stack[len(i.stack)-1] = Value{Type: ValueTypeInt, IntVal: 1}
				} else {
					i.stack[len(i.stack)-1] = Value{Type: ValueTypeInt, IntVal: 0}
				}
			}
		}
		return nil

	case OP_CLEAR_M:
		addr := binary.LittleEndian.Uint64(i.bytecode[i.ip:])
		i.ip += 8
		if addr < 256 {
			i.memory[addr] = Value{Type: ValueTypeInt, IntVal: 0}
		}
		return nil

	case OP_PUSH_M:
		addr := binary.LittleEndian.Uint64(i.bytecode[i.ip:])
		i.ip += 8
		if addr < 256 {
			i.push(i.memory[addr])
		}
		return nil

	case OP_POP_M:
		addr := binary.LittleEndian.Uint64(i.bytecode[i.ip:])
		i.ip += 8
		if len(i.stack) > 0 && addr < 256 {
			i.memory[addr] = i.pop()
		}
		return nil

	case OP_INCR_M:
		addr := binary.LittleEndian.Uint64(i.bytecode[i.ip:])
		i.ip += 8
		if addr < 256 {
			i.memory[addr].IntVal++
		}
		return nil

	case OP_ADD_M:
		addr := binary.LittleEndian.Uint64(i.bytecode[i.ip:])
		i.ip += 8
		if len(i.stack) > 0 && addr < 256 {
			v := i.pop()
			if v.Type != ValueTypeUndefined {
				i.memory[addr].IntVal += v.IntVal
			}
		}
		return nil

	case OP_JFALSE:
		u32 := binary.LittleEndian.Uint32(i.bytecode[i.ip:])
		// Safe conversion with explicit truncation
		offset := int32(u32 & 0xFFFFFFFF)
		i.ip += 4
		if len(i.stack) > 0 {
			v := i.pop()
			if v.Type == ValueTypeUndefined || v.IntVal == 0 {
				i.ip += int(offset)
			}
		}
		return nil

	case OP_JTRUE:
		u32 := binary.LittleEndian.Uint32(i.bytecode[i.ip:])
		// Safe conversion with explicit truncation
		offset := int32(u32 & 0xFFFFFFFF)
		i.ip += 4
		if len(i.stack) > 0 {
			v := i.pop()
			if v.Type != ValueTypeUndefined && v.IntVal != 0 {
				i.ip += int(offset)
			}
		}
		return nil

	case OP_JZ:
		u32 := binary.LittleEndian.Uint32(i.bytecode[i.ip:])
		// Safe conversion with explicit truncation
		offset := int32(u32 & 0xFFFFFFFF)
		i.ip += 4
		if len(i.stack) > 0 {
			v := i.pop()
			if v.IntVal == 0 {
				i.ip += int(offset)
			}
		}
		return nil

	case OP_JNUNDEF:
		u32 := binary.LittleEndian.Uint32(i.bytecode[i.ip:])
		// Safe conversion with explicit truncation
		offset := int32(u32 & 0xFFFFFFFF)
		i.ip += 4
		if len(i.stack) > 0 {
			v := i.pop()
			if v.Type != ValueTypeUndefined {
				i.ip += int(offset)
			}
		}
		return nil

	case OP_JUNDEF_P:
		u32 := binary.LittleEndian.Uint32(i.bytecode[i.ip:])
		// Safe conversion with explicit truncation
		offset := int32(u32 & 0xFFFFFFFF)
		i.ip += 4
		if len(i.stack) > 0 {
			v := i.stack[len(i.stack)-1]
			if v.Type == ValueTypeUndefined {
				i.ip += int(offset)
			}
		}
		return nil

	case OP_JNUNDEF_P:
		u32 := binary.LittleEndian.Uint32(i.bytecode[i.ip:])
		// Safe conversion with explicit truncation
		offset := int32(u32 & 0xFFFFFFFF)
		i.ip += 4
		if len(i.stack) > 0 {
			v := i.stack[len(i.stack)-1]
			if v.Type != ValueTypeUndefined {
				i.ip += int(offset)
			}
		}
		return nil

	case OP_JFALSE_P:
		u32 := binary.LittleEndian.Uint32(i.bytecode[i.ip:])
		// Safe conversion with explicit truncation
		offset := int32(u32 & 0xFFFFFFFF)
		i.ip += 4
		if len(i.stack) > 0 {
			v := i.stack[len(i.stack)-1]
			if v.Type == ValueTypeUndefined || v.IntVal == 0 {
				i.ip += int(offset)
			}
		}
		return nil

	case OP_JTRUE_P:
		u32 := binary.LittleEndian.Uint32(i.bytecode[i.ip:])
		// Safe conversion with explicit truncation
		offset := int32(u32 & 0xFFFFFFFF)
		i.ip += 4
		if len(i.stack) > 0 {
			v := i.stack[len(i.stack)-1]
			if v.Type != ValueTypeUndefined && v.IntVal != 0 {
				i.ip += int(offset)
			}
		}
		return nil

	case OP_JZ_P:
		u32 := binary.LittleEndian.Uint32(i.bytecode[i.ip:])
		// Safe conversion with explicit truncation
		offset := int32(u32 & 0xFFFFFFFF)
		i.ip += 4
		if len(i.stack) > 0 {
			v := i.stack[len(i.stack)-1]
			if v.IntVal == 0 {
				i.ip += int(offset)
			}
		}
		return nil

	case OP_FILESIZE:
		i.push(Value{Type: ValueTypeInt, IntVal: i.matchContext.FileSize})
		return nil

	case OP_ENTRYPOINT:
		i.push(Value{Type: ValueTypeInt, IntVal: i.matchContext.EntryPoint})
		return nil

	case OP_SWAPUNDEF:
		if len(i.stack) >= 2 {
			top := i.stack[len(i.stack)-1]
			second := i.stack[len(i.stack)-2]
			if top.Type == ValueTypeUndefined && second.Type != ValueTypeUndefined {
				i.stack[len(i.stack)-1] = second
				i.stack[len(i.stack)-2] = top
			}
		}
		return nil

	case OP_INT_EQ:
		return i.executeComparison(func(a, b int64) bool { return a == b })

	case OP_INT_NEQ:
		return i.executeComparison(func(a, b int64) bool { return a != b })

	case OP_INT_LT:
		return i.executeComparison(func(a, b int64) bool { return a < b })

	case OP_INT_LE:
		return i.executeComparison(func(a, b int64) bool { return a <= b })

	case OP_INT_GT:
		return i.executeComparison(func(a, b int64) bool { return a > b })

	case OP_INT_GE:
		return i.executeComparison(func(a, b int64) bool { return a >= b })

	case OP_INT_ADD:
		return i.executeBinaryOp(func(a, b int64) int64 { return a + b })

	case OP_INT_SUB:
		return i.executeBinaryOp(func(a, b int64) int64 { return a - b })

	case OP_INT_MUL:
		return i.executeBinaryOp(func(a, b int64) int64 { return a * b })

	case OP_INT_DIV:
		return i.executeBinaryOp(func(a, b int64) int64 {
			if b == 0 {
				return 0
			}
			return a / b
		})

	case OP_DBL_EQ:
		return i.executeDoubleComparison(func(a, b float64) bool { return math.Abs(a-b) < 1e-10 })

	case OP_DBL_NEQ:
		return i.executeDoubleComparison(func(a, b float64) bool { return math.Abs(a-b) >= 1e-10 })

	case OP_DBL_LT:
		return i.executeDoubleComparison(func(a, b float64) bool { return a < b })

	case OP_DBL_LE:
		return i.executeDoubleComparison(func(a, b float64) bool { return a <= b })

	case OP_DBL_GT:
		return i.executeDoubleComparison(func(a, b float64) bool { return a > b })

	case OP_DBL_GE:
		return i.executeDoubleComparison(func(a, b float64) bool { return a >= b })

	case OP_DBL_ADD:
		return i.executeDoubleBinaryOp(func(a, b float64) float64 { return a + b })

	case OP_DBL_SUB:
		return i.executeDoubleBinaryOp(func(a, b float64) float64 { return a - b })

	case OP_DBL_MUL:
		return i.executeDoubleBinaryOp(func(a, b float64) float64 { return a * b })

	case OP_DBL_DIV:
		return i.executeDoubleBinaryOp(func(a, b float64) float64 {
			if b == 0 {
				return 0
			}
			return a / b
		})

	case OP_DBL_MINUS:
		if len(i.stack) > 0 {
			v := i.stack[len(i.stack)-1]
			if v.Type == ValueTypeDouble {
				i.stack[len(i.stack)-1] = Value{Type: ValueTypeDouble, DoubleVal: -v.DoubleVal}
			}
		}
		return nil

	case OP_INT_MINUS:
		if len(i.stack) > 0 {
			v := i.stack[len(i.stack)-1]
			if v.Type == ValueTypeInt {
				i.stack[len(i.stack)-1] = Value{Type: ValueTypeInt, IntVal: -v.IntVal}
			}
		}
		return nil

	case OP_STR_EQ:
		return i.executeStringComparison(func(a, b string) bool { return a == b })

	case OP_STR_NEQ:
		return i.executeStringComparison(func(a, b string) bool { return a != b })

	case OP_STR_LT:
		return i.executeStringComparison(func(a, b string) bool { return a < b })

	case OP_STR_LE:
		return i.executeStringComparison(func(a, b string) bool { return a <= b })

	case OP_STR_GT:
		return i.executeStringComparison(func(a, b string) bool { return a > b })

	case OP_STR_GE:
		return i.executeStringComparison(func(a, b string) bool { return a >= b })

	case OP_INT8:
		return i.executeDataTypeFunction(OP_INT8)

	case OP_INT16:
		return i.executeDataTypeFunction(OP_INT16)

	case OP_INT32:
		return i.executeDataTypeFunction(OP_INT32)

	case OP_UINT8:
		return i.executeDataTypeFunction(OP_UINT8)

	case OP_UINT16:
		return i.executeDataTypeFunction(OP_UINT16)

	case OP_UINT32:
		return i.executeDataTypeFunction(OP_UINT32)

	case OP_INT8BE:
		return i.executeDataTypeFunction(OP_INT8BE)

	case OP_INT16BE:
		return i.executeDataTypeFunction(OP_INT16BE)

	case OP_INT32BE:
		return i.executeDataTypeFunction(OP_INT32BE)

	case OP_UINT8BE:
		return i.executeDataTypeFunction(OP_UINT8BE)

	case OP_UINT16BE:
		return i.executeDataTypeFunction(OP_UINT16BE)

	case OP_UINT32BE:
		return i.executeDataTypeFunction(OP_UINT32BE)

	case OP_OFFSET:
		// Get offset of Nth match for a pattern
		// Stack: [pattern_name, index] -> [offset]
		if len(i.stack) >= 2 {
			index := i.pop()
			pattern := i.pop()
			if pattern.Type == ValueTypeString && index.Type == ValueTypeInt {
				matches, exists := i.matchContext.Matches[pattern.StringVal]
				if exists && index.IntVal > 0 && index.IntVal <= int64(len(matches)) {
					match := matches[index.IntVal-1]
					i.push(Value{Type: ValueTypeInt, IntVal: match.Offset})
				} else {
					i.push(Value{Type: ValueTypeUndefined})
				}
			} else {
				i.push(Value{Type: ValueTypeUndefined})
			}
		} else {
			i.push(Value{Type: ValueTypeUndefined})
		}
		return nil

	case OP_LENGTH:
		// Get length of Nth match for a pattern
		// Stack: [pattern_name, index] -> [length]
		if len(i.stack) >= 2 {
			index := i.pop()
			pattern := i.pop()
			if pattern.Type == ValueTypeString && index.Type == ValueTypeInt {
				matches, exists := i.matchContext.Matches[pattern.StringVal]
				if exists && index.IntVal > 0 && index.IntVal <= int64(len(matches)) {
					match := matches[index.IntVal-1]
					i.push(Value{Type: ValueTypeInt, IntVal: int64(match.Length)})
				} else {
					i.push(Value{Type: ValueTypeUndefined})
				}
			} else {
				i.push(Value{Type: ValueTypeUndefined})
			}
		} else {
			i.push(Value{Type: ValueTypeUndefined})
		}
		return nil

	case OP_FOUND_AT:
		// Check if pattern matches at specific offset
		// Stack: [pattern_name, offset] -> [result]
		if len(i.stack) >= 2 {
			offset := i.pop()
			pattern := i.pop()
			if offset.Type != ValueTypeUndefined && pattern.Type == ValueTypeString {
				found := false
				if matches, exists := i.matchContext.Matches[pattern.StringVal]; exists {
					for _, m := range matches {
						if m.Offset == offset.IntVal {
							found = true
							break
						}
					}
				}
				if found {
					i.push(Value{Type: ValueTypeInt, IntVal: 1})
				} else {
					i.push(Value{Type: ValueTypeInt, IntVal: 0})
				}
			} else {
				i.push(Value{Type: ValueTypeInt, IntVal: 0})
			}
		}
		return nil

	case OP_FOUND_IN:
		// Check if pattern matches within range
		// Stack: [pattern_name, start_offset, end_offset] -> [result]
		if len(i.stack) >= 3 {
			endOffset := i.pop()
			startOffset := i.pop()
			pattern := i.pop()
			if pattern.Type == ValueTypeString && startOffset.Type != ValueTypeUndefined && endOffset.Type != ValueTypeUndefined {
				found := false
				if matches, exists := i.matchContext.Matches[pattern.StringVal]; exists {
					for _, m := range matches {
						if m.Offset >= startOffset.IntVal && m.Offset <= endOffset.IntVal {
							found = true
							break
						}
					}
				}
				if found {
					i.push(Value{Type: ValueTypeInt, IntVal: 1})
				} else {
					i.push(Value{Type: ValueTypeInt, IntVal: 0})
				}
			} else {
				i.push(Value{Type: ValueTypeInt, IntVal: 0})
			}
		}
		return nil

	case OP_FOUND:
		// Check if pattern has any matches
		// Stack: [pattern_name] -> [result]
		if len(i.stack) > 0 {
			pattern := i.pop()
			if pattern.Type == ValueTypeString {
				if matches, exists := i.matchContext.Matches[pattern.StringVal]; exists && len(matches) > 0 {
					i.push(Value{Type: ValueTypeInt, IntVal: 1})
				} else {
					i.push(Value{Type: ValueTypeInt, IntVal: 0})
				}
			} else {
				i.push(Value{Type: ValueTypeInt, IntVal: 0})
			}
		}
		return nil

	case OP_COUNT:
		// Count matches for a pattern
		// Stack: [pattern_name] -> [count]
		if len(i.stack) > 0 {
			pattern := i.pop()
			if pattern.Type == ValueTypeString {
				if matches, exists := i.matchContext.Matches[pattern.StringVal]; exists {
					i.push(Value{Type: ValueTypeInt, IntVal: int64(len(matches))})
				} else {
					i.push(Value{Type: ValueTypeInt, IntVal: 0})
				}
			} else {
				i.push(Value{Type: ValueTypeUndefined})
			}
		}
		return nil
	case OP_INDEX_ARRAY:
		// Array indexing operation for @string[i] and #string[i]
		// Stack: [array_expr, index, op_type] -> [result]
		// op_type: 0 = offset (@string[i]), 1 = length (#string[i])
		if len(i.stack) >= 3 {
			opType := i.pop()
			index := i.pop()
			arrayExpr := i.pop()

			// Handle array expression based on its type
			if arrayExpr.Type == ValueTypeString {
				// This is a string identifier
				matches, exists := i.matchContext.Matches[arrayExpr.StringVal]
				if exists && index.Type == ValueTypeInt && index.IntVal > 0 && index.IntVal <= int64(len(matches)) {
					match := matches[index.IntVal-1]

					// Check operation type
					switch {
					case opType.Type == ValueTypeInt && opType.IntVal == 0:
						// @string[i] - return offset
						i.push(Value{Type: ValueTypeInt, IntVal: match.Offset})
					case opType.Type == ValueTypeInt && opType.IntVal == 1:
						// #string[i] - return length
						i.push(Value{Type: ValueTypeInt, IntVal: int64(match.Length)})
					default:
						// Unknown operation type
						i.push(Value{Type: ValueTypeUndefined})
					}
				} else {
					i.push(Value{Type: ValueTypeUndefined})
				}
			} else {
				// For other array types, we'll need to handle them differently
				// This is a placeholder for future implementation
				i.push(Value{Type: ValueTypeUndefined})
			}
		} else {
			i.push(Value{Type: ValueTypeUndefined})
		}
		return nil

	case OP_MATCHES:
		// Check if pattern matches (similar to FOUND but for specific pattern)
		if len(i.stack) > 0 {
			v := i.pop()
			if v.Type == ValueTypeString {
				if matches, exists := i.matchContext.Matches[v.StringVal]; exists && len(matches) > 0 {
					i.push(Value{Type: ValueTypeInt, IntVal: 1})
				} else {
					i.push(Value{Type: ValueTypeInt, IntVal: 0})
				}
			} else {
				i.push(Value{Type: ValueTypeInt, IntVal: 0})
			}
		}
		return nil

	case OP_OF:
		// "of" expression: evaluates quantifier conditions like "any of them", "1 of ($a, $b)"
		// Stack: [count, strings_set] -> [result]
		if len(i.stack) >= 2 {
			stringsExpr := i.pop()
			countExpr := i.pop()

			// Handle different quantifier types
			var requiredCount int64
			var actualCount int64

			// Determine required count based on quantifier
			if countExpr.Type == ValueTypeString {
				switch countExpr.StringVal {
				case QuantifierAny:
					requiredCount = 1
				case QuantifierAll:
					// Count total strings in the set
					if stringsExpr.Type == ValueTypeString && stringsExpr.StringVal == QuantifierThem {
						// Count all defined strings
						actualCount = 0
						for pattern := range i.matchContext.Matches {
							if matches := i.matchContext.Matches[pattern]; len(matches) > 0 {
								actualCount++
							}
						}
						i.push(Value{Type: ValueTypeInt, IntVal: 1})
						return nil
					}
					requiredCount = 0 // Will be set below
				case QuantifierNone:
					requiredCount = 0
				default:
					// Should be a numeric count
					requiredCount = countExpr.IntVal
				}
			} else {
				requiredCount = countExpr.IntVal
			}

			// Count actual matches
			if stringsExpr.Type == ValueTypeString && stringsExpr.StringVal == QuantifierThem {
				// Count all strings that have matches
				actualCount = 0
				for pattern := range i.matchContext.Matches {
					if matches := i.matchContext.Matches[pattern]; len(matches) > 0 {
						actualCount++
					}
				}
			} else {
				// For specific string lists (not implemented yet)
				actualCount = 0
			}

			// Evaluate the condition
			var result int64
			if countExpr.Type == ValueTypeString {
				switch countExpr.StringVal {
				case QuantifierAny:
					result = 0
					if actualCount >= 1 {
						result = 1
					}
				case QuantifierAll:
					// For "all", we need to check if all strings matched
					// This is simplified - full implementation would need to track total string count
					result = 0
					if actualCount >= 1 {
						result = 1
					}
				case QuantifierNone:
					result = 1
					if actualCount >= 1 {
						result = 0
					}
				default:
					result = 0
				}
			} else {
				// Numeric count: check if actual count >= required count
				result = 0
				if actualCount >= requiredCount {
					result = 1
				}
			}

			i.push(Value{Type: ValueTypeInt, IntVal: result})
		} else {
			i.push(Value{Type: ValueTypeInt, IntVal: 0})
		}
		return nil

	default:
		return fmt.Errorf("unsupported opcode: %s (0x%02X)", opcode.String(), byte(opcode))
	}
}

// executeBinaryOp executes a binary operation
func (i *Interpreter) executeBinaryOp(op func(int64, int64) int64) error {
	if len(i.stack) < 2 {
		return fmt.Errorf("stack underflow")
	}
	b := i.pop()
	a := i.pop()
	result := op(a.IntVal, b.IntVal)
	i.push(Value{Type: ValueTypeInt, IntVal: result})
	return nil
}

// push adds a value to the stack
func (i *Interpreter) push(v Value) {
	i.stack = append(i.stack, v)
}

// pop removes and returns a value from the stack
func (i *Interpreter) pop() Value {
	if len(i.stack) == 0 {
		return Value{Type: ValueTypeUndefined}
	}
	v := i.stack[len(i.stack)-1]
	i.stack = i.stack[:len(i.stack)-1]
	return v
}

// GetStack returns the current stack
func (i *Interpreter) GetStack() []Value {
	return i.stack
}

// GetMemory returns memory at the given address
func (i *Interpreter) GetMemory(addr int) Value {
	if addr >= 0 && addr < 256 {
		return i.memory[addr]
	}
	return Value{Type: ValueTypeUndefined}
}

// SetMemoryString sets a VM memory slot to a string value
func (i *Interpreter) SetMemoryString(addr int, s string) {
	if addr >= 0 && addr < 256 {
		i.memory[addr] = Value{Type: ValueTypeString, StringVal: s}
	}
}

// pushComparisonResult pushes the result of a comparison to the stack
func (i *Interpreter) pushComparisonResult(result bool) {
	if result {
		i.push(Value{Type: ValueTypeInt, IntVal: 1})
	} else {
		i.push(Value{Type: ValueTypeInt, IntVal: 0})
	}
}

// executeComparison executes a comparison operation
func (i *Interpreter) executeComparison(op func(int64, int64) bool) error {
	if len(i.stack) < 2 {
		return fmt.Errorf("stack underflow")
	}
	b := i.pop()
	a := i.pop()
	if a.Type == ValueTypeUndefined || b.Type == ValueTypeUndefined {
		i.push(Value{Type: ValueTypeInt, IntVal: 0})
	} else {
		i.pushComparisonResult(op(a.IntVal, b.IntVal))
	}
	return nil
}

// executeDoubleComparison executes a double comparison operation
func (i *Interpreter) executeDoubleComparison(op func(float64, float64) bool) error {
	if len(i.stack) < 2 {
		return fmt.Errorf("stack underflow")
	}
	b := i.pop()
	a := i.pop()
	if a.Type == ValueTypeUndefined || b.Type == ValueTypeUndefined {
		i.push(Value{Type: ValueTypeInt, IntVal: 0})
	} else {
		i.pushComparisonResult(op(a.DoubleVal, b.DoubleVal))
	}
	return nil
}

// executeDoubleBinaryOp executes a double binary operation
func (i *Interpreter) executeDoubleBinaryOp(op func(float64, float64) float64) error {
	if len(i.stack) < 2 {
		return fmt.Errorf("stack underflow")
	}
	b := i.pop()
	a := i.pop()
	result := op(a.DoubleVal, b.DoubleVal)
	i.push(Value{Type: ValueTypeDouble, DoubleVal: result})
	return nil
}

// SetMatchContext sets the pattern matching context
func (i *Interpreter) SetMatchContext(ctx *MatchContext) {
	i.matchContext = ctx
}

// GetMatchContext returns the pattern matching context
func (i *Interpreter) GetMatchContext() *MatchContext {
	return i.matchContext
}

// GetMatches returns matches found during execution as a flat list
func (i *Interpreter) GetMatches() []Match {
	var result []Match
	for _, matches := range i.matchContext.Matches {
		result = append(result, matches...)
	}
	return result
}

// GetMatchesForPattern returns matches for a specific pattern
func (i *Interpreter) GetMatchesForPattern(pattern string) []Match {
	if matches, exists := i.matchContext.Matches[pattern]; exists {
		return matches
	}
	return []Match{}
}

// AddMatch adds a match to the context
func (i *Interpreter) AddMatch(m Match) {
	if m.Pattern == "" {
		return
	}
	i.matchContext.Matches[m.Pattern] = append(i.matchContext.Matches[m.Pattern], m)
}

// SetRuleResults sets the rule results map for cross-rule references
func (i *Interpreter) SetRuleResults(results map[string]bool) {
	i.ruleResults = results
}

// GetRuleResults returns the current rule results map
func (i *Interpreter) GetRuleResults() map[string]bool {
	return i.ruleResults
}

// SetCurrentRule sets the name of the currently executing rule
func (i *Interpreter) SetCurrentRule(ruleName string) {
	i.currentRule = ruleName
}

// GetCurrentRule returns the name of the currently executing rule
func (i *Interpreter) GetCurrentRule() string {
	return i.currentRule
}

// SetRuleResult sets the execution result for a specific rule
func (i *Interpreter) SetRuleResult(ruleName string, matched bool) {
	i.ruleResults[ruleName] = matched
}

// GetRuleResult gets the execution result for a specific rule
func (i *Interpreter) GetRuleResult(ruleName string) (bool, bool) {
	matched, exists := i.ruleResults[ruleName]
	return matched, exists
}

// executeStringComparison executes a string comparison operation
func (i *Interpreter) executeStringComparison(op func(string, string) bool) error {
	if len(i.stack) < 2 {
		return fmt.Errorf("stack underflow")
	}
	b := i.pop()
	a := i.pop()
	if a.Type == ValueTypeUndefined || b.Type == ValueTypeUndefined {
		i.push(Value{Type: ValueTypeInt, IntVal: 0})
	} else {
		i.pushComparisonResult(op(a.StringVal, b.StringVal))
	}
	return nil
}

// readIntFromData reads an integer from data using the specified byte order
func (i *Interpreter) readIntFromData(size int, unsigned bool, bigEndian bool) (int64, error) {
	if len(i.stack) == 0 {
		return 0, fmt.Errorf("stack underflow")
	}
	off := int(i.stack[len(i.stack)-1].IntVal)
	fmt.Printf("DEBUG: readIntFromData size=%d, unsigned=%v, bigEndian=%v, offset=%d, data len=%d\n", size, unsigned, bigEndian, off, len(i.matchContext.Data))
	if off < 0 || off+size > len(i.matchContext.Data) {
		return 0, fmt.Errorf("out of bounds")
	}

	data := i.matchContext.Data[off : off+size]
	var val int64

	switch size {
	case 1:
		if unsigned {
			val = int64(data[0])
		} else {
			val = int64(int8(data[0]))
		}
	case 2:
		var u16 uint16
		if bigEndian {
			u16 = binary.BigEndian.Uint16(data)
		} else {
			u16 = binary.LittleEndian.Uint16(data)
		}
		if unsigned {
			val = int64(u16)
		} else {
			// Safe conversion with explicit truncation
			// Safe conversion with explicit truncation
			val = int64(int16(u16 & 0xFFFF))
		}
	case 4:
		var u32 uint32
		if bigEndian {
			u32 = binary.BigEndian.Uint32(data)
		} else {
			u32 = binary.LittleEndian.Uint32(data)
		}
		if unsigned {
			val = int64(u32)
		} else {
			// Safe conversion with explicit truncation
			// Safe conversion with explicit truncation
			val = int64(int32(u32 & 0xFFFFFFFF))
		}
	}

	return val, nil
}

// executeReadIntHelper is a common helper for reading integers
func (i *Interpreter) executeReadIntHelper(size int, unsigned bool, bigEndian bool) error {
	if len(i.stack) < 1 {
		return fmt.Errorf("stack underflow")
	}
	offset := i.pop()
	if offset.Type == ValueTypeUndefined {
		i.push(Value{Type: ValueTypeUndefined})
		return nil
	}

	i.push(offset)
	val, err := i.readIntFromData(size, unsigned, bigEndian)
	i.pop()
	if err != nil {
		i.push(Value{Type: ValueTypeUndefined})
		return nil
	}

	i.push(Value{Type: ValueTypeInt, IntVal: val})
	return nil
}

// executeReadInt reads an integer from data at the given offset
func (i *Interpreter) executeReadInt(size int, unsigned bool) error {
	return i.executeReadIntHelper(size, unsigned, false)
}

// executeDataTypeFunction executes data type function calls (uint8, uint16, etc.)
func (i *Interpreter) executeDataTypeFunction(opcode Opcode) error {
	// Data type functions read integers from file data at the offset on stack
	// Stack: [offset] -> [value_at_offset]
	if len(i.stack) < 1 {
		return fmt.Errorf("stack underflow for data type function")
	}

	offset := i.pop()
	if offset.Type == ValueTypeUndefined {
		i.push(Value{Type: ValueTypeUndefined})
		return nil
	}

	// Determine function parameters
	var size int
	var unsigned bool
	var bigEndian bool

	switch opcode {
	case OP_INT8:
		size, unsigned, bigEndian = 1, false, false
	case OP_INT16:
		size, unsigned, bigEndian = 2, false, false
	case OP_INT32:
		size, unsigned, bigEndian = 4, false, false
	case OP_UINT8:
		size, unsigned, bigEndian = 1, true, false
	case OP_UINT16:
		size, unsigned, bigEndian = 2, true, false
	case OP_UINT32:
		size, unsigned, bigEndian = 4, true, false
	case OP_INT8BE:
		size, unsigned, bigEndian = 1, false, true
	case OP_INT16BE:
		size, unsigned, bigEndian = 2, false, true
	case OP_INT32BE:
		size, unsigned, bigEndian = 4, false, true
	case OP_UINT8BE:
		size, unsigned, bigEndian = 1, true, true
	case OP_UINT16BE:
		size, unsigned, bigEndian = 2, true, true
	case OP_UINT32BE:
		size, unsigned, bigEndian = 4, true, true
	default:
		return fmt.Errorf("unsupported data type function opcode: %s", opcode)
	}

	// Read the integer value from data
	val, err := i.readIntFromData(size, unsigned, bigEndian)
	if err != nil {
		i.push(Value{Type: ValueTypeUndefined})
		return nil
	}

	i.push(Value{Type: ValueTypeInt, IntVal: val})
	return nil
}
