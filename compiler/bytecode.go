// Package compiler provides bytecode generation and compilation for YARA rules.
//
// This package implements bytecode format based on libyara's instruction set,
// providing a stack-based virtual machine architecture for efficient pattern matching.
package compiler

import (
	"encoding/binary"
	"fmt"
)

// Opcode represents a bytecode instruction opcode
type Opcode uint8

// All bytecode opcodes based on libyara's instruction set
const (
	// Basic operations (0-15)
	OP_ERROR Opcode = iota
	OP_AND
	OP_OR
	OP_NOT
	OP_BITWISE_NOT
	OP_BITWISE_AND
	OP_BITWISE_OR
	OP_BITWISE_XOR
	OP_SHL
	OP_SHR
	OP_MOD
	OP_INT_TO_DBL
	OP_STR_TO_BOOL
	OP_PUSH
	OP_POP
	OP_CALL

	// Object operations (16-25)
	OP_OBJ_LOAD
	OP_OBJ_VALUE
	OP_OBJ_FIELD
	OP_INDEX_ARRAY
	OP_COUNT
	OP_LENGTH
	OP_FOUND
	OP_FOUND_AT
	OP_FOUND_IN
	OP_OFFSET

	// Rule operations (26-40)
	OP_OF
	OP_PUSH_RULE
	OP_INIT_RULE
	OP_MATCH_RULE
	OP_INCR_M
	OP_CLEAR_M
	OP_ADD_M
	OP_POP_M
	OP_PUSH_M
	OP_SET_M
	OP_SWAPUNDEF
	OP_FILESIZE
	OP_ENTRYPOINT
	OP_UNUSED
	OP_MATCHES

	// Dictionary operations (41-45)
	OP_IMPORT
	OP_LOOKUP_DICT
	OP_JUNDEF // Not used
	OP_JUNDEF_P
	OP_JNUNDEF

	// Jump operations (46-65)
	OP_JNUNDEF_P // Not used
	OP_JFALSE
	OP_JFALSE_P
	OP_JTRUE
	OP_JTRUE_P
	OP_JL_P
	OP_JLE_P
	OP_ITER_NEXT
	OP_ITER_START_ARRAY
	OP_ITER_START_DICT
	OP_ITER_START_INT_RANGE
	OP_ITER_START_INT_ENUM
	OP_ITER_START_STRING_SET
	OP_ITER_CONDITION
	OP_ITER_END
	OP_JZ
	OP_JZ_P

	// Push operations (66-70)
	OP_PUSH_8
	OP_PUSH_16
	OP_PUSH_32
	OP_PUSH_U

	// String operations (71-85)
	OP_CONTAINS
	OP_STARTSWITH
	OP_ENDSWITH
	OP_ICONTAINS
	OP_ISTARTSWITH
	OP_IENDSWITH
	OP_IEQUALS
	OP_OF_PERCENT
	OP_OF_FOUND_IN
	OP_COUNT_IN
	OP_DEFINED
	OP_ITER_START_TEXT_STRING_SET
	OP_OF_FOUND_AT

	// Integer operations (100-110)
	OP_INT_BEGIN = 100
	OP_INT_EQ    = OP_INT_BEGIN + 0
	OP_INT_NEQ   = OP_INT_BEGIN + 1
	OP_INT_LT    = OP_INT_BEGIN + 2
	OP_INT_GT    = OP_INT_BEGIN + 3
	OP_INT_LE    = OP_INT_BEGIN + 4
	OP_INT_GE    = OP_INT_BEGIN + 5
	OP_INT_ADD   = OP_INT_BEGIN + 6
	OP_INT_SUB   = OP_INT_BEGIN + 7
	OP_INT_MUL   = OP_INT_BEGIN + 8
	OP_INT_DIV   = OP_INT_BEGIN + 9
	OP_INT_MINUS = OP_INT_BEGIN + 10
	OP_INT_END   = OP_INT_MINUS

	// Double operations (120-130)
	OP_DBL_BEGIN = 120
	OP_DBL_EQ    = OP_DBL_BEGIN + 0
	OP_DBL_NEQ   = OP_DBL_BEGIN + 1
	OP_DBL_LT    = OP_DBL_BEGIN + 2
	OP_DBL_GT    = OP_DBL_BEGIN + 3
	OP_DBL_LE    = OP_DBL_BEGIN + 4
	OP_DBL_GE    = OP_DBL_BEGIN + 5
	OP_DBL_ADD   = OP_DBL_BEGIN + 6
	OP_DBL_SUB   = OP_DBL_BEGIN + 7
	OP_DBL_MUL   = OP_DBL_BEGIN + 8
	OP_DBL_DIV   = OP_DBL_BEGIN + 9
	OP_DBL_MINUS = OP_DBL_BEGIN + 10
	OP_DBL_END   = OP_DBL_MINUS

	// String operations (140-146)
	OP_STR_BEGIN = 140
	OP_STR_EQ    = OP_STR_BEGIN + 0
	OP_STR_NEQ   = OP_STR_BEGIN + 1
	OP_STR_LT    = OP_STR_BEGIN + 2
	OP_STR_GT    = OP_STR_BEGIN + 3
	OP_STR_LE    = OP_STR_BEGIN + 4
	OP_STR_GE    = OP_STR_BEGIN + 5
	OP_STR_END   = OP_STR_GE

	// Data type functions (240-251)
	OP_READ_INT = 240
	OP_INT8     = OP_READ_INT + 0
	OP_INT16    = OP_READ_INT + 1
	OP_INT32    = OP_READ_INT + 2
	OP_UINT8    = OP_READ_INT + 3
	OP_UINT16   = OP_READ_INT + 4
	OP_UINT32   = OP_READ_INT + 5
	OP_INT8BE   = OP_READ_INT + 6
	OP_INT16BE  = OP_READ_INT + 7
	OP_INT32BE  = OP_READ_INT + 8
	OP_UINT8BE  = OP_READ_INT + 9
	OP_UINT16BE = OP_READ_INT + 10
	OP_UINT32BE = OP_READ_INT + 11

	// Control flow (must be at end to avoid conflicts)
	OP_HALT = 255
	OP_NOP  = 254
)

// Opcode categories for classification
const (
	OpCategoryControl    = "control"
	OpCategoryLogical    = "logical"
	OpCategoryArithmetic = "arithmetic"
	OpCategoryStack      = "stack"
	OpCategoryObject     = "object"
	OpCategoryString     = "string"
	OpCategoryJump       = "jump"
	OpCategoryIterator   = "iterator"
	OpCategoryTypeFunc   = "type_func"
)

// GetCategory returns category of an opcode
func (op Opcode) GetCategory() string {
	switch {
	case op == OP_ERROR || op == OP_HALT || op == OP_NOP:
		return OpCategoryControl
	// Logical operations (AND, OR, NOT, BITWISE_*)
	case op >= OP_AND && op <= OP_BITWISE_XOR:
		return OpCategoryLogical
	// Shift and modulo operations (arithmetic)
	case op >= OP_SHL && op <= OP_MOD:
		return OpCategoryArithmetic
	// Type conversion operations
	case op == OP_INT_TO_DBL || op == OP_STR_TO_BOOL:
		return OpCategoryLogical
	// Stack operations
	case op >= OP_PUSH && op <= OP_CALL:
		return OpCategoryStack
	// Object operations (16-25)
	case op >= OP_OBJ_LOAD && op <= OP_OFFSET:
		return OpCategoryObject
	// Rule operations (26-40) - includes FILESIZE, ENTRYPOINT, etc.
	case op >= OP_OF && op <= OP_MATCHES:
		return OpCategoryObject
	// Dictionary operations (41-45)
	case op >= OP_IMPORT && op <= OP_JNUNDEF:
		return OpCategoryObject
	// Jump operations (46-65) - JNUNDEF_P through JZ_P
	case op >= OP_JNUNDEF_P && op <= OP_JZ_P:
		return OpCategoryJump
	// Iterator operations (within jump range)
	case op >= OP_ITER_NEXT && op <= OP_ITER_END:
		return OpCategoryIterator
	// Push operations (66-70)
	case op >= OP_PUSH_8 && op <= OP_PUSH_U:
		return OpCategoryStack
	// String operations (71-85)
	case op >= OP_CONTAINS && op <= OP_OF_FOUND_AT:
		return OpCategoryString
	// Integer/Double/String arithmetic operations
	case (op >= OP_INT_BEGIN && op <= OP_INT_END) ||
		(op >= OP_DBL_BEGIN && op <= OP_DBL_END) ||
		(op >= OP_STR_BEGIN && op <= OP_STR_END):
		return OpCategoryArithmetic
	// Data type functions
	case op >= OP_READ_INT:
		return OpCategoryTypeFunc
	default:
		return "unknown"
	}
}

// String returns string representation of an opcode
func (op Opcode) String() string {
	switch op {
	case OP_ERROR:
		return "ERROR"
	case OP_HALT:
		return "HALT"
	case OP_NOP:
		return "NOP"
	case OP_AND:
		return "AND"
	case OP_OR:
		return "OR"
	case OP_NOT:
		return "NOT"
	case OP_BITWISE_NOT:
		return "BITWISE_NOT"
	case OP_BITWISE_AND:
		return "BITWISE_AND"
	case OP_BITWISE_OR:
		return "BITWISE_OR"
	case OP_BITWISE_XOR:
		return "BITWISE_XOR"
	case OP_SHL:
		return "SHL"
	case OP_SHR:
		return "SHR"
	case OP_MOD:
		return "MOD"
	case OP_INT_TO_DBL:
		return "INT_TO_DBL"
	case OP_STR_TO_BOOL:
		return "STR_TO_BOOL"
	case OP_PUSH:
		return "PUSH"
	case OP_POP:
		return "POP"
	case OP_CALL:
		return "CALL"
	case OP_OBJ_LOAD:
		return "OBJ_LOAD"
	case OP_OBJ_VALUE:
		return "OBJ_VALUE"
	case OP_OBJ_FIELD:
		return "OBJ_FIELD"
	case OP_INDEX_ARRAY:
		return "INDEX_ARRAY"
	case OP_COUNT:
		return "COUNT"
	case OP_LENGTH:
		return "LENGTH"
	case OP_FOUND:
		return "FOUND"
	case OP_FOUND_AT:
		return "FOUND_AT"
	case OP_FOUND_IN:
		return "FOUND_IN"
	case OP_OFFSET:
		return "OFFSET"
	case OP_OF:
		return "OF"
	case OP_PUSH_RULE:
		return "PUSH_RULE"
	case OP_INIT_RULE:
		return "INIT_RULE"
	case OP_MATCH_RULE:
		return "MATCH_RULE"
	case OP_INCR_M:
		return "INCR_M"
	case OP_CLEAR_M:
		return "CLEAR_M"
	case OP_ADD_M:
		return "ADD_M"
	case OP_POP_M:
		return "POP_M"
	case OP_PUSH_M:
		return "PUSH_M"
	case OP_SET_M:
		return "SET_M"
	case OP_SWAPUNDEF:
		return "SWAPUNDEF"
	case OP_FILESIZE:
		return "FILESIZE"
	case OP_ENTRYPOINT:
		return "ENTRYPOINT"
	case OP_UNUSED:
		return "UNUSED"
	case OP_MATCHES:
		return "MATCHES"
	case OP_IMPORT:
		return "IMPORT"
	case OP_LOOKUP_DICT:
		return "LOOKUP_DICT"
	case OP_JUNDEF:
		return "JUNDEF"
	case OP_JUNDEF_P:
		return "JUNDEF_P"
	case OP_JNUNDEF:
		return "JNUNDEF"
	case OP_JNUNDEF_P:
		return "JNUNDEF_P"
	case OP_JFALSE:
		return "JFALSE"
	case OP_JFALSE_P:
		return "JFALSE_P"
	case OP_JTRUE:
		return "JTRUE"
	case OP_JTRUE_P:
		return "JTRUE_P"
	case OP_JL_P:
		return "JL_P"
	case OP_JLE_P:
		return "JLE_P"
	case OP_ITER_NEXT:
		return "ITER_NEXT"
	case OP_ITER_START_ARRAY:
		return "ITER_START_ARRAY"
	case OP_ITER_START_DICT:
		return "ITER_START_DICT"
	case OP_ITER_START_INT_RANGE:
		return "ITER_START_INT_RANGE"
	case OP_ITER_START_INT_ENUM:
		return "ITER_START_INT_ENUM"
	case OP_ITER_START_STRING_SET:
		return "ITER_START_STRING_SET"
	case OP_ITER_CONDITION:
		return "ITER_CONDITION"
	case OP_ITER_END:
		return "ITER_END"
	case OP_JZ:
		return "JZ"
	case OP_JZ_P:
		return "JZ_P"
	case OP_PUSH_8:
		return "PUSH_8"
	case OP_PUSH_16:
		return "PUSH_16"
	case OP_PUSH_32:
		return "PUSH_32"
	case OP_PUSH_U:
		return "PUSH_U"
	case OP_CONTAINS:
		return "CONTAINS"
	case OP_STARTSWITH:
		return "STARTSWITH"
	case OP_ENDSWITH:
		return "ENDSWITH"
	case OP_ICONTAINS:
		return "ICONTAINS"
	case OP_ISTARTSWITH:
		return "ISTARTSWITH"
	case OP_IENDSWITH:
		return "IENDSWITH"
	case OP_IEQUALS:
		return "IEQUALS"
	case OP_OF_PERCENT:
		return "OF_PERCENT"
	case OP_OF_FOUND_IN:
		return "OF_FOUND_IN"
	case OP_COUNT_IN:
		return "COUNT_IN"
	case OP_DEFINED:
		return "DEFINED"
	case OP_ITER_START_TEXT_STRING_SET:
		return "ITER_START_TEXT_STRING_SET"
	case OP_OF_FOUND_AT:
		return "OF_FOUND_AT"
	default:
		// Integer operations
		if op >= OP_INT_BEGIN && op <= OP_INT_END {
			switch op - OP_INT_BEGIN {
			case 0:
				return "INT_EQ"
			case 1:
				return "INT_NEQ"
			case 2:
				return "INT_LT"
			case 3:
				return "INT_GT"
			case 4:
				return "INT_LE"
			case 5:
				return "INT_GE"
			case 6:
				return "INT_ADD"
			case 7:
				return "INT_SUB"
			case 8:
				return "INT_MUL"
			case 9:
				return "INT_DIV"
			case 10:
				return "INT_MINUS"
			}
		}

		// Double operations
		if op >= OP_DBL_BEGIN && op <= OP_DBL_END {
			switch op - OP_DBL_BEGIN {
			case 0:
				return "DBL_EQ"
			case 1:
				return "DBL_NEQ"
			case 2:
				return "DBL_LT"
			case 3:
				return "DBL_GT"
			case 4:
				return "DBL_LE"
			case 5:
				return "DBL_GE"
			case 6:
				return "DBL_ADD"
			case 7:
				return "DBL_SUB"
			case 8:
				return "DBL_MUL"
			case 9:
				return "DBL_DIV"
			case 10:
				return "DBL_MINUS"
			}
		}

		// String operations
		if op >= OP_STR_BEGIN && op <= OP_STR_END {
			switch op - OP_STR_BEGIN {
			case 0:
				return "STR_EQ"
			case 1:
				return "STR_NEQ"
			case 2:
				return "STR_LT"
			case 3:
				return "STR_GT"
			case 4:
				return "STR_LE"
			case 5:
				return "STR_GE"
			}
		}

		// Data type functions
		if op >= OP_READ_INT {
			switch op - OP_READ_INT {
			case 0:
				return "INT8"
			case 1:
				return "INT16"
			case 2:
				return "INT32"
			case 3:
				return "UINT8"
			case 4:
				return "UINT16"
			case 5:
				return "UINT32"
			case 6:
				return "INT8BE"
			case 7:
				return "INT16BE"
			case 8:
				return "INT32BE"
			case 9:
				return "UINT8BE"
			case 10:
				return "UINT16BE"
			case 11:
				return "UINT32BE"
			}
		}

		return fmt.Sprintf("OPCODE_%d", int(op))
	}
}

// OperandType represents type of an operand
type OperandType uint8

const (
	// OperandNone represents no operand
	OperandNone OperandType = iota
	// OperandImmediate8 represents an 8-bit immediate value
	OperandImmediate8
	// OperandImmediate16 represents a 16-bit immediate value
	OperandImmediate16
	// OperandImmediate32 represents a 32-bit immediate value
	OperandImmediate32
	// OperandImmediate64 represents a 64-bit immediate value
	OperandImmediate64
	// OperandRelative8 represents an 8-bit relative offset
	OperandRelative8
	// OperandRelative16 represents a 16-bit relative offset
	OperandRelative16
	// OperandRelative32 represents a 32-bit relative offset
	OperandRelative32
	// OperandAbsolute32 represents a 32-bit absolute address
	OperandAbsolute32
	// OperandAbsolute64 represents a 64-bit absolute address
	OperandAbsolute64
)

// Operand represents a bytecode operand
type Operand struct {
	Type  OperandType
	Value uint64
}

// Instruction represents a single bytecode instruction
type Instruction struct {
	Opcode   Opcode
	Operand  Operand
	Line     int // Source line number for debugging
	Position int // Byte position in source for diagnostics
}

// NewInstruction creates a new instruction with given opcode
func NewInstruction(opcode Opcode, line, pos int) *Instruction {
	return &Instruction{
		Opcode:   opcode,
		Operand:  Operand{Type: OperandNone},
		Line:     line,
		Position: pos,
	}
}

// NewInstructionWithOperand creates a new instruction with opcode and operand
func NewInstructionWithOperand(opcode Opcode, operand Operand, line, pos int) *Instruction {
	return &Instruction{
		Opcode:   opcode,
		Operand:  operand,
		Line:     line,
		Position: pos,
	}
}

// String returns a string representation of instruction
// formatOperand formats operand for display
func (inst *Instruction) formatOperand() string {
	switch inst.Operand.Type {
	case OperandNone:
		return ""
	case OperandImmediate8:
		if inst.Operand.Value > 0xFF {
			// Safe conversion with explicit truncation
			return fmt.Sprintf(" 0x%02X (truncated)", uint8(inst.Operand.Value&0xFF))
		}
		// Safe conversion with explicit truncation
		return fmt.Sprintf(" 0x%02X", uint8(inst.Operand.Value&0xFF))
	case OperandImmediate16:
		if inst.Operand.Value > 0xFFFF {
			// Safe conversion with explicit truncation
			return fmt.Sprintf(" 0x%04X (truncated)", uint16(inst.Operand.Value&0xFFFF))
		}
		// Safe conversion with explicit truncation
		return fmt.Sprintf(" 0x%04X", uint16(inst.Operand.Value&0xFFFF))
	case OperandImmediate32:
		if inst.Operand.Value > 0xFFFFFFFF {
			// Safe conversion with explicit truncation
			return fmt.Sprintf(" 0x%08X (truncated)", uint32(inst.Operand.Value&0xFFFFFFFF))
		}
		// Safe conversion with explicit truncation
		return fmt.Sprintf(" 0x%08X", uint32(inst.Operand.Value&0xFFFFFFFF))
	case OperandImmediate64:
		return fmt.Sprintf(" 0x%016X", inst.Operand.Value)
	case OperandRelative8:
		if inst.Operand.Value > 0x7F {
			// Safe conversion with explicit truncation
			return fmt.Sprintf(" %+d (truncated)", int8(inst.Operand.Value&0xFF))
		}
		// Safe conversion with explicit truncation
		return fmt.Sprintf(" %+d", int8(inst.Operand.Value&0xFF))
	case OperandRelative16:
		if inst.Operand.Value > 0x7FFF {
			// Safe conversion with explicit truncation
			return fmt.Sprintf(" %+d (truncated)", int16(inst.Operand.Value&0xFFFF))
		}
		// Safe conversion with explicit truncation
		return fmt.Sprintf(" %+d", int16(inst.Operand.Value&0xFFFF))
	case OperandRelative32:
		if inst.Operand.Value > 0x7FFFFFFF {
			// Safe conversion with explicit truncation
			return fmt.Sprintf(" %+d (truncated)", int32(inst.Operand.Value&0xFFFFFFFF))
		}
		// Safe conversion with explicit truncation
		return fmt.Sprintf(" %+d", int32(inst.Operand.Value&0xFFFFFFFF))
	case OperandAbsolute32:
		if inst.Operand.Value > 0xFFFFFFFF {
			// Safe conversion with explicit truncation
			return fmt.Sprintf(" @0x%08X (truncated)", uint32(inst.Operand.Value&0xFFFFFFFF))
		}
		// Safe conversion with explicit truncation
		return fmt.Sprintf(" @0x%08X", uint32(inst.Operand.Value&0xFFFFFFFF))
	case OperandAbsolute64:
		return fmt.Sprintf(" @0x%016X", inst.Operand.Value)
	default:
		return fmt.Sprintf(" (invalid operand type %d)", inst.Operand.Type)
	}
}

func (inst *Instruction) String() string {
	return inst.Opcode.String() + inst.formatOperand()
}

// appendOperand appends operand bytes to buffer
func (inst *Instruction) appendOperand(buf []byte) []byte {
	switch inst.Operand.Type {
	case OperandNone:
		// No operand
	case OperandImmediate8:
		if inst.Operand.Value > 0xFF {
			// Handle overflow safely
			inst.Operand.Value &= 0xFF
		}
		buf = append(buf, byte(inst.Operand.Value&0xFF))
	case OperandImmediate16:
		if inst.Operand.Value > 0xFFFF {
			// Handle overflow safely
			inst.Operand.Value &= 0xFFFF
		}
		// Safe conversion with explicit truncation
		buf = binary.LittleEndian.AppendUint16(buf, uint16(inst.Operand.Value&0xFFFF))
	case OperandImmediate32:
		if inst.Operand.Value > 0xFFFFFFFF {
			// Handle overflow safely
			inst.Operand.Value &= 0xFFFFFFFF
		}
		// Safe conversion with explicit truncation
		buf = binary.LittleEndian.AppendUint32(buf, uint32(inst.Operand.Value&0xFFFFFFFF))
	case OperandImmediate64:
		buf = binary.LittleEndian.AppendUint64(buf, inst.Operand.Value)
	case OperandRelative8:
		if inst.Operand.Value > 0x7F {
			// Handle overflow safely for signed values
			inst.Operand.Value = 0x7F
		}
		buf = append(buf, byte(inst.Operand.Value&0xFF))
	case OperandRelative16:
		if inst.Operand.Value > 0x7FFF {
			// Handle overflow safely for signed values
			inst.Operand.Value = 0x7FFF
		}
		buf = binary.LittleEndian.AppendUint16(buf, uint16(inst.Operand.Value))
	case OperandRelative32:
		if inst.Operand.Value > 0x7FFFFFFF {
			// Handle overflow safely for signed values
			inst.Operand.Value = 0x7FFFFFFF
		}
		// Safe conversion with explicit truncation
		buf = binary.LittleEndian.AppendUint32(buf, uint32(inst.Operand.Value&0xFFFFFFFF))
	case OperandAbsolute32:
		if inst.Operand.Value > 0xFFFFFFFF {
			// Handle overflow safely
			inst.Operand.Value &= 0xFFFFFFFF
		}
		// Safe conversion with explicit truncation
		buf = binary.LittleEndian.AppendUint32(buf, uint32(inst.Operand.Value&0xFFFFFFFF))
	case OperandAbsolute64:
		buf = binary.LittleEndian.AppendUint64(buf, inst.Operand.Value)
	}
	return buf
}

// Bytes returns binary representation of instruction
func (inst *Instruction) Bytes() []byte {
	buf := make([]byte, 1, 9) // Start with capacity for opcode + 8-byte operand
	buf[0] = byte(inst.Opcode)
	return inst.appendOperand(buf)
}

// AppendBytes appends binary representation of instruction to dst and returns dst
func (inst *Instruction) AppendBytes(dst []byte) []byte {
	dst = append(dst, byte(inst.Opcode))
	return inst.appendOperand(dst)
}

// Size returns size of instruction in bytes
func (inst *Instruction) Size() int {
	size := 1 // opcode
	switch inst.Operand.Type {
	case OperandNone:
		// No operand
	case OperandImmediate8, OperandRelative8:
		size += 1
	case OperandImmediate16, OperandRelative16:
		size += 2
	case OperandImmediate32, OperandRelative32, OperandAbsolute32:
		size += 4
	case OperandImmediate64, OperandAbsolute64:
		size += 8
	}
	return size
}

// IsJump returns true if this instruction is a jump
func (inst *Instruction) IsJump() bool {
	return (inst.Opcode >= OP_JUNDEF && inst.Opcode <= OP_JZ_P) ||
		inst.Opcode == OP_ITER_NEXT
}

// IsTypeFunction returns true if this instruction is a data type function
func (inst *Instruction) IsTypeFunction() bool {
	return inst.Opcode >= OP_READ_INT
}

// IsStringOperation returns true if this instruction operates on strings
func (inst *Instruction) IsStringOperation() bool {
	return (inst.Opcode >= OP_CONTAINS && inst.Opcode <= OP_IEQUALS) ||
		(inst.Opcode >= OP_FOUND && inst.Opcode <= OP_OF_FOUND_AT)
}

// HasImmediateOperand returns true if this instruction has an immediate operand
func (inst *Instruction) HasImmediateOperand() bool {
	return inst.Operand.Type == OperandImmediate8 ||
		inst.Operand.Type == OperandImmediate16 ||
		inst.Operand.Type == OperandImmediate32 ||
		inst.Operand.Type == OperandImmediate64
}

// HasRelativeOperand returns true if this instruction has a relative operand
func (inst *Instruction) HasRelativeOperand() bool {
	return inst.Operand.Type == OperandRelative8 ||
		inst.Operand.Type == OperandRelative16 ||
		inst.Operand.Type == OperandRelative32
}

// HasAbsoluteOperand returns true if this instruction has an absolute operand
func (inst *Instruction) HasAbsoluteOperand() bool {
	return inst.Operand.Type == OperandAbsolute32 ||
		inst.Operand.Type == OperandAbsolute64
}

// IsIntOp returns true if opcode is an integer operation.
func IsIntOp(op Opcode) bool { return op >= OP_INT_BEGIN && op <= OP_INT_END }

// IsDblOp returns true if opcode is a double operation.
func IsDblOp(op Opcode) bool { return op >= OP_DBL_BEGIN && op <= OP_DBL_END }

// IsStrOp returns true if opcode is a string operation.
func IsStrOp(op Opcode) bool { return op >= OP_STR_BEGIN && op <= OP_STR_END }

// YRUndefined constant for undefined values
const YRUndefined uint64 = 0xFFFABADAFABADAFF

// IsUndefined checks if a value is undefined
func IsUndefined(x uint64) bool {
	return x == YRUndefined
}

// Operation performs an operation on two operands (handling undefined values)
func Operation(operator func(uint64, uint64) uint64, op1, op2 uint64) uint64 {
	if IsUndefined(op1) || IsUndefined(op2) {
		return YRUndefined
	}
	return operator(op1, op2)
}

// Comparison performs a comparison on two operands (handling undefined values)
func Comparison(operator func(uint64, uint64) bool, op1, op2 uint64) int {
	if IsUndefined(op1) || IsUndefined(op2) {
		return 0
	}
	if operator(op1, op2) {
		return 1
	}
	return 0
}
