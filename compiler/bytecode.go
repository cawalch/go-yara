// Package compiler implements bytecode format based on libyara's instruction set,
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
	// OpError represents an error condition
	OpError Opcode = iota
	OpAnd
	OpOr
	OpNot
	OpBitwiseNot
	OpBitwiseAnd
	OpBitwiseOr
	OpBitwiseXor
	OpShl
	OpShr
	OpMod
	OpIntToDbl
	OpStrToBool
	OpPush
	OpPop
	OpCall

	// OP_OBJ_LOAD loads an object property (16-25)
	OP_OBJ_LOAD
	OP_OBJ_VALUE
	OP_OBJ_FIELD
	OP_INDEX_ARRAY
	OP_COUNT
	OP_LENGTH
	OP_FOUND
	OP_FOUND_AT
	OP_FOUND_IN
	OpOffset

	// OpOf begins rule operations (26-40)
	OpOf
	OpPush_RULE
	OP_INIT_RULE
	OP_MATCH_RULE
	OP_INCR_M
	OP_CLEAR_M
	OP_ADD_M
	OpPop_M
	OpPush_M
	OP_SET_M
	OP_SWAPUNDEF
	OP_FILESIZE
	OP_ENTRYPOINT
	OP_UNUSED
	OP_MATCHES

	// OP_IMPORT begins dictionary operations (41-45)
	OP_IMPORT
	OP_LOOKUP_DICT
	OP_JUNDEF // Not used
	OP_JUNDEF_P
	OP_JNUNDEF

	// OP_JNUNDEF_P begins jump operations (46-65)
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
	OpJz
	OpJzP

	// OpPush_8 begins push operations (66-71)
	OpPush_8
	OpPush_16
	OpPush_32
	OpPush_U
	OpPush_DBL
	OpPush_RULE_REF

	// OP_CONTAINS begins string operations (73-86)
	OP_CONTAINS
	OP_STARTSWITH
	OP_ENDSWITH
	OP_ICONTAINS
	OP_ISTARTSWITH
	OP_IENDSWITH
	OP_IEQUALS
	OpOfPercent
	OpOfFoundIn
	OP_COUNT_IN
	OP_DEFINED
	OP_ITER_START_TEXT_STRING_SET
	OpOfFoundAt

	// OP_INT_BEGIN begins integer operations (100-110)
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

	// OP_DBL_BEGIN begins double operations (120-130)
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

	// OP_STR_BEGIN begins string operations (140-146)
	OP_STR_BEGIN = 140
	OP_STR_EQ    = OP_STR_BEGIN + 0
	OP_STR_NEQ   = OP_STR_BEGIN + 1
	OP_STR_LT    = OP_STR_BEGIN + 2
	OP_STR_GT    = OP_STR_BEGIN + 3
	OP_STR_LE    = OP_STR_BEGIN + 4
	OP_STR_GE    = OP_STR_BEGIN + 5
	OP_STR_END   = OP_STR_GE

	// OP_READ_INT begins data type functions (240-251)
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

	// OP_CONCAT represents string operations (253)
	OP_CONCAT = 253

	// OP_HALT represents control flow (must be at end to avoid conflicts)
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

// isControlOpcode checks if opcode is a control operation
func isControlOpcode(op Opcode) bool {
	return op == OpError || op == OP_HALT || op == OP_NOP
}

// isLogicalOpcode checks if opcode is a logical operation
func isLogicalOpcode(op Opcode) bool {
	return (op >= OpAnd && op <= OpBitwiseXor) ||
		op == OpIntToDbl || op == OpStrToBool
}

// isArithmeticOpcode checks if opcode is an arithmetic operation
func isArithmeticOpcode(op Opcode) bool {
	return (op >= OpShl && op <= OpMod) ||
		(op >= OP_INT_BEGIN && op <= OP_INT_END) ||
		(op >= OP_DBL_BEGIN && op <= OP_DBL_END) ||
		(op >= OP_STR_BEGIN && op <= OP_STR_END)
}

// isStackOpcode checks if opcode is a stack operation
func isStackOpcode(op Opcode) bool {
	return (op >= OpPush && op <= OpCall) ||
		(op >= OpPush_8 && op <= OpPush_RULE_REF)
}

// isObjectOpcode checks if opcode is an object operation
func isObjectOpcode(op Opcode) bool {
	return (op >= OP_OBJ_LOAD && op <= OpOffset) ||
		(op >= OpOf && op <= OP_MATCHES) ||
		(op >= OP_IMPORT && op <= OP_JNUNDEF)
}

// isJumpOpcode checks if opcode is a jump operation
func isJumpOpcode(op Opcode) bool {
	return op >= OP_JNUNDEF_P && op <= OpJzP
}

// isIteratorOpcode checks if opcode is an iterator operation
func isIteratorOpcode(op Opcode) bool {
	return op >= OP_ITER_NEXT && op <= OP_ITER_END
}

// isStringOpcode checks if opcode is a string operation
func isStringOpcode(op Opcode) bool {
	return op >= OP_CONTAINS && op <= OpOfFoundAt
}

// isTypeFuncOpcode checks if opcode is a type function
func isTypeFuncOpcode(op Opcode) bool {
	return op >= OP_READ_INT
}

// GetCategory returns category of an opcode
func (op Opcode) GetCategory() string {
	// Check categories in order of most common to least common for performance
	categoryChecks := []struct {
		check    func(Opcode) bool
		category string
	}{
		{isArithmeticOpcode, OpCategoryArithmetic},
		{isLogicalOpcode, OpCategoryLogical},
		{isStackOpcode, OpCategoryStack},
		{isStringOpcode, OpCategoryString},
		{isJumpOpcode, OpCategoryJump},
		{isObjectOpcode, OpCategoryObject},
		{isIteratorOpcode, OpCategoryIterator},
		{isControlOpcode, OpCategoryControl},
		{isTypeFuncOpcode, OpCategoryTypeFunc},
	}

	for _, check := range categoryChecks {
		if check.check(op) {
			return check.category
		}
	}

	return "unknown"
}

// opcodeNames maps basic opcodes to their string names
var opcodeNames = map[Opcode]string{
	OpError:                       "ERROR",
	OP_HALT:                       "HALT",
	OP_NOP:                        "NOP",
	OpAnd:                         "AND",
	OpOr:                          "OR",
	OpNot:                         "NOT",
	OpBitwiseNot:                  "BITWISE_NOT",
	OpBitwiseAnd:                  "BITWISE_AND",
	OpBitwiseOr:                   "BITWISE_OR",
	OpBitwiseXor:                  "BITWISE_XOR",
	OpShl:                         "SHL",
	OpShr:                         "SHR",
	OpMod:                         "MOD",
	OpIntToDbl:                    "INT_TO_DBL",
	OpStrToBool:                   "STR_TO_BOOL",
	OpPush:                        "PUSH",
	OpPop:                         "POP",
	OpCall:                        "CALL",
	OP_OBJ_LOAD:                   "OBJ_LOAD",
	OP_OBJ_VALUE:                  "OBJ_VALUE",
	OP_OBJ_FIELD:                  "OBJ_FIELD",
	OP_INDEX_ARRAY:                "INDEX_ARRAY",
	OP_COUNT:                      "COUNT",
	OP_LENGTH:                     "LENGTH",
	OP_FOUND:                      "FOUND",
	OP_FOUND_AT:                   "FOUND_AT",
	OP_FOUND_IN:                   "FOUND_IN",
	OpOffset:                      "OFFSET",
	OpOf:                          "OF",
	OpPush_RULE:                   "PUSH_RULE",
	OP_INIT_RULE:                  "INIT_RULE",
	OP_MATCH_RULE:                 "MATCH_RULE",
	OP_INCR_M:                     "INCR_M",
	OP_CLEAR_M:                    "CLEAR_M",
	OP_ADD_M:                      "ADD_M",
	OpPop_M:                       "POP_M",
	OpPush_M:                      "PUSH_M",
	OP_SET_M:                      "SET_M",
	OP_SWAPUNDEF:                  "SWAPUNDEF",
	OP_FILESIZE:                   "FILESIZE",
	OP_ENTRYPOINT:                 "ENTRYPOINT",
	OP_UNUSED:                     "UNUSED",
	OP_MATCHES:                    "MATCHES",
	OP_IMPORT:                     "IMPORT",
	OP_LOOKUP_DICT:                "LOOKUP_DICT",
	OP_JUNDEF:                     "JUNDEF",
	OP_JUNDEF_P:                   "JUNDEF_P",
	OP_JNUNDEF:                    "JNUNDEF",
	OP_JNUNDEF_P:                  "JNUNDEF_P",
	OP_JFALSE:                     "JFALSE",
	OP_JFALSE_P:                   "JFALSE_P",
	OP_JTRUE:                      "JTRUE",
	OP_JTRUE_P:                    "JTRUE_P",
	OP_JL_P:                       "JL_P",
	OP_JLE_P:                      "JLE_P",
	OP_ITER_NEXT:                  "ITER_NEXT",
	OP_ITER_START_ARRAY:           "ITER_START_ARRAY",
	OP_ITER_START_DICT:            "ITER_START_DICT",
	OP_ITER_START_INT_RANGE:       "ITER_START_INT_RANGE",
	OP_ITER_START_INT_ENUM:        "ITER_START_INT_ENUM",
	OP_ITER_START_STRING_SET:      "ITER_START_STRING_SET",
	OP_ITER_CONDITION:             "ITER_CONDITION",
	OP_ITER_END:                   "ITER_END",
	OpJz:                          "JZ",
	OpJzP:                         "JZ_P",
	OpPush_8:                      "PUSH_8",
	OpPush_16:                     "PUSH_16",
	OpPush_32:                     "PUSH_32",
	OpPush_U:                      "PUSH_U",
	OpPush_DBL:                    "PUSH_DBL",
	OpPush_RULE_REF:               "PUSH_RULE_REF",
	OP_CONTAINS:                   "CONTAINS",
	OP_STARTSWITH:                 "STARTSWITH",
	OP_ENDSWITH:                   "ENDSWITH",
	OP_ICONTAINS:                  "ICONTAINS",
	OP_ISTARTSWITH:                "ISTARTSWITH",
	OP_IENDSWITH:                  "IENDSWITH",
	OP_IEQUALS:                    "IEQUALS",
	OpOfPercent:                   "OF_PERCENT",
	OpOfFoundIn:                   "OF_FOUND_IN",
	OP_COUNT_IN:                   "COUNT_IN",
	OP_DEFINED:                    "DEFINED",
	OP_ITER_START_TEXT_STRING_SET: "ITER_START_TEXT_STRING_SET",
	OpOfFoundAt:                   "OF_FOUND_AT",
}

// intOpNames maps integer operations to their string names
var intOpNames = []string{
	"INT_EQ", "INT_NEQ", "INT_LT", "INT_GT", "INT_LE", "INT_GE",
	"INT_ADD", "INT_SUB", "INT_MUL", "INT_DIV", "INT_MINUS",
}

// dblOpNames maps double operations to their string names
var dblOpNames = []string{
	"DBL_EQ", "DBL_NEQ", "DBL_LT", "DBL_GT", "DBL_LE", "DBL_GE",
	"DBL_ADD", "DBL_SUB", "DBL_MUL", "DBL_DIV", "DBL_MINUS",
}

// strOpNames maps string operations to their string names
var strOpNames = []string{
	"STR_EQ", "STR_NEQ", "STR_LT", "STR_GT", "STR_LE", "STR_GE",
}

// dataTypeNames maps data type operations to their string names
var dataTypeNames = []string{
	"INT8", "INT16", "INT32", "UINT8", "UINT16", "UINT32",
	"INT8BE", "INT16BE", "INT32BE", "UINT8BE", "UINT16BE", "UINT32BE",
	"LENGTH", "CONCAT",
}

// getIntOpName returns the name for integer operation opcodes
func (op Opcode) getIntOpName() string {
	offset := int(op - OP_INT_BEGIN)
	if offset < len(intOpNames) {
		return intOpNames[offset]
	}
	return ""
}

// getDblOpName returns the name for double operation opcodes
func (op Opcode) getDblOpName() string {
	offset := int(op - OP_DBL_BEGIN)
	if offset < len(dblOpNames) {
		return dblOpNames[offset]
	}
	return ""
}

// getStrOpName returns the name for string operation opcodes
func (op Opcode) getStrOpName() string {
	offset := int(op - OP_STR_BEGIN)
	if offset < len(strOpNames) {
		return strOpNames[offset]
	}
	return ""
}

// getDataTypeName returns the name for data type function opcodes
func (op Opcode) getDataTypeName() string {
	offset := int(op - OP_READ_INT)
	if offset < len(dataTypeNames) {
		return dataTypeNames[offset]
	}
	return ""
}

// String returns the string representation of the opcode
func (op Opcode) String() string {
	// Check basic opcodes first
	if name, exists := opcodeNames[op]; exists {
		return name
	}

	// Handle specialized opcode ranges
	if name := op.getRangeName(); name != "" {
		return name
	}

	// Fallback for unknown opcodes
	return fmt.Sprintf("OPCODE_%d", int(op))
}

// getRangeName returns the name for opcodes in specific ranges
func (op Opcode) getRangeName() string {
	switch {
	case op >= OP_INT_BEGIN && op <= OP_INT_END:
		return op.getIntOpName()
	case op >= OP_DBL_BEGIN && op <= OP_DBL_END:
		return op.getDblOpName()
	case op >= OP_STR_BEGIN && op <= OP_STR_END:
		return op.getStrOpName()
	case op >= OP_READ_INT:
		return op.getDataTypeName()
	default:
		return ""
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
// formatImmediateOperand formats immediate operands
func (inst *Instruction) formatImmediateOperand(bits int) string {
	value := inst.Operand.Value

	switch bits {
	case 8:
		if value <= 0xFF {
			return fmt.Sprintf(" 0x%02X", value)
		}
		return fmt.Sprintf(" 0x%02X (truncated)", value&0xFF)
	case 16:
		if value <= 0xFFFF {
			return fmt.Sprintf(" 0x%04X", value)
		}
		return fmt.Sprintf(" 0x%04X (truncated)", value&0xFFFF)
	case 32:
		if value <= 0xFFFFFFFF {
			return fmt.Sprintf(" 0x%08X", value)
		}
		return fmt.Sprintf(" 0x%08X (truncated)", value&0xFFFFFFFF)
	case 64:
		return fmt.Sprintf(" 0x%016X", value)
	default:
		return fmt.Sprintf(" (invalid bit width %d)", bits)
	}
}

// formatRelativeOperand formats relative jump operands
func (inst *Instruction) formatRelativeOperand(bits int) string {
	value := inst.Operand.Value

	switch bits {
	case 8:
		if value <= 0x7F {
			return fmt.Sprintf(" %+d", value)
		}
		return fmt.Sprintf(" %+d (truncated)", value&0xFF)
	case 16:
		if value <= 0x7FFF {
			return fmt.Sprintf(" %+d", value)
		}
		return fmt.Sprintf(" %+d (truncated)", value&0xFFFF)
	case 32:
		if value <= 0x7FFFFFFF {
			return fmt.Sprintf(" %+d", value)
		}
		return fmt.Sprintf(" %+d (truncated)", value&0xFFFFFFFF)
	default:
		return fmt.Sprintf(" (invalid bit width %d)", bits)
	}
}

// formatAbsoluteOperand formats absolute address operands
func (inst *Instruction) formatAbsoluteOperand(bits int) string {
	value := inst.Operand.Value

	switch bits {
	case 32:
		if value <= 0xFFFFFFFF {
			return fmt.Sprintf(" @0x%08X", value)
		}
		return fmt.Sprintf(" @0x%08X (truncated)", value&0xFFFFFFFF)
	case 64:
		return fmt.Sprintf(" @0x%016X", value)
	default:
		return fmt.Sprintf(" (invalid bit width %d)", bits)
	}
}

// formatOperand formats operand for display
func (inst *Instruction) formatOperand() string {
	if inst.Operand.Type == OperandNone {
		return ""
	}

	if result, ok := inst.formatTypedOperand(); ok {
		return result
	}

	return fmt.Sprintf(" (invalid operand type %d)", inst.Operand.Type)
}

// formatTypedOperand formats the operand based on its type
func (inst *Instruction) formatTypedOperand() (string, bool) {
	switch inst.Operand.Type {
	case OperandImmediate8, OperandImmediate16, OperandImmediate32, OperandImmediate64:
		bits := inst.getOperandBits()
		return inst.formatImmediateOperand(bits), true

	case OperandRelative8, OperandRelative16, OperandRelative32:
		bits := inst.getOperandBits()
		return inst.formatRelativeOperand(bits), true

	case OperandAbsolute32, OperandAbsolute64:
		bits := inst.getOperandBits()
		return inst.formatAbsoluteOperand(bits), true

	default:
		return "", false
	}
}

// getOperandBits returns the bit size for the current operand
func (inst *Instruction) getOperandBits() int {
	switch inst.Operand.Type {
	case OperandImmediate8, OperandRelative8:
		return 8
	case OperandImmediate16, OperandRelative16:
		return 16
	case OperandImmediate32, OperandRelative32, OperandAbsolute32:
		return 32
	case OperandImmediate64, OperandAbsolute64:
		return 64
	default:
		return 0
	}
}

func (inst *Instruction) String() string {
	return inst.Opcode.String() + inst.formatOperand()
}

// appendImmediateOperand appends immediate operand bytes to buffer
func (inst *Instruction) appendImmediateOperand(buf []byte, bits int) []byte {
	value := inst.Operand.Value

	switch bits {
	case 8:
		if value > 0xFF {
			value &= 0xFF
		}
		// Safe conversion: we've ensured value <= 0xFF
		buf = append(buf, byte(value))
	case 16:
		if value > 0xFFFF {
			value &= 0xFFFF
		}
		// Use PutUint16 to avoid direct conversion
		tmp := make([]byte, 2)
		binary.LittleEndian.PutUint16(tmp, uint16(value)) // #nosec G115 - bounds checked above
		buf = append(buf, tmp...)
	case 32:
		if value > 0xFFFFFFFF {
			value &= 0xFFFFFFFF
		}
		// Use PutUint32 to avoid direct conversion
		tmp := make([]byte, 4)
		binary.LittleEndian.PutUint32(tmp, uint32(value)) // #nosec G115 - bounds checked above
		buf = append(buf, tmp...)
	case 64:
		buf = binary.LittleEndian.AppendUint64(buf, value)
	}
	return buf
}

// appendRelativeOperand appends relative operand bytes to buffer
func (inst *Instruction) appendRelativeOperand(buf []byte, bits int) []byte {
	value := inst.Operand.Value

	switch bits {
	case 8:
		if value > 0x7F {
			value = 0x7F
		}
		// Safe conversion: we've ensured value <= 0x7F
		buf = append(buf, byte(value))
	case 16:
		if value > 0x7FFF {
			value = 0x7FFF
		}
		// Safe conversion: we've ensured value <= 0x7FFF
		tmp := make([]byte, 2)
		binary.LittleEndian.PutUint16(tmp, uint16(value)) // #nosec G115 - bounds checked above
		buf = append(buf, tmp...)
	case 32:
		if value > 0x7FFFFFFF {
			value = 0x7FFFFFFF
		}
		// Safe conversion: we've ensured value <= 0x7FFFFFFF
		tmp := make([]byte, 4)
		binary.LittleEndian.PutUint32(tmp, uint32(value)) // #nosec G115 - bounds checked above
		buf = append(buf, tmp...)
	}
	return buf
}

// appendAbsoluteOperand appends absolute operand bytes to buffer
func (inst *Instruction) appendAbsoluteOperand(buf []byte, bits int) []byte {
	value := inst.Operand.Value

	switch bits {
	case 32:
		if value > 0xFFFFFFFF {
			value &= 0xFFFFFFFF
		}
		// Safe conversion: we've ensured value <= 0xFFFFFFFF
		tmp := make([]byte, 4)
		binary.LittleEndian.PutUint32(tmp, uint32(value)) // #nosec G115 - bounds checked above
		buf = append(buf, tmp...)
	case 64:
		buf = binary.LittleEndian.AppendUint64(buf, value)
	}
	return buf
}

// appendOperand appends operand bytes to buffer
func (inst *Instruction) appendOperand(buf []byte) []byte {
	if inst.Operand.Type == OperandNone {
		return buf
	}

	return inst.appendTypedOperand(buf)
}

// appendTypedOperand appends the operand to the buffer based on its type
func (inst *Instruction) appendTypedOperand(buf []byte) []byte {
	switch inst.Operand.Type {
	case OperandImmediate8, OperandImmediate16, OperandImmediate32, OperandImmediate64:
		bits := inst.getOperandBits()
		return inst.appendImmediateOperand(buf, bits)

	case OperandRelative8, OperandRelative16, OperandRelative32:
		bits := inst.getOperandBits()
		return inst.appendRelativeOperand(buf, bits)

	case OperandAbsolute32, OperandAbsolute64:
		bits := inst.getOperandBits()
		return inst.appendAbsoluteOperand(buf, bits)

	default:
		return buf
	}
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
		size++
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
	return (inst.Opcode >= OP_JUNDEF && inst.Opcode <= OpJzP) ||
		inst.Opcode == OP_ITER_NEXT
}

// IsTypeFunction returns true if this instruction is a data type function
func (inst *Instruction) IsTypeFunction() bool {
	return inst.Opcode >= OP_READ_INT
}

// IsStringOperation returns true if this instruction operates on strings
func (inst *Instruction) IsStringOperation() bool {
	// String operations (71-85) - same as GetCategory logic
	if inst.Opcode >= OP_CONTAINS && inst.Opcode <= OpOfFoundAt {
		return true
	}
	// STR comparison operations are considered arithmetic by GetCategory,
	// but they are logically string operations for IsStringOperation
	return (inst.Opcode >= OP_STR_BEGIN && inst.Opcode <= OP_STR_END)
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
