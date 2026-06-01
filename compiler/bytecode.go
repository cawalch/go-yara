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

	// OpObjLoad loads an object property (16-25)
	OpObjLoad
	OpObjValue
	OpObjField
	OpIndexArray
	OpCount
	OpLength
	OpLengthOf
	OpFound
	OpFoundAt
	OpFoundIn
	OpOffset

	// OpOf begins rule operations (26-40)
	OpOf
	OpPushRule
	OpInitRule
	OpMatchRule
	OpIncrM
	OpClearM
	OpAddM
	OpPopM
	OpPushM
	OpSetM
	OpSwapundef
	OpFilesize
	OpEntrypoint
	OpUnused
	OpMatches

	// OpImport begins dictionary operations (41-45)
	OpImport
	OpLookupDict
	OpJundef // Not used
	OpJundefP
	OpJnundef

	// OpJnundefP begins jump operations (46-65)
	OpJnundefP // Not used
	OpJfalse
	OpJfalseP
	OpJtrue
	OpJtrueP
	OpJlP
	OpJleP
	OpIterNext
	OpIterStartArray
	OpIterStartDict
	OpIterStartIntRange
	OpIterStartIntEnum
	OpIterStartStringSet
	OpIterCondition
	OpIterEnd
	OpJz
	OpJzP

	// OpPush8 begins push operations (64-69)
	OpPush8
	OpPush16
	OpPush32
	OpPushU
	OpPushDbl
	OpPushRuleRef

	// OpContains begins string operations (73-86)
	OpContains
	OpStartswith
	OpEndswith
	OpIcontains
	OpIstartswith
	OpIendswith
	OpIequals
	OpOfPercent
	OpOfFoundIn
	OpCountIn
	OpDefined
	OpIterStartTextStringSet
	OpOfFoundAt
	OpOfPercentIn
	OpOfPercentAt
	OpCountInOf

	// OpIntBegin begins integer operations (100-110)
	OpIntBegin = 100
	OpIntEq    = OpIntBegin + 0
	OpIntNeq   = OpIntBegin + 1
	OpIntLt    = OpIntBegin + 2
	OpIntGt    = OpIntBegin + 3
	OpIntLe    = OpIntBegin + 4
	OpIntGe    = OpIntBegin + 5
	OpIntAdd   = OpIntBegin + 6
	OpIntSub   = OpIntBegin + 7
	OpIntMul   = OpIntBegin + 8
	OpIntDiv   = OpIntBegin + 9
	OpIntMinus = OpIntBegin + 10
	OpIntEnd   = OpIntMinus

	// OpDblBegin begins double operations (120-130)
	OpDblBegin = 120
	OpDblEq    = OpDblBegin + 0
	OpDblNeq   = OpDblBegin + 1
	OpDblLt    = OpDblBegin + 2
	OpDblGt    = OpDblBegin + 3
	OpDblLe    = OpDblBegin + 4
	OpDblGe    = OpDblBegin + 5
	OpDblAdd   = OpDblBegin + 6
	OpDblSub   = OpDblBegin + 7
	OpDblMul   = OpDblBegin + 8
	OpDblDiv   = OpDblBegin + 9
	OpDblMinus = OpDblBegin + 10
	OpDblEnd   = OpDblMinus

	// OpStrBegin begins string operations (140-146)
	OpStrBegin = 140
	OpStrEq    = OpStrBegin + 0
	OpStrNeq   = OpStrBegin + 1
	OpStrLt    = OpStrBegin + 2
	OpStrGt    = OpStrBegin + 3
	OpStrLe    = OpStrBegin + 4
	OpStrGe    = OpStrBegin + 5
	OpStrEnd   = OpStrGe

	// OpReadInt begins data type functions (224-239)
	OpReadInt  = 224
	OpInt8     = OpReadInt + 0
	OpInt16    = OpReadInt + 1
	OpInt32    = OpReadInt + 2
	OpUint8    = OpReadInt + 3
	OpUint16   = OpReadInt + 4
	OpUint32   = OpReadInt + 5
	OpInt8be   = OpReadInt + 6
	OpInt16be  = OpReadInt + 7
	OpInt32be  = OpReadInt + 8
	OpUint8be  = OpReadInt + 9
	OpUint16be = OpReadInt + 10
	OpUint32be = OpReadInt + 11
	OpInt64    = OpReadInt + 12
	OpUint64   = OpReadInt + 13
	OpInt64be  = OpReadInt + 14
	OpUint64be = OpReadInt + 15

	// OpConcat represents string operations (253)
	OpConcat = 253

	// OpHalt represents control flow (must be at end to avoid conflicts)
	OpHalt = 255
	OpNop  = 254
)

// OpPushStr pushes a string literal by index into the rule string literal pool.
// Chosen to avoid shifting existing opcode values.
const OpPushStr Opcode = 90

// OpLoadVar loads a runtime iteration variable by name onto the stack.
const OpLoadVar Opcode = 91

// OpIterPushTotal pushes the total count of the currently active iterator to the stack.
const OpIterPushTotal Opcode = 92

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
	return op == OpError || op == OpHalt || op == OpNop
}

// isLogicalOpcode checks if opcode is a logical operation
func isLogicalOpcode(op Opcode) bool {
	return (op >= OpAnd && op <= OpBitwiseXor) ||
		op == OpIntToDbl || op == OpStrToBool
}

// isArithmeticOpcode checks if opcode is an arithmetic operation
func isArithmeticOpcode(op Opcode) bool {
	return (op >= OpShl && op <= OpMod) ||
		(op >= OpIntBegin && op <= OpIntEnd) ||
		(op >= OpDblBegin && op <= OpDblEnd) ||
		(op >= OpStrBegin && op <= OpStrEnd)
}

// isStackOpcode checks if opcode is a stack operation
func isStackOpcode(op Opcode) bool {
	return (op >= OpPush && op <= OpCall) ||
		(op >= OpPush8 && op <= OpPushRuleRef) ||
		op == OpPushStr
}

// isObjectOpcode checks if opcode is an object operation
func isObjectOpcode(op Opcode) bool {
	return (op >= OpObjLoad && op <= OpOffset) ||
		(op >= OpOf && op <= OpMatches) ||
		(op >= OpImport && op <= OpJnundef)
}

// isJumpOpcode checks if opcode is a jump operation
func isJumpOpcode(op Opcode) bool {
	return op >= OpJnundefP && op <= OpJzP
}

// isIteratorOpcode checks if opcode is an iterator operation
func isIteratorOpcode(op Opcode) bool {
	return (op >= OpIterNext && op <= OpIterEnd) || op == OpIterPushTotal
}

// isStringOpcode checks if opcode is a string operation
func isStringOpcode(op Opcode) bool {
	return (op >= OpContains && op <= OpOfPercentAt) || op == OpConcat
}

// isTypeFuncOpcode checks if opcode is a type function
func isTypeFuncOpcode(op Opcode) bool {
	return op >= OpReadInt && op <= OpUint64be
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
	OpError:                  "ERROR",
	OpHalt:                   "HALT",
	OpNop:                    "NOP",
	OpAnd:                    "AND",
	OpOr:                     "OR",
	OpNot:                    "NOT",
	OpBitwiseNot:             "BITWISE_NOT",
	OpBitwiseAnd:             "BITWISE_AND",
	OpBitwiseOr:              "BITWISE_OR",
	OpBitwiseXor:             "BITWISE_XOR",
	OpShl:                    "SHL",
	OpShr:                    "SHR",
	OpMod:                    "MOD",
	OpIntToDbl:               "INT_TO_DBL",
	OpStrToBool:              "STR_TO_BOOL",
	OpPush:                   "PUSH",
	OpPop:                    "POP",
	OpCall:                   "CALL",
	OpObjLoad:                "OBJ_LOAD",
	OpObjValue:               "OBJ_VALUE",
	OpObjField:               "OBJ_FIELD",
	OpIndexArray:             "INDEX_ARRAY",
	OpCount:                  "COUNT",
	OpLength:                 "LENGTH",
	OpLengthOf:               "LENGTH_OF",
	OpOffset:                 "OFFSET",
	OpFound:                  "FOUND",
	OpFoundAt:                "FOUND_AT",
	OpFoundIn:                "FOUND_IN",
	OpOf:                     "OF",
	OpPushRule:               "PUSH_RULE",
	OpInitRule:               "INIT_RULE",
	OpMatchRule:              "MATCH_RULE",
	OpPushStr:                "PUSH_STR",
	OpIncrM:                  "INCR_M",
	OpClearM:                 "CLEAR_M",
	OpAddM:                   "ADD_M",
	OpPopM:                   "POP_M",
	OpPushM:                  "PUSH_M",
	OpSetM:                   "SET_M",
	OpSwapundef:              "SWAPUNDEF",
	OpFilesize:               "FILESIZE",
	OpEntrypoint:             "ENTRYPOINT",
	OpUnused:                 "UNUSED",
	OpMatches:                "MATCHES",
	OpImport:                 "IMPORT",
	OpLookupDict:             "LOOKUP_DICT",
	OpJundef:                 "JUNDEF",
	OpJundefP:                "JUNDEF_P",
	OpJnundef:                "JNUNDEF",
	OpJnundefP:               "JNUNDEF_P",
	OpJfalse:                 "JFALSE",
	OpJfalseP:                "JFALSE_P",
	OpJtrue:                  "JTRUE",
	OpJtrueP:                 "JTRUE_P",
	OpJlP:                    "JL_P",
	OpJleP:                   "JLE_P",
	OpIterNext:               "ITER_NEXT",
	OpIterStartArray:         "ITER_START_ARRAY",
	OpIterStartDict:          "ITER_START_DICT",
	OpIterStartIntRange:      "ITER_START_INT_RANGE",
	OpIterStartIntEnum:       "ITER_START_INT_ENUM",
	OpIterStartStringSet:     "ITER_START_STRING_SET",
	OpIterCondition:          "ITER_CONDITION",
	OpIterEnd:                "ITER_END",
	OpJz:                     "JZ",
	OpJzP:                    "JZ_P",
	OpPush8:                  "PUSH_8",
	OpPush16:                 "PUSH_16",
	OpPush32:                 "PUSH_32",
	OpPushU:                  "PUSH_U",
	OpPushDbl:                "PUSH_DBL",
	OpPushRuleRef:            "PUSH_RULE_REF",
	OpContains:               "CONTAINS",
	OpStartswith:             "STARTSWITH",
	OpEndswith:               "ENDSWITH",
	OpIcontains:              "ICONTAINS",
	OpIstartswith:            "ISTARTSWITH",
	OpIendswith:              "IENDSWITH",
	OpIequals:                "IEQUALS",
	OpOfPercent:              "OF_PERCENT",
	OpOfFoundIn:              "OF_FOUND_IN",
	OpCountIn:                "COUNT_IN",
	OpDefined:                "DEFINED",
	OpIterStartTextStringSet: "ITER_START_TEXT_STRING_SET",
	OpOfFoundAt:              "OF_FOUND_AT",
	OpOfPercentIn:            "OF_PERCENT_IN",
	OpOfPercentAt:            "OF_PERCENT_AT",
	OpCountInOf:              "COUNT_IN_OF",
	OpConcat:                 "CONCAT",
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
	"INT64", "UINT64", "INT64BE", "UINT64BE",
}

// getIntOpName returns the name for integer operation opcodes
func (op Opcode) getIntOpName() string {
	offset := int(op - OpIntBegin)
	if offset < len(intOpNames) {
		return intOpNames[offset]
	}
	return ""
}

// getDblOpName returns the name for double operation opcodes
func (op Opcode) getDblOpName() string {
	offset := int(op - OpDblBegin)
	if offset < len(dblOpNames) {
		return dblOpNames[offset]
	}
	return ""
}

// getStrOpName returns the name for string operation opcodes
func (op Opcode) getStrOpName() string {
	offset := int(op - OpStrBegin)
	if offset < len(strOpNames) {
		return strOpNames[offset]
	}
	return ""
}

// getDataTypeName returns the name for data type function opcodes
func (op Opcode) getDataTypeName() string {
	offset := int(op - OpReadInt)
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
	case op >= OpIntBegin && op <= OpIntEnd:
		return op.getIntOpName()
	case op >= OpDblBegin && op <= OpDblEnd:
		return op.getDblOpName()
	case op >= OpStrBegin && op <= OpStrEnd:
		return op.getStrOpName()
	case op >= OpReadInt && op <= OpUint64be:
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
//
//nolint:revive // argument-limit: factory method
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
	return (inst.Opcode >= OpJundef && inst.Opcode <= OpJzP) ||
		inst.Opcode == OpIterNext
}

// IsTypeFunction returns true if this instruction is a data type function
func (inst *Instruction) IsTypeFunction() bool {
	return inst.Opcode >= OpReadInt && inst.Opcode <= OpUint64be
}

// IsStringOperation returns true if this instruction operates on strings
func (inst *Instruction) IsStringOperation() bool {
	// String operations - same as GetCategory logic
	if (inst.Opcode >= OpContains && inst.Opcode <= OpOfPercentAt) || inst.Opcode == OpConcat {
		return true
	}
	// STR comparison operations are considered arithmetic by GetCategory,
	// but they are logically string operations for IsStringOperation
	return (inst.Opcode >= OpStrBegin && inst.Opcode <= OpStrEnd)
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
func IsIntOp(op Opcode) bool { return op >= OpIntBegin && op <= OpIntEnd }

// IsDblOp returns true if opcode is a double operation.
func IsDblOp(op Opcode) bool { return op >= OpDblBegin && op <= OpDblEnd }

// IsStrOp returns true if opcode is a string operation.
func IsStrOp(op Opcode) bool { return op >= OpStrBegin && op <= OpStrEnd }

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
