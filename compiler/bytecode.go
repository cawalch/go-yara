package compiler

import (
	"fmt"
)

// The compiler uses a compact stack-based bytecode instruction set.

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
	OpProximity

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

// OpPush64 pushes a 64-bit integer. It has a distinct opcode because OpPushU
// represents an undefined value and carries no operand.
const OpPush64 Opcode = 93

// OpMatchesValue matches a string value without interpreting it as a pattern identifier.
const OpMatchesValue Opcode = 94

// Fused condition instructions index the rule's immutable assertion pool.
// Existing opcode values are preserved for serialized-program compatibility.
const (
	OpAssertUint16Eq Opcode = 160 + iota
	OpAssertUint32Eq
	OpAssertFilesize
	OpAssertStringAt
	OpAssertStringCount
	// OpModuleLoad loads bound structured module data.
	OpModuleLoad
	// OpModuleGetField retrieves a declared structure field.
	OpModuleGetField
	// OpModuleGetIndex retrieves an array or dictionary element.
	OpModuleGetIndex
	// OpIterStartModuleArray starts an array or dictionary iterator.
	OpIterStartModuleArray
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
	return op == OpError || op == OpHalt || op == OpNop
}

// isLogicalOpcode checks if opcode is a logical operation
func isLogicalOpcode(op Opcode) bool {
	return (op >= OpAssertUint16Eq && op <= OpAssertStringCount) || (op >= OpAnd && op <= OpBitwiseXor) ||
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
		op == OpPushStr || op == OpLoadVar || op == OpPush64
}

// isObjectOpcode checks if opcode is an object operation
func isObjectOpcode(op Opcode) bool {
	return (op >= OpModuleLoad && op <= OpIterStartModuleArray) || (op >= OpObjLoad && op <= OpOffset) ||
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
	return (op >= OpContains && op <= OpOfPercentAt) ||
		op == OpCountInOf || op == OpProximity || op == OpConcat || op == OpMatchesValue
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

// opcodeNames maps basic opcodes to their string names.
// #nosec G101 -- Fixed bytecode mnemonics, not credentials.
var opcodeNames = map[Opcode]string{
	OpModuleLoad:             "MODULE_LOAD",
	OpModuleGetField:         "MODULE_GET_FIELD",
	OpModuleGetIndex:         "MODULE_GET_INDEX",
	OpIterStartModuleArray:   "ITER_START_MODULE_ARRAY",
	OpAssertUint16Eq:         "ASSERT_UINT16_EQ",
	OpAssertUint32Eq:         "ASSERT_UINT32_EQ",
	OpAssertFilesize:         "ASSERT_FILESIZE",
	OpAssertStringAt:         "ASSERT_STRING_AT",
	OpAssertStringCount:      "ASSERT_STRING_COUNT",
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
	OpLoadVar:                "LOAD_VAR",
	OpIterPushTotal:          "ITER_PUSH_TOTAL",
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
	OpMatchesValue:           "MATCHES_VALUE",
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
	OpPush64:                 "PUSH_64",
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
	OpProximity:              "PROXIMITY",
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
