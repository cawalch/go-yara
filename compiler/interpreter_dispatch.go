package compiler

import "fmt"

// OpcodeHandler is the function signature for opcode dispatch table entries.
// Each handler executes exactly one opcode, reading operands from i.bytecode
// starting at i.ip and advancing i.ip past any consumed operand bytes.
type OpcodeHandler func(*Interpreter) error

// opcodeTable maps every valid opcode to its handler function.
// Unassigned opcodes have a nil entry; the main loop returns an error for those.
var opcodeTable [256]OpcodeHandler

func init() {
	// Error / no-op
	opcodeTable[OpError] = (*Interpreter).executeNop
	opcodeTable[OpNop] = (*Interpreter).executeNop

	// Stack operations
	opcodeTable[OpPush8] = (*Interpreter).executePush8
	opcodeTable[OpPush16] = (*Interpreter).executePush16
	opcodeTable[OpPush32] = (*Interpreter).executePush32
	opcodeTable[OpPushU] = (*Interpreter).executePushU
	opcodeTable[OpPushDbl] = (*Interpreter).executePushDouble
	opcodeTable[OpPushRuleRef] = (*Interpreter).executePushRuleRef
	opcodeTable[OpPushStr] = (*Interpreter).executePushString
	opcodeTable[OpPop] = (*Interpreter).executePop
	opcodeTable[OpCall] = (*Interpreter).executeCall

	// Bitwise operations
	opcodeTable[OpBitwiseAnd] = (*Interpreter).executeBitwiseAnd
	opcodeTable[OpBitwiseOr] = (*Interpreter).executeBitwiseOr
	opcodeTable[OpBitwiseXor] = (*Interpreter).executeBitwiseXor
	opcodeTable[OpBitwiseNot] = (*Interpreter).executeBitwiseNot
	opcodeTable[OpShl] = (*Interpreter).executeShiftLeft
	opcodeTable[OpShr] = (*Interpreter).executeShiftRight

	// Integer arithmetic
	opcodeTable[OpIntAdd] = (*Interpreter).executeIntAdd
	opcodeTable[OpIntSub] = (*Interpreter).executeIntSub
	opcodeTable[OpIntMul] = (*Interpreter).executeIntMul
	opcodeTable[OpIntDiv] = (*Interpreter).executeIntDiv
	opcodeTable[OpMod] = (*Interpreter).executeMod
	opcodeTable[OpIntMinus] = (*Interpreter).executeIntMinus

	// Double arithmetic
	opcodeTable[OpDblAdd] = (*Interpreter).executeDblAdd
	opcodeTable[OpDblSub] = (*Interpreter).executeDblSub
	opcodeTable[OpDblMul] = (*Interpreter).executeDblMul
	opcodeTable[OpDblDiv] = (*Interpreter).executeDblDiv
	opcodeTable[OpDblMinus] = (*Interpreter).executeDblMinus

	// Integer comparisons
	opcodeTable[OpIntEq] = (*Interpreter).executeIntEq
	opcodeTable[OpIntNeq] = (*Interpreter).executeIntNeq
	opcodeTable[OpIntLt] = (*Interpreter).executeIntLt
	opcodeTable[OpIntGt] = (*Interpreter).executeIntGt
	opcodeTable[OpIntLe] = (*Interpreter).executeIntLe
	opcodeTable[OpIntGe] = (*Interpreter).executeIntGe

	// Double comparisons
	opcodeTable[OpDblEq] = (*Interpreter).executeDblEq
	opcodeTable[OpDblNeq] = (*Interpreter).executeDblNeq
	opcodeTable[OpDblLt] = (*Interpreter).executeDblLt
	opcodeTable[OpDblGt] = (*Interpreter).executeDblGt
	opcodeTable[OpDblLe] = (*Interpreter).executeDblLe
	opcodeTable[OpDblGe] = (*Interpreter).executeDblGe

	// String comparisons
	opcodeTable[OpStrEq] = (*Interpreter).executeStrEq
	opcodeTable[OpStrNeq] = (*Interpreter).executeStrNeq
	opcodeTable[OpStrLt] = (*Interpreter).executeStrLt
	opcodeTable[OpStrGt] = (*Interpreter).executeStrGt
	opcodeTable[OpStrLe] = (*Interpreter).executeStrLe
	opcodeTable[OpStrGe] = (*Interpreter).executeStrGe

	// Logical operations
	opcodeTable[OpAnd] = (*Interpreter).executeAndOperation
	opcodeTable[OpOr] = (*Interpreter).executeOrOperation
	opcodeTable[OpNot] = (*Interpreter).executeNotOperation
	opcodeTable[OpDefined] = (*Interpreter).executeDefinedOperation

	// Control flow
	opcodeTable[OpHalt] = (*Interpreter).executeHalt
	opcodeTable[OpJz] = (*Interpreter).executeJz
	opcodeTable[OpJzP] = (*Interpreter).executeJzP
	opcodeTable[OpJtrue] = (*Interpreter).executeJtrue
	opcodeTable[OpJfalse] = (*Interpreter).executeJfalse

	// Memory operations
	opcodeTable[OpPushM] = (*Interpreter).executePushMemory
	opcodeTable[OpPopM] = (*Interpreter).executePopMemory
	opcodeTable[OpClearM] = (*Interpreter).executeClearMemory
	opcodeTable[OpIncrM] = (*Interpreter).executeIncrementMemory
	opcodeTable[OpSwapundef] = (*Interpreter).executeSwapUndefined

	// File operations
	opcodeTable[OpEntrypoint] = (*Interpreter).executeEntrypoint
	opcodeTable[OpFilesize] = (*Interpreter).executeFilesize

	// Integer read operations (little-endian)
	opcodeTable[OpInt8] = (*Interpreter).executeReadInt8
	opcodeTable[OpInt16] = (*Interpreter).executeReadInt16
	opcodeTable[OpInt32] = (*Interpreter).executeReadInt32
	opcodeTable[OpInt64] = (*Interpreter).executeReadInt64
	opcodeTable[OpUint8] = (*Interpreter).executeReadUint8
	opcodeTable[OpUint16] = (*Interpreter).executeReadUint16
	opcodeTable[OpUint32] = (*Interpreter).executeReadUint32
	opcodeTable[OpUint64] = (*Interpreter).executeReadUint64

	// Integer read operations (big-endian)
	opcodeTable[OpInt8be] = (*Interpreter).executeReadInt8be
	opcodeTable[OpInt16be] = (*Interpreter).executeReadInt16be
	opcodeTable[OpInt32be] = (*Interpreter).executeReadInt32be
	opcodeTable[OpInt64be] = (*Interpreter).executeReadInt64be
	opcodeTable[OpUint8be] = (*Interpreter).executeReadUint8be
	opcodeTable[OpUint16be] = (*Interpreter).executeReadUint16be
	opcodeTable[OpUint32be] = (*Interpreter).executeReadUint32be
	opcodeTable[OpUint64be] = (*Interpreter).executeReadUint64be

	// String operations
	opcodeTable[OpLength] = (*Interpreter).executeLengthOperation
	opcodeTable[OpCount] = (*Interpreter).executeCountOperation
	opcodeTable[OpLengthOf] = (*Interpreter).executeLengthOfOperation
	opcodeTable[OpFound] = (*Interpreter).executeFoundOperation
	opcodeTable[OpFoundAt] = (*Interpreter).executeFoundAtOperation
	opcodeTable[OpFoundIn] = (*Interpreter).executeFoundInOperation
	opcodeTable[OpOffset] = (*Interpreter).executeOffsetOperation
	opcodeTable[OpOf] = (*Interpreter).executeOfOperation
	opcodeTable[OpOfPercent] = (*Interpreter).executeOfPercentOperation
	opcodeTable[OpOfFoundIn] = (*Interpreter).executeOfFoundIn
	opcodeTable[OpOfFoundAt] = (*Interpreter).executeOfFoundAt
	opcodeTable[OpOfPercentIn] = (*Interpreter).executeOfPercentIn
	opcodeTable[OpOfPercentAt] = (*Interpreter).executeOfPercentAt
	opcodeTable[OpCountIn] = (*Interpreter).executeCountInRange
	opcodeTable[OpCountInOf] = (*Interpreter).executeCountInOf
	opcodeTable[OpMatches] = (*Interpreter).executeMatchesOperation
	opcodeTable[OpContains] = (*Interpreter).executeContainsOperation
	opcodeTable[OpStartswith] = (*Interpreter).executeStartswithOperation
	opcodeTable[OpEndswith] = (*Interpreter).executeEndswithOperation
	opcodeTable[OpIcontains] = (*Interpreter).executeIcontainsOperation
	opcodeTable[OpIstartswith] = (*Interpreter).executeIstartswithOperation
	opcodeTable[OpIendswith] = (*Interpreter).executeIendswithOperation
	opcodeTable[OpIequals] = (*Interpreter).executeIequalsOperation
	opcodeTable[OpIntToDbl] = (*Interpreter).executeIntToDouble
	opcodeTable[OpStrToBool] = (*Interpreter).executeStringToBool

	// Rule operations
	opcodeTable[OpPushRule] = (*Interpreter).executePushRuleOperation
	opcodeTable[OpInitRule] = (*Interpreter).executeInitRuleOperation
	opcodeTable[OpMatchRule] = (*Interpreter).executeMatchRuleOperation

	// Iterator operations
	opcodeTable[OpIterStartIntRange] = (*Interpreter).executeIterStartIntRange
	opcodeTable[OpIterStartStringSet] = (*Interpreter).executeIterStartStringSet
	opcodeTable[OpIterNext] = (*Interpreter).executeIterNext
	opcodeTable[OpIterCondition] = (*Interpreter).executeIterCondition
	opcodeTable[OpIterPushTotal] = (*Interpreter).executeIterPushTotal
	opcodeTable[OpIterEnd] = (*Interpreter).executeIterEnd

	// Iterator operations - not yet implemented
	opcodeTable[OpIterStartArray] = (*Interpreter).executeIterUnimplemented
	opcodeTable[OpIterStartDict] = (*Interpreter).executeIterUnimplemented
	opcodeTable[OpIterStartTextStringSet] = (*Interpreter).executeIterStartTextStringSet
	opcodeTable[OpIterStartIntEnum] = (*Interpreter).executeIterUnimplemented

	// Variable loading
	opcodeTable[OpLoadVar] = (*Interpreter).executeLoadVarOperation
}

func (i *Interpreter) executeMainLoop() error {
	for !i.stopped && i.ip < len(i.bytecode) {
		opcode := Opcode(i.bytecode[i.ip])
		i.ip++

		if i.debugMode {
			i.debugExecution(opcode)
		}

		handler := opcodeTable[opcode]
		if handler == nil {
			err := &InterpreterError{
				Type:    ErrorUnsupportedOpcode,
				Opcode:  opcode,
				Message: fmt.Sprintf("unsupported opcode: %v", opcode),
			}
			i.result = err
			return err
		}
		if err := handler(i); err != nil {
			i.result = err
			return err
		}

		if i.debugMode {
			i.debugStackState(opcode)
		}
	}

	i.storeExecutionResult()
	i.cleanupStack()

	return i.result
}

// executeOpcode dispatches a single opcode via the dispatch table.
// It is kept for test compatibility; production code uses executeMainLoop.
func (i *Interpreter) executeOpcode(opcode Opcode) error {
	handler := opcodeTable[opcode]
	if handler == nil {
		return &InterpreterError{
			Type:    ErrorUnsupportedOpcode,
			Opcode:  opcode,
			Message: fmt.Sprintf("unsupported opcode: %v", opcode),
		}
	}
	return handler(i)
}

func (i *Interpreter) storeExecutionResult() {
	if i.currentRule != "" && len(i.stack) > 0 {
		result := i.stack[len(i.stack)-1]
		if result.Type == ValueTypeInt {
			i.ruleResults[i.currentRule] = result.IntVal != 0
		} else {
			i.ruleResults[i.currentRule] = false
		}
	}
}

func (i *Interpreter) cleanupStack() {
	// Only clean up stack if execution was successful and there are excess values.
	// Leave the final result value on stack for compatibility with tests.
	if i.result == nil && len(i.stack) > 1 {
		i.stack = i.stack[len(i.stack)-1:]
	}
}
