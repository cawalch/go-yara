package compiler

import (
	"crypto/md5"  // #nosec G501 -- required for YARA hash compatibility
	"crypto/sha1" // #nosec G505 -- required for YARA hash compatibility
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync" // NEW

	"github.com/cawalch/go-yara/regex"
)

// Value represents a YARA value that can be int, double, or string
type Value struct {
	Type      ValueType
	IntVal    int64
	DoubleVal float64
	StringRef int64 // Index into stringArena (>=0) or static pool (<0)
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
	// ValueTypeRuleRef represents a rule reference
	ValueTypeRuleRef
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
	bytecode            []byte
	ip                  int        // Instruction pointer
	stack               []Value    // Execution stack
	memory              [256]Value // Memory slots for variables
	iterators           []Iterator // Stack of active iteration frames for loops
	stopped             bool
	result              error
	matchContext        *MatchContext   // Pattern matching context
	ruleResults         map[string]bool // Track execution results of all rules in the program
	currentRule         string          // Name of the currently executing rule
	compiledRules       []*CompiledRule // All compiled rules in the program
	stringLiterals      []string        // String literal pool for OpPushStr
	stringSets          [][]string      // String sets for OpOf
	allStrings          []string        // All string identifiers for current rule
	anonymousStrings    []string        // Anonymous string identifiers for current rule
	stringArena         []string        // Arena for dynamic strings (new in PR 3)
	regexCache          map[string]compiledRegex
	PreserveRuleResults bool // If true, Reset() will not clear ruleResults
	debugMode           bool // Debug mode flag for instruction tracing
}

// Iterator defines the state for a runtime for-loop
type Iterator struct {
	Type       Opcode // The type of iterator (e.g. OpIterStartIntRange)
	Variables  []int  // Memory slots where loop variables are stored
	Count      int    // Number of matches
	Index      int    // Current iteration index
	Total      int    // Total number of elements
	Quantifier int    // Quantifier for condition (e.g. ForAll, ForAny, ForNone, ForExpression)
	QuantExpr  int    // Target expression count if Quantifier == ForExpression
	EndIP      int    // Instruction pointer to jump to when done
	// Range/String Set state
	StartValue int64
	EndValue   int64
	StringIDs  []string
}

type compiledRegex struct {
	code  []byte
	flags regex.Flags
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

// Reset resets the match context
func (mc *MatchContext) Reset(data []byte) {
	mc.Data = data
	for k := range mc.Matches {
		delete(mc.Matches, k)
	}
}

// OpcodeHandler function type for opcode dispatch
type OpcodeHandler func(*Interpreter) error

// opcodeTable is a direct function table for opcode dispatch
var opcodeTable = [256]OpcodeHandler{
	// Control flow operations
	OpNop:          (*Interpreter).executeNop,
	OpHalt:           (*Interpreter).executeHalt,
	OpJz:           (*Interpreter).executeJz,
	OpJzP:          (*Interpreter).executeJzP,
	OpJtrue:          (*Interpreter).executeJtrue,
	OpJtrueP:       (*Interpreter).executeJtrueP,
	OpJfalse:     (*Interpreter).executeJfalse,
	OpJfalseP:      (*Interpreter).executeJfalseP,
	OpJlP:          (*Interpreter).executeJlP,
	OpJleP:         (*Interpreter).executeJleP,
	OpJnundefP:      (*Interpreter).executeJnundefP,
	OpJundefP:       (*Interpreter).executeJundefP,
	OpJundef:        (*Interpreter).executeJundef,
	OpJnundef:      (*Interpreter).executeJnundef,

	// Stack operations
	OpPush:         (*Interpreter).executePush,
	OpPop:          (*Interpreter).executePop,
	OpCall:         (*Interpreter).executeCall,
	OpPush8:        (*Interpreter).executePush8,
	OpPush16:       (*Interpreter).executePush16,
	OpPush32:       (*Interpreter).executePush32,
	OpPushU:          (*Interpreter).executePushU,
	OpPushDbl:      (*Interpreter).executePushDouble,
	OpPushRuleRef: (*Interpreter).executePushRuleRef,
	OpPushStr:      (*Interpreter).executePushString,

	// Bitwise operations
	OpBitwiseAnd:     (*Interpreter).executeBitwiseAnd,
	OpBitwiseOr:     (*Interpreter).executeBitwiseOr,
	OpBitwiseXor:    (*Interpreter).executeBitwiseXor,
	OpBitwiseNot:   (*Interpreter).executeBitwiseNot,
	OpShl:        (*Interpreter).executeShiftLeft,
	OpShr:        (*Interpreter).executeShiftRight,

	// Arithmetic operations
	OpIntAdd:       (*Interpreter).executeIntegerAdd,
	OpIntSub:       (*Interpreter).executeIntegerSub,
	OpIntMul:       (*Interpreter).executeIntegerMul,
	OpIntDiv:     (*Interpreter).executeIntegerDiv,
	OpMod:        (*Interpreter).executeIntegerMod,
	OpIntMinus:  (*Interpreter).executeIntegerNegation,
	OpDblAdd:       (*Interpreter).executeDoubleAdd,
	OpDblSub:       (*Interpreter).executeDoubleSub,
	OpDblMul:       (*Interpreter).executeDoubleMul,
	OpDblDiv:       (*Interpreter).executeDoubleDiv,
	OpDblMinus:  (*Interpreter).executeDoubleNegation,

	// Comparison operations
	OpIntEq:        (*Interpreter).executeIntegerEq,
	OpIntNeq:      (*Interpreter).executeIntegerNeq,
	OpIntLt:        (*Interpreter).executeIntegerLt,
	OpIntGt:        (*Interpreter).executeIntegerGt,
	OpIntLe:        (*Interpreter).executeIntegerLe,
	OpIntGe:      (*Interpreter).executeIntegerGe,
	OpDblEq:       (*Interpreter).executeDoubleEq,
	OpDblNeq:       (*Interpreter).executeDoubleNeq,
	OpDblLt:        (*Interpreter).executeDoubleLt,
	OpDblGt:       (*Interpreter).executeDoubleGt,
	OpDblLe:        (*Interpreter).executeDoubleLe,
	OpDblGe:       (*Interpreter).executeDoubleGe,
	OpStrEq:       (*Interpreter).executeStringEq,
	OpStrNeq:     (*Interpreter).executeStringNeq,
	OpStrLt:       (*Interpreter).executeStringLt,
	OpStrGt:        (*Interpreter).executeStringGt,
	OpStrLe:        (*Interpreter).executeStringLe,
	OpStrGe:       (*Interpreter).executeStringGe,

	// Logical operations
	OpAnd:          (*Interpreter).executeAndOperation,
	OpOr:          (*Interpreter).executeOrOperation,
	OpNot:         (*Interpreter).executeNotOperation,
	OpDefined:      (*Interpreter).executeDefinedOperation,

	// Memory operations
	OpPushM:         (*Interpreter).executePushMemory,
	OpPopM:         (*Interpreter).executePopMemory,
	OpClearM:     (*Interpreter).executeClearMemory,
	OpIncrM:    (*Interpreter).executeIncrementMemory,
	OpSwapundef: (*Interpreter).executeSwapUndefined,
	OpAddM:        (*Interpreter).executeAddMemory,
	OpSetM:        (*Interpreter).executeSetMemory,

	// File operations
	OpEntrypoint:    (*Interpreter).executeEntrypoint,
	OpFilesize:  (*Interpreter).executeFilesize,

	// Integer read operations
	OpInt8:        (*Interpreter).executeReadInt8,
	OpInt16:        (*Interpreter).executeReadInt16,
	OpInt32:        (*Interpreter).executeReadInt32,
	OpInt64:       (*Interpreter).executeReadInt64,
	OpUint8:       (*Interpreter).executeReadUint8,
	OpUint16:     (*Interpreter).executeReadUint16,
	OpUint32:     (*Interpreter).executeReadUint32,
	OpUint64:      (*Interpreter).executeReadUint64,
	OpInt8be:     (*Interpreter).executeReadInt8be,
	OpInt16be:    (*Interpreter).executeReadInt16be,
	OpInt32be:     (*Interpreter).executeReadInt32be,
	OpUint8be:    (*Interpreter).executeReadUint8be,
	OpUint16be:      (*Interpreter).executeReadUint16be,
	OpUint32be:     (*Interpreter).executeReadUint32be,
	OpInt64be:      (*Interpreter).executeReadInt64be,
	OpUint64be:     (*Interpreter).executeReadUint64be,

	// String operations
	OpLength:       (*Interpreter).executeLengthOperation,
	OpCount:        (*Interpreter).executeCountOperation,
	OpFound:        (*Interpreter).executeFoundOperation,
	OpFoundAt:   (*Interpreter).executeFoundAtOperation,
	OpFoundIn:    (*Interpreter).executeFoundInOperation,
	OpOffset:       (*Interpreter).executeOffsetOperation,
	OpOf:         (*Interpreter).executeOfOperation,
	OpMatches:      (*Interpreter).executeMatchesOperation,
	OpContains:     (*Interpreter).executeContainsOperation,
	OpStartswith:  (*Interpreter).executeStartswithOperation,
	OpEndswith:   (*Interpreter).executeEndswithOperation,
	OpIcontains:   (*Interpreter).executeIcontainsOperation,
	OpIstartswith:   (*Interpreter).executeIstartswithOperation,
	OpIendswith:   (*Interpreter).executeIendswithOperation,
	OpIequals:     (*Interpreter).executeIequalsOperation,
	OpIntToDbl:   (*Interpreter).executeIntToDouble,
	OpStrToBool:    (*Interpreter).executeStringToBool,

	// Rule operations
	OpPushRule:    (*Interpreter).executePushRuleOperation,
	OpInitRule:    (*Interpreter).executeInitRuleOperation,
	OpMatchRule:  (*Interpreter).executeMatchRuleOperation,

	// Iterator operations
	OpIterNext:        (*Interpreter).executeIterNext,
	OpIterStartArray:   (*Interpreter).executeIterStartArray,
	OpIterStartDict:  (*Interpreter).executeIterStartDict,
	OpIterStartIntRange: (*Interpreter).executeIterStartIntRange,
	OpIterStartIntEnum: (*Interpreter).executeIterStartIntEnum,
	OpIterStartStringSet: (*Interpreter).executeIterStartStringSet,
	OpIterCondition:  (*Interpreter).executeIterCondition,
	OpIterEnd:       (*Interpreter).executeIterEnd,
	OpIterStartTextStringSet: (*Interpreter).executeIterStartTextStringSet,
	OpOfPercent:     (*Interpreter).executeOfPercent,
	OpOfFoundIn:    (*Interpreter).executeOfFoundIn,
	OpCountIn:        (*Interpreter).executeCountIn,
	OpOfFoundAt:    (*Interpreter).executeOfFoundAt,

	// Object operations
	OpObjLoad:       (*Interpreter).executeObjLoad,
	OpObjValue:    (*Interpreter).executeObjValue,
	OpObjField:       (*Interpreter).executeObjField,
	OpIndexArray:       (*Interpreter).executeIndexArray,

	// Import operations
	OpImport:        (*Interpreter).executeImport,
	OpLookupDict:   (*Interpreter).executeLookupDict,

	// Type conversion
	OpConcat:        (*Interpreter).executeConcat,

	// Unused operations
	OpUnused:         (*Interpreter).executeUnused,

	// Error handling
	OpError:         (*Interpreter).executeError,
}

// interpreterPool allows reusing interpreter instances to reduce allocation overhead
var interpreterPool = sync.Pool{
	New: func() any {
		return &Interpreter{
			stack:       make([]Value, 0, 256),
			ruleResults: make(map[string]bool),
			regexCache:  make(map[string]compiledRegex),
			// memory is array, automatically zero-initialized
		}
	},
}

// matchContextPool allows reusing match context instances to reduce allocation overhead
var matchContextPool = sync.Pool{
	New: func() any {
		return &MatchContext{
			Matches: make(map[string][]Match),
		}
	},
}

// NewInterpreter creates a new bytecode interpreter
func NewInterpreter(bytecode []byte) *Interpreter {
	i := interpreterPool.Get().(*Interpreter)
	i.bytecode = bytecode
	i.ip = 0
	i.stopped = false
	i.result = nil
	i.currentRule = ""

	// Create default match context from pool if needed (mimics original behavior)
	// If the caller overwrites this with SetMatchContext, this one will be GC'd (leaked from pool)
	// which is acceptable.
	if i.matchContext == nil {
		i.matchContext = matchContextPool.Get().(*MatchContext)
	}
	// Note: matchContextPool.Get() returns struct with Matches map initialized.
	i.matchContext.Reset(nil)

	return i
}

// Release returns the interpreter to the pool
func (i *Interpreter) Release() {
	i.Reset()
	interpreterPool.Put(i)
}

// executeMainLoop executes the bytecode program
func (i *Interpreter) executeMainLoop() error {
	for !i.stopped && i.ip < len(i.bytecode) {
		opcode := Opcode(i.bytecode[i.ip])
		i.ip++

		if i.debugMode {
			i.debugExecution(opcode)
		}

		// Direct function table dispatch
		handler := opcodeTable[opcode]
		if handler == nil {
			return &InterpreterError{
				Type:    ErrorUnsupportedOpcode,
				Opcode:  opcode,
				Message: fmt.Sprintf("unsupported opcode: %v", opcode),
			}
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

// debugExecution prints debug information for the current opcode
func (i *Interpreter) debugExecution(opcode Opcode) {
	fmt.Printf("DEBUG: Executing opcode %d (%s) at ip %d\n", opcode, opcode.String(), i.ip-1)

	// Print memory state for specific opcodes that interact with memory
	switch opcode {
	case OpPushM, OpPopM:
		fmt.Printf("DEBUG: Memory slots in use: %d\n", i.countUsedMemorySlots())
	case OpPush, OpPop:
		fmt.Printf("DEBUG: Stack operation - current depth: %d\n", len(i.stack))
	}
}

// debugStackState prints debug information for stack state after opcode execution
func (i *Interpreter) debugStackState(opcode Opcode) {
	fmt.Printf("DEBUG: Stack after %s: len=%d\n", opcode.String(), len(i.stack))
	if len(i.stack) > 0 {
		top := i.stack[len(i.stack)-1]
		switch top.Type {
		case ValueTypeInt:
			fmt.Printf("DEBUG: Top of stack: Type=Int, Value=%d\n", top.IntVal)
		case ValueTypeDouble:
			fmt.Printf("DEBUG: Top of stack: Type=Double, Value=%f\n", top.DoubleVal)
		case ValueTypeString:
			fmt.Printf("DEBUG: Top of stack: Type=String, Length=%d\n", len(i.getString(top)))
		default:
			fmt.Printf("DEBUG: Top of stack: Type=%d, IntVal=%d\n", top.Type, top.IntVal)
		}
	}
}

// countUsedMemorySlots counts how many memory slots are currently in use
func (i *Interpreter) countUsedMemorySlots() int {
	count := 0
	for _, slot := range i.memory {
		if slot.Type != ValueTypeUndefined {
			count++
		}
	}
	return count
}

// storeExecutionResult stores the final execution result
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

// cleanupStack cleans up the stack after execution
func (i *Interpreter) cleanupStack() {
	// Only clean up stack if execution was successful and there are excess values
	// Leave the final result value on stack for compatibility with tests
	if i.result == nil && len(i.stack) > 1 {
		// Keep only the top value (result), remove excess
		i.stack = i.stack[len(i.stack)-1:]
	}
}

// validateBytecodeBounds checks if there are enough bytes remaining to read the specified amount
func (i *Interpreter) validateBytecodeBounds(opcode Opcode, bytesNeeded int) error {
	if i.ip+bytesNeeded > len(i.bytecode) {
		return &InterpreterError{
			Type:    ErrorInvalidBytecode,
			Opcode:  opcode,
			Message: "unexpected end of bytecode",
		}
	}
	return nil
}

// validateStackUnderflow checks if the stack has at least one value
func (i *Interpreter) validateStackUnderflow(opcode Opcode) error {
	if len(i.stack) == 0 {
		return &InterpreterError{
			Type:    ErrorStackUnderflow,
			Opcode:  opcode,
			Message: "stack underflow",
		}
	}
	return nil
}

// validateStackUnderflowN checks if the stack has at least n values
func (i *Interpreter) validateStackUnderflowN(opcode Opcode, n int) error {
	if len(i.stack) < n {
		return &InterpreterError{
			Type:    ErrorStackUnderflow,
			Opcode:  opcode,
			Message: "stack underflow",
		}
	}
	return nil
}

// pushString pushes a string value to the stack
func (i *Interpreter) pushString(s string) error {
	// This is a helper function for string literals
	return i.executePushString()
}

// getString returns the string value for a given Value
func (i *Interpreter) getString(v Value) string {
	if v.StringRef < 0 {
		// Static string reference
		return i.stringLiterals[v.StringRef]
	}
	// Dynamic string reference
	return i.stringArena[v.StringRef]
}

// SetMatchContext sets the match context for pattern matching
func (i *Interpreter) SetMatchContext(ctx *MatchContext) {
	i.matchContext = ctx
}

// SetCompiledRules sets the compiled rules for the interpreter
func (i *Interpreter) SetCompiledRules(rules []*CompiledRule) {
	i.compiledRules = rules
}

// GetMatchContext returns the match context
func (i *Interpreter) GetMatchContext() *MatchContext {
	return i.matchContext
}

// SetCurrentRule sets the current rule being executed
func (i *Interpreter) SetCurrentRule(ruleName string) {
	i.currentRule = ruleName
}

// GetString returns the string value for a given Value
func (i *Interpreter) GetString(v Value) string {
	return i.getString(v)
}

// PushString pushes a string to the stack
func (i *Interpreter) PushString(s string) error {
	return i.executePushString()
}

// SetRuleResults sets the rule results map
func (i *Interpreter) SetRuleResults(ruleResults map[string]bool) {
	i.ruleResults = ruleResults
}

// SetStringLiterals sets the string literals
func (i *Interpreter) SetStringLiterals(literals []string) {
	i.stringLiterals = literals
}

// SetStringSets sets the string sets
func (i *Interpreter) SetStringSets(sets [][]string) {
	i.stringSets = sets
}

// SetMemoryString sets a memory string
func (i *Interpreter) SetMemoryString(index int, identifier string) {
	// This is a helper function for memory string operations
}

// GetRuleResults returns the rule results
func (i *Interpreter) GetRuleResults() map[string]bool {
	return i.ruleResults
}

// GetStack returns the current stack
func (i *Interpreter) GetStack() []Value {
	return i.stack
}

// GetMemory returns the memory slots
func (i *Interpreter) GetMemory() [256]Value {
	return i.memory
}

// GetMemoryAt returns a specific memory slot
func (i *Interpreter) GetMemoryAt(address int) Value {
	return i.memory[address]
}

// Reset resets the interpreter to its initial state
func (i *Interpreter) Reset() {
	i.bytecode = nil
	i.ip = 0
	i.stopped = false
	i.result = nil
	i.currentRule = ""
	i.stack = i.stack[:0]
	i.ruleResults = make(map[string]bool)
	i.matchContext.Reset(nil)
}

// Execute executes the bytecode program
func (i *Interpreter) Execute() error {
	return i.executeMainLoop()
}

// EnableDebugMode enables debug mode
func (i *Interpreter) EnableDebugMode() {
	i.debugMode = true
}

// DisableDebugMode disables debug mode
func (i *Interpreter) DisableDebugMode() {
	i.debugMode = false
}

// IsDebugModeEnabled checks if debug mode is enabled
func (i *Interpreter) IsDebugModeEnabled() bool {
	return i.debugMode
}

// Error types and structures
type InterpreterErrorType int

const (
	ErrorInvalidBytecode InterpreterErrorType = iota
	ErrorStackUnderflow
	ErrorUnsupportedOpcode
)

// InterpreterError represents an error that occurred during interpreter execution
type InterpreterError struct {
	Type    InterpreterErrorType
	Opcode  Opcode
	Message string
}

func (e *InterpreterError) Error() string {
	return fmt.Sprintf("interpreter error (%d): %s", e.Type, e.Message)
}

// Stats represents interpreter statistics
type Stats struct {
	InstructionCount int
	StackDepth       int
	MemorySlots      int
}

// GetStats returns interpreter statistics
func (i *Interpreter) GetStats() map[string]any {
	return map[string]any{
		"instruction_count": i.ip,
		"stack_depth": len(i.stack),
		"memory_slots": i.countUsedMemorySlots(),
	}
}