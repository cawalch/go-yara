package compiler

import (
	"fmt"
	"math"
	"strconv"
	"sync"

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
	currentCompiledRule *CompiledRule   // Currently executing rule (for int string ID resolution)
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
	// Optional offset constraints for string set iteration
	InRange       bool // Filter matches to those within [OffsetMin..OffsetMax]
	OffsetMin     int64
	OffsetMax     int64
	AtOffset      bool // Filter matches to those at exactly AtOffsetValue
	AtOffsetValue int64
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

// Release returns the interpreter to the pool for reuse
func (i *Interpreter) Release() {
	i.bytecode = nil
	i.compiledRules = nil
	i.stringLiterals = nil
	i.stringSets = nil
	i.allStrings = nil
	i.anonymousStrings = nil
	i.matchContext = nil // Don't return to pool as we don't know ownership (caller vs internal)

	// Clear memory (hard reset)
	for idx := range i.memory {
		i.memory[idx] = Value{} // Reset to zero value
	}

	// Clear regex cache?
	// Prefer to keep it for reuse efficiency, assuming keys are consistent across runs.
	// If strict clean state is required, uncomment:
	// clear(i.regexCache)

	// Clear string arena
	i.stringArena = i.stringArena[:0]

	// Clear iterators
	i.iterators = i.iterators[:0]

	interpreterPool.Put(i)
}

// pushString appends a string to the arena and pushes a Value pointing to it
func (i *Interpreter) pushString(s string) error {
	idx := len(i.stringArena)
	i.stringArena = append(i.stringArena, s)
	return i.push(Value{Type: ValueTypeString, StringRef: int64(idx)})
}

// getString resolves a Value to a string
func (i *Interpreter) getString(v Value) string {
	if v.Type != ValueTypeString {
		return ""
	}
	// Postive index = Arena
	if v.StringRef >= 0 {
		if int(v.StringRef) < len(i.stringArena) {
			return i.stringArena[v.StringRef]
		}
		return ""
	}
	// Negative index = Static string literal
	// -1 = stringLiterals[0]
	// -2 = stringLiterals[1]
	idx := -v.StringRef - 1
	if int(idx) < len(i.stringLiterals) {
		return i.stringLiterals[idx]
	}
	return ""
}

// SetMatchContext sets the pattern matching context
func (i *Interpreter) SetMatchContext(ctx *MatchContext) {
	i.matchContext = ctx
}

// SetCompiledRules sets the compiled rules for rule reference resolution
func (i *Interpreter) SetCompiledRules(rules []*CompiledRule) {
	i.compiledRules = rules
	if i.currentRule != "" {
		i.SetCurrentRule(i.currentRule)
	}
}

// GetMatchContext returns the current match context
func (i *Interpreter) GetMatchContext() *MatchContext {
	return i.matchContext
}

// SetCurrentRule sets the name of the currently executing rule
func (i *Interpreter) SetCurrentRule(ruleName string) {
	i.currentRule = ruleName
	if len(i.compiledRules) == 0 {
		return
	}
	for _, rule := range i.compiledRules {
		if rule.Name != ruleName {
			continue
		}
		i.currentCompiledRule = rule
		i.stringLiterals = rule.StringLiterals
		i.stringSets = rule.StringSets
		i.allStrings = rule.StringIdentifiers()
		i.anonymousStrings = rule.AnonymousStrings
		i.bytecode = rule.Bytecode // Ensure bytecode is updated for the rule
		return
	}
}

// GetString resolves a Value to a string (exported version of getString)
func (i *Interpreter) GetString(v Value) string {
	return i.getString(v)
}

// PushString appends a string to the arena and pushes a Value pointing to it (exported)
func (i *Interpreter) PushString(s string) error {
	return i.pushString(s)
}

// SetRuleResults sets the shared rule results map
func (i *Interpreter) SetRuleResults(ruleResults map[string]bool) {
	i.ruleResults = ruleResults
}

// SetStringLiterals sets the string literal pool for OpPushStr.
func (i *Interpreter) SetStringLiterals(literals []string) {
	i.stringLiterals = literals
}

// SetStringSets sets the string sets used by OpOf.
func (i *Interpreter) SetStringSets(sets [][]string) {
	i.stringSets = sets
}

// SetMemoryString sets a string identifier in memory at the specified index
func (i *Interpreter) SetMemoryString(index int, identifier string) {
	if index >= 0 && index < len(i.memory) {
		idx := len(i.stringArena)
		i.stringArena = append(i.stringArena, identifier)
		i.memory[index] = Value{
			Type:      ValueTypeString,
			StringRef: int64(idx),
		}
	}
}

// GetRuleResults returns the execution results for all rules
func (i *Interpreter) GetRuleResults() map[string]bool {
	return i.ruleResults
}

// GetStack returns a copy of the current stack (for debugging)
func (i *Interpreter) GetStack() []Value {
	stackCopy := make([]Value, len(i.stack))
	copy(stackCopy, i.stack)
	return stackCopy
}

// GetMemory returns a copy of the current memory state (for debugging)
func (i *Interpreter) GetMemory() [256]Value {
	return i.memory
}

// GetMemoryAt returns the value at a specific memory address
func (i *Interpreter) GetMemoryAt(address int) Value {
	if address >= 0 && address < len(i.memory) {
		return i.memory[address]
	}
	return Value{Type: ValueTypeUndefined}
}

// Reset resets the interpreter state for new execution
func (i *Interpreter) Reset() {
	i.ip = 0
	i.stack = i.stack[:0]
	// Don't clear memory slots that contain string identifiers
	// Only clear undefined values
	for idx := range i.memory {
		if i.memory[idx].Type != ValueTypeString {
			i.memory[idx] = Value{Type: ValueTypeUndefined}
		}
	}
	i.stopped = false
	i.result = nil
	if i.ruleResults == nil {
		i.ruleResults = make(map[string]bool)
	} else if !i.PreserveRuleResults {
		clear(i.ruleResults)
	}
	i.iterators = i.iterators[:0]
}

// Execute runs the bytecode
func (i *Interpreter) Execute() error {
	// Reset interpreter state for clean execution
	i.Reset()

	return i.executeMainLoop()
}

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

	// Iterator operations — not yet implemented
	opcodeTable[OpIterStartArray] = (*Interpreter).executeIterUnimplemented
	opcodeTable[OpIterStartDict] = (*Interpreter).executeIterUnimplemented
	opcodeTable[OpIterStartTextStringSet] = (*Interpreter).executeIterUnimplemented
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

// Value.String() returns a human-readable representation of the value.
func (v Value) String() string {
	switch v.Type {
	case ValueTypeInt:
		return strconv.FormatInt(v.IntVal, 10)
	case ValueTypeDouble:
		if math.IsNaN(v.DoubleVal) {
			return "nan"
		}
		if math.IsInf(v.DoubleVal, 1) {
			return "inf"
		}
		if math.IsInf(v.DoubleVal, -1) {
			return "-inf"
		}
		return fmt.Sprintf("%f", v.DoubleVal)
	case ValueTypeString:
		// Cannot resolve string value without interpreter context easily here
		// Need refactor if Value.String() is critical for debugging without context
		return "string"
	case ValueTypeUndefined:
		return "undefined"
	default:
		return "unknown"
	}
}

// GetStats returns execution statistics
func (i *Interpreter) GetStats() map[string]any {
	return map[string]any{
		"instructions_executed": i.ip,
		"stack_depth":           len(i.stack),
		"rules_executed":        len(i.ruleResults),
		"halted":                i.stopped,
		"current_rule":          i.currentRule,
	}
}

// EnableDebugMode enables debug information collection
func (i *Interpreter) EnableDebugMode() {
	i.debugMode = true
}

// DisableDebugMode disables debug information collection
func (i *Interpreter) DisableDebugMode() {
	i.debugMode = false
}

// IsDebugModeEnabled returns true if debug mode is currently enabled
func (i *Interpreter) IsDebugModeEnabled() bool {
	return i.debugMode
}
