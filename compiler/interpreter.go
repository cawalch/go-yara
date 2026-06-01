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

// executeOpcode executes a single opcode using direct dispatch
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

// executeOpcode executes a single opcode using direct dispatch
// executeNop handles OpError and OpNop — both are no-ops.
func (i *Interpreter) executeNop() error {
	return nil
}

// executeHalt stops the interpreter loop.
func (i *Interpreter) executeHalt() error {
	i.stopped = true
	return nil
}

// executeLoadVarOperation handles OpLoadVar opcode
func (i *Interpreter) executeLoadVarOperation() error {
	slot, err := i.readAndValidateMemorySlot(OpLoadVar)
	if err != nil {
		return err
	}
	return i.push(i.memory[slot])
}

// --- Individual iterator handlers already exist as methods ---

func (i *Interpreter) executeIterStartIntRange() error {
	if err := i.validateStackUnderflowN(OpIterStartIntRange, 2); err != nil {
		return err
	}

	endVal := i.stack[len(i.stack)-1]
	startVal := i.stack[len(i.stack)-2]
	i.stack = i.stack[:len(i.stack)-2]

	if startVal.Type != ValueTypeInt || endVal.Type != ValueTypeInt {
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpIterStartIntRange, Message: "range bounds must be integers"}
	}

	slot1, err := i.readAndValidateMemorySlot(OpIterStartIntRange)
	if err != nil {
		return err
	}

	iter := Iterator{
		Type:       OpIterStartIntRange,
		Variables:  []int{slot1},
		StartValue: startVal.IntVal,
		EndValue:   endVal.IntVal,
		Index:      0,
		Total:      int(endVal.IntVal - startVal.IntVal + 1),
	}

	if iter.Total <= 0 {
		iter.Total = 0
	}

	i.iterators = append(i.iterators, iter)
	return nil
}

func (i *Interpreter) executeIterStartStringSet() error {
	if err := i.validateStackUnderflow(OpIterStartStringSet); err != nil {
		return err
	}

	stringIDVal := i.stack[len(i.stack)-1]
	i.stack = i.stack[:len(i.stack)-1]

	var ids []string
	switch stringIDVal.Type {
	case ValueTypeInt:
		switch stringIDVal.IntVal {
		case stringSetAll:
			ids = i.allStringIdentifiers()
		case stringSetAnonymous:
			ids = i.anonymousStringIdentifiers()
		default:
			if stringIDVal.IntVal < 0 || int(stringIDVal.IntVal) >= len(i.stringSets) {
				return &InterpreterError{Type: ErrorRuntime, Opcode: OpIterStartStringSet, Message: "invalid string set reference"}
			}
			ids = i.stringSets[stringIDVal.IntVal]
		}
	case ValueTypeString:
		ids = []string{i.getString(stringIDVal)}
	default:
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpIterStartStringSet, Message: "invalid string set type"}
	}

	slot1, err := i.readAndValidateMemorySlot(OpIterStartStringSet)
	if err != nil {
		return err
	}

	iter := Iterator{
		Type:      OpIterStartStringSet,
		Variables: []int{slot1},
		StringIDs: ids,
		Index:     0,
		Total:     len(ids),
	}

	i.iterators = append(i.iterators, iter)
	return nil
}

func (i *Interpreter) executeIterNext() error {
	if len(i.iterators) == 0 {
		return &InterpreterError{Type: ErrorRuntime, Opcode: OpIterNext, Message: "no active iterator"}
	}
	if err := i.validateStackUnderflow(OpIterNext); err != nil {
		return err
	}
	// The target IP is on the stack
	targetIPVal := i.stack[len(i.stack)-1]
	i.stack = i.stack[:len(i.stack)-1]

	iter := &i.iterators[len(i.iterators)-1]

	if iter.Index < iter.Total {
		// Update variables based on type
		switch iter.Type {
		case OpIterStartIntRange:
			i.memory[iter.Variables[0]] = Value{Type: ValueTypeInt, IntVal: iter.StartValue + int64(iter.Index)}
		case OpIterStartStringSet:
			id := iter.StringIDs[iter.Index]
			i.memory[iter.Variables[0]] = Value{Type: ValueTypeString, StringRef: i.resolveStringRef(id)}
		}

		iter.Index++
		i.ip = int(targetIPVal.IntVal)
		return nil
	}

	// Iteration finished, do not jump
	return nil
}

// resolveStringRef resolves a string to a StringRef for the interpreter stack.
func (i *Interpreter) resolveStringRef(str string) int64 {
	// First check pre-computed map on current rule (O(1) lookup)
	if i.currentCompiledRule != nil && i.currentCompiledRule.StringNameToRef != nil {
		if ref, ok := i.currentCompiledRule.StringNameToRef[str]; ok {
			return ref
		}
	}

	// Check static pool
	for idx, s := range i.stringLiterals {
		if s == str {
			return int64(-1 - idx)
		}
	}

	// Otherwise put back in arena
	if err := i.pushString(str); err == nil {
		val := i.stack[len(i.stack)-1]
		i.stack = i.stack[:len(i.stack)-1]
		return val.StringRef
	}
	return -1
}

func (i *Interpreter) executeIterCondition() error {
	if len(i.iterators) == 0 {
		return &InterpreterError{Type: ErrorRuntime, Opcode: OpIterCondition, Message: "no active iterator"}
	}
	if err := i.validateStackUnderflow(OpIterCondition); err != nil {
		return err
	}

	condVal := i.stack[len(i.stack)-1]
	i.stack = i.stack[:len(i.stack)-1]

	iter := &i.iterators[len(i.iterators)-1]
	if i.isTruthy(condVal) {
		iter.Count++
	}

	return nil
}

func (i *Interpreter) executeIterPushTotal() error {
	if len(i.iterators) == 0 {
		return &InterpreterError{Type: ErrorRuntime, Opcode: OpIterPushTotal, Message: "no active iterator"}
	}

	iter := i.iterators[len(i.iterators)-1]
	return i.push(Value{Type: ValueTypeInt, IntVal: int64(iter.Total)})
}

func (i *Interpreter) executeIterEnd() error {
	if len(i.iterators) == 0 {
		return &InterpreterError{Type: ErrorRuntime, Opcode: OpIterEnd, Message: "no active iterator"}
	}

	iter := i.iterators[len(i.iterators)-1]
	i.iterators = i.iterators[:len(i.iterators)-1]

	return i.push(Value{Type: ValueTypeInt, IntVal: int64(iter.Count)})
}

// executeStackOpcode handles stack operations
// executeIterUnimplemented returns an error for iterator types not yet implemented.
func (i *Interpreter) executeIterUnimplemented() error {
	return &InterpreterError{
		Type:    ErrorUnsupportedOpcode,
		Opcode:  OpIterStartArray, // representative
		Message: "iterator type not yet implemented",
	}
}

// executePush8 handles OpPush8 opcode
func (i *Interpreter) executePush8() error {
	if err := i.validateBytecodeBounds(OpPush8, 1); err != nil {
		return err
	}
	val := int64(i.bytecode[i.ip])
	i.ip++
	return i.push(Value{Type: ValueTypeInt, IntVal: val})
}

// executePush16 handles OpPush16 opcode
func (i *Interpreter) executePush16() error {
	if err := i.validateBytecodeBounds(OpPush16, 2); err != nil {
		return err
	}
	val := int64(i.bytecode[i.ip]) | int64(i.bytecode[i.ip+1])<<8
	i.ip += 2
	return i.push(Value{Type: ValueTypeInt, IntVal: val})
}

// executePush32 handles OpPush32 opcode
func (i *Interpreter) executePush32() error {
	if err := i.validateBytecodeBounds(OpPush32, 4); err != nil {
		return err
	}
	val := int64(i.bytecode[i.ip]) | int64(i.bytecode[i.ip+1])<<8 |
		int64(i.bytecode[i.ip+2])<<16 | int64(i.bytecode[i.ip+3])<<24
	i.ip += 4
	return i.push(Value{Type: ValueTypeInt, IntVal: val})
}

// executePushU handles OpPush_U opcode
func (i *Interpreter) executePushU() error {
	if i.ip+3 >= len(i.bytecode) {
		return i.push(Value{Type: ValueTypeUndefined})
	}
	val := int64(i.bytecode[i.ip]) | int64(i.bytecode[i.ip+1])<<8 |
		int64(i.bytecode[i.ip+2])<<16 | int64(i.bytecode[i.ip+3])<<24
	i.ip += 4
	return i.push(Value{Type: ValueTypeInt, IntVal: val})
}

// executePushDouble handles OpPushDbl opcode
func (i *Interpreter) executePushDouble() error {
	if err := i.validateBytecodeBounds(OpPushDbl, 8); err != nil {
		return err
	}
	bits := uint64(i.bytecode[i.ip]) | uint64(i.bytecode[i.ip+1])<<8 |
		uint64(i.bytecode[i.ip+2])<<16 | uint64(i.bytecode[i.ip+3])<<24 |
		uint64(i.bytecode[i.ip+4])<<32 | uint64(i.bytecode[i.ip+5])<<40 |
		uint64(i.bytecode[i.ip+6])<<48 | uint64(i.bytecode[i.ip+7])<<56
	i.ip += 8
	val := math.Float64frombits(bits)
	return i.push(Value{Type: ValueTypeDouble, DoubleVal: val})
}

// executePushRuleRef handles OpPushRuleRef opcode
func (i *Interpreter) executePushRuleRef() error {
	if err := i.validateBytecodeBounds(OpPushRuleRef, 1); err != nil {
		return err
	}
	ruleIdx := int(i.bytecode[i.ip])
	i.ip++
	if ruleIdx >= len(i.compiledRules) {
		return &InterpreterError{Type: ErrorInvalidBytecode, Opcode: OpPushRuleRef, Message: fmt.Sprintf("rule index %d out of range", ruleIdx)}
	}
	ruleName := i.compiledRules[ruleIdx].Name
	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(i.ruleResults[ruleName])})
}

// executePushString handles OpPushStr opcode
func (i *Interpreter) executePushString() error {
	if err := i.validateBytecodeBounds(OpPushStr, 4); err != nil {
		return err
	}
	idx := int(uint32(i.bytecode[i.ip]) |
		uint32(i.bytecode[i.ip+1])<<8 |
		uint32(i.bytecode[i.ip+2])<<16 |
		uint32(i.bytecode[i.ip+3])<<24)
	i.ip += 4
	if idx < 0 || idx >= len(i.stringLiterals) {
		return i.push(Value{Type: ValueTypeUndefined})
	}
	// Push reference to static string literal (negative index)
	// -1 -> index 0, -2 -> index 1, etc.
	return i.push(Value{Type: ValueTypeString, StringRef: int64(-1 - idx)})
}

// executePop handles OpPop opcode
func (i *Interpreter) executePop() error {
	if err := i.validateStackUnderflow(OpPop); err != nil {
		return err
	}
	i.stack = i.stack[:len(i.stack)-1]
	return nil
}

// executeCall handles OpCall opcode for built-in functions.
func (i *Interpreter) executeCall() error {
	if err := i.validateBytecodeBounds(OpCall, 4); err != nil {
		return err
	}
	encoded := uint32(i.bytecode[i.ip]) |
		uint32(i.bytecode[i.ip+1])<<8 |
		uint32(i.bytecode[i.ip+2])<<16 |
		uint32(i.bytecode[i.ip+3])<<24
	i.ip += 4

	fn, argc := decodeBuiltinCall(encoded)
	if argc <= 0 {
		return &InterpreterError{Type: ErrorInvalidBytecode, Opcode: OpCall, Message: "invalid argument count"}
	}
	if err := i.validateStackUnderflowN(OpCall, argc); err != nil {
		return err
	}

	args := make([]Value, argc)
	for idx := argc - 1; idx >= 0; idx-- {
		args[idx] = i.stack[len(i.stack)-1]
		i.stack = i.stack[:len(i.stack)-1]
	}

	switch fn {
	case builtinConcat:
		return i.executeBuiltinConcat(args)
	case builtinToString:
		return i.executeBuiltinToString(args)
	case builtinInt:
		return i.executeBuiltinInt(args)
	case builtinMD5:
		return i.executeBuiltinMD5(args)
	case builtinSHA1:
		return i.executeBuiltinSHA1(args)
	case builtinSHA256:
		return i.executeBuiltinSHA256(args)
	default:
		return &InterpreterError{Type: ErrorInvalidBytecode, Opcode: OpCall, Message: "unknown builtin"}
	}
}

func (i *Interpreter) executeBuiltinConcat(args []Value) error {
	if len(args) < 2 {
		return &InterpreterError{Type: ErrorRuntime, Opcode: OpCall, Message: "concat requires at least 2 arguments"}
	}
	var sb strings.Builder
	for _, arg := range args {
		str, err := i.valueToString(arg)
		if err != nil {
			return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpCall, Message: err.Error()}
		}
		sb.WriteString(str)
	}
	return i.pushString(sb.String())
}

func (i *Interpreter) executeBuiltinToString(args []Value) error {
	if len(args) != 1 {
		return &InterpreterError{Type: ErrorRuntime, Opcode: OpCall, Message: "tostring requires exactly 1 argument"}
	}
	str, err := i.valueToString(args[0])
	if err != nil {
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpCall, Message: err.Error()}
	}
	return i.pushString(str)
}

func (i *Interpreter) executeBuiltinInt(args []Value) error {
	if len(args) != 1 {
		return &InterpreterError{Type: ErrorRuntime, Opcode: OpCall, Message: "int requires exactly 1 argument"}
	}
	switch v := args[0]; v.Type {
	case ValueTypeInt:
		return i.push(v)
	case ValueTypeDouble:
		return i.push(Value{Type: ValueTypeInt, IntVal: int64(v.DoubleVal)})
	case ValueTypeString:
		s := i.getString(v)
		if s == "" {
			return i.push(Value{Type: ValueTypeInt, IntVal: 0})
		}
		if parsed, err := strconv.ParseInt(strings.TrimSpace(s), 0, 64); err == nil {
			return i.push(Value{Type: ValueTypeInt, IntVal: parsed})
		}
		return i.push(Value{Type: ValueTypeInt, IntVal: 0})
	case ValueTypeUndefined:
		return i.push(Value{Type: ValueTypeInt, IntVal: 0})
	default:
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpCall, Message: "unsupported int() argument type"}
	}
}

func (i *Interpreter) executeBuiltinMD5(args []Value) error {
	data, err := i.extractHashInput(args)
	if err != nil {
		return &InterpreterError{Type: ErrorRuntime, Opcode: OpCall, Message: err.Error()}
	}
	sum := md5.Sum(data) // #nosec G401 -- YARA defines md5() for compatibility
	return i.pushString(hex.EncodeToString(sum[:]))
}

func (i *Interpreter) executeBuiltinSHA1(args []Value) error {
	data, err := i.extractHashInput(args)
	if err != nil {
		return &InterpreterError{Type: ErrorRuntime, Opcode: OpCall, Message: err.Error()}
	}
	sum := sha1.Sum(data) // #nosec G401 -- YARA defines sha1() for compatibility
	return i.pushString(hex.EncodeToString(sum[:]))
}

func (i *Interpreter) executeBuiltinSHA256(args []Value) error {
	data, err := i.extractHashInput(args)
	if err != nil {
		return &InterpreterError{Type: ErrorRuntime, Opcode: OpCall, Message: err.Error()}
	}
	sum := sha256.Sum256(data)
	return i.pushString(hex.EncodeToString(sum[:]))
}

func (i *Interpreter) extractHashInput(args []Value) ([]byte, error) {
	switch len(args) {
	case 1:
		if args[0].Type != ValueTypeString {
			return nil, fmt.Errorf("hash functions expect string or (offset,size)")
		}
		return []byte(i.getString(args[0])), nil
	case 2:
		if args[0].Type != ValueTypeInt || args[1].Type != ValueTypeInt {
			return nil, fmt.Errorf("hash functions expect integer offset and size")
		}
		if args[0].IntVal < 0 || args[1].IntVal < 0 {
			return nil, fmt.Errorf("hash range must be non-negative")
		}
		if i.matchContext == nil || i.matchContext.Data == nil {
			return nil, fmt.Errorf("hash functions require data context")
		}
		start := int(args[0].IntVal)
		size := int(args[1].IntVal)
		if start > len(i.matchContext.Data) || start+size > len(i.matchContext.Data) {
			return nil, fmt.Errorf("hash range out of bounds")
		}
		return i.matchContext.Data[start : start+size], nil
	default:
		return nil, fmt.Errorf("hash functions expect 1 or 2 arguments")
	}
}

func (i *Interpreter) valueToString(v Value) (string, error) {
	switch v.Type {
	case ValueTypeString:
		return i.getString(v), nil
	case ValueTypeInt:
		return strconv.FormatInt(v.IntVal, 10), nil
	case ValueTypeDouble:
		return strconv.FormatFloat(v.DoubleVal, 'g', -1, 64), nil
	case ValueTypeUndefined:
		return "", nil
	default:
		return "", fmt.Errorf("unsupported string conversion")
	}
}

// executeBitwiseAnd handles OpBitwiseAnd opcode
func (i *Interpreter) executeBitwiseAnd() error {
	return i.executeBinaryOp(func(a, b int64) int64 { return a & b }, nil)
}

// executeBitwiseOr handles OpBitwiseOr opcode
func (i *Interpreter) executeBitwiseOr() error {
	return i.executeBinaryOp(func(a, b int64) int64 { return a | b }, nil)
}

// executeBitwiseXor handles OpBitwiseXor opcode
func (i *Interpreter) executeBitwiseXor() error {
	return i.executeBinaryOp(func(a, b int64) int64 { return a ^ b }, nil)
}

// executeBitwiseNot handles OpBitwiseNot opcode
func (i *Interpreter) executeBitwiseNot() error {
	if err := i.validateStackUnderflow(OpBitwiseNot); err != nil {
		return err
	}

	v := i.stack[len(i.stack)-1]
	switch v.Type {
	case ValueTypeInt:
		i.stack[len(i.stack)-1] = Value{Type: ValueTypeInt, IntVal: ^v.IntVal}
	case ValueTypeUndefined:
		i.stack[len(i.stack)-1] = Value{Type: ValueTypeUndefined}
	default:
		i.stack[len(i.stack)-1] = Value{Type: ValueTypeUndefined}
	}
	return nil
}

// executeShiftLeft handles OpShl opcode
func (i *Interpreter) executeShiftLeft() error {
	return i.executeBinaryOp(func(a, b int64) int64 {
		if b < 0 {
			return a << 0
		}
		if b > 63 {
			b = 63
		}
		return a << uint64(b) // #nosec G115 - safe conversion with bounds check above
	}, nil)
}

// executeShiftRight handles OpShr opcode
func (i *Interpreter) executeShiftRight() error {
	return i.executeBinaryOp(func(a, b int64) int64 {
		if b < 0 {
			return a >> 0
		}
		if b > 63 {
			b = 63
		}
		return a >> uint64(b) // #nosec G115 - safe conversion with bounds check above
	}, nil)
}

// Helper methods for opcode classification

// executeAndOperation handles AND logical operation
func (i *Interpreter) executeAndOperation() error {
	return i.executeBinaryOp(func(a, b int64) int64 {
		result := a != 0 && b != 0
		if result {
			return 1
		}
		return 0
	}, nil)
}

// executeOrOperation handles OR logical operation
func (i *Interpreter) executeOrOperation() error {
	return i.executeBinaryOp(func(a, b int64) int64 {
		result := a != 0 || b != 0
		if result {
			return 1
		}
		return 0
	}, nil)
}

// executeNotOperation handles NOT logical operation
func (i *Interpreter) executeNotOperation() error {
	if err := i.validateStackUnderflow(OpNot); err != nil {
		return err
	}
	v := i.stack[len(i.stack)-1]
	result := i.isTruthy(v)
	i.stack[len(i.stack)-1] = Value{Type: ValueTypeInt, IntVal: boolToInt(!result)}
	return nil
}

// executeDefinedOperation handles DEFINED logical operation
func (i *Interpreter) executeDefinedOperation() error {
	if err := i.validateStackUnderflow(OpDefined); err != nil {
		return err
	}
	v := i.stack[len(i.stack)-1]
	defined := v.Type != ValueTypeUndefined
	i.stack[len(i.stack)-1] = Value{Type: ValueTypeInt, IntVal: boolToInt(defined)}
	return nil
}

// executeControlOpcode handles control flow operations
// executeJz jumps if the top-of-stack value is falsy (does not pop).
func (i *Interpreter) executeJz() error {
	return i.executeConditionalJump(OpJz)
}

// executeJzP jumps if the top-of-stack value is falsy (pops first).
func (i *Interpreter) executeJzP() error {
	return i.executeConditionalJump(OpJzP)
}

// executeJtrue jumps if the top-of-stack value is truthy (does not pop).
func (i *Interpreter) executeJtrue() error {
	return i.executeConditionalJump(OpJtrue)
}

// executeJfalse jumps if the top-of-stack value is falsy (does not pop).
func (i *Interpreter) executeJfalse() error {
	return i.executeConditionalJump(OpJfalse)
}

// executeConditionalJump handles jump operations with common logic
func (i *Interpreter) executeConditionalJump(opcode Opcode) error {
	if err := i.validateStackUnderflow(opcode); err != nil {
		return err
	}

	condition := i.stack[len(i.stack)-1]

	if opcode == OpJzP {
		i.stack = i.stack[:len(i.stack)-1]
	}

	// Read the 4-byte relative jump offset operand
	if err := i.validateBytecodeBounds(opcode, 4); err != nil {
		return err
	}
	relativeOffset := int32(i.bytecode[i.ip]) | int32(i.bytecode[i.ip+1])<<8 |
		int32(i.bytecode[i.ip+2])<<16 | int32(i.bytecode[i.ip+3])<<24

	var shouldJump bool
	switch opcode {
	case OpJz, OpJzP:
		shouldJump = !i.isTruthy(condition)
	case OpJtrue:
		shouldJump = i.isTruthy(condition)
	case OpJfalse:
		shouldJump = !i.isTruthy(condition)
	}

	if shouldJump {
		// Jump to the target: the emitter computed the relative offset from the END
		// of the jump instruction (after the 4-byte operand). So the target is:
		// (ip + 4) + relativeOffset, where ip points to the start of the operand
		target := i.ip + 4 + int(relativeOffset)
		if target < 0 || target > len(i.bytecode) {
			return &InterpreterError{Type: ErrorInvalidBytecode, Opcode: opcode,
				Message: fmt.Sprintf("jump target out of bounds: %d (bytecode len: %d)", target, len(i.bytecode))}
		}
		i.ip = target
	} else {
		// Skip past the 4-byte operand
		i.ip += 4
	}
	return nil
}

// readAndValidateMemorySlot reads and validates a memory slot from bytecode.
// Memory slot operands are stored as OperandImmediate32 (4 bytes, little-endian).
func (i *Interpreter) readAndValidateMemorySlot(opcode Opcode) (int, error) {
	if err := i.validateBytecodeBounds(opcode, 4); err != nil {
		return 0, err
	}
	slot := int(i.bytecode[i.ip]) | int(i.bytecode[i.ip+1])<<8 |
		int(i.bytecode[i.ip+2])<<16 | int(i.bytecode[i.ip+3])<<24
	i.ip += 4
	if slot < 0 || slot >= 256 {
		return 0, &InterpreterError{Type: ErrorInvalidBytecode, Opcode: opcode, Message: fmt.Sprintf("memory slot %d out of range", slot)}
	}
	return slot, nil
}

// executePushMemory handles PUSH_M operation
func (i *Interpreter) executePushMemory() error {
	slot, err := i.readAndValidateMemorySlot(OpPushM)
	if err != nil {
		return err
	}
	return i.push(i.memory[slot])
}

// executePopMemory handles POP_M operation
func (i *Interpreter) executePopMemory() error {
	if err := i.validateStackUnderflow(OpPopM); err != nil {
		return err
	}
	slot, err := i.readAndValidateMemorySlot(OpPopM)
	if err != nil {
		return err
	}
	i.memory[slot] = i.stack[len(i.stack)-1]
	i.stack = i.stack[:len(i.stack)-1]
	return nil
}

// executeClearMemory handles CLEAR_M operation
func (i *Interpreter) executeClearMemory() error {
	slot, err := i.readAndValidateMemorySlot(OpClearM)
	if err != nil {
		return err
	}
	i.memory[slot] = Value{Type: ValueTypeUndefined}
	return nil
}

// executeIncrementMemory handles INCR_M operation
func (i *Interpreter) executeIncrementMemory() error {
	slot, err := i.readAndValidateMemorySlot(OpIncrM)
	if err != nil {
		return err
	}
	switch i.memory[slot].Type {
	case ValueTypeInt:
		i.memory[slot].IntVal++
	case ValueTypeUndefined:
		i.memory[slot] = Value{Type: ValueTypeInt, IntVal: 1}
	default:
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpIncrM, Message: "memory slot contains non-integer value"}
	}
	return nil
}

// executeSwapUndefined handles SWAPUNDEF operation
func (i *Interpreter) executeSwapUndefined() error {
	if err := i.validateStackUnderflowN(OpSwapundef, 2); err != nil {
		return err
	}
	top := i.stack[len(i.stack)-1]
	second := i.stack[len(i.stack)-2]
	if top.Type == ValueTypeUndefined && second.Type != ValueTypeUndefined {
		i.stack[len(i.stack)-1] = second
		i.stack[len(i.stack)-2] = top
	}
	return nil
}

// executeFileOperation handles file operations
// executeEntrypoint pushes the file entry point onto the stack.
func (i *Interpreter) executeEntrypoint() error {
	if i.matchContext != nil {
		return i.push(Value{Type: ValueTypeInt, IntVal: i.matchContext.EntryPoint})
	}
	return i.push(Value{Type: ValueTypeInt, IntVal: 0})
}

// executeFilesize pushes the file size onto the stack.
func (i *Interpreter) executeFilesize() error {
	if i.matchContext != nil {
		return i.push(Value{Type: ValueTypeInt, IntVal: i.matchContext.FileSize})
	}
	return i.push(Value{Type: ValueTypeInt, IntVal: 0})
}

// executeIntegerReadOpcode handles integer read operations
// --- Individual integer read handlers ---
// Each handler calls the parameterized executeReadIntOp or executeReadIntOpBE
// with the correct size and signedness, eliminating the per-instruction switch.

func (i *Interpreter) executeReadInt8() error   { return i.executeReadIntOp(1, true) }
func (i *Interpreter) executeReadInt16() error  { return i.executeReadIntOp(2, true) }
func (i *Interpreter) executeReadInt32() error  { return i.executeReadIntOp(4, true) }
func (i *Interpreter) executeReadInt64() error  { return i.executeReadIntOp(8, true) }
func (i *Interpreter) executeReadUint8() error  { return i.executeReadIntOp(1, false) }
func (i *Interpreter) executeReadUint16() error { return i.executeReadIntOp(2, false) }
func (i *Interpreter) executeReadUint32() error { return i.executeReadIntOp(4, false) }
func (i *Interpreter) executeReadUint64() error { return i.executeReadIntOp(8, false) }

func (i *Interpreter) executeReadInt8be() error   { return i.executeReadIntOpBE(1, true) }
func (i *Interpreter) executeReadInt16be() error  { return i.executeReadIntOpBE(2, true) }
func (i *Interpreter) executeReadInt32be() error  { return i.executeReadIntOpBE(4, true) }
func (i *Interpreter) executeReadInt64be() error  { return i.executeReadIntOpBE(8, true) }
func (i *Interpreter) executeReadUint8be() error  { return i.executeReadIntOpBE(1, false) }
func (i *Interpreter) executeReadUint16be() error { return i.executeReadIntOpBE(2, false) }
func (i *Interpreter) executeReadUint32be() error { return i.executeReadIntOpBE(4, false) }
func (i *Interpreter) executeReadUint64be() error { return i.executeReadIntOpBE(8, false) }

// executeStringOperation handles string operations using direct dispatch
// to avoid per-call map allocation on this hot path.

// executeIntToDouble handles OpIntToDbl opcode
func (i *Interpreter) executeIntToDouble() error {
	if err := i.validateStackUnderflow(OpIntToDbl); err != nil {
		return err
	}

	v := i.stack[len(i.stack)-1]
	if v.Type == ValueTypeInt {
		i.stack[len(i.stack)-1] = Value{Type: ValueTypeDouble, DoubleVal: float64(v.IntVal)}
		return nil
	}

	return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpIntToDbl, Message: "integer operand required"}
}

// executeStringToBool handles OpStrToBool opcode
func (i *Interpreter) executeStringToBool() error {
	if err := i.validateStackUnderflow(OpStrToBool); err != nil {
		return err
	}

	v := i.stack[len(i.stack)-1]
	if v.Type == ValueTypeString {
		result := i.getString(v) != ""
		i.stack[len(i.stack)-1] = Value{Type: ValueTypeInt, IntVal: boolToInt(result)}
		return nil
	}

	return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpStrToBool, Message: "string operand required"}
}

// executePushRuleOperation handles OpPushRule opcode
func (i *Interpreter) executePushRuleOperation() error {
	if err := i.validateBytecodeBounds(OpPushRule, 1); err != nil {
		return err
	}
	ruleIdx := int(i.bytecode[i.ip])
	i.ip++
	if ruleIdx >= len(i.compiledRules) {
		return &InterpreterError{Type: ErrorInvalidBytecode, Opcode: OpPushRule, Message: fmt.Sprintf("rule index %d out of range", ruleIdx)}
	}
	ruleName := i.compiledRules[ruleIdx].Name
	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(i.ruleResults[ruleName])})
}

// executeInitRuleOperation handles OpInitRule opcode
func (i *Interpreter) executeInitRuleOperation() error {
	if err := i.validateBytecodeBounds(OpInitRule, 1); err != nil {
		return err
	}
	ruleIdx := int(i.bytecode[i.ip])
	i.ip++
	if ruleIdx >= len(i.compiledRules) {
		return &InterpreterError{Type: ErrorInvalidBytecode, Opcode: OpInitRule, Message: fmt.Sprintf("rule index %d out of range", ruleIdx)}
	}
	i.currentRule = i.compiledRules[ruleIdx].Name
	return i.push(Value{Type: ValueTypeInt, IntVal: 1})
}

// executeMatchRuleOperation handles OpMatchRule opcode
func (i *Interpreter) executeMatchRuleOperation() error {
	if err := i.validateStackUnderflow(OpMatchRule); err != nil {
		return err
	}
	condition := i.stack[len(i.stack)-1]
	i.stack = i.stack[:len(i.stack)-1]
	if i.currentRule == "" {
		return &InterpreterError{Type: ErrorRuntime, Opcode: OpMatchRule, Message: "no current rule context"}
	}
	i.ruleResults[i.currentRule] = i.isTruthy(condition)
	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(i.ruleResults[i.currentRule])})
}

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

// executeStringComparison executes a string comparison operation (for testing)
func (i *Interpreter) executeStringComparison(comparison func(string, string) bool) error {
	a, b, err := i.popTwo()
	if err != nil {
		return err
	}

	if a.Type != ValueTypeString || b.Type != ValueTypeString {
		return &InterpreterError{
			Type:    ErrorTypeMismatch,
			Message: "string comparison operation requires string operands",
		}
	}

	result := int64(0)
	if comparison(i.getString(a), i.getString(b)) {
		result = 1
	}

	return i.push(Value{Type: ValueTypeInt, IntVal: result})
}

// executeReadInt reads an integer from the match context data (for testing)
func (i *Interpreter) executeReadInt(offset int64, size int, unsigned bool) (int64, error) {
	if err := i.validateReadIntAccess(offset); err != nil {
		return 0, err
	}

	data := i.matchContext.Data
	switch size {
	case 1:
		return i.readInt8(data, offset, unsigned)
	case 2:
		return i.readInt16(data, offset, unsigned)
	case 4:
		return i.readInt32(data, offset, unsigned)
	case 8:
		return i.readInt64(data, offset, unsigned)
	default:
		return 0, &InterpreterError{
			Type:    ErrorInvalidMemoryAccess,
			Message: fmt.Sprintf("unsupported integer size: %d", size),
		}
	}
}

func (i *Interpreter) validateReadIntAccess(offset int64) error {
	if i.matchContext == nil {
		return &InterpreterError{
			Type:    ErrorInvalidMemoryAccess,
			Message: "no match context available for reading data",
		}
	}

	data := i.matchContext.Data
	if offset < 0 || int(offset) >= len(data) {
		return &InterpreterError{
			Type:    ErrorInvalidMemoryAccess,
			Message: fmt.Sprintf("offset %d is out of bounds", offset),
		}
	}
	return nil
}

func (i *Interpreter) readInt8(data []byte, offset int64, unsigned bool) (int64, error) {
	val := data[offset]
	if unsigned {
		return int64(val), nil
	}
	return int64(int8(val)), nil
}

func (i *Interpreter) readInt16(data []byte, offset int64, unsigned bool) (int64, error) {
	if offset+1 >= int64(len(data)) {
		return 0, &InterpreterError{
			Type:    ErrorInvalidMemoryAccess,
			Message: "16-bit read extends beyond data bounds",
		}
	}
	val := uint16(data[offset]) | uint16(data[offset+1])<<8
	return safeUint16ToInt64(val, unsigned), nil
}

func (i *Interpreter) readInt32(data []byte, offset int64, unsigned bool) (int64, error) {
	if offset+3 >= int64(len(data)) {
		return 0, &InterpreterError{
			Type:    ErrorInvalidMemoryAccess,
			Message: "32-bit read extends beyond data bounds",
		}
	}
	val := uint32(data[offset]) | uint32(data[offset+1])<<8 |
		uint32(data[offset+2])<<16 | uint32(data[offset+3])<<24
	return safeUint32ToInt64(val, unsigned), nil
}

func (i *Interpreter) readInt64(data []byte, offset int64, unsigned bool) (int64, error) {
	if offset+7 >= int64(len(data)) {
		return 0, &InterpreterError{
			Type:    ErrorInvalidMemoryAccess,
			Message: "64-bit read extends beyond data bounds",
		}
	}
	val := uint64(data[offset]) | uint64(data[offset+1])<<8 |
		uint64(data[offset+2])<<16 | uint64(data[offset+3])<<24 |
		uint64(data[offset+4])<<32 | uint64(data[offset+5])<<40 |
		uint64(data[offset+6])<<48 | uint64(data[offset+7])<<56
	return safeUint64ToInt64(val, unsigned), nil
}

// Helper functions for safe integer conversions
func safeUint16ToInt64(val uint16, unsigned bool) int64 {
	if unsigned {
		return int64(val)
	}
	// For signed values, check if the high bit is set (negative number)
	if val&0x8000 != 0 {
		// Convert from two's complement
		return int64(val) - 0x10000
	}
	return int64(val)
}

func safeUint32ToInt64(val uint32, unsigned bool) int64 {
	if unsigned {
		return int64(val)
	}
	// For signed values, check if the high bit is set (negative number)
	if val&0x80000000 != 0 {
		// Convert from two's complement
		return int64(val) - 0x100000000
	}
	return int64(val)
}

func safeUint64ToInt64(val uint64, unsigned bool) int64 {
	if unsigned {
		return int64(val)
	}
	// For signed values, check if the high bit is set (negative number)
	if val&0x8000000000000000 != 0 {
		// Convert from two's complement using bitwise complement
		return int64(^val + 1)
	}
	return int64(val)
}

func safeByteToInt64(b byte, signed bool) int64 {
	if signed {
		// Check if high bit is set (negative number)
		if b&0x80 != 0 {
			return int64(b) - 0x100
		}
	}
	return int64(b)
}

// Helper functions for opcode execution

// boolToInt converts a boolean to integer (1 for true, 0 for false)
func boolToInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// isTruthy determines if a value is considered truthy
func (i *Interpreter) isTruthy(v Value) bool {
	switch v.Type {
	case ValueTypeInt:
		return v.IntVal != 0
	case ValueTypeDouble:
		return v.DoubleVal != 0
	case ValueTypeString:
		return i.getString(v) != ""
	default:
		return false
	}
}

// executeTypedComparison executes comparison operations for both integer and double types
func (i *Interpreter) executeTypedComparison(opcode Opcode) error {
	if err := i.validateStackUnderflowN(opcode, 2); err != nil {
		return err
	}

	b := i.stack[len(i.stack)-1]
	a := i.stack[len(i.stack)-2]
	i.stack = i.stack[:len(i.stack)-2]

	result, err := i.compareValues(a, b, opcode)
	if err != nil {
		return err
	}

	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(result)})
}

func (i *Interpreter) compareValues(a, b Value, opcode Opcode) (bool, error) {
	switch a.Type {
	case ValueTypeInt:
		return i.compareIntegers(a, b, opcode)
	case ValueTypeDouble:
		return i.compareDoubles(a, b, opcode)
	default:
		return false, &InterpreterError{Type: ErrorTypeMismatch, Message: "numeric operands required"}
	}
}

func (i *Interpreter) compareIntegers(a, b Value, opcode Opcode) (bool, error) {
	if b.Type != ValueTypeInt {
		return false, &InterpreterError{Type: ErrorTypeMismatch, Message: "integer operands required"}
	}

	switch opcode {
	case OpIntEq, OpDblEq:
		return a.IntVal == b.IntVal, nil
	case OpIntNeq, OpDblNeq:
		return a.IntVal != b.IntVal, nil
	case OpIntLt, OpDblLt:
		return a.IntVal < b.IntVal, nil
	case OpIntLe, OpDblLe:
		return a.IntVal <= b.IntVal, nil
	case OpIntGt, OpDblGt:
		return a.IntVal > b.IntVal, nil
	case OpIntGe, OpDblGe:
		return a.IntVal >= b.IntVal, nil
	default:
		return false, &InterpreterError{Type: ErrorUnsupportedOpcode, Message: "invalid comparison opcode"}
	}
}

func (i *Interpreter) compareDoubles(a, b Value, opcode Opcode) (bool, error) {
	if b.Type != ValueTypeDouble {
		return false, &InterpreterError{Type: ErrorTypeMismatch, Message: "double operands required"}
	}

	switch opcode {
	case OpIntEq, OpDblEq:
		return a.DoubleVal == b.DoubleVal, nil
	case OpIntNeq, OpDblNeq:
		return a.DoubleVal != b.DoubleVal, nil
	case OpIntLt, OpDblLt:
		return a.DoubleVal < b.DoubleVal, nil
	case OpIntLe, OpDblLe:
		return a.DoubleVal <= b.DoubleVal, nil
	case OpIntGt, OpDblGt:
		return a.DoubleVal > b.DoubleVal, nil
	case OpIntGe, OpDblGe:
		return a.DoubleVal >= b.DoubleVal, nil
	default:
		return false, &InterpreterError{Type: ErrorUnsupportedOpcode, Message: "invalid comparison opcode"}
	}
}

// executeReadIntOp executes integer reading operations (little-endian)
func (i *Interpreter) executeReadIntOp(size int, signed bool) error {
	if err := i.validateStackUnderflow(OpInt8); err != nil {
		return err
	}

	offsetVal := i.stack[len(i.stack)-1]
	if offsetVal.Type != ValueTypeInt {
		return &InterpreterError{Type: ErrorTypeMismatch, Message: "integer offset required"}
	}

	offset := offsetVal.IntVal
	val, err := i.executeReadInt(offset, size, signed)
	if err != nil {
		return err
	}

	i.stack[len(i.stack)-1] = Value{Type: ValueTypeInt, IntVal: val}
	return nil
}

// executeReadIntOpBE executes integer reading operations (big-endian)
func (i *Interpreter) executeReadIntOpBE(size int, signed bool) error {
	if err := i.validateStackUnderflow(OpInt8be); err != nil {
		return err
	}

	offsetVal := i.stack[len(i.stack)-1]
	if offsetVal.Type != ValueTypeInt {
		return &InterpreterError{Type: ErrorTypeMismatch, Message: "integer offset required"}
	}

	if i.matchContext == nil {
		return &InterpreterError{Type: ErrorRuntime, Message: "no match context available"}
	}

	data := i.matchContext.Data
	offset := offsetVal.IntVal

	if err := i.validateReadIntAccess(offset); err != nil {
		return err
	}

	val, err := i.readIntBE(data, offset, size, signed)
	if err != nil {
		return err
	}

	i.stack[len(i.stack)-1] = Value{Type: ValueTypeInt, IntVal: val}
	return nil
}

func (i *Interpreter) readIntBE(data []byte, offset int64, size int, signed bool) (int64, error) {
	switch size {
	case 1:
		b := data[offset]
		return safeByteToInt64(b, signed), nil

	case 2:
		if err := i.validateBounds(offset, 1, "16-bit read"); err != nil {
			return 0, err
		}
		b1 := data[offset]
		b2 := data[offset+1]
		combined := uint16(b1)<<8 | uint16(b2)
		return safeUint16ToInt64(combined, !signed), nil

	case 4:
		if err := i.validateBounds(offset, 3, "32-bit read"); err != nil {
			return 0, err
		}
		b1 := data[offset]
		b2 := data[offset+1]
		b3 := data[offset+2]
		b4 := data[offset+3]
		combined := uint32(b1)<<24 | uint32(b2)<<16 | uint32(b3)<<8 | uint32(b4)
		return safeUint32ToInt64(combined, !signed), nil

	case 8:
		if err := i.validateBounds(offset, 7, "64-bit read"); err != nil {
			return 0, err
		}
		b1 := data[offset]
		b2 := data[offset+1]
		b3 := data[offset+2]
		b4 := data[offset+3]
		b5 := data[offset+4]
		b6 := data[offset+5]
		b7 := data[offset+6]
		b8 := data[offset+7]
		combined := uint64(b1)<<56 | uint64(b2)<<48 | uint64(b3)<<40 | uint64(b4)<<32 |
			uint64(b5)<<24 | uint64(b6)<<16 | uint64(b7)<<8 | uint64(b8)
		return safeUint64ToInt64(combined, !signed), nil

	default:
		return 0, &InterpreterError{
			Type:    ErrorInvalidMemoryAccess,
			Message: fmt.Sprintf("unsupported integer size: %d", size),
		}
	}
}

func (i *Interpreter) validateBounds(offset int64, extraBytes int, operation string) error {
	if offset+int64(extraBytes) >= int64(len(i.matchContext.Data)) {
		return &InterpreterError{
			Type:    ErrorInvalidMemoryAccess,
			Message: operation + " extends beyond data bounds",
		}
	}
	return nil
}

// executeLengthOperation executes OpLength
func (i *Interpreter) executeLengthOperation() error {
	if err := i.validateStackUnderflowN(OpLength, 2); err != nil {
		return err
	}

	index := i.stack[len(i.stack)-1]
	pattern := i.stack[len(i.stack)-2]
	i.stack = i.stack[:len(i.stack)-2]

	if pattern.Type != ValueTypeString {
		return &InterpreterError{Type: ErrorTypeMismatch, Message: "string pattern operand required"}
	}

	if index.Type != ValueTypeInt {
		return &InterpreterError{Type: ErrorTypeMismatch, Message: "integer index operand required"}
	}

	if i.matchContext == nil {
		return i.push(Value{Type: ValueTypeInt, IntVal: 0})
	}

	matches, exists := i.matchContext.Matches[i.getString(pattern)]
	if !exists || index.IntVal < 1 || int(index.IntVal-1) >= len(matches) {
		return i.push(Value{Type: ValueTypeInt, IntVal: 0})
	}

	match := matches[index.IntVal-1] // Convert to 0-based indexing
	return i.push(Value{Type: ValueTypeInt, IntVal: int64(match.Length)})
}

// executeCountOperation executes OpCount
func (i *Interpreter) executeCountOperation() error {
	if err := i.validateStackUnderflow(OpCount); err != nil {
		return err
	}

	pattern := i.stack[len(i.stack)-1]
	i.stack = i.stack[:len(i.stack)-1] // Pop the pattern

	if pattern.Type != ValueTypeString {
		return &InterpreterError{Type: ErrorTypeMismatch, Message: "string pattern operand required"}
	}

	if i.matchContext == nil {
		return i.push(Value{Type: ValueTypeInt, IntVal: 0})
	}

	matches, exists := i.matchContext.Matches[i.getString(pattern)]
	if !exists {
		return i.push(Value{Type: ValueTypeInt, IntVal: 0})
	}

	return i.push(Value{Type: ValueTypeInt, IntVal: int64(len(matches))})
}

// executeFoundOperation executes OpFound
func (i *Interpreter) executeFoundOperation() error {
	if err := i.validateStackUnderflow(OpFound); err != nil {
		return err
	}

	pattern := i.stack[len(i.stack)-1]
	i.stack = i.stack[:len(i.stack)-1] // Pop the pattern

	if pattern.Type != ValueTypeString {
		return &InterpreterError{Type: ErrorTypeMismatch, Message: "string pattern operand required"}
	}

	if i.matchContext == nil {
		return i.push(Value{Type: ValueTypeInt, IntVal: 0})
	}

	matches, exists := i.matchContext.Matches[i.getString(pattern)]
	found := exists && len(matches) > 0
	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(found)})
}

// executeFoundAtOperation executes OpFoundAt
func (i *Interpreter) executeFoundAtOperation() error {
	if err := i.validateStackUnderflowN(OpFoundAt, 2); err != nil {
		return err
	}

	offset := i.stack[len(i.stack)-1]
	pattern := i.stack[len(i.stack)-2]
	i.stack = i.stack[:len(i.stack)-2]

	if pattern.Type != ValueTypeString {
		return &InterpreterError{Type: ErrorTypeMismatch, Message: "string pattern operand required"}
	}

	if offset.Type != ValueTypeInt {
		return &InterpreterError{Type: ErrorTypeMismatch, Message: "integer offset operand required"}
	}

	if i.matchContext == nil {
		return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(false)})
	}

	matches, exists := i.matchContext.Matches[i.getString(pattern)]
	if !exists {
		return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(false)})
	}

	// Check if any match is at the specified offset
	for _, match := range matches {
		if match.Offset == offset.IntVal {
			return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(true)})
		}
	}

	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(false)})
}

// executeFoundInOperation executes OpFoundIn
func (i *Interpreter) executeFoundInOperation() error {
	if err := i.validateStackUnderflowN(OpFoundIn, 3); err != nil {
		return err
	}

	endOffset := i.stack[len(i.stack)-1]
	startOffset := i.stack[len(i.stack)-2]
	pattern := i.stack[len(i.stack)-3]
	i.stack = i.stack[:len(i.stack)-3]

	if pattern.Type != ValueTypeString {
		return &InterpreterError{Type: ErrorTypeMismatch, Message: "string pattern operand required"}
	}

	if startOffset.Type != ValueTypeInt || endOffset.Type != ValueTypeInt {
		return &InterpreterError{Type: ErrorTypeMismatch, Message: "integer offset operands required"}
	}

	if i.matchContext == nil {
		return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(false)})
	}

	matches, exists := i.matchContext.Matches[i.getString(pattern)]
	if !exists {
		return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(false)})
	}

	// Check if any match is within the given range [startOffset, endOffset]
	for _, match := range matches {
		if match.Offset >= startOffset.IntVal && match.Offset <= endOffset.IntVal {
			return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(true)})
		}
	}

	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(false)})
}

// executeOffsetOperation executes OpOffset
func (i *Interpreter) executeOffsetOperation() error {
	if err := i.validateStackUnderflowN(OpOffset, 2); err != nil {
		return err
	}

	index := i.stack[len(i.stack)-1]
	pattern := i.stack[len(i.stack)-2]
	i.stack = i.stack[:len(i.stack)-2]

	if pattern.Type != ValueTypeString {
		return &InterpreterError{Type: ErrorTypeMismatch, Message: "string pattern operand required"}
	}

	if index.Type != ValueTypeInt {
		return &InterpreterError{Type: ErrorTypeMismatch, Message: "integer index operand required"}
	}

	if i.matchContext == nil {
		return i.push(Value{Type: ValueTypeInt, IntVal: -1})
	}

	matches, exists := i.matchContext.Matches[i.getString(pattern)]
	if !exists || index.IntVal < 1 || int(index.IntVal-1) >= len(matches) {
		return i.push(Value{Type: ValueTypeUndefined})
	}

	match := matches[index.IntVal-1] // Convert to 0-based indexing
	return i.push(Value{Type: ValueTypeInt, IntVal: match.Offset})
}

// executeOfOperation executes OpOf
func (i *Interpreter) executeOfOperation() error {
	if err := i.validateStackUnderflowN(OpOf, 2); err != nil {
		return err
	}

	// Pop strings identifier and count
	stringsID := i.stack[len(i.stack)-1]
	count := i.stack[len(i.stack)-2]
	i.stack = i.stack[:len(i.stack)-2]

	set, err := i.resolveStringSet(stringsID)
	if err != nil {
		return err
	}
	result := i.applyCountLogic(set, count)
	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(result)})
}

func (i *Interpreter) resolveStringSet(stringsID Value) ([]string, error) {
	switch stringsID.Type {
	case ValueTypeInt:
		// Special marker for "them"
		if stringsID.IntVal == stringSetAll {
			return i.allStringIdentifiers(), nil
		}
		if stringsID.IntVal == stringSetAnonymous {
			return i.anonymousStringIdentifiers(), nil
		}
		if stringsID.IntVal < 0 || int(stringsID.IntVal) >= len(i.stringSets) {
			return nil, &InterpreterError{Type: ErrorRuntime, Opcode: OpOf, Message: "string set index out of range"}
		}
		return i.stringSets[stringsID.IntVal], nil
	case ValueTypeString:
		return []string{i.getString(stringsID)}, nil
	case ValueTypeUndefined:
		return nil, nil
	default:
		return nil, &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpOf, Message: "string set operand required"}
	}
}

func (i *Interpreter) allStringIdentifiers() []string {
	if len(i.allStrings) > 0 {
		return i.allStrings
	}
	if i.matchContext == nil {
		return nil
	}
	ids := make([]string, 0, len(i.matchContext.Matches))
	for id := range i.matchContext.Matches {
		ids = append(ids, id)
	}
	return ids
}

func (i *Interpreter) anonymousStringIdentifiers() []string {
	if len(i.anonymousStrings) == 0 {
		return nil
	}
	ids := make([]string, len(i.anonymousStrings))
	copy(ids, i.anonymousStrings)
	return ids
}

func (i *Interpreter) applyCountLogic(ids []string, count Value) bool {
	if i.matchContext == nil {
		return false
	}
	total := len(ids)
	matched := 0
	for _, id := range ids {
		if matches, ok := i.matchContext.Matches[id]; ok && len(matches) > 0 {
			matched++
		}
	}
	if count.Type != ValueTypeInt {
		return false
	}
	switch count.IntVal {
	case 0:
		return matched == 0
	case countAll:
		return total > 0 && matched == total
	default:
		if count.IntVal < 0 {
			return false
		}
		return matched >= int(count.IntVal)
	}
}

// executeMatchesOperation executes OpMatches
func (i *Interpreter) executeMatchesOperation() error {
	if err := i.validateStackUnderflowN(OpMatches, 2); err != nil {
		return err
	}

	regexVal := i.stack[len(i.stack)-1]
	value := i.stack[len(i.stack)-2]
	i.stack = i.stack[:len(i.stack)-2]

	if regexVal.Type != ValueTypeString || value.Type != ValueTypeString {
		return &InterpreterError{Type: ErrorTypeMismatch, Message: "string operands required"}
	}

	compiled, flags, err := i.compileRegexLiteral(i.getString(regexVal))
	if err != nil {
		return &InterpreterError{Type: ErrorRuntime, Opcode: OpMatches, Message: err.Error()}
	}

	matched := regex.Exec(compiled, []byte(i.getString(value)), flags|regex.FlagsScan)
	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(matched)})
}

func (i *Interpreter) compileRegexLiteral(literal string) ([]byte, regex.Flags, error) {
	if cached, ok := i.regexCache[literal]; ok {
		return cached.code, cached.flags, nil
	}
	cleaned := cleanRegexPattern(literal)
	flags := parseInlineRegexFlags(literal)
	parser := regex.NewParser(0)
	astRe, err := parser.Parse(cleaned)
	if err != nil {
		return nil, flags, fmt.Errorf("parse regex: %w", err)
	}
	code, err := regex.Compile(astRe)
	if err != nil {
		return nil, flags, fmt.Errorf("compile regex: %w", err)
	}
	i.regexCache[literal] = compiledRegex{code: code, flags: flags}
	return code, flags, nil
}

func parseInlineRegexFlags(pattern string) regex.Flags {
	var flags regex.Flags
	if len(pattern) < 2 || pattern[0] != '/' {
		return flags
	}
	endIdx := len(pattern) - 1
	for endIdx > 0 && pattern[endIdx] != '/' {
		endIdx--
	}
	if endIdx > 0 && endIdx < len(pattern)-1 {
		for i := endIdx + 1; i < len(pattern); i++ {
			switch pattern[i] {
			case 'i', 'I':
				flags |= regex.FlagsNoCase
			case 's', 'S':
				flags |= regex.FlagsDotAll
			}
		}
	}
	return flags
}

func (i *Interpreter) executeContainsOperation() error {
	return i.executeStringBinaryOp(OpContains, strings.Contains)
}

func (i *Interpreter) executeStartswithOperation() error {
	return i.executeStringBinaryOp(OpStartswith, strings.HasPrefix)
}

func (i *Interpreter) executeEndswithOperation() error {
	return i.executeStringBinaryOp(OpEndswith, strings.HasSuffix)
}

func (i *Interpreter) executeIcontainsOperation() error {
	return i.executeStringBinaryOp(OpIcontains, func(a, b string) bool {
		return strings.Contains(strings.ToLower(a), strings.ToLower(b))
	})
}

func (i *Interpreter) executeIstartswithOperation() error {
	return i.executeStringBinaryOp(OpIstartswith, func(a, b string) bool {
		return strings.HasPrefix(strings.ToLower(a), strings.ToLower(b))
	})
}

func (i *Interpreter) executeIendswithOperation() error {
	return i.executeStringBinaryOp(OpIendswith, func(a, b string) bool {
		return strings.HasSuffix(strings.ToLower(a), strings.ToLower(b))
	})
}

func (i *Interpreter) executeIequalsOperation() error {
	return i.executeStringBinaryOp(OpIequals, strings.EqualFold)
}

func (i *Interpreter) executeStringBinaryOp(op Opcode, fn func(string, string) bool) error {
	if err := i.validateStackUnderflowN(op, 2); err != nil {
		return err
	}
	right := i.stack[len(i.stack)-1]
	left := i.stack[len(i.stack)-2]
	i.stack = i.stack[:len(i.stack)-2]
	if left.Type != ValueTypeString || right.Type != ValueTypeString {
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: op, Message: "string operands required"}
	}
	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(fn(i.getString(left), i.getString(right)))})
}

// --- Individual integer arithmetic handlers ---

func (i *Interpreter) executeIntAdd() error {
	return i.executeBinaryOp(func(a, b int64) int64 { return a + b }, nil)
}
func (i *Interpreter) executeIntSub() error {
	return i.executeBinaryOp(func(a, b int64) int64 { return a - b }, nil)
}
func (i *Interpreter) executeIntMul() error {
	return i.executeBinaryOp(func(a, b int64) int64 { return a * b }, nil)
}
func (i *Interpreter) executeIntDiv() error {
	return i.executeBinaryOpWithCheck(func(a, b int64) (int64, error) {
		if b == 0 {
			return 0, &InterpreterError{Type: ErrorDivisionByZero, Opcode: OpIntDiv, Message: "division by zero"}
		}
		return a / b, nil
	}, nil)
}
func (i *Interpreter) executeMod() error {
	return i.executeBinaryOpWithCheck(func(a, b int64) (int64, error) {
		if b == 0 {
			return 0, &InterpreterError{Type: ErrorDivisionByZero, Opcode: OpMod, Message: "modulo by zero"}
		}
		return a % b, nil
	}, nil)
}
func (i *Interpreter) executeIntMinus() error {
	if err := i.validateStackUnderflow(OpIntMinus); err != nil {
		return err
	}
	v := i.stack[len(i.stack)-1]
	if v.Type != ValueTypeInt {
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpIntMinus, Message: "integer operand required"}
	}
	i.stack[len(i.stack)-1] = Value{Type: ValueTypeInt, IntVal: -v.IntVal}
	return nil
}

// --- Individual double arithmetic handlers ---

func (i *Interpreter) executeDblAdd() error {
	return i.executeDoubleOp(func(a, b float64) float64 { return a + b })
}
func (i *Interpreter) executeDblSub() error {
	return i.executeDoubleOp(func(a, b float64) float64 { return a - b })
}
func (i *Interpreter) executeDblMul() error {
	return i.executeDoubleOp(func(a, b float64) float64 { return a * b })
}
func (i *Interpreter) executeDblDiv() error {
	return i.executeDoubleOp(func(a, b float64) float64 { return a / b })
}
func (i *Interpreter) executeDblMinus() error {
	if err := i.validateStackUnderflow(OpDblMinus); err != nil {
		return err
	}
	v := i.stack[len(i.stack)-1]
	if v.Type != ValueTypeDouble {
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpDblMinus, Message: "double operand required"}
	}
	i.stack[len(i.stack)-1] = Value{Type: ValueTypeDouble, DoubleVal: -v.DoubleVal}
	return nil
}

// --- Individual comparison handlers ---

func (i *Interpreter) executeIntEq() error  { return i.executeTypedComparison(OpIntEq) }
func (i *Interpreter) executeIntNeq() error { return i.executeTypedComparison(OpIntNeq) }
func (i *Interpreter) executeIntLt() error  { return i.executeTypedComparison(OpIntLt) }
func (i *Interpreter) executeIntGt() error  { return i.executeTypedComparison(OpIntGt) }
func (i *Interpreter) executeIntLe() error  { return i.executeTypedComparison(OpIntLe) }
func (i *Interpreter) executeIntGe() error  { return i.executeTypedComparison(OpIntGe) }

func (i *Interpreter) executeDblEq() error  { return i.executeTypedComparison(OpDblEq) }
func (i *Interpreter) executeDblNeq() error { return i.executeTypedComparison(OpDblNeq) }
func (i *Interpreter) executeDblLt() error  { return i.executeTypedComparison(OpDblLt) }
func (i *Interpreter) executeDblGt() error  { return i.executeTypedComparison(OpDblGt) }
func (i *Interpreter) executeDblLe() error  { return i.executeTypedComparison(OpDblLe) }
func (i *Interpreter) executeDblGe() error  { return i.executeTypedComparison(OpDblGe) }

func (i *Interpreter) executeStrEq() error {
	return i.executeStringComparison(func(a, b string) bool { return a == b })
}
func (i *Interpreter) executeStrNeq() error {
	return i.executeStringComparison(func(a, b string) bool { return a != b })
}
func (i *Interpreter) executeStrLt() error {
	return i.executeStringComparison(func(a, b string) bool { return a < b })
}
func (i *Interpreter) executeStrGt() error {
	return i.executeStringComparison(func(a, b string) bool { return a > b })
}
func (i *Interpreter) executeStrLe() error {
	return i.executeStringComparison(func(a, b string) bool { return a <= b })
}
func (i *Interpreter) executeStrGe() error {
	return i.executeStringComparison(func(a, b string) bool { return a >= b })
}
