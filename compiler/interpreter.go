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
	bytecode         []byte
	ip               int        // Instruction pointer
	stack            []Value    // Execution stack
	memory           [256]Value // Memory slots for variables
	stopped          bool
	result           error
	matchContext     *MatchContext   // Pattern matching context
	ruleResults      map[string]bool // Track execution results of all rules in the program
	currentRule      string          // Name of the currently executing rule
	compiledRules    []*CompiledRule // All compiled rules in the program
	stringLiterals   []string        // String literal pool for OpPushStr
	stringSets       [][]string      // String sets for OpOf
	allStrings       []string        // All string identifiers for current rule
	anonymousStrings []string        // Anonymous string identifiers for current rule
	regexCache       map[string]compiledRegex
	debugMode        bool // Debug mode flag for instruction tracing
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

	interpreterPool.Put(i)
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
		i.stringLiterals = rule.StringLiterals
		i.stringSets = rule.StringSets
		i.allStrings = rule.StringIdentifiers()
		i.anonymousStrings = rule.AnonymousStrings
		return
	}
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
		i.memory[index] = Value{
			Type:      ValueTypeString,
			StringVal: identifier,
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
	i.stopped = false
	i.result = nil
	if i.ruleResults == nil {
		i.ruleResults = make(map[string]bool)
	} else {
		clear(i.ruleResults)
	}
	i.currentRule = ""
}

// Execute runs the bytecode
func (i *Interpreter) Execute() error {
	// Reset interpreter state for clean execution
	i.Reset()

	return i.executeMainLoop()
}

func (i *Interpreter) executeMainLoop() error {
	for !i.stopped && i.ip < len(i.bytecode) {
		opcode := Opcode(i.bytecode[i.ip])
		i.ip++

		if i.debugMode {
			i.debugExecution(opcode)
		}

		if err := i.executeOpcode(opcode); err != nil {
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
			fmt.Printf("DEBUG: Top of stack: Type=String, Length=%d\n", len(top.StringVal))
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
func (i *Interpreter) executeOpcode(opcode Opcode) error {
	switch opcode {
	case OpError:
		return nil

	// Stack operations
	case OpPush8, OpPush16, OpPush32, OpPushU, OpPushDbl, OpPushRuleRef, OpPushStr, OpPop, OpCall:
		return i.executeStackOpcode(opcode)

	// Bitwise operations
	case OpBitwiseAnd, OpBitwiseOr, OpBitwiseXor, OpBitwiseNot, OpShl, OpShr:
		return i.executeBitwiseOpcode(opcode)

	// Arithmetic operations
	case OpIntAdd, OpIntSub, OpIntMul, OpIntDiv, OpMod, OpIntMinus,
		OpDblAdd, OpDblSub, OpDblMul, OpDblDiv, OpDblMinus:
		return i.executeArithmeticOperation(opcode)

	// Comparison operations
	case OpIntEq, OpIntNeq, OpIntLt, OpIntLe, OpIntGt, OpIntGe,
		OpDblEq, OpDblNeq, OpDblLt, OpDblLe, OpDblGt, OpDblGe,
		OpStrEq, OpStrNeq, OpStrLt, OpStrLe, OpStrGt, OpStrGe:
		return i.executeComparisonOperation(opcode)

	// Logical operations
	case OpAnd, OpOr, OpNot, OpDefined:
		return i.executeLogicalOpcode(opcode)

	// Control flow operations
	case OpNop, OpHalt, OpJz, OpJtrue, OpJfalse:
		return i.executeControlFlowOpcode(opcode)

	// Memory operations
	case OpPushM, OpPopM, OpClearM, OpIncrM, OpSwapundef:
		return i.executeMemoryOpcode(opcode)

	// File operations
	case OpEntrypoint, OpFilesize:
		return i.executeFileOperation(opcode)

	// Integer read operations
	case OpInt8, OpInt16, OpInt32, OpInt64, OpUint8, OpUint16, OpUint32, OpUint64,
		OpInt8be, OpUint8be, OpInt16be, OpUint16be, OpInt32be, OpUint32be:
		// OpInt64be (254) and OpUint64be (255) are masked by OpNop and OpHalt respectively
		return i.executeIntegerReadOpcode(opcode)

	// String operations
	case OpLength, OpCount, OpFound, OpFoundAt, OpFoundIn, OpOffset, OpOf, OpMatches,
		OpContains, OpStartswith, OpEndswith, OpIcontains, OpIstartswith, OpIendswith, OpIequals,
		OpIntToDbl, OpStrToBool:
		return i.executeStringOperation(opcode)

	// Rule operations
	case OpPushRule, OpInitRule, OpMatchRule:
		return i.executeRuleOperation(opcode)

	default:
		return &InterpreterError{
			Type:    ErrorUnsupportedOpcode,
			Opcode:  opcode,
			Message: fmt.Sprintf("unsupported opcode: %v", opcode),
		}
	}
}

// executeStackOpcode handles stack operations
func (i *Interpreter) executeStackOpcode(opcode Opcode) error {
	switch opcode {
	case OpPush8:
		return i.executePush8()
	case OpPush16:
		return i.executePush16()
	case OpPush32:
		return i.executePush32()
	case OpPushU:
		return i.executePushU()
	case OpPushDbl:
		return i.executePushDouble()
	case OpPushRuleRef:
		return i.executePushRuleRef()
	case OpPushStr:
		return i.executePushString()
	case OpPop:
		return i.executePop()
	case OpCall:
		return i.executeCall()
	default:
		return &InterpreterError{Type: ErrorInvalidBytecode, Opcode: opcode, Message: "invalid stack opcode"}
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
	return i.push(Value{Type: ValueTypeRuleRef, StringVal: ruleName})
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
	return i.push(Value{Type: ValueTypeString, StringVal: i.stringLiterals[idx]})
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
		str, err := valueToString(arg)
		if err != nil {
			return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpCall, Message: err.Error()}
		}
		sb.WriteString(str)
	}
	return i.push(Value{Type: ValueTypeString, StringVal: sb.String()})
}

func (i *Interpreter) executeBuiltinToString(args []Value) error {
	if len(args) != 1 {
		return &InterpreterError{Type: ErrorRuntime, Opcode: OpCall, Message: "tostring requires exactly 1 argument"}
	}
	str, err := valueToString(args[0])
	if err != nil {
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpCall, Message: err.Error()}
	}
	return i.push(Value{Type: ValueTypeString, StringVal: str})
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
		if v.StringVal == "" {
			return i.push(Value{Type: ValueTypeInt, IntVal: 0})
		}
		if parsed, err := strconv.ParseInt(strings.TrimSpace(v.StringVal), 0, 64); err == nil {
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
	return i.push(Value{Type: ValueTypeString, StringVal: hex.EncodeToString(sum[:])})
}

func (i *Interpreter) executeBuiltinSHA1(args []Value) error {
	data, err := i.extractHashInput(args)
	if err != nil {
		return &InterpreterError{Type: ErrorRuntime, Opcode: OpCall, Message: err.Error()}
	}
	sum := sha1.Sum(data) // #nosec G401 -- YARA defines sha1() for compatibility
	return i.push(Value{Type: ValueTypeString, StringVal: hex.EncodeToString(sum[:])})
}

func (i *Interpreter) executeBuiltinSHA256(args []Value) error {
	data, err := i.extractHashInput(args)
	if err != nil {
		return &InterpreterError{Type: ErrorRuntime, Opcode: OpCall, Message: err.Error()}
	}
	sum := sha256.Sum256(data)
	return i.push(Value{Type: ValueTypeString, StringVal: hex.EncodeToString(sum[:])})
}

func (i *Interpreter) extractHashInput(args []Value) ([]byte, error) {
	switch len(args) {
	case 1:
		if args[0].Type != ValueTypeString {
			return nil, fmt.Errorf("hash functions expect string or (offset,size)")
		}
		return []byte(args[0].StringVal), nil
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

func valueToString(v Value) (string, error) {
	switch v.Type {
	case ValueTypeString:
		return v.StringVal, nil
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

// executeBitwiseOpcode handles bitwise operations
func (i *Interpreter) executeBitwiseOpcode(opcode Opcode) error {
	switch opcode {
	case OpBitwiseAnd:
		return i.executeBitwiseAnd()
	case OpBitwiseOr:
		return i.executeBitwiseOr()
	case OpBitwiseXor:
		return i.executeBitwiseXor()
	case OpBitwiseNot:
		return i.executeBitwiseNot()
	case OpShl:
		return i.executeShiftLeft()
	case OpShr:
		return i.executeShiftRight()
	default:
		return &InterpreterError{Type: ErrorInvalidBytecode, Opcode: opcode, Message: "invalid bitwise opcode"}
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

// executeLogicalOpcode handles logical operations
func (i *Interpreter) executeLogicalOpcode(opcode Opcode) error {
	switch opcode {
	case OpAnd:
		return i.executeAndOperation()
	case OpOr:
		return i.executeOrOperation()
	case OpNot:
		return i.executeNotOperation()
	case OpDefined:
		return i.executeDefinedOperation()
	default:
		return &InterpreterError{Type: ErrorInvalidBytecode, Opcode: opcode, Message: "invalid logical opcode"}
	}
}

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

// executeControlFlowOpcode handles control flow operations
func (i *Interpreter) executeControlFlowOpcode(opcode Opcode) error {
	switch opcode {
	case OpNop:
		return nil

	case OpHalt:
		i.stopped = true
		return nil

	case OpJz, OpJtrue, OpJfalse:
		return i.executeJumpOpcode(opcode)

	default:
		return &InterpreterError{Type: ErrorInvalidBytecode, Opcode: opcode, Message: "invalid control flow opcode"}
	}
}

// executeJumpOpcode handles jump operations with common logic
func (i *Interpreter) executeJumpOpcode(opcode Opcode) error {
	if err := i.validateStackUnderflow(opcode); err != nil {
		return err
	}
	v := i.stack[len(i.stack)-1]
	i.stack = i.stack[:len(i.stack)-1]

	shouldJump := false
	switch opcode {
	case OpJz:
		shouldJump = !i.isTruthy(v)
	case OpJtrue:
		shouldJump = i.isTruthy(v)
	case OpJfalse:
		shouldJump = !i.isTruthy(v)
	}

	if shouldJump {
		if i.ip >= len(i.bytecode) {
			return &InterpreterError{Type: ErrorInvalidBytecode, Opcode: opcode, Message: "jump target out of bounds"}
		}
		i.ip++
	} else {
		i.ip++
	}
	return nil
}

// executeMemoryOpcode handles memory operations
func (i *Interpreter) executeMemoryOpcode(opcode Opcode) error {
	switch opcode {
	case OpPushM:
		return i.executePushMemory()
	case OpPopM:
		return i.executePopMemory()
	case OpClearM:
		return i.executeClearMemory()
	case OpIncrM:
		return i.executeIncrementMemory()
	case OpSwapundef:
		return i.executeSwapUndefined()
	default:
		return &InterpreterError{Type: ErrorInvalidBytecode, Opcode: opcode, Message: "invalid memory opcode"}
	}
}

// readAndValidateMemorySlot reads and validates a memory slot from bytecode
func (i *Interpreter) readAndValidateMemorySlot(opcode Opcode) (int, error) {
	if err := i.validateBytecodeBounds(opcode, 1); err != nil {
		return 0, err
	}
	slot := int(i.bytecode[i.ip])
	i.ip++
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
func (i *Interpreter) executeFileOperation(opcode Opcode) error {
	switch opcode {
	case OpEntrypoint:
		if i.matchContext != nil {
			return i.push(Value{Type: ValueTypeInt, IntVal: i.matchContext.EntryPoint})
		}
		return i.push(Value{Type: ValueTypeInt, IntVal: 0})

	case OpFilesize:
		if i.matchContext != nil {
			return i.push(Value{Type: ValueTypeInt, IntVal: i.matchContext.FileSize})
		}
		return i.push(Value{Type: ValueTypeInt, IntVal: 0})

	default:
		return &InterpreterError{Type: ErrorInvalidBytecode, Opcode: opcode, Message: "invalid file operation"}
	}
}

// executeIntegerReadOpcode handles integer read operations
func (i *Interpreter) executeIntegerReadOpcode(opcode Opcode) error {
	// Handle little-endian integer reads
	switch opcode {
	case OpInt8, OpInt16, OpInt32, OpInt64:
		return i.executeReadIntOp(int(opcode-OpInt8)+1, true)
	case OpUint8, OpUint16, OpUint32, OpUint64:
		return i.executeReadIntOp(int(opcode-OpUint8)+1, false)
	}

	// Handle big-endian integer reads
	switch opcode {
	case OpInt8be, OpInt16be, OpInt32be, OpInt64be:
		return i.executeReadIntOpBE(int(opcode-OpInt8be)+1, true)
	case OpUint8be, OpUint16be, OpUint32be, OpUint64be:
		return i.executeReadIntOpBE(int(opcode-OpUint8be)+1, false)
	}

	return &InterpreterError{Type: ErrorInvalidBytecode, Opcode: opcode, Message: "invalid integer read opcode"}
}

// executeStringOperation handles string operations using direct dispatch
// to avoid per-call map allocation on this hot path.
func (i *Interpreter) executeStringOperation(opcode Opcode) error {
	switch opcode {
	case OpLength:
		return i.executeLengthOperation()
	case OpCount:
		return i.executeCountOperation()
	case OpFound:
		return i.executeFoundOperation()
	case OpFoundAt:
		return i.executeFoundAtOperation()
	case OpFoundIn:
		return i.executeFoundInOperation()
	case OpOffset:
		return i.executeOffsetOperation()
	case OpOf:
		return i.executeOfOperation()
	case OpMatches:
		return i.executeMatchesOperation()
	case OpContains:
		return i.executeContainsOperation()
	case OpStartswith:
		return i.executeStartswithOperation()
	case OpEndswith:
		return i.executeEndswithOperation()
	case OpIcontains:
		return i.executeIcontainsOperation()
	case OpIstartswith:
		return i.executeIstartswithOperation()
	case OpIendswith:
		return i.executeIendswithOperation()
	case OpIequals:
		return i.executeIequalsOperation()
	case OpIntToDbl:
		return i.executeIntToDouble()
	case OpStrToBool:
		return i.executeStringToBool()
	default:
		return &InterpreterError{Type: ErrorInvalidBytecode, Opcode: opcode, Message: "invalid string operation"}
	}
}

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
		result := v.StringVal != ""
		i.stack[len(i.stack)-1] = Value{Type: ValueTypeInt, IntVal: boolToInt(result)}
		return nil
	}

	return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpStrToBool, Message: "string operand required"}
}

// executeRuleOperation handles rule operations
func (i *Interpreter) executeRuleOperation(opcode Opcode) error {
	switch opcode {
	case OpPushRule:
		return i.executePushRuleOperation()
	case OpInitRule:
		return i.executeInitRuleOperation()
	case OpMatchRule:
		return i.executeMatchRuleOperation()
	default:
		return &InterpreterError{Type: ErrorInvalidBytecode, Opcode: opcode, Message: "invalid rule operation"}
	}
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
	return i.push(Value{Type: ValueTypeString, StringVal: ruleName})
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
		return fmt.Sprintf("%q", v.StringVal)
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
	if comparison(a.StringVal, b.StringVal) {
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
		return v.StringVal != ""
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

	matches, exists := i.matchContext.Matches[pattern.StringVal]
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

	matches, exists := i.matchContext.Matches[pattern.StringVal]
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

	matches, exists := i.matchContext.Matches[pattern.StringVal]
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

	matches, exists := i.matchContext.Matches[pattern.StringVal]
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

	matches, exists := i.matchContext.Matches[pattern.StringVal]
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

	matches, exists := i.matchContext.Matches[pattern.StringVal]
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
		return []string{stringsID.StringVal}, nil
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

	compiled, flags, err := i.compileRegexLiteral(regexVal.StringVal)
	if err != nil {
		return &InterpreterError{Type: ErrorRuntime, Opcode: OpMatches, Message: err.Error()}
	}

	matched := regex.Exec(compiled, []byte(value.StringVal), flags|regex.FlagsScan)
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
	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(fn(left.StringVal, right.StringVal))})
}

// executeArithmeticOperation handles all arithmetic operations (integer and double)
func (i *Interpreter) executeArithmeticOperation(opcode Opcode) error {
	if i.isIntegerArithmetic(opcode) {
		return i.executeIntegerArithmetic(opcode)
	}
	if i.isDoubleArithmetic(opcode) {
		return i.executeDoubleArithmetic(opcode)
	}
	return &InterpreterError{
		Type:    ErrorUnsupportedOpcode,
		Opcode:  opcode,
		Message: fmt.Sprintf("unsupported arithmetic opcode: %v", opcode),
	}
}

func (i *Interpreter) isIntegerArithmetic(opcode Opcode) bool {
	switch opcode {
	case OpIntAdd, OpIntSub, OpIntMul, OpIntDiv, OpMod, OpIntMinus:
		return true
	default:
		return false
	}
}

func (i *Interpreter) isDoubleArithmetic(opcode Opcode) bool {
	switch opcode {
	case OpDblAdd, OpDblSub, OpDblMul, OpDblDiv, OpDblMinus:
		return true
	default:
		return false
	}
}

func (i *Interpreter) executeIntegerArithmetic(opcode Opcode) error {
	switch opcode {
	case OpIntAdd, OpIntSub, OpIntMul:
		op := i.getIntegerOp(opcode)
		return i.executeBinaryOp(op, nil)
	case OpIntDiv:
		return i.executeBinaryOpWithCheck(func(a, b int64) (int64, error) {
			if b == 0 {
				return 0, &InterpreterError{Type: ErrorDivisionByZero, Opcode: opcode, Message: "division by zero"}
			}
			return a / b, nil
		}, nil)
	case OpMod:
		return i.executeBinaryOpWithCheck(func(a, b int64) (int64, error) {
			if b == 0 {
				return 0, &InterpreterError{Type: ErrorDivisionByZero, Opcode: opcode, Message: "modulo by zero"}
			}
			return a % b, nil
		}, nil)
	case OpIntMinus:
		return i.executeIntegerNegation(opcode)
	default:
		return &InterpreterError{
			Type:    ErrorUnsupportedOpcode,
			Opcode:  opcode,
			Message: fmt.Sprintf("unsupported integer arithmetic opcode: %v", opcode),
		}
	}
}

func (i *Interpreter) getIntegerOp(opcode Opcode) func(int64, int64) int64 {
	switch opcode {
	case OpIntAdd:
		return func(a, b int64) int64 { return a + b }
	case OpIntSub:
		return func(a, b int64) int64 { return a - b }
	case OpIntMul:
		return func(a, b int64) int64 { return a * b }
	default:
		return func(a, _ int64) int64 { return a } // fallback
	}
}

func (i *Interpreter) executeIntegerNegation(opcode Opcode) error {
	if err := i.validateStackUnderflow(opcode); err != nil {
		return err
	}
	v := i.stack[len(i.stack)-1]
	if v.Type != ValueTypeInt {
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: opcode, Message: "integer operand required"}
	}
	i.stack[len(i.stack)-1] = Value{Type: ValueTypeInt, IntVal: -v.IntVal}
	return nil
}

func (i *Interpreter) executeDoubleArithmetic(opcode Opcode) error {
	switch opcode {
	case OpDblAdd, OpDblSub, OpDblMul, OpDblDiv:
		op := i.getDoubleOp(opcode)
		return i.executeDoubleOp(op)
	case OpDblMinus:
		return i.executeDoubleNegation(opcode)
	default:
		return &InterpreterError{
			Type:    ErrorUnsupportedOpcode,
			Opcode:  opcode,
			Message: fmt.Sprintf("unsupported double arithmetic opcode: %v", opcode),
		}
	}
}

func (i *Interpreter) getDoubleOp(opcode Opcode) func(float64, float64) float64 {
	switch opcode {
	case OpDblAdd:
		return func(a, b float64) float64 { return a + b }
	case OpDblSub:
		return func(a, b float64) float64 { return a - b }
	case OpDblMul:
		return func(a, b float64) float64 { return a * b }
	case OpDblDiv:
		return func(a, b float64) float64 { return a / b }
	default:
		return func(a, _ float64) float64 { return a } // fallback
	}
}

func (i *Interpreter) executeDoubleNegation(opcode Opcode) error {
	if err := i.validateStackUnderflow(opcode); err != nil {
		return err
	}
	v := i.stack[len(i.stack)-1]
	if v.Type != ValueTypeDouble {
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: opcode, Message: "double operand required"}
	}
	i.stack[len(i.stack)-1] = Value{Type: ValueTypeDouble, DoubleVal: -v.DoubleVal}
	return nil
}

// executeComparisonOperation handles all comparison operations (integer, double, string)
func (i *Interpreter) executeComparisonOperation(opcode Opcode) error {
	if i.isNumericComparison(opcode) {
		return i.executeTypedComparison(opcode)
	}
	if i.isStringComparison(opcode) {
		comparison := i.getStringComparisonFunc(opcode)
		return i.executeStringComparison(comparison)
	}
	return &InterpreterError{
		Type:    ErrorUnsupportedOpcode,
		Opcode:  opcode,
		Message: fmt.Sprintf("unsupported comparison opcode: %v", opcode),
	}
}

func (i *Interpreter) isNumericComparison(opcode Opcode) bool {
	switch opcode {
	case OpIntEq, OpIntNeq, OpIntLt, OpIntLe, OpIntGt, OpIntGe,
		OpDblEq, OpDblNeq, OpDblLt, OpDblLe, OpDblGt, OpDblGe:
		return true
	default:
		return false
	}
}

func (i *Interpreter) isStringComparison(opcode Opcode) bool {
	switch opcode {
	case OpStrEq, OpStrNeq, OpStrLt, OpStrLe, OpStrGt, OpStrGe:
		return true
	default:
		return false
	}
}

func (i *Interpreter) getStringComparisonFunc(opcode Opcode) func(string, string) bool {
	switch opcode {
	case OpStrEq:
		return func(a, b string) bool { return a == b }
	case OpStrNeq:
		return func(a, b string) bool { return a != b }
	case OpStrLt:
		return func(a, b string) bool { return a < b }
	case OpStrLe:
		return func(a, b string) bool { return a <= b }
	case OpStrGt:
		return func(a, b string) bool { return a > b }
	case OpStrGe:
		return func(a, b string) bool { return a >= b }
	default:
		return func(_, _ string) bool { return false } // fallback
	}
}
