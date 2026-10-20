package compiler

import (
	"fmt"
	"maps"
	"math"
	"slices"
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

const interpreterMemorySlotCount = 256

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
	ip                  int                               // Instruction pointer
	stack               []Value                           // Execution stack
	memory              [interpreterMemorySlotCount]Value // Memory slots for variables
	iterators           []Iterator                        // Stack of active iteration frames for loops
	stopped             bool
	result              error
	matchContext        *MatchContext            // Pattern matching context
	ruleResults         map[string]bool          // Track execution results of all rules in the program
	ruleResultsDense    []bool                   // Direct indexed rule execution results
	currentRule         string                   // Name of the currently executing rule
	currentRuleIndex    int                      // Index of the currently executing rule (-1 if unset)
	currentCompiledRule *CompiledRule            // Currently executing rule (for int string ID resolution)
	compiledRules       []*CompiledRule          // All compiled rules in the program
	ruleMap             map[string]*CompiledRule // Index for O(1) rule lookup by name
	stringLiterals      []string                 // String literal pool for OpPushStr
	stringSets          [][]string               // String sets for OpOf
	textStringSets      [][]string               // Text string sets for text-string-set iteration
	allStrings          []string                 // All string identifiers for current rule
	anonymousStrings    []string                 // Anonymous string identifiers for current rule
	stringArena         []string                 // Arena for dynamic strings
	regexCache          map[string]compiledRegex
	PreserveRuleResults bool // If true, Reset() will not clear ruleResults
	itersmax            int  // Max total iterations across all for-loops (0 = unlimited)
	iterations          int  // Current total iteration count
}

// Iterator defines the state for a runtime for-loop
type Iterator struct {
	Variables []int // Memory slots where loop variables are stored
	StringIDs []string
	// Text strings for text-string-set iteration (e.g. for any s in ("a", "b") : ...)
	TextStrings []string
	// Integer values for integer-enumeration iteration (e.g. for any i in (1, 2, 3) : ...)
	IntValues     []int64
	Count         int // Number of matches
	Index         int // Current iteration index
	Total         int // Total number of elements
	Quantifier    int // Quantifier for condition (e.g. ForAll, ForAny, ForNone, ForExpression)
	QuantExpr     int // Target expression count if Quantifier == ForExpression
	EndIP         int // Instruction pointer to jump to when done
	StartValue    int64
	EndValue      int64
	OffsetMin     int64
	OffsetMax     int64
	AtOffsetValue int64
	Type          Opcode // The type of iterator (e.g. OpIterStartIntRange)
	InRange       bool   // Filter matches to those within [OffsetMin..OffsetMax]
	AtOffset      bool   // Filter matches to those at exactly AtOffsetValue
}

type compiledRegex struct {
	code  []byte
	flags regex.Flags
}

// interpreterPool reuses interpreter allocations between executions.
var interpreterPool = sync.Pool{
	New: func() any {
		return &Interpreter{
			stack:      make([]Value, 0, 256),
			regexCache: make(map[string]compiledRegex),
		}
	},
}

// SetItersmax sets the maximum number of for-loop iterations.
// A value of 0 means unlimited.
func (i *Interpreter) SetItersmax(limit int) {
	i.itersmax = limit
}

// ResetIterationCount resets the iteration counter.
func (i *Interpreter) ResetIterationCount() {
	i.iterations = 0
}

// NewInterpreter creates a bytecode interpreter with an owned snapshot of
// bytecode. Callers may reuse or modify the input after construction.
func NewInterpreter(bytecode []byte) *Interpreter {
	i := interpreterPool.Get().(*Interpreter)
	i.bytecode = slices.Clone(bytecode)
	i.matchContext = &MatchContext{Matches: make(map[string][]Match)}

	return i
}

// Release returns the interpreter to the pool for reuse
func (i *Interpreter) Release() {
	i.resetForPool()
	interpreterPool.Put(i)
}

func (i *Interpreter) resetForPool() {
	clear(i.stringArena[:cap(i.stringArena)])
	clear(i.iterators[:cap(i.iterators)])
	clear(i.regexCache)
	*i = Interpreter{
		stack:       i.stack[:0],
		stringArena: i.stringArena[:0],
		iterators:   i.iterators[:0],
		regexCache:  i.regexCache,
	}
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
	// Nonnegative references index the arena; negative references encode
	// stringLiterals as -(index + 1).
	if v.StringRef >= 0 {
		if int(v.StringRef) < len(i.stringArena) {
			return i.stringArena[v.StringRef]
		}
		return ""
	}
	idx := -v.StringRef - 1
	if int(idx) < len(i.stringLiterals) {
		return i.stringLiterals[idx]
	}
	return ""
}

// SetMatchContext sets the pattern matching context. The context is borrowed
// and must remain valid while the interpreter uses it.
func (i *Interpreter) SetMatchContext(ctx *MatchContext) {
	i.matchContext = ctx
}

// SetCompiledRules sets the compiled rules for rule reference resolution. The
// input slice is copied; the compiled rule pointers are borrowed and should be
// treated as immutable while the interpreter uses them.
func (i *Interpreter) SetCompiledRules(rules []*CompiledRule) {
	i.setCompiledRules(slices.Clone(rules))
}

func (i *Interpreter) setCompiledRules(rules []*CompiledRule) {
	i.compiledRules = rules
	// Build O(1) lookup map by rule name
	i.ruleMap = make(map[string]*CompiledRule, len(rules))
	for _, rule := range rules {
		i.ruleMap[rule.Name] = rule
	}
	if i.currentRule != "" {
		i.SetCurrentRule(i.currentRule)
	}
}

// GetMatchContext returns the interpreter's live match context. The returned
// pointer is borrowed and intended for advanced VM integrations.
func (i *Interpreter) GetMatchContext() *MatchContext {
	return i.matchContext
}

// SetCurrentRule sets the name of the currently executing rule
func (i *Interpreter) SetCurrentRule(ruleName string) {
	i.currentRule = ruleName
	if rule, ok := i.ruleMap[ruleName]; ok {
		i.setCurrentCompiledRule(rule)
		return
	}
	i.currentCompiledRule = nil
}

func (i *Interpreter) setCurrentCompiledRule(rule *CompiledRule) {
	i.currentRule = rule.Name
	i.currentRuleIndex = rule.Index
	i.currentCompiledRule = rule
	i.stringLiterals = rule.StringLiterals
	i.stringSets = rule.StringSets
	i.textStringSets = rule.TextStringSets
	i.allStrings = rule.IndexToStringID // Pre-built in BuildStringIndex()
	i.anonymousStrings = rule.AnonymousStrings
	i.bytecode = rule.Bytecode // Ensure bytecode is updated for the rule
}

// GetString resolves a Value to a string (exported version of getString)
func (i *Interpreter) GetString(v Value) string {
	return i.getString(v)
}

// PushString appends a string to the arena and pushes a Value pointing to it (exported)
func (i *Interpreter) PushString(s string) error {
	return i.pushString(s)
}

// SetRuleResults sets the shared rule results map. The map is borrowed because
// rule execution writes results that the caller may consume.
func (i *Interpreter) SetRuleResults(ruleResults map[string]bool) {
	i.ruleResults = ruleResults
}

// SetRuleResultsDense sets the direct-indexed boolean slice for rule results.
func (i *Interpreter) SetRuleResultsDense(dense []bool) {
	i.ruleResultsDense = dense
}

// SetStringLiterals sets an owned snapshot of the string literal pool for
// OpPushStr.
func (i *Interpreter) SetStringLiterals(literals []string) {
	i.stringLiterals = slices.Clone(literals)
}

// SetStringSets sets an owned snapshot of the string sets used by OpOf.
func (i *Interpreter) SetStringSets(sets [][]string) {
	i.stringSets = cloneStringSlices(sets)
}

// SetTextStringSets sets an owned snapshot of the text string sets used for
// text-string-set iteration.
func (i *Interpreter) SetTextStringSets(sets [][]string) {
	i.textStringSets = cloneStringSlices(sets)
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

// GetRuleResults returns an owned snapshot of all rule results.
func (i *Interpreter) GetRuleResults() map[string]bool {
	return maps.Clone(i.ruleResults)
}

func (i *Interpreter) ruleResultByIndex(idx int, name string) bool {
	if idx >= 0 && idx < len(i.ruleResultsDense) {
		return i.ruleResultsDense[idx]
	}
	if i.ruleResults != nil {
		return i.ruleResults[name]
	}
	return false
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
	// Memory is cleared by prepareInterpreter before Execute().
	// This method is also called standalone (e.g., in tests), so clear
	// memory only when not using the scanner's prepareInterpreter path.
	if i.matchContext == nil {
		for idx := range i.memory {
			i.memory[idx] = Value{Type: ValueTypeUndefined}
		}
	}
	i.stopped = false
	i.result = nil
	if i.ruleResults == nil {
		if i.ruleResultsDense == nil {
			i.ruleResults = make(map[string]bool)
		}
	} else if !i.PreserveRuleResults {
		clear(i.ruleResults)
	}
	if i.ruleResultsDense != nil && !i.PreserveRuleResults {
		clear(i.ruleResultsDense)
	}
	i.iterators = i.iterators[:0]
}

// Execute runs the bytecode
func (i *Interpreter) Execute() error {
	// Reset interpreter state for clean execution
	i.Reset()

	if i.matchContext != nil && i.matchContext.cancelDone != nil {
		return i.executeMainLoopWithCancel(i.matchContext.cancelDone)
	}
	return i.executeMainLoop()
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
