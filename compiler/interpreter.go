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
	currentRule         string                   // Name of the currently executing rule
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
	debugMode           bool // Debug mode flag for instruction tracing
	itersmax            int  // Max total iterations across all for-loops (0 = unlimited)
	iterations          int  // Current total iteration count
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
	// Text strings for text-string-set iteration (e.g. for any s in ("a", "b") : ...)
	TextStrings []string
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
	Data         []byte
	Matches      map[string][]Match // Pattern -> list of matches
	FileSize     int64
	EntryPoint   int64
	matchBuffers map[string][]Match
	spans        map[string][]matchSpan
	spanBuffers  map[string][]matchSpan
	compact      bool
}

// matchSpan is the scanner's compact representation of a match. Pattern is
// supplied by the containing map and public Match values are materialized only
// at the result boundary, keeping the evaluation hot path to offset and length.
type matchSpan struct {
	Offset int64
	Length int
}

// Match represents a pattern match
type Match struct {
	Pattern              string
	Offset               int64
	Length               int
	Base                 int64 // Base address for match
	MatchedData          []byte
	ContextBefore        []byte
	ContextAfter         []byte
	MatchedDataTruncated bool
}

// AddMatch adds a match to the context
func (mc *MatchContext) AddMatch(m Match) {
	if m.Pattern == "" {
		return
	}
	if mc.compact {
		mc.addMatchSpan(m.Pattern, matchSpan{Offset: m.Offset, Length: m.Length})
		return
	}
	if mc.Matches == nil {
		mc.Matches = make(map[string][]Match)
	}
	matches, exists := mc.Matches[m.Pattern]
	if !exists && mc.matchBuffers != nil {
		matches = mc.matchBuffers[m.Pattern]
	}
	mc.Matches[m.Pattern] = append(matches, m)
}

func (mc *MatchContext) addMatchSpan(id string, span matchSpan) {
	if id == "" {
		return
	}
	if mc.spans == nil {
		mc.spans = make(map[string][]matchSpan)
	}
	spans, exists := mc.spans[id]
	if !exists && mc.spanBuffers != nil {
		spans = mc.spanBuffers[id]
	}
	mc.spans[id] = append(spans, span)
}

func (mc *MatchContext) matchCount(id string) int {
	if mc == nil {
		return 0
	}
	if mc.compact {
		return len(mc.spans[id])
	}
	return len(mc.Matches[id])
}

func (mc *MatchContext) matchAt(id string, index int) (matchSpan, bool) {
	if mc == nil || index < 0 {
		return matchSpan{}, false
	}
	if mc.compact {
		spans := mc.spans[id]
		if index >= len(spans) {
			return matchSpan{}, false
		}
		return spans[index], true
	}
	matches := mc.Matches[id]
	if index >= len(matches) {
		return matchSpan{}, false
	}
	return matchSpan{Offset: matches[index].Offset, Length: matches[index].Length}, true
}

func (mc *MatchContext) eachMatch(id string, visit func(matchSpan) bool) {
	if mc == nil || visit == nil {
		return
	}
	if mc.compact {
		for _, span := range mc.spans[id] {
			if !visit(span) {
				return
			}
		}
		return
	}
	for _, match := range mc.Matches[id] {
		if !visit(matchSpan{Offset: match.Offset, Length: match.Length}) {
			return
		}
	}
}

func (mc *MatchContext) anyMatch(id string, predicate func(matchSpan) bool) bool {
	found := false
	mc.eachMatch(id, func(span matchSpan) bool {
		if predicate(span) {
			found = true
			return false
		}
		return true
	})
	return found
}

func (mc *MatchContext) matchIDs() []string {
	if mc == nil {
		return nil
	}
	if mc.compact {
		ids := make([]string, 0, len(mc.spans))
		for id := range mc.spans {
			ids = append(ids, id)
		}
		return ids
	}
	ids := make([]string, 0, len(mc.Matches))
	for id := range mc.Matches {
		ids = append(ids, id)
	}
	return ids
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
// SetItersmax sets the maximum number of for-loop iterations.
// A value of 0 means unlimited.
func (i *Interpreter) SetItersmax(limit int) {
	i.itersmax = limit
}

// ResetIterationCount resets the iteration counter.
func (i *Interpreter) ResetIterationCount() {
	i.iterations = 0
}

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
	i.matchContext.compact = false
	i.matchContext.Reset(nil)

	i.stack = i.stack[:0] // Ensure clean stack on reuse

	return i
}

// Release returns the interpreter to the pool for reuse
func (i *Interpreter) Release() {
	i.bytecode = nil
	i.compiledRules = nil
	i.ruleMap = nil
	i.stringLiterals = nil
	i.stringSets = nil
	i.textStringSets = nil
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

	// Clear stack
	i.stack = i.stack[:0]

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
	// Build O(1) lookup map by rule name
	i.ruleMap = make(map[string]*CompiledRule, len(rules))
	for _, rule := range rules {
		i.ruleMap[rule.Name] = rule
	}
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
	if rule, ok := i.ruleMap[ruleName]; ok {
		i.currentCompiledRule = rule
		i.stringLiterals = rule.StringLiterals
		i.stringSets = rule.StringSets
		i.textStringSets = rule.TextStringSets
		i.allStrings = rule.IndexToStringID // Pre-built in BuildStringIndex()
		i.anonymousStrings = rule.AnonymousStrings
		i.bytecode = rule.Bytecode // Ensure bytecode is updated for the rule
		return
	}
	i.currentCompiledRule = nil
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

// SetTextStringSets sets the text string sets for text-string-set iteration.
func (i *Interpreter) SetTextStringSets(sets [][]string) {
	i.textStringSets = sets
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
