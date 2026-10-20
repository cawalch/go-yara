package compiler

import (
	"cmp"
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

// MatchContext holds pattern matching state
type MatchContext struct {
	Data         []byte
	Blocks       []MemoryBlock
	Matches      map[string][]Match // Pattern -> list of matches
	matchBuffers map[string][]Match
	spans        map[string][]matchSpan
	spanBuffers  map[string][]matchSpan
	cancelDone   <-chan struct{}
	regexBatch   regex.VMBatch
	FileSize     int64
	EntryPoint   int64
	// maxMatchesPerPattern bounds retained occurrences. Zero means unlimited.
	maxMatchesPerPattern int
	// maxMatchSpan bounds the maximum byte length of a single regex match. Zero means unlimited.
	maxMatchSpan int
	compact      bool
}

func (mc *MatchContext) dataRange(offset, size int64) ([]byte, bool) {
	if mc == nil || offset < 0 || size < 0 {
		return nil, false
	}
	if mc.Data != nil {
		if offset > int64(len(mc.Data)) || size > int64(len(mc.Data))-offset {
			return nil, false
		}
		return mc.Data[offset : offset+size], true
	}
	for _, block := range mc.Blocks {
		if offset < block.Base {
			continue
		}
		relative := offset - block.Base
		if relative <= int64(len(block.Data)) && size <= int64(len(block.Data))-relative {
			return block.Data[relative : relative+size], true
		}
	}
	return nil, false
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
	MatchedData          []byte
	ContextBefore        []byte
	ContextAfter         []byte
	Captures             []Capture
	Offset               int64
	Length               int
	Base                 int64 // Base address for match
	MatchedDataTruncated bool
}

// AddMatch adds a match to the context
func (mc *MatchContext) AddMatch(m Match) {
	if m.Pattern == "" {
		return
	}
	if mc.maxMatchesPerPattern > 0 && mc.matchCount(m.Pattern) >= mc.maxMatchesPerPattern {
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
	if mc.maxMatchesPerPattern > 0 && mc.matchCount(id) >= mc.maxMatchesPerPattern {
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

// hasMatchAt returns true if string id has a match at targetOffset in O(log N) time.
func (mc *MatchContext) hasMatchAt(id string, targetOffset int64) bool {
	if mc == nil || targetOffset < 0 {
		return false
	}
	if mc.compact {
		return hasSpanAt(mc.spans[id], targetOffset)
	}
	return hasMatchObjAt(mc.Matches[id], targetOffset)
}

func hasSpanAt(spans []matchSpan, targetOffset int64) bool {
	n := len(spans)
	if n == 0 || spans[0].Offset > targetOffset || spans[n-1].Offset < targetOffset {
		return false
	}
	idx, found := slices.BinarySearchFunc(spans, targetOffset, func(span matchSpan, target int64) int {
		return cmp.Compare(span.Offset, target)
	})
	if found && idx < n {
		return true
	}
	if spans[0].Offset > spans[n-1].Offset {
		for _, span := range spans {
			if span.Offset == targetOffset {
				return true
			}
		}
	}
	return false
}

func hasMatchObjAt(matches []Match, targetOffset int64) bool {
	n := len(matches)
	if n == 0 || matches[0].Offset > targetOffset || matches[n-1].Offset < targetOffset {
		return false
	}
	idx, found := slices.BinarySearchFunc(matches, targetOffset, func(m Match, target int64) int {
		return cmp.Compare(m.Offset, target)
	})
	if found && idx < n {
		return true
	}
	if matches[0].Offset > matches[n-1].Offset {
		for _, m := range matches {
			if m.Offset == targetOffset {
				return true
			}
		}
	}
	return false
}

// hasMatchInRange returns true if string id has at least one match with Offset in [minOffset, maxOffset] in O(log N) time.
func (mc *MatchContext) hasMatchInRange(id string, minOffset, maxOffset int64) bool {
	if mc == nil || minOffset > maxOffset || maxOffset < 0 {
		return false
	}
	if mc.compact {
		return hasSpanInRange(mc.spans[id], minOffset, maxOffset)
	}
	return hasMatchObjInRange(mc.Matches[id], minOffset, maxOffset)
}

func hasSpanInRange(spans []matchSpan, minOffset, maxOffset int64) bool {
	n := len(spans)
	if n == 0 || spans[0].Offset > maxOffset || spans[n-1].Offset < minOffset {
		return false
	}
	idx, _ := slices.BinarySearchFunc(spans, minOffset, func(span matchSpan, target int64) int {
		return cmp.Compare(span.Offset, target)
	})
	if idx < n && spans[idx].Offset <= maxOffset {
		return true
	}
	if spans[0].Offset > spans[n-1].Offset {
		for _, span := range spans {
			if span.Offset >= minOffset && span.Offset <= maxOffset {
				return true
			}
		}
	}
	return false
}

func hasMatchObjInRange(matches []Match, minOffset, maxOffset int64) bool {
	n := len(matches)
	if n == 0 || matches[0].Offset > maxOffset || matches[n-1].Offset < minOffset {
		return false
	}
	idx, _ := slices.BinarySearchFunc(matches, minOffset, func(m Match, target int64) int {
		return cmp.Compare(m.Offset, target)
	})
	if idx < n && matches[idx].Offset <= maxOffset {
		return true
	}
	if matches[0].Offset > matches[n-1].Offset {
		for _, m := range matches {
			if m.Offset >= minOffset && m.Offset <= maxOffset {
				return true
			}
		}
	}
	return false
}

// hasProximity tests whether there exists a pair of matches (matchA, matchB) such that
// minDist <= matchB.Offset - matchA.Offset <= maxDist.
// Because matches are ordered monotonically by offset, this runs in O(N + M) time
// via a two-pointer linear scan with zero allocations.
//
//nolint:revive // argument-limit: internal helper requires (idA, idB, minDist, maxDist)
func (mc *MatchContext) hasProximity(idA, idB string, minDist, maxDist int64) bool {
	if mc == nil || minDist > maxDist {
		return false
	}
	if mc.compact {
		return hasProximitySpans(mc.spans[idA], mc.spans[idB], minDist, maxDist)
	}
	return hasProximityMatches(mc.Matches[idA], mc.Matches[idB], minDist, maxDist)
}

//nolint:revive // argument-limit: internal helper requires (spansA, spansB, minDist, maxDist)
func hasProximitySpans(spansA, spansB []matchSpan, minDist, maxDist int64) bool {
	nA, nB := len(spansA), len(spansB)
	if nA == 0 || nB == 0 {
		return false
	}
	if !isSortedSpans(spansA) {
		spansA = cloneAndSortSpans(spansA)
	}
	if !isSortedSpans(spansB) {
		spansB = cloneAndSortSpans(spansB)
	}
	i, j := 0, 0
	for i < nA && j < nB {
		diff := spansB[j].Offset - spansA[i].Offset
		switch {
		case diff < minDist:
			j++
		case diff > maxDist:
			i++
		default:
			return true
		}
	}
	return false
}

//nolint:revive // argument-limit: internal helper requires (matchesA, matchesB, minDist, maxDist)
func hasProximityMatches(matchesA, matchesB []Match, minDist, maxDist int64) bool {
	nA, nB := len(matchesA), len(matchesB)
	if nA == 0 || nB == 0 {
		return false
	}
	if !isSortedMatches(matchesA) {
		matchesA = cloneAndSortMatches(matchesA)
	}
	if !isSortedMatches(matchesB) {
		matchesB = cloneAndSortMatches(matchesB)
	}
	i, j := 0, 0
	for i < nA && j < nB {
		diff := matchesB[j].Offset - matchesA[i].Offset
		switch {
		case diff < minDist:
			j++
		case diff > maxDist:
			i++
		default:
			return true
		}
	}
	return false
}

func isSortedSpans(spans []matchSpan) bool {
	for k := 1; k < len(spans); k++ {
		if spans[k].Offset < spans[k-1].Offset {
			return false
		}
	}
	return true
}

func cloneAndSortSpans(spans []matchSpan) []matchSpan {
	cloned := slices.Clone(spans)
	slices.SortFunc(cloned, func(a, b matchSpan) int {
		if a.Offset < b.Offset {
			return -1
		}
		if a.Offset > b.Offset {
			return 1
		}
		return 0
	})
	return cloned
}

func isSortedMatches(matches []Match) bool {
	for k := 1; k < len(matches); k++ {
		if matches[k].Offset < matches[k-1].Offset {
			return false
		}
	}
	return true
}

func cloneAndSortMatches(matches []Match) []Match {
	cloned := slices.Clone(matches)
	slices.SortFunc(cloned, func(a, b Match) int {
		if a.Offset < b.Offset {
			return -1
		}
		if a.Offset > b.Offset {
			return 1
		}
		return 0
	})
	return cloned
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
