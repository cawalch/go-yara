package compiler

import (
	"fmt"
	"math"
	"strconv"
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
	bytecode      []byte
	ip            int        // Instruction pointer
	stack         []Value    // Execution stack
	memory        [256]Value // Memory slots for variables
	stopped       bool
	result        error
	matchContext  *MatchContext    // Pattern matching context
	ruleResults   map[string]bool  // Track execution results of all rules in the program
	currentRule   string           // Name of the currently executing rule
	compiledRules []*CompiledRule  // All compiled rules in the program
	handlers      *HandlerRegistry // Opcode handlers
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

// NewInterpreter creates a new bytecode interpreter
func NewInterpreter(bytecode []byte) *Interpreter {
	return &Interpreter{
		bytecode: bytecode,
		ip:       0,
		stack:    make([]Value, 0, 256),
		stopped:  false,
		handlers: NewHandlerRegistry(),
		matchContext: &MatchContext{
			Matches: make(map[string][]Match),
		},
		ruleResults: make(map[string]bool),
	}
}

// SetMatchContext sets the pattern matching context
func (i *Interpreter) SetMatchContext(ctx *MatchContext) {
	i.matchContext = ctx
}

// SetCompiledRules sets the compiled rules for rule reference resolution
func (i *Interpreter) SetCompiledRules(rules []*CompiledRule) {
	i.compiledRules = rules
}

// isBinaryFile checks if the current data represents a binary file format
// This is a simple heuristic to determine if we should use entrypoint=0 or -1
func (i *Interpreter) isBinaryFile() bool {
	if i.matchContext == nil || len(i.matchContext.Data) == 0 {
		return false
	}

	// Simple heuristic: if the data contains null bytes or non-printable characters,
	// it's likely a binary file
	data := i.matchContext.Data
	nullCount := 0
	nonPrintableCount := 0

	for _, b := range data {
		if b == 0 {
			nullCount++
		}
		if b < 32 && b != 9 && b != 10 && b != 13 { // Not tab, newline, or carriage return
			nonPrintableCount++
		}
	}

	// If we have significant null bytes or non-printable characters, consider it binary
	return nullCount > 0 || float64(nonPrintableCount)/float64(len(data)) > 0.1
}

// GetMatchContext returns the current match context
func (i *Interpreter) GetMatchContext() *MatchContext {
	return i.matchContext
}

// SetCurrentRule sets the name of the currently executing rule
func (i *Interpreter) SetCurrentRule(ruleName string) {
	i.currentRule = ruleName
}

// SetRuleResults sets the shared rule results map
func (i *Interpreter) SetRuleResults(ruleResults map[string]bool) {
	i.ruleResults = ruleResults
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
	i.result = nil
	i.ruleResults = make(map[string]bool)
	i.currentRule = ""
}

// Execute runs the bytecode
func (i *Interpreter) Execute() error {
	// Reset interpreter state for clean execution
	i.Reset()

	for !i.stopped && i.ip < len(i.bytecode) {
		opcode := Opcode(i.bytecode[i.ip])
		i.ip++

		if err := i.executeOpcode(opcode); err != nil {
			i.result = err
			return err
		}
	}

	// Store the execution result for the current rule
	if i.currentRule != "" && len(i.stack) > 0 {
		result := i.stack[len(i.stack)-1]
		if result.Type == ValueTypeInt {
			i.ruleResults[i.currentRule] = result.IntVal != 0
		} else {
			i.ruleResults[i.currentRule] = false
		}
	}

	return i.result
}

// executeOpcode executes a single opcode using the handler system
func (i *Interpreter) executeOpcode(opcode Opcode) error {
	if i.handlers == nil {
		return &InterpreterError{
			Type:    ErrorUnimplemented,
			Opcode:  opcode,
			Message: "interpreter handler registry not initialized",
		}
	}

	handler := i.handlers.GetHandler(opcode)

	// For direct calls (like in tests), we need to handle the case where
	// the instruction pointer isn't properly positioned for bytecode access
	switch h := handler.(type) {
	case *PatternHandler:
		// Pattern handlers need special handling for direct test calls
		return h.executeWithOpcode(i, opcode)
	case *StringHandler:
		// String handlers need special handling for direct test calls
		return h.executeWithOpcode(i, opcode)
	}

	if err := handler.Execute(i); err != nil {
		return fmt.Errorf("opcode handler execution: %w", err)
	}
	return nil
}

// String returns a string representation of the value
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
	// TODO: Implement debug mode with instruction tracing
}

// DisableDebugMode disables debug information collection
func (i *Interpreter) DisableDebugMode() {
	// TODO: Implement debug mode disabling
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
	if i.matchContext == nil {
		return 0, &InterpreterError{
			Type:    ErrorInvalidMemoryAccess,
			Message: "no match context available for reading data",
		}
	}

	data := i.matchContext.Data
	if offset < 0 || int(offset) >= len(data) {
		return 0, &InterpreterError{
			Type:    ErrorInvalidMemoryAccess,
			Message: fmt.Sprintf("offset %d is out of bounds", offset),
		}
	}

	switch size {
	case 1:
		val := data[offset]
		if unsigned {
			return int64(val), nil
		}
		return int64(int8(val)), nil

	case 2:
		if offset+1 >= int64(len(data)) {
			return 0, &InterpreterError{
				Type:    ErrorInvalidMemoryAccess,
				Message: "16-bit read extends beyond data bounds",
			}
		}
		val := uint16(data[offset]) | uint16(data[offset+1])<<8
		if unsigned {
			return int64(val), nil
		}
		return int64(int16(val)), nil

	case 4:
		if offset+3 >= int64(len(data)) {
			return 0, &InterpreterError{
				Type:    ErrorInvalidMemoryAccess,
				Message: "32-bit read extends beyond data bounds",
			}
		}
		val := uint32(data[offset]) | uint32(data[offset+1])<<8 |
			uint32(data[offset+2])<<16 | uint32(data[offset+3])<<24
		if unsigned {
			return int64(val), nil
		}
		return int64(int32(val)), nil

	default:
		return 0, &InterpreterError{
			Type:    ErrorInvalidMemoryAccess,
			Message: fmt.Sprintf("unsupported integer size: %d", size),
		}
	}
}
