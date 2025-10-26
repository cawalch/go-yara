// Package compiler provides bytecode generation and compilation for YARA rules.
package compiler

import (
	"fmt"
	"sync"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/regex"
)

// RuleCompiler handles compilation of complete YARA rules
type RuleCompiler struct {
	emitter           *Emitter
	stringCompiler    *StringCompiler
	conditionCompiler *ConditionCompiler
	automaton         *ACAutomaton
	currentRule       *ast.Rule
	ruleIndex         int
}

// NewRuleCompiler creates a new rule compiler
func NewRuleCompiler() *RuleCompiler {
	emitter := NewEmitter()
	automaton := NewACAutomaton()

	return &RuleCompiler{
		emitter:           emitter,
		stringCompiler:    NewStringCompiler(emitter),
		conditionCompiler: NewConditionCompiler(emitter, make(map[string]int)),
		automaton:         automaton,
		ruleIndex:         0,
	}
}

// CompileRule compiles a complete YARA rule to bytecode
func (rc *RuleCompiler) CompileRule(rule *ast.Rule) (*CompiledRule, error) {
	rc.currentRule = rule

	// Reset components for new rule
	rc.emitter.Reset()
	rc.automaton.Reset()

	// Compile strings first
	if err := rc.compileStrings(rule); err != nil {
		return nil, fmt.Errorf("compiling strings: %w", err)
	}

	// Compile the automaton if we have strings
	if len(rule.Strings) > 0 {
		if err := rc.automaton.Compile(); err != nil {
			return nil, fmt.Errorf("compiling automaton: %w", err)
		}
	}

	// Compile condition
	if err := rc.compileCondition(rule); err != nil {
		return nil, fmt.Errorf("compiling condition: %w", err)
	}

	// Finalize bytecode
	bytecode, err := rc.emitter.GetBytecode()
	if err != nil {
		return nil, fmt.Errorf("generating bytecode: %w", err)
	}

	// Create compiled rule
	compiledRule := &CompiledRule{
		Name:         rule.Name,
		Index:        rc.ruleIndex,
		Bytecode:     bytecode,
		StringCount:  len(rule.Strings),
		Automaton:    rc.automaton,
		Stats:        nil, // Lazy: computed on demand
		ruleCompiler: rc,  // Store reference for lazy computation
	}

	rc.ruleIndex++
	return compiledRule, nil
}

// compileStrings compiles all strings in the rule
func (rc *RuleCompiler) compileStrings(rule *ast.Rule) error {
	// First pass: validate and prepare strings
	for _, str := range rule.Strings {
		if err := rc.stringCompiler.ValidateStringModifiers(str.Modifiers); err != nil {
			return fmt.Errorf("validating string %s: %w", str.Identifier, err)
		}
	}

	// Pre-size buffers to reduce allocations
	rc.emitter.ReserveInstructions(2*len(rule.Strings) + 32)
	rc.automaton.ReserveStrings(len(rule.Strings))

	// Rough upper-bound estimate of states: 1 (root) + sum of pattern byte lengths
	expectedStates := 1
	for _, str := range rule.Strings {
		switch p := str.Pattern.(type) {
		case *ast.TextString:
			l := len(p.Value)
			// Wide strings double the byte length
			for _, m := range str.Modifiers {
				if m.Type == ast.StringModifierWide {
					l *= 2
					break
				}
			}
			expectedStates += l
		case *ast.HexString:
			// Approximate: two hex digits per byte; ignore comments/whitespace
			expectedStates += len(p.Value) / 2
		case *ast.RegexPattern:
			// Fallback to pattern length
			expectedStates += len(p.Value)
		}
	}
	rc.automaton.ReserveStates(expectedStates)

	// Second pass: compile strings and build automaton
	for _, str := range rule.Strings {
		if err := rc.compileSingleString(str); err != nil {
			return fmt.Errorf("compiling string %s: %w", str.Identifier, err)
		}
	}

	return nil
}

// compileSingleString compiles a single string and adds it to the automaton
func (rc *RuleCompiler) compileSingleString(str *ast.String) error {
	var patternData []byte
	isRegex := false
	var rflags regex.Flags

	// Extract pattern data based on pattern type
	switch p := str.Pattern.(type) {
	case *ast.TextString:
		encoded := rc.stringCompiler.encodeTextString(p.Value, str.Modifiers)
		patternData = rc.stringCompiler.OptimizePattern(encoded, str.Modifiers)
	case *ast.HexString:
		hexData := rc.stringCompiler.parseHexString(p.Value)
		encoded := rc.stringCompiler.encodeHexString(hexData, str.Modifiers)
		patternData = rc.stringCompiler.OptimizePattern(encoded, str.Modifiers)
	case *ast.RegexPattern:
		code, err := rc.stringCompiler.compileRegex(p.Value, str.Modifiers)
		if err != nil {
			return fmt.Errorf("compile regex pattern: %w", err)
		}
		patternData = code // VM bytecode
		isRegex = true

		// Derive VM flags from string modifiers
		for _, m := range str.Modifiers {
			switch m.Type {
			case ast.StringModifierWide:
				rflags |= regex.FlagsWide
			case ast.StringModifierNocase:
				rflags |= regex.FlagsNoCase
			}
		}

		// Derive inline regex flags from literal suffix (e.g., /.../is)
		// We scan from the end to the closing '/' and interpret trailing flag letters.
		if len(p.Value) >= 2 && p.Value[0] == '/' {
			endIdx := len(p.Value) - 1
			for endIdx > 0 && p.Value[endIdx] != '/' {
				endIdx--
			}
			if endIdx > 0 && endIdx < len(p.Value)-1 {
				for i := endIdx + 1; i < len(p.Value); i++ {
					switch p.Value[i] {
					case 'i', 'I':
						rflags |= regex.FlagsNoCase
					case 's', 'S':
						rflags |= regex.FlagsDotAll
					}
				}
			}
		}
	default:
		return fmt.Errorf("unsupported pattern type")
	}

	// Record string offset for condition compiler
	// Use the automaton string count as the offset
	offset := rc.automaton.StringCount
	rc.stringCompiler.stringOffsets[str.Identifier] = offset

	// Add to automaton (regex strings are marked and will be executed via VM)
	if isRegex {
		if err := rc.automaton.AddStringWithFlags(str.Identifier, patternData, false, isRegex, rflags); err != nil {
			return fmt.Errorf("adding regex string to automaton: %w", err)
		}
	} else {
		if err := rc.automaton.AddString(str.Identifier, patternData, false, isRegex); err != nil {
			return fmt.Errorf("adding string to automaton: %w", err)
		}
	}

	return nil
}

// compileCondition compiles the rule condition
func (rc *RuleCompiler) compileCondition(rule *ast.Rule) error {
	// Set up string offsets for condition compiler
	stringOffsets := rc.stringCompiler.GetStringOffsets()
	rc.conditionCompiler.SetStringOffsets(stringOffsets)

	// Compile the condition expression
	if err := rc.conditionCompiler.compileExpression(rule.Condition); err != nil {
		return fmt.Errorf("compiling condition: %w", err)
	}

	// Emit final halt instruction (use a default position)
	rc.emitter.EmitHalt(0, 0)

	return nil
}

// CompileProgram compiles a complete YARA program (multiple rules)
func (rc *RuleCompiler) CompileProgram(program *ast.Program) ([]*CompiledRule, error) {
	var compiledRules []*CompiledRule

	// First, register all external variables with the condition compiler
	for _, extVar := range program.ExternalVariables {
		rc.registerExternalVariable(extVar)
	}

	for _, rule := range program.Rules {
		compiledRule, err := rc.CompileRule(rule)
		if err != nil {
			return nil, fmt.Errorf("compiling rule %s: %w", rule.Name, err)
		}
		compiledRules = append(compiledRules, compiledRule)
	}

	return compiledRules, nil
}

// registerExternalVariable registers an external variable with the condition compiler
func (rc *RuleCompiler) registerExternalVariable(extVar *ast.ExternalVariable) {
	// Generate a unique index for this external variable
	index := len(rc.conditionCompiler.externalVariables)
	rc.conditionCompiler.externalVariables[extVar.Name] = index
}

// getCompilationStats returns statistics about the compilation process
func (rc *RuleCompiler) getCompilationStats() map[string]interface{} {
	stats := make(map[string]interface{})

	stats["instruction_count"] = rc.emitter.GetInstructionCount()
	stats["bytecode_size"] = rc.emitter.GetSize()
	stats["string_count"] = len(rc.currentRule.Strings)
	stats["automaton_states"] = rc.automaton.GetStateCount()
	stats["variables"] = len(rc.conditionCompiler.GetVariableMap())

	// Add emitter stats
	emitterStats := rc.emitter.GetStats()
	for k, v := range emitterStats {
		stats["emitter_"+k] = v
	}

	// Add string compiler stats
	stringInfo := rc.stringCompiler.GetStringInfo()
	stats["string_info"] = stringInfo

	return stats
}

// CompiledRule represents a compiled YARA rule
type CompiledRule struct {
	Name         string                 // Rule name
	Index        int                    // Rule index in program
	Bytecode     []byte                 // Compiled bytecode
	StringCount  int                    // Number of strings
	Automaton    *ACAutomaton           // Aho-Corasick automaton for pattern matching
	Stats        map[string]interface{} // Compilation statistics (lazy computed)
	statsOnce    sync.Once              // Ensure stats computed only once
	ruleCompiler *RuleCompiler          // Reference for lazy stats computation
}

// GetName returns the rule name
func (cr *CompiledRule) GetName() string {
	return cr.Name
}

// GetBytecode returns the compiled bytecode
func (cr *CompiledRule) GetBytecode() []byte {
	return cr.Bytecode
}

// GetStringCount returns the number of strings in the rule
func (cr *CompiledRule) GetStringCount() int {
	return cr.StringCount
}

// GetStats returns compilation statistics (computed lazily on first access)
func (cr *CompiledRule) GetStats() map[string]interface{} {
	cr.statsOnce.Do(func() {
		if cr.ruleCompiler != nil {
			cr.Stats = cr.ruleCompiler.getCompilationStats()
		} else {
			cr.Stats = make(map[string]interface{})
		}
	})
	return cr.Stats
}

// GetAutomaton returns the Aho-Corasick automaton
func (cr *CompiledRule) GetAutomaton() *ACAutomaton {
	return cr.Automaton
}

// Validate validates the compiled rule
func (cr *CompiledRule) Validate() error {
	if len(cr.Bytecode) == 0 {
		return fmt.Errorf("empty bytecode")
	}

	if cr.StringCount > 0 && cr.Automaton == nil {
		return fmt.Errorf("strings present but no automaton")
	}

	if cr.Automaton != nil {
		if err := cr.Automaton.Validate(); err != nil {
			return fmt.Errorf("invalid automaton: %w", err)
		}
	}

	return nil
}

// GetMemoryUsage estimates the memory usage of the compiled rule
func (cr *CompiledRule) GetMemoryUsage() int {
	usage := len(cr.Bytecode)

	if cr.Automaton != nil {
		usage += cr.Automaton.EstimateMemoryUsage()
	}

	// Add stats map overhead (rough estimate)
	usage += len(cr.Stats) * 100

	return usage
}

// PrintDebug prints debug information about the compiled rule
func (cr *CompiledRule) PrintDebug() {
	fmt.Printf("Compiled Rule: %s\n", cr.Name)
	fmt.Printf("  Index: %d\n", cr.Index)
	fmt.Printf("  Bytecode Size: %d bytes\n", len(cr.Bytecode))
	fmt.Printf("  String Count: %d\n", cr.StringCount)
	fmt.Printf("  Memory Usage: ~%d bytes\n", cr.GetMemoryUsage())

	if cr.Automaton != nil {
		fmt.Printf("  Automaton States: %d\n", cr.Automaton.GetStateCount())
	}

	fmt.Printf("  Instructions: %d\n", cr.Stats["instruction_count"])

	// Print bytecode if not too large
	if len(cr.Bytecode) <= 64 {
		fmt.Printf("  Bytecode: %X\n", cr.Bytecode)
	} else {
		fmt.Printf("  Bytecode: %X... (truncated)\n", cr.Bytecode[:32])
	}
}

// CompiledProgram represents a complete compiled YARA program
type CompiledProgram struct {
	Rules []*CompiledRule
	Stats map[string]interface{}
}

// NewCompiledProgram creates a new compiled program
func NewCompiledProgram(rules []*CompiledRule) *CompiledProgram {
	return &CompiledProgram{
		Rules: rules,
		Stats: make(map[string]interface{}),
	}
}

// GetRuleCount returns the number of compiled rules
func (cp *CompiledProgram) GetRuleCount() int {
	return len(cp.Rules)
}

// GetTotalBytecodeSize returns the total size of all bytecode
func (cp *CompiledProgram) GetTotalBytecodeSize() int {
	total := 0
	for _, rule := range cp.Rules {
		total += len(rule.Bytecode)
	}
	return total
}

// GetTotalMemoryUsage returns the estimated total memory usage
func (cp *CompiledProgram) GetTotalMemoryUsage() int {
	total := 0
	for _, rule := range cp.Rules {
		total += rule.GetMemoryUsage()
	}
	return total
}

// Validate validates all compiled rules
func (cp *CompiledProgram) Validate() error {
	for i, rule := range cp.Rules {
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("validating rule %d (%s): %w", i, rule.Name, err)
		}
	}
	return nil
}

// GetRuleByName finds a rule by name
func (cp *CompiledProgram) GetRuleByName(name string) (*CompiledRule, bool) {
	for _, rule := range cp.Rules {
		if rule.Name == name {
			return rule, true
		}
	}
	return nil, false
}

// PrintDebug prints debug information about the compiled program
func (cp *CompiledProgram) PrintDebug() {
	fmt.Printf("Compiled Program Debug Information:\n")
	fmt.Printf("  Rule Count: %d\n", len(cp.Rules))
	fmt.Printf("  Total Bytecode Size: %d bytes\n", cp.GetTotalBytecodeSize())
	fmt.Printf("  Total Memory Usage: ~%d bytes\n", cp.GetTotalMemoryUsage())

	fmt.Printf("\nRules:\n")
	for i, rule := range cp.Rules {
		fmt.Printf("  [%d] %s: %d bytes, %d strings\n",
			i, rule.Name, len(rule.Bytecode), rule.StringCount)
	}
}

// Optimize optimizes the compiled program for better performance
func (cp *CompiledProgram) Optimize() error {
	// This would perform various optimizations:
	// - Merge similar automata
	// - Eliminate redundant bytecode
	// - Optimize memory layout

	// For now, just validate
	return cp.Validate()
}

// GetExecutionPlan creates an execution plan for the compiled program
func (cp *CompiledProgram) GetExecutionPlan() *ExecutionPlan {
	plan := &ExecutionPlan{
		RuleCount:         len(cp.Rules),
		TotalInstructions: 0,
		MemoryLayout:      make([]MemoryRegion, 0),
	}

	// Calculate total instructions
	for _, rule := range cp.Rules {
		if stats, ok := rule.Stats["instruction_count"].(int); ok {
			plan.TotalInstructions += stats
		}
	}

	// Plan memory layout
	offset := 0
	for _, rule := range cp.Rules {
		size := len(rule.Bytecode)
		plan.MemoryLayout = append(plan.MemoryLayout, MemoryRegion{
			RuleIndex: rule.Index,
			Offset:    offset,
			Size:      size,
		})
		offset += size
	}

	return plan
}

// ExecutionPlan represents the execution plan for a compiled program
type ExecutionPlan struct {
	RuleCount         int
	TotalInstructions int
	MemoryLayout      []MemoryRegion
}

// MemoryRegion represents a memory region in the execution plan
type MemoryRegion struct {
	RuleIndex int
	Offset    int
	Size      int
}

// GetRuleOffset returns the bytecode offset for a rule
func (ep *ExecutionPlan) GetRuleOffset(ruleIndex int) (int, bool) {
	for _, region := range ep.MemoryLayout {
		if region.RuleIndex == ruleIndex {
			return region.Offset, true
		}
	}
	return 0, false
}

// GetTotalSize returns the total size of the execution plan
func (ep *ExecutionPlan) GetTotalSize() int {
	if len(ep.MemoryLayout) == 0 {
		return 0
	}
	lastRegion := ep.MemoryLayout[len(ep.MemoryLayout)-1]
	return lastRegion.Offset + lastRegion.Size
}
