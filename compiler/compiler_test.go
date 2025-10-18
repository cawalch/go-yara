// Package compiler provides comprehensive tests for the YARA compiler.
package compiler

import (
	"fmt"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

// TestBytecodeOpcodes tests all bytecode opcodes
func TestBytecodeOpcodes(t *testing.T) {
	tests := []struct {
		opcode   Opcode
		expected string
		category string
	}{
		{OP_ERROR, "ERROR", OpCategoryControl},
		{OP_HALT, "HALT", OpCategoryControl},
		{OP_NOP, "NOP", OpCategoryControl},
		{OP_AND, "AND", OpCategoryLogical},
		{OP_OR, "OR", OpCategoryLogical},
		{OP_NOT, "NOT", OpCategoryLogical},
		{OP_PUSH, "PUSH", OpCategoryStack},
		{OP_POP, "POP", OpCategoryStack},
		{OP_INT_ADD, "INT_ADD", OpCategoryArithmetic},
		{OP_INT_EQ, "INT_EQ", OpCategoryArithmetic},
		{OP_FILESIZE, "FILESIZE", OpCategoryObject},
		{OP_CONTAINS, "CONTAINS", OpCategoryString},
		{OP_JZ, "JZ", OpCategoryJump},
		{OP_INT8, "INT8", OpCategoryTypeFunc},
	}

	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			if got := test.opcode.String(); got != test.expected {
				t.Errorf("Opcode.String() = %v, want %v", got, test.expected)
			}

			if got := test.opcode.GetCategory(); got != test.category {
				t.Errorf("Opcode.GetCategory() = %v, want %v", got, test.category)
			}
		})
	}
}

// TestInstructionCreation tests instruction creation and encoding
func TestInstructionCreation(t *testing.T) {
	tests := []struct {
		name     string
		inst     *Instruction
		expected string
		size     int
	}{
		{
			name:     "simple opcode",
			inst:     NewInstruction(OP_NOP, 1, 1),
			expected: "NOP",
			size:     1,
		},
		{
			name:     "push 8-bit",
			inst:     NewInstructionWithOperand(OP_PUSH_8, Operand{Type: OperandImmediate8, Value: 0x42}, 1, 1),
			expected: "PUSH_8 0x42",
			size:     2,
		},
		{
			name:     "push 32-bit",
			inst:     NewInstructionWithOperand(OP_PUSH_32, Operand{Type: OperandImmediate32, Value: 0x12345678}, 1, 1),
			expected: "PUSH_32 0x12345678",
			size:     5,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.inst.String(); got != test.expected {
				t.Errorf("Instruction.String() = %v, want %v", got, test.expected)
			}

			if got := test.inst.Size(); got != test.size {
				t.Errorf("Instruction.Size() = %v, want %v", got, test.size)
			}

			// Test that Bytes() doesn't panic and returns correct size
			bytes := test.inst.Bytes()
			if len(bytes) != test.size {
				t.Errorf("len(Instruction.Bytes()) = %v, want %v", len(bytes), test.size)
			}
		})
	}
}

// TestEmitter tests the bytecode emitter
func TestEmitter(t *testing.T) {
	emitter := NewEmitter()

	// Test basic emission
	offset1 := emitter.EmitOpcode(OP_PUSH, 1, 1)
	offset2 := emitter.EmitOpcode(OP_NOP, 1, 5)

	if offset1 != 0 {
		t.Errorf("First instruction offset = %v, want 0", offset1)
	}

	if offset2 != 1 {
		t.Errorf("Second instruction offset = %v, want 1", offset2)
	}

	// Test push operations
	pushOffset := emitter.EmitPush(0x12345678, 1, 10)
	if pushOffset != 2 {
		t.Errorf("Push instruction offset = %v, want 2", pushOffset)
	}

	// Test instruction count
	if count := emitter.GetInstructionCount(); count != 3 {
		t.Errorf("Instruction count = %v, want 3", count)
	}

	// Test bytecode generation
	bytecode, err := emitter.GetBytecode()
	if err != nil {
		t.Errorf("GetBytecode() error = %v", err)
	}

	expectedSize := emitter.GetSize()
	if len(bytecode) != expectedSize {
		t.Errorf("Bytecode length = %v, want %v", len(bytecode), expectedSize)
	}
}

// TestStringCompiler tests the string compilation system
func TestStringCompiler(t *testing.T) {
	emitter := NewEmitter()
	sc := NewStringCompiler(emitter)

	// Test text string encoding
	text := "Hello, World!"
	modifiers := []ast.StringModifier{
		{Type: ast.StringModifierNocase},
	}

	encoded := sc.encodeTextString(text, modifiers)
	if len(encoded) == 0 {
		t.Error("Text string encoding returned empty result")
	}

	// Test hex string parsing (simplified)
	hexStr := "48656c6c6f"
	hexData := sc.parseHexString(hexStr)
	if len(hexData) == 0 {
		t.Error("Hex string parsing returned empty result")
	}

	// Test pattern optimization
	optimized := sc.OptimizePattern(encoded, modifiers)
	if len(optimized) == 0 {
		t.Error("Pattern optimization returned empty result")
	}

	// Test string info
	info := sc.GetStringInfo()
	if len(info) != 0 {
		t.Error("Expected no string info before compilation")
	}
}

// TestACAutomaton tests the Aho-Corasick automaton
func TestACAutomaton(t *testing.T) {
	ac := NewACAutomaton()

	// Test adding strings
	testStrings := []struct {
		id   string
		data string
	}{
		{"test1", "hello"},
		{"test2", "world"},
		{"test3", "hello world"},
	}

	for _, ts := range testStrings {
		err := ac.AddString(ts.id, []byte(ts.data), false, false)
		if err != nil {
			t.Errorf("Failed to add string %s: %v", ts.id, err)
		}
	}

	// Test compilation
	err := ac.Compile()
	if err != nil {
		t.Errorf("Automaton compilation failed: %v", err)
	}

	// Test search
	testData := []byte("hello world")
	matches := ac.Search(testData)

	if len(matches) == 0 {
		t.Error("Expected matches but found none")
	}

	// Check that we found our test strings
	found := make(map[string]bool)
	for _, match := range matches {
		found[match.StringID] = true
	}

	for _, ts := range testStrings {
		if !found[ts.id] {
			t.Errorf("Expected to find string %s in matches", ts.id)
		}
	}
}

// TestConditionCompiler tests the condition compilation system
func TestConditionCompiler(t *testing.T) {
	emitter := NewEmitter()
	cc := NewConditionCompiler(emitter, make(map[string]int))

	// Test literal compilation
	literal := &ast.Literal{
		Pos:   token.Position{Line: 1, Column: 1},
		Type:  token.TRUE,
		Value: true,
	}

	err := cc.compileLiteral(literal)
	if err != nil {
		t.Errorf("Literal compilation failed: %v", err)
	}

	// Test identifier compilation
	identifier := &ast.Identifier{
		Pos:  token.Position{Line: 1, Column: 1},
		Name: "test_var",
	}

	// Add variable to map first
	cc.AddVariable("test_var", 0)

	err = cc.compileIdentifier(identifier)
	if err != nil {
		t.Errorf("Identifier compilation failed: %v", err)
	}

	// Test binary operation compilation
	binOp := &ast.BinaryOp{
		Pos:   token.Position{Line: 1, Column: 1},
		Left:  &ast.Literal{Pos: token.Position{Line: 1, Column: 1}, Type: token.TRUE, Value: true},
		Op:    token.AND,
		Right: &ast.Literal{Pos: token.Position{Line: 1, Column: 1}, Type: token.FALSE, Value: false},
	}

	err = cc.compileBinaryOp(binOp)
	if err != nil {
		t.Errorf("Binary operation compilation failed: %v", err)
	}
}

// TestRuleCompiler tests the rule compilation system
func TestRuleCompiler(t *testing.T) {
	rc := NewRuleCompiler()

	// Create a simple test rule
	rule := &ast.Rule{
		Pos:   token.Position{Line: 1, Column: 1},
		Name:  "test_rule",
		Strings: []*ast.String{
			{
				Pos:       token.Position{Line: 2, Column: 1},
				Identifier: "$s1",
				Pattern: &ast.TextString{
					Pos:   token.Position{Line: 2, Column: 5},
					Value: "test string",
				},
				Modifiers: []ast.StringModifier{},
			},
		},
		Condition: &ast.Literal{
			Pos:   token.Position{Line: 3, Column: 1},
			Type:  token.TRUE,
			Value: true,
		},
	}

	// Compile the rule
	compiledRule, err := rc.CompileRule(rule)
	if err != nil {
		t.Errorf("Rule compilation failed: %v", err)
	}

	// Validate the compiled rule
	if compiledRule == nil {
		t.Fatal("Compiled rule is nil")
	}

	if compiledRule.Name != "test_rule" {
		t.Errorf("Rule name = %v, want test_rule", compiledRule.Name)
	}

	if len(compiledRule.Bytecode) == 0 {
		t.Error("Compiled rule has empty bytecode")
	}

	// Test rule validation
	err = compiledRule.Validate()
	if err != nil {
		t.Errorf("Rule validation failed: %v", err)
	}
}

// TestCompilerIntegration tests the full compiler pipeline
func TestCompilerIntegration(t *testing.T) {
	// Create a simple YARA rule as source
	source := `
rule test_rule {
    strings:
        $s1 = "hello"
        $s2 = "world"
    condition:
        $s1 and $s2
}`

	compiler := NewCompiler()

	// Compile the source
	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Logf("Compilation errors: %v", compiler.GetErrors())
		t.Fatalf("Source compilation failed: %v", err)
	}

	// Validate the program
	if program == nil {
		t.Fatal("Compiled program is nil")
	}

	if program.GetRuleCount() != 1 {
		t.Logf("Compilation stats: %+v", compiler.GetStats())
		t.Errorf("Expected 1 rule, got %d", program.GetRuleCount())
	}

	// Check compilation statistics
	stats := compiler.GetStats()
	if stats.RulesCompiled != 1 {
		t.Errorf("Stats show %d rules compiled, want 1", stats.RulesCompiled)
	}

	// Test program validation
	err = program.Validate()
	if err != nil {
		t.Errorf("Program validation failed: %v", err)
	}
}

// TestOpcodeClassification tests opcode classification functions
func TestOpcodeClassification(t *testing.T) {
	tests := []struct {
		opcode   Opcode
		isIntOp  bool
		isDblOp  bool
		isStrOp  bool
		isJump   bool
		isTypeFn bool
	}{
		{OP_INT_ADD, true, false, false, false, false},
		{OP_DBL_ADD, false, true, false, false, false},
		{OP_STR_EQ, false, false, true, false, false},
		{OP_JZ, false, false, false, true, false},
		{OP_INT8, false, false, false, false, true},
		{OP_NOP, false, false, false, false, false},
	}

	for _, test := range tests {
		t.Run(test.opcode.String(), func(t *testing.T) {
			if got := IsIntOp(test.opcode); got != test.isIntOp {
				t.Errorf("IsIntOp(%v) = %v, want %v", test.opcode, got, test.isIntOp)
			}

			if got := IsDblOp(test.opcode); got != test.isDblOp {
				t.Errorf("IsDblOp(%v) = %v, want %v", test.opcode, got, test.isDblOp)
			}

			if got := IsStrOp(test.opcode); got != test.isStrOp {
				t.Errorf("IsStrOp(%v) = %v, want %v", test.opcode, got, test.isStrOp)
			}
		})
	}
}

// TestUndefinedValues tests undefined value handling
func TestUndefinedValues(t *testing.T) {
	if !IsUndefined(YR_UNDEFINED) {
		t.Error("YR_UNDEFINED should be recognized as undefined")
	}

	if IsUndefined(0) {
		t.Error("0 should not be recognized as undefined")
	}

	if IsUndefined(42) {
		t.Error("42 should not be recognized as undefined")
	}

	// Test operation with undefined values
	result := Operation(func(a, b uint64) uint64 { return a + b }, YR_UNDEFINED, 5)
	if !IsUndefined(result) {
		t.Error("Operation with undefined operand should return undefined")
	}

	result = Operation(func(a, b uint64) uint64 { return a + b }, 5, YR_UNDEFINED)
	if !IsUndefined(result) {
		t.Error("Operation with undefined operand should return undefined")
	}

	result = Operation(func(a, b uint64) uint64 { return a + b }, 3, 7)
	if IsUndefined(result) {
		t.Error("Operation with defined operands should not return undefined")
	}

	if result != 10 {
		t.Errorf("Operation result = %v, want 10", result)
	}
}

// TestEmitterStats tests emitter statistics
func TestEmitterStats(t *testing.T) {
	emitter := NewEmitter()

	// Emit some instructions
	emitter.EmitOpcode(OP_PUSH, 1, 1)
	emitter.EmitOpcode(OP_NOP, 1, 2)
	emitter.EmitPush(0x12345678, 1, 3)

	stats := emitter.GetStats()

	if stats["instruction_count"] != 3 {
		t.Errorf("Instruction count = %v, want 3", stats["instruction_count"])
	}

	expectedSize := 1 + 1 + 5 // PUSH + NOP + PUSH_32
	if stats["bytecode_size"] != expectedSize {
		t.Errorf("Bytecode size = %v, want %v", stats["bytecode_size"], expectedSize)
	}
}

// TestStringCompilerValidation tests string modifier validation
func TestStringCompilerValidation(t *testing.T) {
	emitter := NewEmitter()
	sc := NewStringCompiler(emitter)

	// Test incompatible modifiers
	incompatibleModifiers := []ast.StringModifier{
		{Type: ast.StringModifierWide},
		{Type: ast.StringModifierASCII},
	}

	err := sc.ValidateStringModifiers(incompatibleModifiers)
	if err == nil {
		t.Error("Expected error for incompatible modifiers")
	}

	// Test compatible modifiers
	compatibleModifiers := []ast.StringModifier{
		{Type: ast.StringModifierNocase},
		{Type: ast.StringModifierFullword},
	}

	err = sc.ValidateStringModifiers(compatibleModifiers)
	if err != nil {
		t.Errorf("Compatible modifiers should be valid: %v", err)
	}
}

// TestACAutomatonSearch tests pattern searching
func TestACAutomatonSearch(t *testing.T) {
	ac := NewACAutomaton()

	// Add test patterns
	patterns := []string{"test", "pattern", "search"}
	for i, pattern := range patterns {
		err := ac.AddString(fmt.Sprintf("p%d", i), []byte(pattern), false, false)
		if err != nil {
			t.Errorf("Failed to add pattern %s: %v", pattern, err)
		}
	}

	// Compile automaton
	err := ac.Compile()
	if err != nil {
		t.Errorf("Automaton compilation failed: %v", err)
	}

	// Test search
	testData := []byte("This is a test pattern for searching")
	matches := ac.Search(testData)

	if len(matches) == 0 {
		t.Error("Expected to find matches in test data")
	}

	// Verify matches
	foundPatterns := make(map[string]bool)
	for _, match := range matches {
		foundPatterns[match.StringID] = true
	}

	// Should find "test" and "pattern"
	if !foundPatterns["p0"] || !foundPatterns["p1"] {
		t.Error("Expected to find test and pattern matches")
	}
}

// TestCompiledRuleMemoryUsage tests memory usage estimation
func TestCompiledRuleMemoryUsage(t *testing.T) {
	rc := NewRuleCompiler()

	rule := &ast.Rule{
		Pos:   token.Position{Line: 1, Column: 1},
		Name:  "memory_test",
		Strings: []*ast.String{
			{
				Pos:       token.Position{Line: 2, Column: 1},
				Identifier: "$s1",
				Pattern: &ast.TextString{
					Pos:   token.Position{Line: 2, Column: 5},
					Value: "memory test string",
				},
				Modifiers: []ast.StringModifier{},
			},
		},
		Condition: &ast.Literal{
			Pos:   token.Position{Line: 3, Column: 1},
			Type:  token.TRUE,
			Value: true,
		},
	}

	compiledRule, err := rc.CompileRule(rule)
	if err != nil {
		t.Errorf("Rule compilation failed: %v", err)
	}

	// Test memory usage estimation
	usage := compiledRule.GetMemoryUsage()
	if usage <= 0 {
		t.Error("Memory usage should be positive")
	}

	// Test debug printing (should not panic)
	compiledRule.PrintDebug()
}

// TestCompilerOptions tests compiler options
func TestCompilerOptions(t *testing.T) {
	// Test default options
	compiler := NewCompiler()
	options := compiler.GetOptions()

	if !options.EnableOptimizations {
		t.Error("Optimizations should be enabled by default")
	}

	if options.TargetVersion != "1.0" {
		t.Errorf("Default target version = %v, want 1.0", options.TargetVersion)
	}

	// Test custom options
	customOptions := CompilationOptions{
		EnableOptimizations: false,
		EnableDebugInfo:     true,
		EnableWarnings:      false,
		TargetVersion:       "2.0",
	}

	compilerWithOptions := NewCompilerWithOptions(customOptions)
	retrievedOptions := compilerWithOptions.GetOptions()

	if retrievedOptions.EnableOptimizations {
		t.Error("Optimizations should be disabled")
	}

	if !retrievedOptions.EnableDebugInfo {
		t.Error("Debug info should be enabled")
	}

	if retrievedOptions.EnableWarnings {
		t.Error("Warnings should be disabled")
	}

	if retrievedOptions.TargetVersion != "2.0" {
		t.Errorf("Target version = %v, want 2.0", retrievedOptions.TargetVersion)
	}
}

// BenchmarkEmitter benchmarks the bytecode emitter
func BenchmarkEmitter(b *testing.B) {
	emitter := NewEmitter()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		emitter.Reset()
		emitter.EmitOpcode(OP_PUSH, 1, 1)
		emitter.EmitOpcode(OP_NOP, 1, 2)
		emitter.EmitPush(0x12345678, 1, 3)
		emitter.GetBytecode()
	}
}

// BenchmarkACAutomaton benchmarks the Aho-Corasick automaton
func BenchmarkACAutomaton(b *testing.B) {
	ac := NewACAutomaton()

	// Add test patterns
	patterns := []string{"test", "pattern", "search", "benchmark", "performance"}
	for i, pattern := range patterns {
		ac.AddString(fmt.Sprintf("p%d", i), []byte(pattern), false, false)
	}

	ac.Compile()

	testData := []byte("This is a test pattern for searching and benchmarking performance")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ac.Search(testData)
	}
}

// BenchmarkStringCompiler benchmarks the string compiler
func BenchmarkStringCompiler(b *testing.B) {
	emitter := NewEmitter()
	sc := NewStringCompiler(emitter)

	text := "This is a test string for benchmarking the string compiler"
	modifiers := []ast.StringModifier{
		{Type: ast.StringModifierNocase},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sc.encodeTextString(text, modifiers)
	}
}

// TestErrorHandling tests error handling in compilation
func TestErrorHandling(t *testing.T) {
	compiler := NewCompiler()

	// Test with invalid source
	source := `
rule invalid_rule {
    strings:
        $s1 = "test"
    condition:
        invalid_syntax_here
}`

	_, err := compiler.CompileSource(source)
	// We expect this to fail, but not panic
	if err == nil {
		t.Error("Expected compilation to fail for invalid source")
	}
}

// TestCompilationStats tests compilation statistics collection
func TestCompilationStats(t *testing.T) {
	compiler := NewCompiler()

	// Compile a simple valid rule
	source := `
rule test_rule {
    strings:
        $s1 = "hello"
    condition:
        $s1
}`

	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Errorf("Compilation failed: %v", err)
	}

	stats := compiler.GetStats()

	if stats.RulesCompiled != 1 {
		t.Errorf("Expected 1 rule compiled, got %d", stats.RulesCompiled)
	}

	if stats.TotalTime == 0 {
		t.Error("Total time should be greater than 0")
	}

	if stats.LexerTime == 0 {
		t.Error("Lexer time should be greater than 0")
	}

	if stats.ParserTime == 0 {
		t.Error("Parser time should be greater than 0")
	}

	// Test program statistics
	if program.GetRuleCount() != 1 {
		t.Errorf("Program should have 1 rule, got %d", program.GetRuleCount())
	}

	totalSize := program.GetTotalBytecodeSize()
	if totalSize <= 0 {
		t.Error("Total bytecode size should be greater than 0")
	}
}

// TestCompilationReport tests the compilation report generation
func TestCompilationReport(t *testing.T) {
	compiler := NewCompiler()

	source := `
rule test_rule {
    strings:
        $s1 = "hello"
    condition:
        $s1
}`

	_, err := compiler.CompileSource(source)
	if err != nil {
		t.Errorf("Compilation failed: %v", err)
	}

	report := compiler.GetCompilationReport()
	if report == "" {
		t.Error("Compilation report should not be empty")
	}

	// Check that report contains expected sections
	if !strings.Contains(report, "Go-YARA Compilation Report") {
		t.Error("Report should contain title")
	}

	if !strings.Contains(report, "Timing:") {
		t.Error("Report should contain timing section")
	}

	if !strings.Contains(report, "Results:") {
		t.Error("Report should contain results section")
	}
}

// TestPatternComplexityEstimation tests the pattern complexity estimation
func TestPatternComplexityEstimation(t *testing.T) {
	emitter := NewEmitter()
	sc := NewStringCompiler(emitter)

	tests := []struct {
		name       string
		pattern    []byte
		modifiers  []ast.StringModifier
		minQuality int // Minimum expected quality
	}{
		{
			name:       "simple_ascii",
			pattern:    []byte{0x01, 0x02, 0x03, 0x04},
			modifiers:  []ast.StringModifier{},
			minQuality: 80, // 20+20+20+20+8 = 88
		},
		{
			name:       "common_bytes",
			pattern:    []byte{0x00, 0x01},
			modifiers:  []ast.StringModifier{},
			minQuality: 30, // 12+20+4 = 36
		},
		{
			name:       "alphabetic",
			pattern:    []byte{'a', 'b'},
			modifiers:  []ast.StringModifier{},
			minQuality: 35, // 18+18+4 = 40
		},
		{
			name:       "empty_pattern",
			pattern:    []byte{},
			modifiers:  []ast.StringModifier{},
			minQuality: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			quality := sc.EstimatePatternComplexity(tt.pattern, tt.modifiers)
			if quality < tt.minQuality {
				t.Errorf("Expected quality >= %d, got %d", tt.minQuality, quality)
			}
		})
	}
}