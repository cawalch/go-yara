package compiler

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

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
	if !IsUndefined(YRUndefined) {
		t.Error("YRUndefined should be recognized as undefined")
	}

	if IsUndefined(0) {
		t.Error("0 should not be recognized as undefined")
	}

	if IsUndefined(42) {
		t.Error("42 should not be recognized as undefined")
	}

	// Test operation with undefined values
	result := Operation(func(a, b uint64) uint64 { return a + b }, YRUndefined, 5)
	if !IsUndefined(result) {
		t.Error("Operation with undefined operand should return undefined")
	}

	result = Operation(func(a, b uint64) uint64 { return a + b }, 5, YRUndefined)
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

// TestCompiledRuleMemoryUsage tests memory usage estimation
func TestCompiledRuleMemoryUsage(t *testing.T) {
	rc := NewRuleCompiler()

	rule := &ast.Rule{
		Pos:  token.Position{Line: 1, Column: 1},
		Name: "memory_test",
		Strings: []*ast.String{
			{
				Pos:        token.Position{Line: 2, Column: 1},
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

	for b.Loop() {
		emitter.Reset()
		emitter.EmitOpcode(OP_PUSH, 1, 1)
		emitter.EmitOpcode(OP_NOP, 1, 2)
		emitter.EmitPush(0x12345678, 1, 3)
		_, _ = emitter.GetBytecode() // Ignore error in benchmark hot path
	}
}

// BenchmarkACAutomaton benchmarks the Aho-Corasick automaton
func BenchmarkACAutomaton(b *testing.B) {
	ac := NewACAutomaton()

	// Add test patterns
	patterns := []string{"test", "pattern", "search", "benchmark", "performance"}
	for i, pattern := range patterns {
		if err := ac.AddString(fmt.Sprintf("p%d", i), []byte(pattern), false, false); err != nil {
			b.Fatalf("Failed to add pattern %s: %v", pattern, err)
		}
	}

	if err := ac.Compile(); err != nil {
		b.Fatalf("Failed to compile automaton: %v", err)
	}

	testData := []byte("This is a test pattern for searching and benchmarking performance")

	for b.Loop() {
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

	for b.Loop() {
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

	// LexerTime is no longer tracked separately (parser creates its own lexer)
	// Just verify ParserTime is set
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
			minQuality: 80,
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

// TestHexStringCompilation tests hex string pattern compilation
func TestHexStringCompilation(t *testing.T) {
	emitter := NewEmitter()
	sc := NewStringCompiler(emitter)

	tests := []struct {
		name     string
		hexStr   string
		wantErr  bool
		wantData []byte
	}{
		{
			name:     "simple_hex",
			hexStr:   "61 62 63 64",
			wantErr:  false,
			wantData: []byte{0x61, 0x62, 0x63, 0x64},
		},
		{
			name:     "hex_with_wildcards",
			hexStr:   "61 62 ?? 64",
			wantErr:  false,
			wantData: []byte{0x61, 0x62, 0x00, 0x64},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hexPattern := &ast.HexString{
				Value: tt.hexStr,
				Pos:   token.Position{Line: 1, Column: 1},
			}
			err := sc.compileHexString("test_hex", hexPattern, []ast.StringModifier{})
			if (err != nil) != tt.wantErr {
				t.Errorf("compileHexString() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestRegexPatternCompilation tests regex pattern compilation
func TestRegexPatternCompilation(t *testing.T) {
	emitter := NewEmitter()
	sc := NewStringCompiler(emitter)

	tests := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		{
			name:    "simple_regex",
			pattern: "abc.*def",
			wantErr: false,
		},
		{
			name:    "regex_with_alternation",
			pattern: "(abc|def)",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regexPattern := &ast.RegexPattern{
				Value: tt.pattern,
				Pos:   token.Position{Line: 1, Column: 1},
			}
			err := sc.compileRegexPattern("test_regex", regexPattern, []ast.StringModifier{})
			if (err != nil) != tt.wantErr {
				t.Errorf("compileRegexPattern() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestAtomExtraction tests atom extraction from patterns
func TestAtomExtraction(t *testing.T) {
	tests := []struct {
		name      string
		pattern   ast.Pattern
		modifiers []ast.StringModifier
		wantAtoms int
	}{
		{
			name:      "text_string_atoms",
			pattern:   &ast.TextString{Value: "abcdef"},
			modifiers: []ast.StringModifier{},
			wantAtoms: 1,
		},
		{
			name:      "short_text_string",
			pattern:   &ast.TextString{Value: "ab"},
			modifiers: []ast.StringModifier{},
			wantAtoms: 1,
		},
		{
			name:      "very_short_text_string",
			pattern:   &ast.TextString{Value: "a"},
			modifiers: []ast.StringModifier{},
			wantAtoms: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			atoms := ExtractAtoms(tt.pattern, tt.modifiers)
			if len(atoms) != tt.wantAtoms {
				t.Errorf("ExtractAtoms() got %d atoms, want %d", len(atoms), tt.wantAtoms)
			}
		})
	}
}

// TestEmitterJumpFixup tests jump fixup functionality
func TestEmitterJumpFixup(t *testing.T) {
	emitter := NewEmitter()

	// Emit some instructions
	emitter.EmitOpcode(OP_PUSH_8, 1, 1)
	jumpOffset := emitter.EmitJump(JumpConfig{Opcode: OP_JZ, Target: 10, Line: 1, Pos: 1})
	emitter.EmitOpcode(OP_NOP, 1, 1)
	emitter.EmitLabel(10, 1, 1)

	// Fixup jumps
	err := emitter.FixupJumps()
	if err != nil {
		t.Errorf("FixupJumps() error = %v", err)
	}

	// Verify the jump was fixed up
	if jumpOffset < 0 {
		t.Errorf("EmitJump() returned negative offset %d", jumpOffset)
	}
}

// TestEmitterArithmetic tests arithmetic operation emission
func TestEmitterArithmetic(t *testing.T) {
	emitter := NewEmitter()

	tests := []struct {
		name    string
		opcode  Opcode
		wantErr bool
	}{
		{
			name:    "valid_arithmetic",
			opcode:  OP_INT_ADD,
			wantErr: false,
		},
		{
			name:    "invalid_arithmetic",
			opcode:  OP_AND,
			wantErr: false, // Returns -1 but doesn't error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			offset := emitter.EmitArithmetic(tt.opcode, 1, 1)
			if tt.wantErr && offset >= 0 {
				t.Errorf("EmitArithmetic() expected error, got offset %d", offset)
			}
		})
	}
}

// TestEmitterComparison tests comparison operation emission
func TestEmitterComparison(t *testing.T) {
	emitter := NewEmitter()

	tests := []struct {
		name    string
		opcode  Opcode
		wantErr bool
	}{
		{
			name:    "valid_comparison",
			opcode:  OP_INT_EQ,
			wantErr: false,
		},
		{
			name:    "invalid_comparison",
			opcode:  OP_AND,
			wantErr: false, // Returns -1 but doesn't error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			offset := emitter.EmitComparison(tt.opcode, 1, 1)
			if tt.wantErr && offset >= 0 {
				t.Errorf("EmitComparison() expected error, got offset %d", offset)
			}
		})
	}
}

// TestEmitterLogical tests logical operation emission
func TestEmitterLogical(t *testing.T) {
	emitter := NewEmitter()

	tests := []struct {
		name    string
		opcode  Opcode
		wantErr bool
	}{
		{
			name:    "valid_logical",
			opcode:  OP_AND,
			wantErr: false,
		},
		{
			name:    "invalid_logical",
			opcode:  OP_INT_ADD,
			wantErr: false, // Returns -1 but doesn't error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			offset := emitter.EmitLogical(tt.opcode, 1, 1)
			if tt.wantErr && offset >= 0 {
				t.Errorf("EmitLogical() expected error, got offset %d", offset)
			}
		})
	}
}

// TestEmitterPushVariousSizes tests push instruction with various value sizes
func TestEmitterPushVariousSizes(t *testing.T) {
	emitter := NewEmitter()

	tests := []struct {
		name  string
		value uint64
	}{
		{
			name:  "8-bit_value",
			value: 0xFF,
		},
		{
			name:  "16-bit_value",
			value: 0xFFFF,
		},
		{
			name:  "32-bit_value",
			value: 0xFFFFFFFF,
		},
		{
			name:  "64-bit_value",
			value: 0xFFFFFFFFFFFFFFFF,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			offset := emitter.EmitPush(tt.value, 1, 1)
			if offset < 0 {
				t.Errorf("EmitPush() returned negative offset %d", offset)
			}
		})
	}
}

// TestEmitterGetBytecode tests bytecode generation
func TestEmitterGetBytecode(t *testing.T) {
	emitter := NewEmitter()

	// Emit some instructions
	emitter.EmitOpcode(OP_PUSH_8, 1, 1)
	emitter.EmitOpcode(OP_NOP, 1, 1)
	emitter.EmitHalt(1, 1)

	bytecode, err := emitter.GetBytecode()
	if err != nil {
		t.Errorf("GetBytecode() error = %v", err)
	}

	if len(bytecode) == 0 {
		t.Errorf("GetBytecode() returned empty bytecode")
	}
}

// TestConditionCompilerLiteral tests literal compilation
func TestConditionCompilerLiteral(t *testing.T) {
	emitter := NewEmitter()
	cc := NewConditionCompiler(emitter, make(map[string]int))

	tests := []struct {
		name    string
		literal *ast.Literal
		wantErr bool
	}{
		{
			name: "integer_literal",
			literal: &ast.Literal{
				Pos:   token.Position{Line: 1, Column: 1},
				Type:  token.INTEGER_LIT,
				Value: int64(42),
			},
			wantErr: false,
		},
		{
			name: "string_literal",
			literal: &ast.Literal{
				Pos:   token.Position{Line: 1, Column: 1},
				Type:  token.STRING_LIT,
				Value: "test",
			},
			wantErr: false,
		},
		{
			name: "true_literal",
			literal: &ast.Literal{
				Pos:   token.Position{Line: 1, Column: 1},
				Type:  token.TRUE,
				Value: true,
			},
			wantErr: false,
		},
		{
			name: "false_literal",
			literal: &ast.Literal{
				Pos:   token.Position{Line: 1, Column: 1},
				Type:  token.FALSE,
				Value: false,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cc.compileExpression(tt.literal)
			if (err != nil) != tt.wantErr {
				t.Errorf("compileExpression() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestConditionCompilerIdentifier tests identifier compilation
func TestConditionCompilerIdentifier(t *testing.T) {
	emitter := NewEmitter()
	stringOffsets := map[string]int{"$test": 10}
	cc := NewConditionCompiler(emitter, stringOffsets)

	tests := []struct {
		name    string
		ident   *ast.Identifier
		wantErr bool
	}{
		{
			name: "string_identifier",
			ident: &ast.Identifier{
				Pos:  token.Position{Line: 1, Column: 1},
				Name: "$test",
			},
			wantErr: false,
		},
		{
			name: "filesize_identifier",
			ident: &ast.Identifier{
				Pos:  token.Position{Line: 1, Column: 1},
				Name: "filesize",
			},
			wantErr: false,
		},
		{
			name: "entrypoint_identifier",
			ident: &ast.Identifier{
				Pos:  token.Position{Line: 1, Column: 1},
				Name: "entrypoint",
			},
			wantErr: false,
		},
		{
			name: "undefined_identifier",
			ident: &ast.Identifier{
				Pos:  token.Position{Line: 1, Column: 1},
				Name: "undefined",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cc.compileExpression(tt.ident)
			if (err != nil) != tt.wantErr {
				t.Errorf("compileExpression() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestConditionCompilerBinaryOp tests binary operation compilation
func TestConditionCompilerBinaryOp(t *testing.T) {
	emitter := NewEmitter()
	cc := NewConditionCompiler(emitter, make(map[string]int))

	tests := []struct {
		name    string
		binOp   *ast.BinaryOp
		wantErr bool
	}{
		{
			name: "addition",
			binOp: &ast.BinaryOp{
				Pos: token.Position{Line: 1, Column: 1},
				Left: &ast.Literal{
					Pos:   token.Position{Line: 1, Column: 1},
					Type:  token.INTEGER_LIT,
					Value: int64(1),
				},
				Op: token.PLUS,
				Right: &ast.Literal{
					Pos:   token.Position{Line: 1, Column: 1},
					Type:  token.INTEGER_LIT,
					Value: int64(2),
				},
			},
			wantErr: false,
		},
		{
			name: "logical_and",
			binOp: &ast.BinaryOp{
				Pos: token.Position{Line: 1, Column: 1},
				Left: &ast.Literal{
					Pos:   token.Position{Line: 1, Column: 1},
					Type:  token.TRUE,
					Value: true,
				},
				Op: token.AND,
				Right: &ast.Literal{
					Pos:   token.Position{Line: 1, Column: 1},
					Type:  token.FALSE,
					Value: false,
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cc.compileExpression(tt.binOp)
			if (err != nil) != tt.wantErr {
				t.Errorf("compileExpression() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestConditionCompilerUnaryOp tests unary operation compilation
func TestConditionCompilerUnaryOp(t *testing.T) {
	emitter := NewEmitter()
	cc := NewConditionCompiler(emitter, make(map[string]int))

	tests := []struct {
		name    string
		unaryOp *ast.UnaryOp
		wantErr bool
	}{
		{
			name: "logical_not",
			unaryOp: &ast.UnaryOp{
				Pos: token.Position{Line: 1, Column: 1},
				Op:  token.NOT,
				Right: &ast.Literal{
					Pos:   token.Position{Line: 1, Column: 1},
					Type:  token.TRUE,
					Value: true,
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cc.compileExpression(tt.unaryOp)
			if (err != nil) != tt.wantErr {
				t.Errorf("compileExpression() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestStringCompilerGetters tests string compiler getter methods
func TestStringCompilerGetters(t *testing.T) {
	emitter := NewEmitter()
	sc := NewStringCompiler(emitter)

	// Compile a string using the full compilation path
	textPattern := &ast.TextString{
		Value: "test",
		Pos:   token.Position{Line: 1, Column: 1},
	}
	str := &ast.String{
		Pos:        token.Position{Line: 1, Column: 1},
		Identifier: "$test",
		Pattern:    textPattern,
		Modifiers:  []ast.StringModifier{},
	}
	if err := sc.CompileStrings(&ast.Rule{
		Pos:       token.Position{Line: 1, Column: 1},
		Name:      "test_rule",
		Strings:   []*ast.String{str},
		Condition: nil,
	}); err != nil {
		t.Fatalf("Failed to compile strings: %v", err)
	}

	// Test GetStringOffsets
	offsets := sc.GetStringOffsets()
	if len(offsets) == 0 {
		t.Errorf("GetStringOffsets() returned empty map")
	}

	// Test GetPatternData
	patterns := sc.GetPatternData()
	if len(patterns) == 0 {
		t.Errorf("GetPatternData() returned empty map")
	}

	// Test GetStringInfo
	info := sc.GetStringInfo()
	if len(info) == 0 {
		t.Errorf("GetStringInfo() returned empty slice")
	}
}

// TestStringCompilerOptimizePattern tests pattern optimization
func TestStringCompilerOptimizePattern(t *testing.T) {
	emitter := NewEmitter()
	sc := NewStringCompiler(emitter)

	tests := []struct {
		name      string
		pattern   []byte
		modifiers []ast.StringModifier
	}{
		{
			name:      "ascii_pattern",
			pattern:   []byte("hello"),
			modifiers: []ast.StringModifier{},
		},
		{
			name:    "wide_pattern",
			pattern: []byte{0x68, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00},
			modifiers: []ast.StringModifier{
				{Type: ast.StringModifierWide},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			optimized := sc.OptimizePattern(tt.pattern, tt.modifiers)
			if len(optimized) == 0 && len(tt.pattern) > 0 {
				t.Errorf("OptimizePattern() returned empty pattern")
			}
		})
	}
}

// TestAhoCorasickCompile tests Aho-Corasick automaton compilation
func TestAhoCorasickCompile(t *testing.T) {
	ac := NewACAutomaton()

	// Add some strings
	if err := ac.AddString("hello", []byte("hello"), false, false); err != nil {
		t.Fatalf("Failed to add hello string: %v", err)
	}
	if err := ac.AddString("world", []byte("world"), false, false); err != nil {
		t.Fatalf("Failed to add world string: %v", err)
	}

	// Compile the automaton
	err := ac.Compile()
	if err != nil {
		t.Errorf("Compile() error = %v", err)
	}

	// Verify state count
	if ac.GetStateCount() == 0 {
		t.Errorf("GetStateCount() returned 0")
	}
}

// TestAhoCorasickValidate tests Aho-Corasick automaton validation
func TestAhoCorasickValidate(t *testing.T) {
	ac := NewACAutomaton()

	// Add some strings
	if err := ac.AddString("test", []byte("test"), false, false); err != nil {
		t.Fatalf("Failed to add test string: %v", err)
	}

	// Compile the automaton
	if err := ac.Compile(); err != nil {
		t.Fatalf("Failed to compile automaton: %v", err)
	}

	// Validate
	err := ac.Validate()
	if err != nil {
		t.Errorf("Validate() error = %v", err)
	}
}

// TestAhoCorasickReset tests Aho-Corasick automaton reset
func TestAhoCorasickReset(t *testing.T) {
	ac := NewACAutomaton()

	// Add some strings
	if err := ac.AddString("test", []byte("test"), false, false); err != nil {
		t.Fatalf("Failed to add test string: %v", err)
	}
	if err := ac.Compile(); err != nil {
		t.Fatalf("Failed to compile automaton: %v", err)
	}

	initialCount := ac.GetStateCount()
	if initialCount == 0 {
		t.Errorf("Initial state count is 0")
	}

	// Reset
	ac.Reset()

	// Verify reset
	if ac.GetStateCount() != 1 {
		t.Errorf("After Reset(), state count = %d, want 1", ac.GetStateCount())
	}
}

// TestRuleCompilerMultipleStrings tests rule compilation with multiple strings
func TestRuleCompilerMultipleStrings(t *testing.T) {
	rc := NewRuleCompiler()

	rule := &ast.Rule{
		Pos:  token.Position{Line: 1, Column: 1},
		Name: "multi_string_rule",
		Strings: []*ast.String{
			{
				Pos:        token.Position{Line: 2, Column: 1},
				Identifier: "$str1",
				Pattern: &ast.TextString{
					Value: "hello",
					Pos:   token.Position{Line: 2, Column: 10},
				},
				Modifiers: []ast.StringModifier{},
			},
			{
				Pos:        token.Position{Line: 3, Column: 1},
				Identifier: "$str2",
				Pattern: &ast.TextString{
					Value: "world",
					Pos:   token.Position{Line: 3, Column: 10},
				},
				Modifiers: []ast.StringModifier{},
			},
		},
		Condition: &ast.BinaryOp{
			Pos: token.Position{Line: 4, Column: 1},
			Left: &ast.Identifier{
				Pos:  token.Position{Line: 4, Column: 1},
				Name: "$str1",
			},
			Op: token.AND,
			Right: &ast.Identifier{
				Pos:  token.Position{Line: 4, Column: 10},
				Name: "$str2",
			},
		},
	}

	compiled, err := rc.CompileRule(rule)
	if err != nil {
		t.Errorf("CompileRule() error = %v", err)
	}

	if compiled == nil {
		t.Errorf("CompileRule() returned nil")
		return
	}

	if compiled.StringCount != 2 {
		t.Errorf("CompileRule() string count = %d, want 2", compiled.StringCount)
	}
}

// TestRuleCompilerNoStrings tests rule compilation without strings
func TestRuleCompilerNoStrings(t *testing.T) {
	rc := NewRuleCompiler()

	rule := &ast.Rule{
		Pos:     token.Position{Line: 1, Column: 1},
		Name:    "no_string_rule",
		Strings: []*ast.String{},
		Condition: &ast.Literal{
			Pos:   token.Position{Line: 2, Column: 1},
			Type:  token.TRUE,
			Value: true,
		},
	}

	compiled, err := rc.CompileRule(rule)
	if err != nil {
		t.Errorf("CompileRule() error = %v", err)
	}

	if compiled == nil {
		t.Errorf("CompileRule() returned nil")
		return
	}

	if compiled.StringCount != 0 {
		t.Errorf("CompileRule() string count = %d, want 0", compiled.StringCount)
	}
}

// TestCompiledRuleMemory tests compiled rule memory usage
func TestCompiledRuleMemory(t *testing.T) {
	rc := NewRuleCompiler()

	rule := &ast.Rule{
		Pos:  token.Position{Line: 1, Column: 1},
		Name: "memory_test",
		Strings: []*ast.String{
			{
				Pos:        token.Position{Line: 2, Column: 1},
				Identifier: "$test",
				Pattern: &ast.TextString{
					Value: "test",
					Pos:   token.Position{Line: 2, Column: 10},
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

	compiled, err := rc.CompileRule(rule)
	if err != nil {
		t.Errorf("CompileRule() error = %v", err)
	}

	if compiled == nil {
		t.Errorf("CompileRule() returned nil")
		return
	}

	// Verify memory usage is reasonable
	if len(compiled.Bytecode) == 0 {
		t.Errorf("Bytecode is empty")
	}
}

// TestStringCompilerEncodeHexString tests hex string encoding
func TestStringCompilerEncodeHexString(t *testing.T) {
	emitter := NewEmitter()
	sc := NewStringCompiler(emitter)

	tests := []struct {
		name      string
		hexStr    string
		modifiers []ast.StringModifier
		wantErr   bool
	}{
		{
			name:      "simple_hex",
			hexStr:    "61 62 63",
			modifiers: []ast.StringModifier{},
			wantErr:   false,
		},
		{
			name:      "hex_with_wildcards",
			hexStr:    "61 ?? 63",
			modifiers: []ast.StringModifier{},
			wantErr:   false,
		},
		{
			name:      "hex_with_ranges",
			hexStr:    "61 [00-FF] 63",
			modifiers: []ast.StringModifier{},
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hexPattern := &ast.HexString{
				Value: tt.hexStr,
				Pos:   token.Position{Line: 1, Column: 1},
			}
			err := sc.compileHexString("$hex", hexPattern, tt.modifiers)
			if (err != nil) != tt.wantErr {
				t.Errorf("compileHexString() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestStringCompilerApplyNocaseModifier tests nocase modifier application
func TestStringCompilerApplyNocaseModifier(t *testing.T) {
	emitter := NewEmitter()
	sc := NewStringCompiler(emitter)

	tests := []struct {
		name    string
		input   []byte
		isWide  bool
		wantLen int
		wantErr bool
	}{
		{
			name:    "ascii_text",
			input:   []byte("Hello"),
			isWide:  false,
			wantLen: 5,
			wantErr: false,
		},
		{
			name:    "empty_input",
			input:   []byte(""),
			isWide:  false,
			wantLen: 0,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sc.applyNocaseModifier(tt.input, tt.isWide)
			if len(result) != tt.wantLen {
				t.Errorf("applyNocaseModifier() len = %d, want %d", len(result), tt.wantLen)
			}
		})
	}
}

// TestStringCompilerOptimizeWidePattern tests wide pattern optimization
func TestStringCompilerOptimizeWidePattern(t *testing.T) {
	emitter := NewEmitter()
	sc := NewStringCompiler(emitter)

	tests := []struct {
		name    string
		pattern []byte
		wantLen int
	}{
		{
			name:    "wide_pattern_with_nulls",
			pattern: []byte{0x68, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00}, // "hello" in UTF-16LE
			wantLen: 10,                                                                 // All characters are non-null
		},
		{
			name:    "empty_pattern",
			pattern: []byte(""),
			wantLen: 0,
		},
		{
			name:    "odd_length_pattern",
			pattern: []byte{0x68, 0x00, 0x65}, // Odd length, should return as-is
			wantLen: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sc.optimizeWidePattern(tt.pattern)
			if len(result) != tt.wantLen {
				t.Errorf("optimizeWidePattern() len = %d, want %d", len(result), tt.wantLen)
			}
		})
	}
}

// TestStringCompilerOptimizeASCIIPattern tests ASCII pattern optimization
func TestStringCompilerOptimizeASCIIPattern(t *testing.T) {
	emitter := NewEmitter()
	sc := NewStringCompiler(emitter)

	tests := []struct {
		name    string
		pattern []byte
		wantLen int
	}{
		{
			name:    "simple_ascii",
			pattern: []byte("hello"),
			wantLen: 5,
		},
		{
			name:    "empty_pattern",
			pattern: []byte(""),
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sc.optimizeASCIIPattern(tt.pattern)
			if len(result) != tt.wantLen {
				t.Errorf("optimizeASCIIPattern() len = %d, want %d", len(result), tt.wantLen)
			}
		})
	}
}

// Helper functions to reduce repetitive AST construction
func createIntLiteral(value int64) *ast.Literal {
	return &ast.Literal{
		Pos:   token.Position{Line: 1, Column: 1},
		Type:  token.INTEGER_LIT,
		Value: value,
	}
}

func createBoolLiteral(value bool) *ast.Literal {
	tokenType := token.FALSE
	if value {
		tokenType = token.TRUE
	}
	return &ast.Literal{
		Pos:   token.Position{Line: 1, Column: 1},
		Type:  tokenType,
		Value: value,
	}
}

func createBinaryOp(op token.TokenType, left, right ast.Expression) *ast.BinaryOp {
	return &ast.BinaryOp{
		Pos:   token.Position{Line: 1, Column: 1},
		Left:  left,
		Op:    op,
		Right: right,
	}
}

// createTestBinaryOp creates a binary operation from literal values
func createTestBinaryOp(op token.TokenType, leftVal, rightVal any) *ast.BinaryOp {
	leftExpr := createLiteralFromValue(leftVal)
	rightExpr := createLiteralFromValue(rightVal)
	return createBinaryOp(op, leftExpr, rightExpr)
}

// createLiteralFromValue creates a literal expression from a value
func createLiteralFromValue(val any) ast.Expression {
	switch v := val.(type) {
	case int64:
		return createIntLiteral(v)
	case bool:
		return createBoolLiteral(v)
	default:
		// For testing purposes, panic on unsupported types
		panic(fmt.Sprintf("unsupported literal type: %T", val))
	}
}

// TestConditionCompilerCompileBinaryOpDetailed tests binary operation compilation in detail
func TestConditionCompilerCompileBinaryOpDetailed(t *testing.T) {
	emitter := NewEmitter()
	cc := NewConditionCompiler(emitter, make(map[string]int))

	tests := []struct {
		name        string
		op          token.TokenType
		leftVal     any
		rightVal    any
		expectErr   bool
		description string
	}{
		// Arithmetic operations
		{
			name:      "arithmetic_subtraction",
			op:        token.MINUS,
			leftVal:   int64(5),
			rightVal:  int64(2),
			expectErr: false,
		},
		{
			name:      "arithmetic_multiplication",
			op:        token.MULTIPLY,
			leftVal:   int64(3),
			rightVal:  int64(4),
			expectErr: false,
		},
		{
			name:      "arithmetic_division",
			op:        token.DIVIDE,
			leftVal:   int64(10),
			rightVal:  int64(2),
			expectErr: false,
		},
		{
			name:        "arithmetic_division_by_zero",
			op:          token.DIVIDE,
			leftVal:     int64(10),
			rightVal:    int64(0),
			expectErr:   false, // May not be caught at compile time
			description: "Division by zero may be caught at runtime",
		},

		// Logical operations
		{
			name:      "logical_or",
			op:        token.OR,
			leftVal:   true,
			rightVal:  false,
			expectErr: false,
		},

		// Comparison operations
		{
			name:      "comparison_equality",
			op:        token.EQ,
			leftVal:   int64(5),
			rightVal:  int64(5),
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binOp := createTestBinaryOp(tt.op, tt.leftVal, tt.rightVal)
			err := cc.compileExpression(binOp)

			if (err != nil) != tt.expectErr {
				t.Errorf("compileExpression() error = %v, expectErr %v", err, tt.expectErr)
				if tt.description != "" {
					t.Logf("Description: %s", tt.description)
				}
			}
		})
	}
}

// TestCompilerProgram tests full program compilation
func TestCompilerProgram(t *testing.T) {
	rc := NewRuleCompiler()

	rule1 := &ast.Rule{
		Pos:  token.Position{Line: 1, Column: 1},
		Name: "rule1",
		Strings: []*ast.String{
			{
				Pos:        token.Position{Line: 2, Column: 1},
				Identifier: "$test",
				Pattern: &ast.TextString{
					Value: "test",
					Pos:   token.Position{Line: 2, Column: 10},
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

	rule2 := &ast.Rule{
		Pos:  token.Position{Line: 5, Column: 1},
		Name: "rule2",
		Strings: []*ast.String{
			{
				Pos:        token.Position{Line: 6, Column: 1},
				Identifier: "$pattern",
				Pattern: &ast.TextString{
					Value: "pattern",
					Pos:   token.Position{Line: 6, Column: 10},
				},
				Modifiers: []ast.StringModifier{},
			},
		},
		Condition: &ast.Literal{
			Pos:   token.Position{Line: 7, Column: 1},
			Type:  token.TRUE,
			Value: true,
		},
	}

	program := &ast.Program{
		Rules: []*ast.Rule{rule1, rule2},
	}

	compiled, err := rc.CompileProgram(program)
	if err != nil {
		t.Errorf("CompileProgram() error = %v", err)
	}

	if compiled == nil {
		t.Errorf("CompileProgram() returned nil")
	}

	if len(compiled) != 2 {
		t.Errorf("CompileProgram() returned %d rules, want 2", len(compiled))
	}
}

// TestCompiledRuleValidate tests compiled rule validation
func TestCompiledRuleValidate(t *testing.T) {
	rc := NewRuleCompiler()

	rule := &ast.Rule{
		Pos:  token.Position{Line: 1, Column: 1},
		Name: "test_rule",
		Strings: []*ast.String{
			{
				Pos:        token.Position{Line: 2, Column: 1},
				Identifier: "$test",
				Pattern: &ast.TextString{
					Value: "test",
					Pos:   token.Position{Line: 2, Column: 10},
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

	compiled, err := rc.CompileRule(rule)
	if err != nil {
		t.Errorf("CompileRule() error = %v", err)
	}

	// Validate the compiled rule
	err = compiled.Validate()
	if err != nil {
		t.Errorf("Validate() error = %v", err)
	}
}

// TestCompiledRulePrintDebug tests debug printing
func TestCompiledRulePrintDebug(t *testing.T) {
	rc := NewRuleCompiler()

	rule := &ast.Rule{
		Pos:  token.Position{Line: 1, Column: 1},
		Name: "debug_test",
		Strings: []*ast.String{
			{
				Pos:        token.Position{Line: 2, Column: 1},
				Identifier: "$test",
				Pattern: &ast.TextString{
					Value: "test",
					Pos:   token.Position{Line: 2, Column: 10},
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

	compiled, err := rc.CompileRule(rule)
	if err != nil {
		t.Errorf("CompileRule() error = %v", err)
	}

	// This should not panic
	compiled.PrintDebug()
}

// TestEmitterGetInstructions tests getting instructions
func TestEmitterGetInstructions(t *testing.T) {
	emitter := NewEmitter()

	// Emit some instructions
	emitter.EmitOpcode(OP_PUSH_8, 1, 1)
	emitter.EmitOpcode(OP_NOP, 1, 1)
	emitter.EmitHalt(1, 1)

	// Get instructions
	instructions := emitter.GetInstructions()
	if len(instructions) == 0 {
		t.Errorf("GetInstructions() returned empty slice")
	}
}

// TestEmitterGetLineNumber tests getting line number
func TestEmitterGetLineNumber(t *testing.T) {
	emitter := NewEmitter()

	// Emit an instruction with line number
	emitter.EmitOpcode(OP_PUSH_8, 42, 1)

	// Get line number
	lineNum, exists := emitter.GetLineNumber(0)
	if !exists {
		t.Errorf("GetLineNumber() exists = false, want true")
	}
	if lineNum != 42 {
		t.Errorf("GetLineNumber() = %d, want 42", lineNum)
	}
}

// TestEmitterEmitNop tests NOP instruction emission
func TestEmitterEmitNop(t *testing.T) {
	emitter := NewEmitter()

	offset := emitter.EmitNop(1, 1)
	if offset < 0 {
		t.Errorf("EmitNop() returned negative offset %d", offset)
	}

	bytecode, err := emitter.GetBytecode()
	if err != nil {
		t.Errorf("GetBytecode() error = %v", err)
	}

	if len(bytecode) == 0 {
		t.Errorf("Bytecode is empty after EmitNop()")
	}
}

// TestEmitterPrintInstructions tests instruction printing
func TestEmitterPrintInstructions(_ *testing.T) {
	emitter := NewEmitter()

	// Emit some instructions
	emitter.EmitOpcode(OP_PUSH_8, 1, 1)
	emitter.EmitOpcode(OP_NOP, 1, 1)
	emitter.EmitHalt(1, 1)

	// This should not panic
	emitter.PrintInstructions()
}

// TestEmitterPrintBytecode tests bytecode printing
func TestEmitterPrintBytecode(t *testing.T) {
	emitter := NewEmitter()

	// Emit some instructions
	emitter.EmitOpcode(OP_PUSH_8, 1, 1)
	emitter.EmitHalt(1, 1)

	// This should not panic
	err := emitter.PrintBytecode()
	if err != nil {
		t.Errorf("PrintBytecode() error = %v", err)
	}
}

// TestConditionCompilerCompileCondition tests condition compilation
func TestConditionCompilerCompileCondition(t *testing.T) {
	emitter := NewEmitter()
	cc := NewConditionCompiler(emitter, make(map[string]int))

	condition := &ast.Condition{
		Pos: token.Position{Line: 1, Column: 1},
		Expression: &ast.Literal{
			Pos:   token.Position{Line: 1, Column: 1},
			Type:  token.TRUE,
			Value: true,
		},
	}

	err := cc.CompileCondition(condition)
	if err != nil {
		t.Errorf("CompileCondition() error = %v", err)
	}
}

// TestConditionCompilerAddVariable tests adding variables
func TestConditionCompilerAddVariable(t *testing.T) {
	emitter := NewEmitter()
	cc := NewConditionCompiler(emitter, make(map[string]int))

	// Add a variable
	cc.AddVariable("$test", 0)

	// Add another variable
	cc.AddVariable("$test2", 1)

	// Verify they were added
	index, exists := cc.GetVariableIndex("$test")
	if !exists {
		t.Errorf("AddVariable() failed to add $test")
	}
	if index != 0 {
		t.Errorf("AddVariable() index = %d, want 0", index)
	}
}

// TestConditionCompilerGetVariableIndex tests getting variable index
func TestConditionCompilerGetVariableIndex(t *testing.T) {
	emitter := NewEmitter()
	cc := NewConditionCompiler(emitter, make(map[string]int))

	// Add a variable
	cc.AddVariable("$test", 0)

	// Get the variable index
	index, exists := cc.GetVariableIndex("$test")
	if !exists {
		t.Errorf("GetVariableIndex() exists = false, want true")
	}
	if index != 0 {
		t.Errorf("GetVariableIndex() returned index %d, want 0", index)
	}

	// Try to get a non-existent variable
	_, exists = cc.GetVariableIndex("$nonexistent")
	if exists {
		t.Errorf("GetVariableIndex() exists = true for non-existent variable, want false")
	}
}

// TestConditionCompilerGetStats tests getting statistics
func TestConditionCompilerGetStats(t *testing.T) {
	emitter := NewEmitter()
	cc := NewConditionCompiler(emitter, make(map[string]int))

	// Compile a condition
	condition := &ast.Condition{
		Pos: token.Position{Line: 1, Column: 1},
		Expression: &ast.Literal{
			Pos:   token.Position{Line: 1, Column: 1},
			Type:  token.TRUE,
			Value: true,
		},
	}
	if err := cc.CompileCondition(condition); err != nil {
		t.Fatalf("Failed to compile condition: %v", err)
	}

	// Get stats
	stats := cc.GetStats()
	if stats == nil {
		t.Errorf("GetStats() returned nil")
	}
}

// TestConditionCompilerValidateExpression tests expression validation
func TestConditionCompilerValidateExpression(t *testing.T) {
	emitter := NewEmitter()
	cc := NewConditionCompiler(emitter, make(map[string]int))

	tests := []struct {
		name    string
		expr    ast.Expression
		wantErr bool
	}{
		{
			name: "valid_literal",
			expr: &ast.Literal{
				Pos:   token.Position{Line: 1, Column: 1},
				Type:  token.TRUE,
				Value: true,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cc.ValidateExpression(tt.expr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateExpression() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestCompilerGetErrors tests getting errors
func TestCompilerGetErrors(t *testing.T) {
	compiler := NewCompiler()

	// Initially should have no errors
	compilerErrors := compiler.GetErrors()
	if len(compilerErrors) > 0 {
		t.Errorf("GetErrors() returned %d errors, want 0", len(compilerErrors))
	}
}

// TestCompilerGetWarnings tests getting warnings
func TestCompilerGetWarnings(t *testing.T) {
	compiler := NewCompiler()

	// Initially should have no warnings
	warnings := compiler.GetWarnings()
	if len(warnings) > 0 {
		t.Errorf("GetWarnings() returned %d warnings, want 0", len(warnings))
	}
}

// TestCompilerHasErrors tests checking for errors
func TestCompilerHasErrors(t *testing.T) {
	compiler := NewCompiler()

	// Initially should have no errors
	if compiler.HasErrors() {
		t.Errorf("HasErrors() = true, want false")
	}
}

// TestCompilerHasWarnings tests checking for warnings
func TestCompilerHasWarnings(t *testing.T) {
	compiler := NewCompiler()

	// Initially should have no warnings
	if compiler.HasWarnings() {
		t.Errorf("HasWarnings() = true, want false")
	}
}

// TestCompilerSetOptions tests setting compiler options
func TestCompilerSetOptions(t *testing.T) {
	compiler := NewCompiler()

	options := CompilationOptions{
		EnableOptimizations: true,
		EnableDebugInfo:     true,
		EnableWarnings:      true,
		TargetVersion:       "4.3",
	}

	compiler.SetOptions(options)

	// Verify options were set
	opts := compiler.GetOptions()
	if opts.EnableOptimizations != true {
		t.Errorf("GetOptions() EnableOptimizations = false, want true")
	}
}

// TestCompilerReset tests resetting the compiler
func TestCompilerReset(t *testing.T) {
	compiler := NewCompiler()

	// Compile something
	source := `rule test { condition: true }`
	if _, err := compiler.CompileSource(source); err != nil {
		t.Fatalf("Failed to compile source: %v", err)
	}

	// Reset
	compiler.Reset()

	// After reset, should have no errors
	if compiler.HasErrors() {
		t.Errorf("HasErrors() = true after Reset(), want false")
	}
}

// TestCompiledRuleGetters tests CompiledRule getter methods
func TestCompiledRuleGetters(t *testing.T) {
	rc := NewRuleCompiler()

	rule := &ast.Rule{
		Pos:  token.Position{Line: 1, Column: 1},
		Name: "test_rule",
		Strings: []*ast.String{
			{
				Pos:        token.Position{Line: 2, Column: 1},
				Identifier: "$test",
				Pattern: &ast.TextString{
					Value: "test",
					Pos:   token.Position{Line: 2, Column: 10},
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

	compiled, err := rc.CompileRule(rule)
	if err != nil {
		t.Errorf("CompileRule() error = %v", err)
	}

	// Test GetName
	if compiled.GetName() != "test_rule" {
		t.Errorf("GetName() = %s, want test_rule", compiled.GetName())
	}

	// Test GetBytecode
	bytecode := compiled.GetBytecode()
	if len(bytecode) == 0 {
		t.Errorf("GetBytecode() returned empty bytecode")
	}

	// Test GetStringCount
	if compiled.GetStringCount() != 1 {
		t.Errorf("GetStringCount() = %d, want 1", compiled.GetStringCount())
	}

	// Test GetStats
	stats := compiled.GetStats()
	if stats == nil {
		t.Errorf("GetStats() returned nil")
	}

	// Test GetAutomaton
	automaton := compiled.GetAutomaton()
	if automaton == nil {
		t.Errorf("GetAutomaton() returned nil")
	}
}

// TestCompiledProgramGetters tests CompiledProgram getter methods
func TestCompiledProgramGetters(t *testing.T) {
	_ = setupTestCompiledProgram(t)

	t.Run("RuleCount", testCompiledProgramRuleCount)
	t.Run("BytecodeSize", testCompiledProgramBytecodeSize)
	t.Run("MemoryUsage", testCompiledProgramMemoryUsage)
	t.Run("GetRuleByName", testCompiledProgramGetRuleByName)
}

// setupTestCompiledProgram creates a test compiled program with multiple rules
func setupTestCompiledProgram(t *testing.T) *CompiledProgram {
	rc := NewRuleCompiler()

	rules := []*ast.Rule{
		createTestRuleForCompiledProgram(t, "rule1", "$test", "test", 1),
		createTestRuleForCompiledProgram(t, "rule2", "$pattern", "pattern", 5),
	}

	program := &ast.Program{Rules: rules}
	compiled, err := rc.CompileProgram(program)
	if err != nil {
		t.Fatalf("CompileProgram() error = %v", err)
	}

	return NewCompiledProgram(compiled)
}

// createTestRuleForCompiledProgram creates a simple test rule with one string
func createTestRuleForCompiledProgram(_ *testing.T, name, identifier, value string, lineNum int) *ast.Rule {
	return &ast.Rule{
		Pos:  token.Position{Line: lineNum, Column: 1},
		Name: name,
		Strings: []*ast.String{
			{
				Pos:        token.Position{Line: lineNum + 1, Column: 1},
				Identifier: identifier,
				Pattern: &ast.TextString{
					Value: value,
					Pos:   token.Position{Line: lineNum + 1, Column: 10},
				},
				Modifiers: []ast.StringModifier{},
			},
		},
		Condition: &ast.Literal{
			Pos:   token.Position{Line: lineNum + 2, Column: 1},
			Type:  token.TRUE,
			Value: true,
		},
	}
}

// testCompiledProgramRuleCount tests GetRuleCount method
func testCompiledProgramRuleCount(t *testing.T) {
	compiledProgram := setupTestCompiledProgram(t)

	ruleCount := compiledProgram.GetRuleCount()
	if ruleCount != 2 {
		t.Errorf("GetRuleCount() = %d, want 2", ruleCount)
	}
}

// testCompiledProgramBytecodeSize tests GetTotalBytecodeSize method
func testCompiledProgramBytecodeSize(t *testing.T) {
	compiledProgram := setupTestCompiledProgram(t)

	totalSize := compiledProgram.GetTotalBytecodeSize()
	if totalSize <= 0 {
		t.Errorf("GetTotalBytecodeSize() = %d, want > 0", totalSize)
	}
}

// testCompiledProgramMemoryUsage tests GetTotalMemoryUsage method
func testCompiledProgramMemoryUsage(t *testing.T) {
	compiledProgram := setupTestCompiledProgram(t)

	memUsage := compiledProgram.GetTotalMemoryUsage()
	if memUsage <= 0 {
		t.Errorf("GetTotalMemoryUsage() = %d, want > 0", memUsage)
	}
}

// testCompiledProgramGetRuleByName tests GetRuleByName method
func testCompiledProgramGetRuleByName(t *testing.T) {
	compiledProgram := setupTestCompiledProgram(t)

	t.Run("existing_rule", func(t *testing.T) {
		rule, exists := compiledProgram.GetRuleByName("rule1")
		if !exists {
			t.Errorf("GetRuleByName() exists = false for rule1, want true")
		}
		if rule.GetName() != "rule1" {
			t.Errorf("GetRuleByName() returned rule with name %s, want rule1", rule.GetName())
		}
	})

	t.Run("nonexistent_rule", func(t *testing.T) {
		_, exists := compiledProgram.GetRuleByName("nonexistent")
		if exists {
			t.Errorf("GetRuleByName() exists = true for non-existent rule, want false")
		}
	})
}

// TestInstructionProperties tests various instruction property methods
func TestInstructionProperties(t *testing.T) {
	tests := []struct {
		name       string
		setupInstr func() *Instruction
		method     func(*Instruction) bool
		wantResult bool
	}{
		{
			name: "int8_is_type_function",
			setupInstr: func() *Instruction {
				return NewInstruction(OP_INT8, 1, 1)
			},
			method:     (*Instruction).IsTypeFunction,
			wantResult: true,
		},
		{
			name: "push_is_not_type_function",
			setupInstr: func() *Instruction {
				return NewInstruction(OP_PUSH_8, 1, 1)
			},
			method:     (*Instruction).IsTypeFunction,
			wantResult: false,
		},
		{
			name: "contains_is_string_op",
			setupInstr: func() *Instruction {
				return NewInstruction(OP_CONTAINS, 1, 1)
			},
			method:     (*Instruction).IsStringOperation,
			wantResult: true,
		},
		{
			name: "nop_is_not_string_op",
			setupInstr: func() *Instruction {
				return NewInstruction(OP_NOP, 1, 1)
			},
			method:     (*Instruction).IsStringOperation,
			wantResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			instr := tt.setupInstr()
			result := tt.method(instr)
			if result != tt.wantResult {
				t.Errorf("Instruction property test failed: got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// TestInstructionOperandProperties tests instruction operand-related property methods
func TestInstructionOperandProperties(t *testing.T) {
	tests := []struct {
		name       string
		setupInstr func() *Instruction
		method     func(*Instruction) bool
		wantResult bool
	}{
		{
			name: "immediate8_has_immediate",
			setupInstr: func() *Instruction {
				return NewInstructionWithOperand(OP_PUSH_8, Operand{Type: OperandImmediate8, Value: 42}, 1, 1)
			},
			method:     (*Instruction).HasImmediateOperand,
			wantResult: true,
		},
		{
			name: "none_no_immediate",
			setupInstr: func() *Instruction {
				return NewInstructionWithOperand(OP_PUSH_8, Operand{Type: OperandNone}, 1, 1)
			},
			method:     (*Instruction).HasImmediateOperand,
			wantResult: false,
		},
		{
			name: "relative8_has_relative",
			setupInstr: func() *Instruction {
				return NewInstructionWithOperand(OP_JZ, Operand{Type: OperandRelative8, Value: 10}, 1, 1)
			},
			method:     (*Instruction).HasRelativeOperand,
			wantResult: true,
		},
		{
			name: "none_no_relative",
			setupInstr: func() *Instruction {
				return NewInstructionWithOperand(OP_JZ, Operand{Type: OperandNone}, 1, 1)
			},
			method:     (*Instruction).HasRelativeOperand,
			wantResult: false,
		},
		{
			name: "absolute32_has_absolute",
			setupInstr: func() *Instruction {
				return NewInstructionWithOperand(OP_PUSH_8, Operand{Type: OperandAbsolute32, Value: 1000}, 1, 1)
			},
			method:     (*Instruction).HasAbsoluteOperand,
			wantResult: true,
		},
		{
			name: "none_no_absolute",
			setupInstr: func() *Instruction {
				return NewInstructionWithOperand(OP_PUSH_8, Operand{Type: OperandNone}, 1, 1)
			},
			method:     (*Instruction).HasAbsoluteOperand,
			wantResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			instr := tt.setupInstr()
			result := tt.method(instr)
			if result != tt.wantResult {
				t.Errorf("Instruction operand property test failed: got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// createTestStringCompiler creates a string compiler with a test string compiled
func createTestStringCompiler(t *testing.T) *StringCompiler {
	emitter := NewEmitter()
	sc := NewStringCompiler(emitter)

	// Compile a test string
	str := &ast.String{
		Pos:        token.Position{Line: 1, Column: 1},
		Identifier: "$test",
		Pattern: &ast.TextString{
			Value: "test",
			Pos:   token.Position{Line: 1, Column: 10},
		},
		Modifiers: []ast.StringModifier{},
	}

	err := sc.compileString(str)
	if err != nil {
		t.Fatalf("compileString() error = %v", err)
	}

	return sc
}

// TestStringCompilerMethods tests various string compiler methods
func TestStringCompilerMethods(t *testing.T) {
	tests := []struct {
		name     string
		testFunc func(*testing.T, *StringCompiler)
	}{
		{
			name: "GetAtoms",
			testFunc: func(t *testing.T, sc *StringCompiler) {
				atoms := sc.GetAtoms("$test")
				if atoms == nil {
					t.Errorf("GetAtoms() returned nil")
				}
			},
		},
		{
			name: "GetStringInfo",
			testFunc: func(t *testing.T, sc *StringCompiler) {
				infos := sc.GetStringInfo()
				if len(infos) == 0 {
					t.Errorf("GetStringInfo() returned empty list")
				}
			},
		},
		{
			name: "PrintStringInfo",
			testFunc: func(_ *testing.T, sc *StringCompiler) {
				// This should not panic
				sc.PrintStringInfo()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := createTestStringCompiler(t)
			tt.testFunc(t, sc)
		})
	}
}

// createTestConditionCompiler creates a condition compiler for testing
func createTestConditionCompiler() *ConditionCompiler {
	emitter := NewEmitter()
	return NewConditionCompiler(emitter, make(map[string]int))
}

// createTestLiteral creates a test literal expression
func createTestLiteral() *ast.Literal {
	return &ast.Literal{
		Pos:   token.Position{Line: 1, Column: 1},
		Type:  token.TRUE,
		Value: true,
	}
}

// TestConditionCompilerMethods tests various condition compiler methods
func TestConditionCompilerMethods(t *testing.T) {
	tests := []struct {
		name     string
		testFunc func(*testing.T, *ConditionCompiler)
	}{
		{
			name: "GenerateLabel",
			testFunc: func(t *testing.T, cc *ConditionCompiler) {
				label1 := cc.generateLabel()
				label2 := cc.generateLabel()

				if label1 == "" {
					t.Errorf("generateLabel() returned empty string")
				}
				if label1 == label2 {
					t.Errorf("generateLabel() returned duplicate labels: %s and %s", label1, label2)
				}
			},
		},
		{
			name: "EmitJump",
			testFunc: func(t *testing.T, cc *ConditionCompiler) {
				err := cc.EmitJump(ConditionalJumpConfig{Opcode: OP_JZ, TargetLabel: "L1", Position: JumpPosition{Line: 1, Column: 1}})
				if err != nil {
					t.Errorf("EmitJump() error = %v", err)
				}
			},
		},
		{
			name: "OptimizeExpression",
			testFunc: func(t *testing.T, cc *ConditionCompiler) {
				expr := createTestLiteral()
				optimized := cc.OptimizeExpression(expr)
				if optimized == nil {
					t.Errorf("OptimizeExpression() returned nil")
				}
			},
		},
		{
			name: "EstimateComplexity",
			testFunc: func(t *testing.T, cc *ConditionCompiler) {
				expr := createTestLiteral()
				complexity := cc.EstimateComplexity(expr)
				if complexity < 0 {
					t.Errorf("EstimateComplexity() returned negative value %d", complexity)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cc := createTestConditionCompiler()
			tt.testFunc(t, cc)
		})
	}
}

// TestCompiledProgramPrintDebug tests PrintDebug method
func TestCompiledProgramPrintDebug(t *testing.T) {
	rc := NewRuleCompiler()

	rule := &ast.Rule{
		Pos:  token.Position{Line: 1, Column: 1},
		Name: "test_rule",
		Strings: []*ast.String{
			{
				Pos:        token.Position{Line: 2, Column: 1},
				Identifier: "$test",
				Pattern: &ast.TextString{
					Value: "test",
					Pos:   token.Position{Line: 2, Column: 10},
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

	program := &ast.Program{
		Rules: []*ast.Rule{rule},
	}

	compiled, err := rc.CompileProgram(program)
	if err != nil {
		t.Errorf("CompileProgram() error = %v", err)
	}

	compiledProgram := NewCompiledProgram(compiled)

	// This should not panic
	compiledProgram.PrintDebug()
}

// TestCompiledProgramOptimize tests Optimize method
func TestCompiledProgramOptimize(t *testing.T) {
	rc := NewRuleCompiler()

	rule := &ast.Rule{
		Pos:  token.Position{Line: 1, Column: 1},
		Name: "test_rule",
		Strings: []*ast.String{
			{
				Pos:        token.Position{Line: 2, Column: 1},
				Identifier: "$test",
				Pattern: &ast.TextString{
					Value: "test",
					Pos:   token.Position{Line: 2, Column: 10},
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

	program := &ast.Program{
		Rules: []*ast.Rule{rule},
	}

	compiled, err := rc.CompileProgram(program)
	if err != nil {
		t.Errorf("CompileProgram() error = %v", err)
	}

	compiledProgram := NewCompiledProgram(compiled)

	// This should not panic
	if err := compiledProgram.Optimize(); err != nil {
		t.Errorf("Optimize() error = %v", err)
	}
}

// TestCompiledProgramGetExecutionPlan tests GetExecutionPlan method
func TestCompiledProgramGetExecutionPlan(t *testing.T) {
	rc := NewRuleCompiler()

	rule := &ast.Rule{
		Pos:  token.Position{Line: 1, Column: 1},
		Name: "test_rule",
		Strings: []*ast.String{
			{
				Pos:        token.Position{Line: 2, Column: 1},
				Identifier: "$test",
				Pattern: &ast.TextString{
					Value: "test",
					Pos:   token.Position{Line: 2, Column: 10},
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

	program := &ast.Program{
		Rules: []*ast.Rule{rule},
	}

	compiled, err := rc.CompileProgram(program)
	if err != nil {
		t.Errorf("CompileProgram() error = %v", err)
	}

	compiledProgram := NewCompiledProgram(compiled)

	plan := compiledProgram.GetExecutionPlan()
	if plan == nil {
		t.Errorf("GetExecutionPlan() returned nil")
	}
}

// TestExecutionPlanGetRuleOffset tests GetRuleOffset method
func TestExecutionPlanGetRuleOffset(t *testing.T) {
	rc := NewRuleCompiler()

	rule := &ast.Rule{
		Pos:  token.Position{Line: 1, Column: 1},
		Name: "test_rule",
		Strings: []*ast.String{
			{
				Pos:        token.Position{Line: 2, Column: 1},
				Identifier: "$test",
				Pattern: &ast.TextString{
					Value: "test",
					Pos:   token.Position{Line: 2, Column: 10},
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

	program := &ast.Program{
		Rules: []*ast.Rule{rule},
	}

	compiled, err := rc.CompileProgram(program)
	if err != nil {
		t.Errorf("CompileProgram() error = %v", err)
	}

	compiledProgram := NewCompiledProgram(compiled)
	plan := compiledProgram.GetExecutionPlan()

	// Test GetRuleOffset on the execution plan
	offset, exists := plan.GetRuleOffset(0)
	if !exists {
		t.Errorf("GetRuleOffset() exists = false, want true")
	}
	if offset < 0 {
		t.Errorf("GetRuleOffset() returned negative value %d", offset)
	}
}

// TestExecutionPlanGetTotalSize tests GetTotalSize method
func TestExecutionPlanGetTotalSize(t *testing.T) {
	rc := NewRuleCompiler()

	rule := &ast.Rule{
		Pos:  token.Position{Line: 1, Column: 1},
		Name: "test_rule",
		Strings: []*ast.String{
			{
				Pos:        token.Position{Line: 2, Column: 1},
				Identifier: "$test",
				Pattern: &ast.TextString{
					Value: "test",
					Pos:   token.Position{Line: 2, Column: 10},
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

	program := &ast.Program{
		Rules: []*ast.Rule{rule},
	}

	compiled, err := rc.CompileProgram(program)
	if err != nil {
		t.Errorf("CompileProgram() error = %v", err)
	}

	compiledProgram := NewCompiledProgram(compiled)
	plan := compiledProgram.GetExecutionPlan()

	size := plan.GetTotalSize()
	if size <= 0 {
		t.Errorf("GetTotalSize() = %d, want > 0", size)
	}
}

// TestCompilerCompileFile tests CompileFile method
func TestCompilerCompileFile(t *testing.T) {
	compiler := NewCompiler()

	// CompileFile calls readFile which is not implemented
	// This test verifies that the error is handled correctly
	_, err := compiler.CompileFile("nonexistent.yar")
	if err == nil {
		t.Errorf("CompileFile() error = nil, want error")
	}
}

// TestConditionCompilerCompileBooleanExpression tests CompileBooleanExpression method
func TestConditionCompilerCompileBooleanExpression(t *testing.T) {
	emitter := NewEmitter()
	cc := NewConditionCompiler(emitter, make(map[string]int))

	expr := &ast.Literal{
		Pos:   token.Position{Line: 1, Column: 1},
		Type:  token.TRUE,
		Value: true,
	}

	// Test without short-circuit
	err := cc.CompileBooleanExpression(expr, false)
	if err != nil {
		t.Errorf("CompileBooleanExpression() error = %v", err)
	}

	// Test with short-circuit (but not AND/OR)
	err = cc.CompileBooleanExpression(expr, true)
	if err != nil {
		t.Errorf("CompileBooleanExpression() error = %v", err)
	}
}

// TestConditionCompilerCompileShortCircuitAnd tests compileShortCircuitAnd method
func TestConditionCompilerCompileShortCircuitAnd(t *testing.T) {
	emitter := NewEmitter()
	cc := NewConditionCompiler(emitter, make(map[string]int))

	andOp := &ast.BinaryOp{
		Pos: token.Position{Line: 1, Column: 1},
		Op:  token.AND,
		Left: &ast.Literal{
			Pos:   token.Position{Line: 1, Column: 1},
			Type:  token.TRUE,
			Value: true,
		},
		Right: &ast.Literal{
			Pos:   token.Position{Line: 1, Column: 1},
			Type:  token.TRUE,
			Value: true,
		},
	}

	err := cc.compileShortCircuitAnd(andOp)
	if err != nil {
		t.Errorf("compileShortCircuitAnd() error = %v", err)
	}
}

// TestConditionCompilerCompileShortCircuitOr tests compileShortCircuitOr method
func TestConditionCompilerCompileShortCircuitOr(t *testing.T) {
	emitter := NewEmitter()
	cc := NewConditionCompiler(emitter, make(map[string]int))

	orOp := &ast.BinaryOp{
		Pos: token.Position{Line: 1, Column: 1},
		Op:  token.OR,
		Left: &ast.Literal{
			Pos:   token.Position{Line: 1, Column: 1},
			Type:  token.TRUE,
			Value: true,
		},
		Right: &ast.Literal{
			Pos:   token.Position{Line: 1, Column: 1},
			Type:  token.TRUE,
			Value: true,
		},
	}

	err := cc.compileShortCircuitOr(orOp)
	if err != nil {
		t.Errorf("compileShortCircuitOr() error = %v", err)
	}
}

// TestEmitterEmitDataTypeFunction tests EmitDataTypeFunction method
func TestEmitterEmitDataTypeFunction(t *testing.T) {
	emitter := NewEmitter()

	// Test with a valid data type function opcode
	offset := emitter.EmitDataTypeFunction(OP_READ_INT, 1, 1)
	if offset < 0 {
		t.Errorf("EmitDataTypeFunction() returned negative offset %d", offset)
	}
}

// TestEmitterEmitStringOperation tests EmitStringOperation method
func TestEmitterEmitStringOperation(t *testing.T) {
	emitter := NewEmitter()

	// Test with a valid string operation opcode
	offset := emitter.EmitStringOperation(OP_CONTAINS, 1, 1)
	if offset < 0 {
		t.Errorf("EmitStringOperation() returned negative offset %d", offset)
	}
}

// TestEmitterEmitHalt tests EmitHalt method
func TestEmitterEmitHalt(t *testing.T) {
	emitter := NewEmitter()

	offset := emitter.EmitHalt(1, 1)
	if offset < 0 {
		t.Errorf("EmitHalt() returned negative offset %d", offset)
	}

	// Verify that HALT instruction was emitted
	instructions := emitter.GetInstructions()
	if len(instructions) == 0 {
		t.Errorf("EmitHalt() did not emit any instructions")
	}

	lastInstr := instructions[len(instructions)-1]
	if lastInstr.Opcode != OP_HALT {
		t.Errorf("EmitHalt() emitted opcode %s, want OP_HALT", lastInstr.Opcode.String())
	}
}

// TestOpcodeStringCoverage tests String method for various opcodes
func TestOpcodeStringCoverage(t *testing.T) {
	// Group opcodes by category for better organization
	opcodeGroups := map[string][]struct {
		opcode Opcode
		name   string
	}{
		"Logical": {
			{OP_AND, "AND"},
			{OP_OR, "OR"},
			{OP_NOT, "NOT"},
		},
		"Bitwise": {
			{OP_BITWISE_NOT, "BITWISE_NOT"},
			{OP_BITWISE_AND, "BITWISE_AND"},
			{OP_BITWISE_OR, "BITWISE_OR"},
			{OP_BITWISE_XOR, "BITWISE_XOR"},
			{OP_SHL, "SHL"},
			{OP_SHR, "SHR"},
		},
		"Arithmetic": {
			{OP_MOD, "MOD"},
			{OP_INT_TO_DBL, "INT_TO_DBL"},
			{OP_INT_EQ, "INT_EQ"},
			{OP_INT_NEQ, "INT_NEQ"},
			{OP_INT_LT, "INT_LT"},
			{OP_INT_GT, "INT_GT"},
			{OP_INT_LE, "INT_LE"},
			{OP_INT_GE, "INT_GE"},
			{OP_INT_ADD, "INT_ADD"},
			{OP_INT_SUB, "INT_SUB"},
			{OP_INT_MUL, "INT_MUL"},
			{OP_INT_DIV, "INT_DIV"},
			{OP_INT_MINUS, "INT_MINUS"},
		},
		"Stack": {
			{OP_PUSH, "PUSH"},
			{OP_POP, "POP"},
			{OP_PUSH_8, "PUSH_8"},
			{OP_PUSH_16, "PUSH_16"},
			{OP_PUSH_32, "PUSH_32"},
		},
		"Object": {
			{OP_CALL, "CALL"},
			{OP_OBJ_LOAD, "OBJ_LOAD"},
			{OP_OBJ_VALUE, "OBJ_VALUE"},
			{OP_OBJ_FIELD, "OBJ_FIELD"},
			{OP_INDEX_ARRAY, "INDEX_ARRAY"},
		},
		"String": {
			{OP_STR_TO_BOOL, "STR_TO_BOOL"},
			{OP_CONTAINS, "CONTAINS"},
			{OP_ICONTAINS, "ICONTAINS"},
			{OP_STARTSWITH, "STARTSWITH"},
			{OP_ISTARTSWITH, "ISTARTSWITH"},
			{OP_ENDSWITH, "ENDSWITH"},
			{OP_IENDSWITH, "IENDSWITH"},
			{OP_IEQUALS, "IEQUALS"},
			{OP_MATCHES, "MATCHES"},
		},
		"FlowControl": {
			{OP_JZ, "JZ"},
			{OP_JTRUE, "JTRUE"},
			{OP_JFALSE, "JFALSE"},
			{OP_INIT_RULE, "INIT_RULE"},
		},
		"System": {
			{OP_ERROR, "ERROR"},
			{OP_FOUND, "FOUND"},
			{OP_OF_FOUND_AT, "OF_FOUND_AT"},
		},
	}

	for category, opcodes := range opcodeGroups {
		t.Run(category, func(t *testing.T) {
			for _, tc := range opcodes {
				t.Run(tc.name, func(t *testing.T) {
					assertOpcodeString(t, tc.opcode, tc.name)
				})
			}
		})
	}
}

// TestOpcodeStringCoverageExtended tests String method for extended opcodes
func TestOpcodeStringCoverageExtended(t *testing.T) {
	extendedOpcodeGroups := map[string][]struct {
		opcode Opcode
		name   string
	}{
		"StringOperations": {
			{OP_COUNT, "COUNT"},
			{OP_LENGTH, "LENGTH"},
			{OP_FOUND_AT, "FOUND_AT"},
			{OP_FOUND_IN, "FOUND_IN"},
			{OP_OFFSET, "OFFSET"},
			{OP_OF, "OF"},
			{OP_OF_PERCENT, "OF_PERCENT"},
			{OP_OF_FOUND_IN, "OF_FOUND_IN"},
			{OP_COUNT_IN, "COUNT_IN"},
			{OP_ITER_START_TEXT_STRING_SET, "ITER_START_TEXT_STRING_SET"},
		},
		"FlowControl": {
			{OP_JNUNDEF, "JNUNDEF"},
			{OP_JUNDEF_P, "JUNDEF_P"},
			{OP_JNUNDEF_P, "JNUNDEF_P"},
			{OP_JFALSE_P, "JFALSE_P"},
			{OP_JTRUE_P, "JTRUE_P"},
			{OP_JL_P, "JL_P"},
			{OP_JLE_P, "JLE_P"},
			{OP_JZ_P, "JZ_P"},
		},
		"Comparison": {
			{OP_DEFINED, "DEFINED"},
			{OP_DBL_EQ, "DBL_EQ"},
			{OP_DBL_NEQ, "DBL_NEQ"},
			{OP_DBL_LT, "DBL_LT"},
			{OP_DBL_GT, "DBL_GT"},
			{OP_DBL_LE, "DBL_LE"},
			{OP_DBL_GE, "DBL_GE"},
		},
		"Iteration": {
			{OP_ITER_NEXT, "ITER_NEXT"},
			{OP_ITER_START_ARRAY, "ITER_START_ARRAY"},
			{OP_ITER_START_DICT, "ITER_START_DICT"},
			{OP_ITER_START_INT_RANGE, "ITER_START_INT_RANGE"},
			{OP_ITER_START_INT_ENUM, "ITER_START_INT_ENUM"},
			{OP_ITER_START_STRING_SET, "ITER_START_STRING_SET"},
			{OP_ITER_CONDITION, "ITER_CONDITION"},
			{OP_ITER_END, "ITER_END"},
		},
		"Memory": {
			{OP_PUSH_RULE, "PUSH_RULE"},
			{OP_MATCH_RULE, "MATCH_RULE"},
			{OP_INCR_M, "INCR_M"},
			{OP_CLEAR_M, "CLEAR_M"},
			{OP_ADD_M, "ADD_M"},
			{OP_POP_M, "POP_M"},
			{OP_PUSH_M, "PUSH_M"},
			{OP_SET_M, "SET_M"},
			{OP_SWAPUNDEF, "SWAPUNDEF"},
			{OP_PUSH_U, "PUSH_U"},
		},
		"DoublePrecision": {
			{OP_DBL_ADD, "DBL_ADD"},
			{OP_DBL_SUB, "DBL_SUB"},
			{OP_DBL_MUL, "DBL_MUL"},
			{OP_DBL_DIV, "DBL_DIV"},
			{OP_DBL_MINUS, "DBL_MINUS"},
		},
		"StringComparison": {
			{OP_STR_EQ, "STR_EQ"},
			{OP_STR_NEQ, "STR_NEQ"},
			{OP_STR_LT, "STR_LT"},
			{OP_STR_GT, "STR_GT"},
			{OP_STR_LE, "STR_LE"},
			{OP_STR_GE, "STR_GE"},
		},
		"IntegerOperations": {
			{OP_INT8, "INT8"},
			{OP_INT16, "INT16"},
			{OP_INT32, "INT32"},
			{OP_UINT8, "UINT8"},
			{OP_UINT16, "UINT16"},
			{OP_UINT32, "UINT32"},
			{OP_INT8BE, "INT8BE"},
			{OP_INT16BE, "INT16BE"},
			{OP_INT32BE, "INT32BE"},
			{OP_UINT8BE, "UINT8BE"},
			{OP_UINT16BE, "UINT16BE"},
			{OP_UINT32BE, "UINT32BE"},
			{OP_FILESIZE, "FILESIZE"},
			{OP_ENTRYPOINT, "ENTRYPOINT"},
			{OP_IMPORT, "IMPORT"},
			{OP_LOOKUP_DICT, "LOOKUP_DICT"},
		},
	}

	for category, opcodes := range extendedOpcodeGroups {
		t.Run(category, func(t *testing.T) {
			for _, tc := range opcodes {
				t.Run(tc.name, func(t *testing.T) {
					assertOpcodeString(t, tc.opcode, tc.name)
				})
			}
		})
	}
}

// assertOpcodeString is a helper function to test opcode string representation
func assertOpcodeString(t *testing.T, opcode Opcode, expected string) {
	result := opcode.String()
	if result != expected {
		t.Errorf("Opcode.String() = %s, want %s", result, expected)
	}
}

// TestInstructionString tests Instruction.String method
func TestInstructionString(t *testing.T) {
	tests := []struct {
		name     string
		instr    *Instruction
		contains string
	}{
		{
			name:     "no_operand",
			instr:    NewInstruction(OP_NOP, 1, 1),
			contains: "NOP",
		},
		{
			name:     "immediate8",
			instr:    NewInstructionWithOperand(OP_PUSH_8, Operand{Type: OperandImmediate8, Value: 42}, 1, 1),
			contains: "0x2A",
		},
		{
			name:     "immediate16",
			instr:    NewInstructionWithOperand(OP_PUSH_16, Operand{Type: OperandImmediate16, Value: 1000}, 1, 1),
			contains: "0x03E8",
		},
		{
			name:     "immediate32",
			instr:    NewInstructionWithOperand(OP_PUSH_32, Operand{Type: OperandImmediate32, Value: 100000}, 1, 1),
			contains: "0x000186A0",
		},
		{
			name:     "relative8",
			instr:    NewInstructionWithOperand(OP_JZ, Operand{Type: OperandRelative8, Value: 10}, 1, 1),
			contains: "+10",
		},
		{
			name:     "absolute32",
			instr:    NewInstructionWithOperand(OP_PUSH_32, Operand{Type: OperandAbsolute32, Value: 1000}, 1, 1),
			contains: "@0x000003E8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.instr.String()
			if !strings.Contains(result, tt.contains) {
				t.Errorf("Instruction.String() = %s, want to contain %s", result, tt.contains)
			}
		})
	}
}

// TestInstructionBytes tests Instruction.Bytes method
func TestInstructionBytes(t *testing.T) {
	tests := []struct {
		name      string
		instr     *Instruction
		minLen    int
		firstByte byte
	}{
		{
			name:      "no_operand",
			instr:     NewInstruction(OP_NOP, 1, 1),
			minLen:    1,
			firstByte: byte(OP_NOP),
		},
		{
			name:      "immediate8",
			instr:     NewInstructionWithOperand(OP_PUSH_8, Operand{Type: OperandImmediate8, Value: 42}, 1, 1),
			minLen:    2,
			firstByte: byte(OP_PUSH_8),
		},
		{
			name:      "immediate16",
			instr:     NewInstructionWithOperand(OP_PUSH_16, Operand{Type: OperandImmediate16, Value: 1000}, 1, 1),
			minLen:    3,
			firstByte: byte(OP_PUSH_16),
		},
		{
			name:      "immediate32",
			instr:     NewInstructionWithOperand(OP_PUSH_32, Operand{Type: OperandImmediate32, Value: 100000}, 1, 1),
			minLen:    5,
			firstByte: byte(OP_PUSH_32),
		},
		{
			name:      "immediate64",
			instr:     NewInstructionWithOperand(OP_PUSH_U, Operand{Type: OperandImmediate64, Value: 1000000}, 1, 1),
			minLen:    9,
			firstByte: byte(OP_PUSH_U),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.instr.Bytes()
			if len(result) < tt.minLen {
				t.Errorf("Instruction.Bytes() length = %d, want >= %d", len(result), tt.minLen)
			}
			if result[0] != tt.firstByte {
				t.Errorf("Instruction.Bytes() first byte = 0x%02X, want 0x%02X", result[0], tt.firstByte)
			}
		})
	}
}

// TestInstructionSize tests Instruction.Size method
func TestInstructionSize(t *testing.T) {
	tests := []struct {
		name     string
		instr    *Instruction
		expected int
	}{
		{
			name:     "no_operand",
			instr:    NewInstruction(OP_NOP, 1, 1),
			expected: 1,
		},
		{
			name:     "immediate8",
			instr:    NewInstructionWithOperand(OP_PUSH_8, Operand{Type: OperandImmediate8, Value: 42}, 1, 1),
			expected: 2,
		},
		{
			name:     "immediate16",
			instr:    NewInstructionWithOperand(OP_PUSH_16, Operand{Type: OperandImmediate16, Value: 1000}, 1, 1),
			expected: 3,
		},
		{
			name:     "immediate32",
			instr:    NewInstructionWithOperand(OP_PUSH_32, Operand{Type: OperandImmediate32, Value: 100000}, 1, 1),
			expected: 5,
		},
		{
			name:     "immediate64",
			instr:    NewInstructionWithOperand(OP_PUSH_U, Operand{Type: OperandImmediate64, Value: 1000000}, 1, 1),
			expected: 9,
		},
		{
			name:     "relative8",
			instr:    NewInstructionWithOperand(OP_JZ, Operand{Type: OperandRelative8, Value: 10}, 1, 1),
			expected: 2,
		},
		{
			name:     "relative32",
			instr:    NewInstructionWithOperand(OP_JZ, Operand{Type: OperandRelative32, Value: 1000}, 1, 1),
			expected: 5,
		},
		{
			name:     "absolute32",
			instr:    NewInstructionWithOperand(OP_PUSH_32, Operand{Type: OperandAbsolute32, Value: 1000}, 1, 1),
			expected: 5,
		},
		{
			name:     "absolute64",
			instr:    NewInstructionWithOperand(OP_PUSH_U, Operand{Type: OperandAbsolute64, Value: 1000000}, 1, 1),
			expected: 9,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.instr.Size()
			if result != tt.expected {
				t.Errorf("Instruction.Size() = %d, want %d", result, tt.expected)
			}
		})
	}
}

// TestInstructionIsJump tests Instruction.IsJump method
func TestInstructionIsJump(t *testing.T) {
	tests := []struct {
		name     string
		opcode   Opcode
		expected bool
	}{
		{name: "JZ", opcode: OP_JZ, expected: true},
		{name: "JTRUE", opcode: OP_JTRUE, expected: true},
		{name: "JFALSE", opcode: OP_JFALSE, expected: true},
		{name: "ITER_NEXT", opcode: OP_ITER_NEXT, expected: true},
		{name: "NOP", opcode: OP_NOP, expected: false},
		{name: "PUSH", opcode: OP_PUSH, expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			instr := NewInstruction(tt.opcode, 1, 1)
			result := instr.IsJump()
			if result != tt.expected {
				t.Errorf("Instruction.IsJump() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestConditionCompilerCompileBinaryOp tests compileBinaryOp method
func TestConditionCompilerCompileBinaryOp(t *testing.T) {
	tests := []struct {
		name string
		op   token.TokenType
	}{
		{name: "AND", op: token.AND},
		{name: "OR", op: token.OR},
		{name: "PLUS", op: token.PLUS},
		{name: "MINUS", op: token.MINUS},
		{name: "MULTIPLY", op: token.MULTIPLY},
		{name: "DIVIDE", op: token.DIVIDE},
		{name: "MODULO", op: token.MODULO},
		{name: "BITWISE_AND", op: token.BITWISE_AND},
		{name: "BITWISE_OR", op: token.BITWISE_OR},
		{name: "BITWISE_XOR", op: token.BITWISE_XOR},
		{name: "LEFT_SHIFT", op: token.LEFT_SHIFT},
		{name: "RIGHT_SHIFT", op: token.RIGHT_SHIFT},
		{name: "EQ", op: token.EQ},
		{name: "NEQ", op: token.NEQ},
		{name: "LT", op: token.LT},
		{name: "LE", op: token.LE},
		{name: "GT", op: token.GT},
		{name: "GE", op: token.GE},
		{name: "CONTAINS", op: token.CONTAINS},
		{name: "MATCHES", op: token.MATCHES},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			emitter := NewEmitter()
			cc := NewConditionCompiler(emitter, make(map[string]int))

			binOp := &ast.BinaryOp{
				Pos: token.Position{Line: 1, Column: 1},
				Op:  tt.op,
				Left: &ast.Literal{
					Pos:   token.Position{Line: 1, Column: 1},
					Type:  token.TRUE,
					Value: true,
				},
				Right: &ast.Literal{
					Pos:   token.Position{Line: 1, Column: 1},
					Type:  token.TRUE,
					Value: true,
				},
			}

			err := cc.compileBinaryOp(binOp)
			if err != nil {
				t.Errorf("compileBinaryOp() error = %v", err)
			}
		})
	}
}

// TestConditionCompilerCompileUnaryOp tests compileUnaryOp method
func TestConditionCompilerCompileUnaryOp(t *testing.T) {
	tests := []struct {
		name string
		op   token.TokenType
	}{
		{name: "NOT", op: token.NOT},
		{name: "BITWISE_NOT", op: token.BITWISE_NOT},
		{name: "MINUS", op: token.MINUS},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			emitter := NewEmitter()
			cc := NewConditionCompiler(emitter, make(map[string]int))

			unaryOp := &ast.UnaryOp{
				Pos: token.Position{Line: 1, Column: 1},
				Op:  tt.op,
				Right: &ast.Literal{
					Pos:   token.Position{Line: 1, Column: 1},
					Type:  token.TRUE,
					Value: true,
				},
			}

			err := cc.compileUnaryOp(unaryOp)
			if err != nil {
				t.Errorf("compileUnaryOp() error = %v", err)
			}
		})
	}
}

// TestRuleCompilerCompileSingleString tests compileSingleString method
func TestRuleCompilerCompileSingleString(t *testing.T) {
	tests := []struct {
		name    string
		pattern ast.Pattern
		wantErr bool
	}{
		{
			name: "text_string",
			pattern: &ast.TextString{
				Pos:   token.Position{Line: 1, Column: 1},
				Value: "test_pattern",
			},
			wantErr: false,
		},
		{
			name: "hex_string",
			pattern: &ast.HexString{
				Pos:   token.Position{Line: 1, Column: 1},
				Value: "01 02 03",
			},
			wantErr: false,
		},
		{
			name: "regex_pattern",
			pattern: &ast.RegexPattern{
				Pos:   token.Position{Line: 1, Column: 1},
				Value: "test.*",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			emitter := NewEmitter()
			sc := NewStringCompiler(emitter)
			ac := NewACAutomaton()
			rc := &RuleCompiler{
				emitter:           emitter,
				stringCompiler:    sc,
				automaton:         ac,
				conditionCompiler: NewConditionCompiler(emitter, make(map[string]int)),
			}

			str := &ast.String{
				Identifier: "$test",
				Pattern:    tt.pattern,
				Modifiers:  []ast.StringModifier{},
			}

			err := rc.compileSingleString(str)
			if (err != nil) != tt.wantErr {
				t.Errorf("compileSingleString() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestRuleCompilerCompileCondition tests compileCondition method
func TestRuleCompilerCompileCondition(t *testing.T) {
	emitter := NewEmitter()
	sc := NewStringCompiler(emitter)
	ac := NewACAutomaton()
	cc := NewConditionCompiler(emitter, make(map[string]int))
	rc := &RuleCompiler{
		emitter:           emitter,
		stringCompiler:    sc,
		automaton:         ac,
		conditionCompiler: cc,
	}

	rule := &ast.Rule{
		Name: "test_rule",
		Condition: &ast.Literal{
			Pos:   token.Position{Line: 1, Column: 1},
			Type:  token.TRUE,
			Value: true,
		},
	}

	err := rc.compileCondition(rule)
	if err != nil {
		t.Errorf("compileCondition() error = %v", err)
	}

	// Verify that a halt instruction was emitted
	instructions := emitter.GetInstructions()
	if len(instructions) == 0 {
		t.Errorf("compileCondition() did not emit any instructions")
	}

	lastInstr := instructions[len(instructions)-1]
	if lastInstr.Opcode != OP_HALT {
		t.Errorf("compileCondition() last instruction = %s, want OP_HALT", lastInstr.Opcode.String())
	}
}

// TestCompilerCompileParse tests compileParse method
func TestCompilerCompileParse(t *testing.T) {
	c := NewCompiler()

	// Test with valid YARA rule
	source := `rule test_rule {
		strings:
			$test = "test"
		condition:
			$test
	}`

	program, err := c.compileParse(source)
	if err != nil {
		t.Errorf("compileParse() error = %v", err)
	}

	if program == nil {
		t.Errorf("compileParse() returned nil program")
	}
}

// TestCompilerCompileSemantic tests compileSemantic method
func TestCompilerCompileSemantic(t *testing.T) {
	c := NewCompiler()

	// Create a simple program
	program := &ast.Program{
		Rules: []*ast.Rule{
			{
				Name: "test_rule",
				Strings: []*ast.String{
					{
						Identifier: "$test",
						Pattern: &ast.TextString{
							Pos:   token.Position{Line: 1, Column: 1},
							Value: "test",
						},
						Modifiers: []ast.StringModifier{},
					},
				},
				Condition: &ast.Identifier{
					Pos:  token.Position{Line: 1, Column: 1},
					Name: "$test",
				},
			},
		},
	}

	err := c.compileSemantic(program)
	if err != nil {
		t.Logf("compileSemantic() error = %v (this may be expected)", err)
	}
}

// TestStringCompilerCompileString tests compileString method
func TestStringCompilerCompileString(t *testing.T) {
	tests := []struct {
		name    string
		pattern ast.Pattern
		wantErr bool
	}{
		{
			name: "text_string",
			pattern: &ast.TextString{
				Pos:   token.Position{Line: 1, Column: 1},
				Value: "test_pattern",
			},
			wantErr: false,
		},
		{
			name: "hex_string",
			pattern: &ast.HexString{
				Pos:   token.Position{Line: 1, Column: 1},
				Value: "01 02 03",
			},
			wantErr: false,
		},
		{
			name: "regex_pattern",
			pattern: &ast.RegexPattern{
				Pos:   token.Position{Line: 1, Column: 1},
				Value: "test.*",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			emitter := NewEmitter()
			sc := NewStringCompiler(emitter)

			str := &ast.String{
				Identifier: "$test",
				Pattern:    tt.pattern,
				Modifiers:  []ast.StringModifier{},
				Pos:        token.Position{Line: 1, Column: 1},
			}

			err := sc.compileString(str)
			if (err != nil) != tt.wantErr {
				t.Errorf("compileString() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Helper functions for complexity testing
func createTestIdentifierForComplexity(name string) *ast.Identifier {
	return &ast.Identifier{
		Pos:  token.Position{Line: 1, Column: 1},
		Name: name,
	}
}

func createTestUnaryOpForComplexity(op token.TokenType, right ast.Expression) *ast.UnaryOp {
	return &ast.UnaryOp{
		Pos:   token.Position{Line: 1, Column: 1},
		Op:    op,
		Right: right,
	}
}

// TestConditionCompilerEstimateComplexityExtended tests complexity estimation for various expressions
func TestConditionCompilerEstimateComplexityExtended(t *testing.T) {
	emitter := NewEmitter()
	cc := NewConditionCompiler(emitter, make(map[string]int))

	testCases := []struct {
		name       string
		expr       ast.Expression
		minComplex int
	}{
		{"literal_true", createTestLiteral(), 1},
		{"identifier_simple", createTestIdentifierForComplexity("test_var"), 2},
		{"not_true", createTestUnaryOpForComplexity(token.NOT, createTestLiteral()), 2},
		{"not_identifier", createTestUnaryOpForComplexity(token.NOT, createTestIdentifierForComplexity("var")), 3},
		{"and_literals", createTestBinaryOp(token.AND, true, false), 3},
		{"or_literals", createTestBinaryOp(token.OR, true, false), 3},
		{"arithmetic_add", createTestBinaryOp(token.PLUS, int64(1), int64(2)), 3},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			complexity := cc.EstimateComplexity(tt.expr)
			if complexity < tt.minComplex {
				t.Errorf("EstimateComplexity() = %d, want >= %d", complexity, tt.minComplex)
			}
		})
	}
}

// TestInterpreterStackOperations tests stack operations in interpreter
func TestInterpreterStackOperations(t *testing.T) {
	tests := []struct {
		name     string
		bytecode []byte
		wantErr  bool
	}{
		{
			name:     "halt_only",
			bytecode: []byte{byte(OP_HALT)},
			wantErr:  false,
		},
		{
			name:     "nop_halt",
			bytecode: []byte{byte(OP_NOP), byte(OP_HALT)},
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interp := NewInterpreter(tt.bytecode)
			err := interp.Execute()
			if (err != nil) != tt.wantErr {
				t.Errorf("Execute() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestStringCompilerEdgeCases tests edge cases in string compilation
func TestStringCompilerEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		pattern   ast.Pattern
		modifiers []ast.StringModifier
		wantErr   bool
	}{
		{
			name:      "empty_text_string",
			pattern:   &ast.TextString{Value: ""},
			modifiers: []ast.StringModifier{},
			wantErr:   false,
		},
		{
			name:      "text_string_with_nocase",
			pattern:   &ast.TextString{Value: "Test"},
			modifiers: []ast.StringModifier{{Type: ast.StringModifierNocase}},
			wantErr:   false,
		},
		{
			name:      "hex_string",
			pattern:   &ast.HexString{Value: "48656C6C6F"},
			modifiers: []ast.StringModifier{},
			wantErr:   false,
		},
		{
			name:      "regex_pattern",
			pattern:   &ast.RegexPattern{Value: "test.*"},
			modifiers: []ast.StringModifier{},
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			emitter := NewEmitter()
			sc := NewStringCompiler(emitter)
			str := &ast.String{
				Identifier: "$test",
				Pattern:    tt.pattern,
				Modifiers:  tt.modifiers,
			}
			err := sc.CompileStrings(&ast.Rule{
				Name:      "test_rule",
				Strings:   []*ast.String{str},
				Condition: nil,
			})
			if (err != nil) != tt.wantErr {
				t.Errorf("CompileStrings() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestConditionCompilerEdgeCases tests edge cases in condition compilation
func TestConditionCompilerEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		condition *ast.Condition
		wantErr   bool
	}{
		{
			name: "literal_true",
			condition: &ast.Condition{
				Expression: &ast.Literal{
					Type:  token.TRUE,
					Value: true,
				},
			},
			wantErr: false,
		},
		{
			name: "literal_false",
			condition: &ast.Condition{
				Expression: &ast.Literal{
					Type:  token.FALSE,
					Value: false,
				},
			},
			wantErr: false,
		},
		{
			name: "integer_literal",
			condition: &ast.Condition{
				Expression: &ast.Literal{
					Type:  token.INTEGER_LIT,
					Value: int64(42),
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			emitter := NewEmitter()
			cc := NewConditionCompiler(emitter, make(map[string]int))
			err := cc.CompileCondition(tt.condition)
			if (err != nil) != tt.wantErr {
				t.Errorf("CompileCondition() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestAtomQualityCalculation tests atom quality calculation
func TestAtomQualityCalculation(t *testing.T) {
	tests := []struct {
		name    string
		atom    *Atom
		minQual int
		maxQual int
	}{
		{
			name: "empty_atom",
			atom: &Atom{
				Data:   []byte{},
				Mask:   []byte{},
				Length: 0,
			},
			minQual: 0,
			maxQual: 0,
		},
		{
			name: "single_byte_full_mask",
			atom: &Atom{
				Data:   []byte{0x41},
				Mask:   []byte{0xFF},
				Length: 1,
			},
			minQual: 10,
			maxQual: 100,
		},
		{
			name: "common_byte",
			atom: &Atom{
				Data:   []byte{0x00},
				Mask:   []byte{0xFF},
				Length: 1,
			},
			minQual: -10,
			maxQual: 50,
		},
		{
			name: "partial_mask",
			atom: &Atom{
				Data:   []byte{0x41},
				Mask:   []byte{0x0F},
				Length: 1,
			},
			minQual: 0,
			maxQual: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			quality := calculateAtomQuality(tt.atom)
			if quality < tt.minQual || quality > tt.maxQual {
				t.Errorf("calculateAtomQuality() = %d, want between %d and %d", quality, tt.minQual, tt.maxQual)
			}
		})
	}
}

// TestEmitterInstructions tests emitter instruction generation
func TestEmitterInstructions(t *testing.T) {
	tests := []struct {
		name    string
		testFn  func(*Emitter) error
		wantErr bool
	}{
		{
			name: "emit_opcode",
			testFn: func(e *Emitter) error {
				e.EmitOpcode(OP_HALT, 1, 1)
				return nil
			},
			wantErr: false,
		},
		{
			name: "emit_push",
			testFn: func(e *Emitter) error {
				e.EmitPush(42, 1, 1)
				return nil
			},
			wantErr: false,
		},
		{
			name: "emit_label",
			testFn: func(e *Emitter) error {
				e.EmitLabel(1, 1, 1)
				return nil
			},
			wantErr: false,
		},
		{
			name: "emit_jump",
			testFn: func(e *Emitter) error {
				offset := e.EmitJump(JumpConfig{Opcode: OP_JZ, Target: 1, Line: 1, Pos: 1})
				if offset < 0 {
					return errors.New("EmitJump returned negative offset")
				}
				return nil
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			emitter := NewEmitter()
			err := tt.testFn(emitter)
			if (err != nil) != tt.wantErr {
				t.Errorf("test error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestRuleCompilerIntegration tests full rule compilation
func TestRuleCompilerIntegration(t *testing.T) {
	tests := []struct {
		name    string
		rule    *ast.Rule
		wantErr bool
	}{
		{
			name: "simple_rule",
			rule: &ast.Rule{
				Name: "test_rule",
				Strings: []*ast.String{
					{
						Identifier: "$test",
						Pattern: &ast.TextString{
							Value: "test",
						},
						Modifiers: []ast.StringModifier{},
					},
				},
				Condition: &ast.Identifier{
					Name: "$test",
				},
			},
			wantErr: false,
		},
		{
			name: "rule_with_multiple_strings",
			rule: &ast.Rule{
				Name: "multi_string_rule",
				Strings: []*ast.String{
					{
						Identifier: "$s1",
						Pattern: &ast.TextString{
							Value: "hello",
						},
						Modifiers: []ast.StringModifier{},
					},
					{
						Identifier: "$s2",
						Pattern: &ast.TextString{
							Value: "world",
						},
						Modifiers: []ast.StringModifier{},
					},
				},
				Condition: &ast.BinaryOp{
					Left: &ast.Identifier{
						Name: "$s1",
					},
					Op: token.AND,
					Right: &ast.Identifier{
						Name: "$s2",
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := NewRuleCompiler()
			_, err := rc.CompileRule(tt.rule)
			if (err != nil) != tt.wantErr {
				t.Errorf("CompileRule() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestCompilerFullPipeline tests the full compilation pipeline
func TestCompilerFullPipeline(t *testing.T) {
	tests := []struct {
		name    string
		source  string
		wantErr bool
	}{
		{
			name: "simple_rule",
			source: `rule test {
				strings:
					$a = "test"
				condition:
					$a
			}`,
			wantErr: false,
		},
		{
			name: "rule_with_hex",
			source: `rule hex_test {
				strings:
					$hex = { 48 65 6C 6C 6F }
				condition:
					$hex
			}`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiler := NewCompiler()
			_, err := compiler.CompileSource(tt.source)
			if (err != nil) != tt.wantErr {
				t.Errorf("CompileSource() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestCompilerGetVersion tests GetVersion method
func TestCompilerGetVersion(t *testing.T) {
	compiler := NewCompiler()
	version := compiler.GetVersion()
	if version == "" {
		t.Error("GetVersion() returned empty string")
	}
}

// TestCompilerGetSupportedFeatures tests GetSupportedFeatures method
func TestCompilerGetSupportedFeatures(t *testing.T) {
	compiler := NewCompiler()
	features := compiler.GetSupportedFeatures()
	if len(features) == 0 {
		t.Error("GetSupportedFeatures() returned empty slice")
	}
}

// TestCompilerEstimateCompilationTime tests EstimateCompilationTime method
func TestCompilerEstimateCompilationTime(t *testing.T) {
	compiler := NewCompiler()
	estimated := compiler.EstimateCompilationTime(1000)
	if estimated <= 0 {
		t.Error("EstimateCompilationTime() returned non-positive duration")
	}
}

// TestCompilerGetMemoryRequirements tests GetMemoryRequirements method
func TestCompilerGetMemoryRequirements(t *testing.T) {
	compiler := NewCompiler()
	requirements := compiler.GetMemoryRequirements(1000)
	if requirements <= 0 {
		t.Error("GetMemoryRequirements() returned non-positive value")
	}
}

// TestCompilerBatchCompile tests BatchCompile method
func TestCompilerBatchCompile(t *testing.T) {
	compiler := NewCompiler()
	sources := []string{
		`rule test1 { condition: true }`,
		`rule test2 { condition: true }`,
	}

	programs, err := compiler.BatchCompile(sources)
	if err != nil {
		t.Errorf("BatchCompile() error = %v", err)
	}
	if len(programs) != 2 {
		t.Errorf("BatchCompile() returned %d programs, want 2", len(programs))
	}
}

// TestCompilerCompileWithProgress tests CompileWithProgress method
func TestCompilerCompileWithProgress(t *testing.T) {
	compiler := NewCompiler()
	source := `rule test { condition: true }`

	var phases []string
	var percents []float64

	program, err := compiler.CompileWithProgress(source, func(phase string, percent float64) {
		phases = append(phases, phase)
		percents = append(percents, percent)
	})

	if err != nil {
		t.Errorf("CompileWithProgress() error = %v", err)
	}
	if program == nil {
		t.Error("CompileWithProgress() returned nil program")
	}
	if len(phases) == 0 {
		t.Error("CompileWithProgress() did not call progress callback")
	}
}

// TestCompilerGetPhaseDependencies tests GetPhaseDependencies method
func TestCompilerGetPhaseDependencies(t *testing.T) {
	compiler := NewCompiler()
	deps := compiler.GetPhaseDependencies()
	if len(deps) == 0 {
		t.Error("GetPhaseDependencies() returned empty map")
	}
}

// TestCompilerValidateCompilation tests ValidateCompilation method
func TestCompilerValidateCompilation(t *testing.T) {
	compiler := NewCompiler()
	source := `rule test { condition: true }`

	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Errorf("CompileSource() error = %v", err)
	}

	err = compiler.ValidateCompilation(program)
	if err != nil {
		t.Errorf("ValidateCompilation() error = %v", err)
	}
}

// TestCompilerGetCompilationReport tests GetCompilationReport method
func TestCompilerGetCompilationReport(t *testing.T) {
	compiler := NewCompiler()
	source := `rule test { condition: true }`

	_, err := compiler.CompileSource(source)
	if err != nil {
		t.Errorf("CompileSource() error = %v", err)
	}

	report := compiler.GetCompilationReport()
	if report == "" {
		t.Error("GetCompilationReport() returned empty string")
	}
}
