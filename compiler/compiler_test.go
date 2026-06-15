package compiler

import (
	"context"
	"errors"
	"fmt"
	"os"
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
		{OpIntAdd, true, false, false, false, false},
		{OpDblAdd, false, true, false, false, false},
		{OpStrEq, false, false, true, false, false},
		{OpJz, false, false, false, true, false},
		{OpInt8, false, false, false, false, true},
		{OpNop, false, false, false, false, false},
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
	// Capture stdout to avoid cluttering test output
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	compiledRule.PrintDebug()
	_ = w.Close()
	os.Stdout = oldStdout
	_ = r.Close()
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
		emitter.EmitOpcode(OpPush, 1, 1)
		emitter.EmitOpcode(OpNop, 1, 2)
		emitter.EmitPush(0x12345678, 1, 3)
		_, _ = emitter.GetBytecode() // Ignore error in benchmark hot path
	}
}

// BenchmarkACAutomaton benchmarks the Aho-Corasick automaton iterator
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
		for range ac.SearchIter(testData) {
			// zero allocation
		}
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
		// If compilation failed, we can't continue testing program statistics
		return
	}

	// Program should not be nil if compilation succeeded
	if program == nil {
		t.Fatal("Program is nil after successful compilation")
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
	emitter.EmitOpcode(OpPush8, 1, 1)
	jumpOffset := emitter.EmitJump(JumpConfig{Opcode: OpJz, Target: 10, Line: 1, Pos: 1})
	emitter.EmitOpcode(OpNop, 1, 1)
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
			opcode:  OpIntAdd,
			wantErr: false,
		},
		{
			name:    "invalid_arithmetic",
			opcode:  OpAnd,
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
			opcode:  OpIntEq,
			wantErr: false,
		},
		{
			name:    "invalid_comparison",
			opcode:  OpAnd,
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
			opcode:  OpAnd,
			wantErr: false,
		},
		{
			name:    "invalid_logical",
			opcode:  OpIntAdd,
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
	emitter.EmitOpcode(OpPush8, 1, 1)
	emitter.EmitOpcode(OpNop, 1, 1)
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
				Type:  token.IntegerLit,
				Value: int64(42),
			},
			wantErr: false,
		},
		{
			name: "string_literal",
			literal: &ast.Literal{
				Pos:   token.Position{Line: 1, Column: 1},
				Type:  token.StringLit,
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
					Type:  token.IntegerLit,
					Value: int64(1),
				},
				Op: token.PLUS,
				Right: &ast.Literal{
					Pos:   token.Position{Line: 1, Column: 1},
					Type:  token.IntegerLit,
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
		Type:  token.IntegerLit,
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

func createBinaryOp(op token.Type, left, right ast.Expression) *ast.BinaryOp {
	return &ast.BinaryOp{
		Pos:   token.Position{Line: 1, Column: 1},
		Left:  left,
		Op:    op,
		Right: right,
	}
}

// createTestBinaryOp creates a binary operation from literal values
func createTestBinaryOp(op token.Type, leftVal, rightVal any) (*ast.BinaryOp, error) {
	leftExpr, err := createLiteralFromValue(leftVal)
	if err != nil {
		return nil, err
	}
	rightExpr, err := createLiteralFromValue(rightVal)
	if err != nil {
		return nil, err
	}
	return createBinaryOp(op, leftExpr, rightExpr), nil
}

// createLiteralFromValue creates a literal expression from a value
func createLiteralFromValue(val any) (ast.Expression, error) {
	switch v := val.(type) {
	case int64:
		return createIntLiteral(v), nil
	case bool:
		return createBoolLiteral(v), nil
	default:
		// Return error for unsupported types
		return nil, fmt.Errorf("unsupported literal type: %T", val)
	}
}

// TestConditionCompilerCompileBinaryOpDetailed tests binary operation compilation in detail
func TestConditionCompilerCompileBinaryOpDetailed(t *testing.T) {
	emitter := NewEmitter()
	cc := NewConditionCompiler(emitter, make(map[string]int))

	tests := []struct {
		name        string
		op          token.Type
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
			binOp, err := createTestBinaryOp(tt.op, tt.leftVal, tt.rightVal)
			if err != nil {
				t.Fatalf("Failed to create test binary op: %v", err)
			}
			err = cc.compileExpression(binOp)

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
	// Capture stdout to avoid cluttering test output
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	compiled.PrintDebug()
	_ = w.Close()
	os.Stdout = oldStdout
	_ = r.Close()
}

// TestEmitterGetInstructions tests getting instructions
func TestEmitterGetInstructions(t *testing.T) {
	emitter := NewEmitter()

	// Emit some instructions
	emitter.EmitOpcode(OpPush8, 1, 1)
	emitter.EmitOpcode(OpNop, 1, 1)
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
	emitter.EmitOpcode(OpPush8, 42, 1)

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
	emitter.EmitOpcode(OpPush8, 1, 1)
	emitter.EmitOpcode(OpNop, 1, 1)
	emitter.EmitHalt(1, 1)

	// This should not panic
	// Capture stdout to avoid cluttering test output
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	emitter.PrintInstructions()
	_ = w.Close()
	os.Stdout = oldStdout
	_ = r.Close()
}

// TestEmitterPrintBytecode tests bytecode printing
func TestEmitterPrintBytecode(t *testing.T) {
	emitter := NewEmitter()

	// Emit some instructions
	emitter.EmitOpcode(OpPush8, 1, 1)
	emitter.EmitHalt(1, 1)

	// This should not panic
	// Capture stdout to avoid cluttering test output
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := emitter.PrintBytecode()
	_ = w.Close()
	os.Stdout = oldStdout
	_ = r.Close()
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

func TestCompiledRuleStatsSurviveRuleCompilerReuse(t *testing.T) {
	rc := NewRuleCompiler()

	firstRule := createTestRuleForCompiledProgram(t, "first_rule", "$first", "first", 1)
	firstCompiled, err := rc.CompileRule(firstRule)
	if err != nil {
		t.Fatalf("CompileRule(first) error = %v", err)
	}

	secondRule := &ast.Rule{
		Pos:  token.Position{Line: 10, Column: 1},
		Name: "second_rule",
		Strings: []*ast.String{
			{
				Pos:        token.Position{Line: 11, Column: 1},
				Identifier: "$second1",
				Pattern: &ast.TextString{
					Value: "second one",
					Pos:   token.Position{Line: 11, Column: 10},
				},
			},
			{
				Pos:        token.Position{Line: 12, Column: 1},
				Identifier: "$second2",
				Pattern: &ast.TextString{
					Value: "second two",
					Pos:   token.Position{Line: 12, Column: 10},
				},
			},
		},
		Condition: &ast.Literal{
			Pos:   token.Position{Line: 13, Column: 1},
			Type:  token.TRUE,
			Value: true,
		},
	}
	secondCompiled, err := rc.CompileRule(secondRule)
	if err != nil {
		t.Fatalf("CompileRule(second) error = %v", err)
	}

	firstStats := firstCompiled.GetStats()
	if got := firstStats["string_count"]; got != 1 {
		t.Fatalf("first rule string_count = %v, want 1", got)
	}

	secondStats := secondCompiled.GetStats()
	if got := secondStats["string_count"]; got != 2 {
		t.Fatalf("second rule string_count = %v, want 2", got)
	}
}

func TestCompiledRuleGetStatsReturnsCopy(t *testing.T) {
	rc := NewRuleCompiler()
	rule := createTestRuleForCompiledProgram(t, "copy_rule", "$copy", "copy", 1)

	compiled, err := rc.CompileRule(rule)
	if err != nil {
		t.Fatalf("CompileRule() error = %v", err)
	}
	compiled.Stats["string_info"] = []StringInfo{
		{
			Identifier: "$copy",
			Pattern:    []byte("copy"),
		},
	}

	stats := compiled.GetStats()
	stats["instruction_count"] = -1

	categories, ok := stats["emitter_categories"].(map[string]int)
	if !ok {
		t.Fatalf("emitter_categories has type %T, want map[string]int", stats["emitter_categories"])
	}
	categories["control"] = -99

	stringInfo, ok := stats["string_info"].([]StringInfo)
	if !ok {
		t.Fatalf("string_info has type %T, want []StringInfo", stats["string_info"])
	}
	if len(stringInfo) != 1 {
		t.Fatalf("string_info length = %d, want 1", len(stringInfo))
	}
	stringInfo[0].Pattern[0] = 'X'

	freshStats := compiled.GetStats()
	if got := freshStats["instruction_count"]; got == -1 {
		t.Fatalf("GetStats returned mutable top-level map; instruction_count = %v", got)
	}

	freshCategories, ok := freshStats["emitter_categories"].(map[string]int)
	if !ok {
		t.Fatalf("fresh emitter_categories has type %T, want map[string]int", freshStats["emitter_categories"])
	}
	if got := freshCategories["control"]; got == -99 {
		t.Fatalf("GetStats returned mutable nested category map; control = %d", got)
	}

	freshStringInfo, ok := freshStats["string_info"].([]StringInfo)
	if !ok {
		t.Fatalf("fresh string_info has type %T, want []StringInfo", freshStats["string_info"])
	}
	if got := string(freshStringInfo[0].Pattern); got != "copy" {
		t.Fatalf("GetStats returned mutable string pattern data = %q, want copy", got)
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
//
//nolint:revive // argument-limit: test helper
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
				return NewInstruction(OpInt8, 1, 1)
			},
			method:     (*Instruction).IsTypeFunction,
			wantResult: true,
		},
		{
			name: "push_is_not_type_function",
			setupInstr: func() *Instruction {
				return NewInstruction(OpPush8, 1, 1)
			},
			method:     (*Instruction).IsTypeFunction,
			wantResult: false,
		},
		{
			name: "contains_is_string_op",
			setupInstr: func() *Instruction {
				return NewInstruction(OpContains, 1, 1)
			},
			method:     (*Instruction).IsStringOperation,
			wantResult: true,
		},
		{
			name: "nop_is_not_string_op",
			setupInstr: func() *Instruction {
				return NewInstruction(OpNop, 1, 1)
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
				return NewInstructionWithOperand(OpPush8, Operand{Type: OperandImmediate8, Value: 42}, 1, 1)
			},
			method:     (*Instruction).HasImmediateOperand,
			wantResult: true,
		},
		{
			name: "none_no_immediate",
			setupInstr: func() *Instruction {
				return NewInstructionWithOperand(OpPush8, Operand{Type: OperandNone}, 1, 1)
			},
			method:     (*Instruction).HasImmediateOperand,
			wantResult: false,
		},
		{
			name: "relative8_has_relative",
			setupInstr: func() *Instruction {
				return NewInstructionWithOperand(OpJz, Operand{Type: OperandRelative8, Value: 10}, 1, 1)
			},
			method:     (*Instruction).HasRelativeOperand,
			wantResult: true,
		},
		{
			name: "none_no_relative",
			setupInstr: func() *Instruction {
				return NewInstructionWithOperand(OpJz, Operand{Type: OperandNone}, 1, 1)
			},
			method:     (*Instruction).HasRelativeOperand,
			wantResult: false,
		},
		{
			name: "absolute32_has_absolute",
			setupInstr: func() *Instruction {
				return NewInstructionWithOperand(OpPush8, Operand{Type: OperandAbsolute32, Value: 1000}, 1, 1)
			},
			method:     (*Instruction).HasAbsoluteOperand,
			wantResult: true,
		},
		{
			name: "none_no_absolute",
			setupInstr: func() *Instruction {
				return NewInstructionWithOperand(OpPush8, Operand{Type: OperandNone}, 1, 1)
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
				// Capture stdout to avoid cluttering test output
				oldStdout := os.Stdout
				r, w, _ := os.Pipe()
				os.Stdout = w
				sc.PrintStringInfo()
				_ = w.Close()
				os.Stdout = oldStdout
				_ = r.Close()
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
				err := cc.EmitJump(ConditionalJumpConfig{Opcode: OpJz, TargetLabel: "L1", Position: JumpPosition{Line: 1, Column: 1}})
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
	// Capture stdout to avoid cluttering test output
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	compiledProgram.PrintDebug()
	_ = w.Close()
	os.Stdout = oldStdout
	_ = r.Close()
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

	// Test with nonexistent file - should return error
	_, err := compiler.CompileFile("nonexistent.yar")
	if err == nil {
		t.Errorf("CompileFile() error = nil, want error for nonexistent file")
	}

	// Test with a valid YARA rule - create a temporary test file
	tempFile := t.TempDir() + "/test_rule.yar"
	yaraContent := `
rule test_rule {
	strings:
		$test = "hello world"
	condition:
		$test
}
`

	err = os.WriteFile(tempFile, []byte(yaraContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Test compilation of the file
	program, err := compiler.CompileFile(tempFile)
	if err != nil {
		t.Errorf("CompileFile() error = %v, want no error for valid YARA file", err)
	}

	if program == nil {
		t.Error("CompileFile() returned nil program, want valid program")
	}

	if program != nil && len(program.Rules) != 1 {
		t.Errorf("CompileFile() returned %d rules, want 1", len(program.Rules))
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
	offset, err := emitter.EmitDataTypeFunction(OpReadInt, 1, 1)
	if err != nil {
		t.Errorf("EmitDataTypeFunction() unexpected error: %v", err)
	}
	if offset < 0 {
		t.Errorf("EmitDataTypeFunction() returned negative offset %d", offset)
	}

	// Test with invalid opcode
	_, err = emitter.EmitDataTypeFunction(OpIntAdd, 1, 1)
	if err == nil {
		t.Error("EmitDataTypeFunction() expected error for invalid opcode")
	}
}

// TestEmitterEmitStringOperation tests EmitStringOperation method
func TestEmitterEmitStringOperation(t *testing.T) {
	emitter := NewEmitter()

	// Test with a valid string operation opcode
	offset, err := emitter.EmitStringOperation(OpContains, 1, 1)
	if err != nil {
		t.Errorf("EmitStringOperation() unexpected error: %v", err)
	}
	if offset < 0 {
		t.Errorf("EmitStringOperation() returned negative offset %d", offset)
	}

	// Test with invalid opcode
	_, err = emitter.EmitStringOperation(OpIntAdd, 1, 1)
	if err == nil {
		t.Error("EmitStringOperation() expected error for invalid opcode")
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
	if lastInstr.Opcode != OpHalt {
		t.Errorf("EmitHalt() emitted opcode %s, want OpHalt", lastInstr.Opcode.String())
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
			{OpAnd, "AND"},
			{OpOr, "OR"},
			{OpNot, "NOT"},
		},
		"Bitwise": {
			{OpBitwiseNot, "BITWISE_NOT"},
			{OpBitwiseAnd, "BITWISE_AND"},
			{OpBitwiseOr, "BITWISE_OR"},
			{OpBitwiseXor, "BITWISE_XOR"},
			{OpShl, "SHL"},
			{OpShr, "SHR"},
		},
		"Arithmetic": {
			{OpMod, "MOD"},
			{OpIntToDbl, "INT_TO_DBL"},
			{OpIntEq, "INT_EQ"},
			{OpIntNeq, "INT_NEQ"},
			{OpIntLt, "INT_LT"},
			{OpIntGt, "INT_GT"},
			{OpIntLe, "INT_LE"},
			{OpIntGe, "INT_GE"},
			{OpIntAdd, "INT_ADD"},
			{OpIntSub, "INT_SUB"},
			{OpIntMul, "INT_MUL"},
			{OpIntDiv, "INT_DIV"},
			{OpIntMinus, "INT_MINUS"},
		},
		"Stack": {
			{OpPush, "PUSH"},
			{OpPop, "POP"},
			{OpPush8, "PUSH_8"},
			{OpPush16, "PUSH_16"},
			{OpPush32, "PUSH_32"},
			{OpPushStr, "PUSH_STR"},
		},
		"Object": {
			{OpCall, "CALL"},
			{OpObjLoad, "OBJ_LOAD"},
			{OpObjValue, "OBJ_VALUE"},
			{OpObjField, "OBJ_FIELD"},
			{OpIndexArray, "INDEX_ARRAY"},
		},
		"String": {
			{OpStrToBool, "STR_TO_BOOL"},
			{OpContains, "CONTAINS"},
			{OpIcontains, "ICONTAINS"},
			{OpStartswith, "STARTSWITH"},
			{OpIstartswith, "ISTARTSWITH"},
			{OpEndswith, "ENDSWITH"},
			{OpIendswith, "IENDSWITH"},
			{OpIequals, "IEQUALS"},
			{OpMatches, "MATCHES"},
		},
		"FlowControl": {
			{OpJz, "JZ"},
			{OpJtrue, "JTRUE"},
			{OpJfalse, "JFALSE"},
			{OpInitRule, "INIT_RULE"},
		},
		"System": {
			{OpError, "ERROR"},
			{OpFound, "FOUND"},
			{OpOfFoundAt, "OF_FOUND_AT"},
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
			{OpCount, "COUNT"},
			{OpLength, "LENGTH"},
			{OpFoundAt, "FOUND_AT"},
			{OpFoundIn, "FOUND_IN"},
			{OpOffset, "OFFSET"},
			{OpOf, "OF"},
			{OpOfPercent, "OF_PERCENT"},
			{OpOfFoundIn, "OF_FOUND_IN"},
			{OpCountIn, "COUNT_IN"},
			{OpIterStartTextStringSet, "ITER_START_TEXT_STRING_SET"},
		},
		"FlowControl": {
			{OpJnundef, "JNUNDEF"},
			{OpJnundefP, "JNUNDEF_P"},
			{OpJfalseP, "JFALSE_P"},
			{OpJtrueP, "JTRUE_P"},
			{OpJlP, "JL_P"},
			{OpJleP, "JLE_P"},
			{OpJzP, "JZ_P"},
		},
		"Comparison": {
			{OpDefined, "DEFINED"},
			{OpDblEq, "DBL_EQ"},
			{OpDblNeq, "DBL_NEQ"},
			{OpDblLt, "DBL_LT"},
			{OpDblGt, "DBL_GT"},
			{OpDblLe, "DBL_LE"},
			{OpDblGe, "DBL_GE"},
		},
		"Iteration": {
			{OpIterNext, "ITER_NEXT"},
			{OpIterStartArray, "ITER_START_ARRAY"},
			{OpIterStartDict, "ITER_START_DICT"},
			{OpIterStartIntRange, "ITER_START_INT_RANGE"},
			{OpIterStartIntEnum, "ITER_START_INT_ENUM"},
			{OpIterStartStringSet, "ITER_START_STRING_SET"},
			{OpIterCondition, "ITER_CONDITION"},
			{OpIterEnd, "ITER_END"},
		},
		"Memory": {
			{OpPushRule, "PUSH_RULE"},
			{OpMatchRule, "MATCH_RULE"},
			{OpIncrM, "INCR_M"},
			{OpClearM, "CLEAR_M"},
			{OpAddM, "ADD_M"},
			{OpPopM, "POP_M"},
			{OpPushM, "PUSH_M"},
			{OpSetM, "SET_M"},
			{OpSwapundef, "SWAPUNDEF"},
			{OpPushU, "PUSH_U"},
		},
		"DoublePrecision": {
			{OpDblAdd, "DBL_ADD"},
			{OpDblSub, "DBL_SUB"},
			{OpDblMul, "DBL_MUL"},
			{OpDblDiv, "DBL_DIV"},
			{OpDblMinus, "DBL_MINUS"},
		},
		"StringComparison": {
			{OpStrEq, "STR_EQ"},
			{OpStrNeq, "STR_NEQ"},
			{OpStrLt, "STR_LT"},
			{OpStrGt, "STR_GT"},
			{OpStrLe, "STR_LE"},
			{OpStrGe, "STR_GE"},
		},
		"IntegerOperations": {
			{OpInt8, "INT8"},
			{OpInt16, "INT16"},
			{OpInt32, "INT32"},
			{OpUint8, "UINT8"},
			{OpUint16, "UINT16"},
			{OpUint32, "UINT32"},
			{OpInt8be, "INT8BE"},
			{OpInt16be, "INT16BE"},
			{OpInt32be, "INT32BE"},
			{OpUint8be, "UINT8BE"},
			{OpUint16be, "UINT16BE"},
			{OpUint32be, "UINT32BE"},
			{OpFilesize, "FILESIZE"},
			{OpEntrypoint, "ENTRYPOINT"},
			{OpImport, "IMPORT"},
			{OpLookupDict, "LOOKUP_DICT"},
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
			instr:    NewInstruction(OpNop, 1, 1),
			contains: "NOP",
		},
		{
			name:     "immediate8",
			instr:    NewInstructionWithOperand(OpPush8, Operand{Type: OperandImmediate8, Value: 42}, 1, 1),
			contains: "0x2A",
		},
		{
			name:     "immediate16",
			instr:    NewInstructionWithOperand(OpPush16, Operand{Type: OperandImmediate16, Value: 1000}, 1, 1),
			contains: "0x03E8",
		},
		{
			name:     "immediate32",
			instr:    NewInstructionWithOperand(OpPush32, Operand{Type: OperandImmediate32, Value: 100000}, 1, 1),
			contains: "0x000186A0",
		},
		{
			name:     "relative8",
			instr:    NewInstructionWithOperand(OpJz, Operand{Type: OperandRelative8, Value: 10}, 1, 1),
			contains: "+10",
		},
		{
			name:     "absolute32",
			instr:    NewInstructionWithOperand(OpPush32, Operand{Type: OperandAbsolute32, Value: 1000}, 1, 1),
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
			instr:     NewInstruction(OpNop, 1, 1),
			minLen:    1,
			firstByte: byte(OpNop),
		},
		{
			name:      "immediate8",
			instr:     NewInstructionWithOperand(OpPush8, Operand{Type: OperandImmediate8, Value: 42}, 1, 1),
			minLen:    2,
			firstByte: byte(OpPush8),
		},
		{
			name:      "immediate16",
			instr:     NewInstructionWithOperand(OpPush16, Operand{Type: OperandImmediate16, Value: 1000}, 1, 1),
			minLen:    3,
			firstByte: byte(OpPush16),
		},
		{
			name:      "immediate32",
			instr:     NewInstructionWithOperand(OpPush32, Operand{Type: OperandImmediate32, Value: 100000}, 1, 1),
			minLen:    5,
			firstByte: byte(OpPush32),
		},
		{
			name:      "immediate64",
			instr:     NewInstructionWithOperand(OpPushU, Operand{Type: OperandImmediate64, Value: 1000000}, 1, 1),
			minLen:    9,
			firstByte: byte(OpPushU),
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
			instr:    NewInstruction(OpNop, 1, 1),
			expected: 1,
		},
		{
			name:     "immediate8",
			instr:    NewInstructionWithOperand(OpPush8, Operand{Type: OperandImmediate8, Value: 42}, 1, 1),
			expected: 2,
		},
		{
			name:     "immediate16",
			instr:    NewInstructionWithOperand(OpPush16, Operand{Type: OperandImmediate16, Value: 1000}, 1, 1),
			expected: 3,
		},
		{
			name:     "immediate32",
			instr:    NewInstructionWithOperand(OpPush32, Operand{Type: OperandImmediate32, Value: 100000}, 1, 1),
			expected: 5,
		},
		{
			name:     "immediate64",
			instr:    NewInstructionWithOperand(OpPushU, Operand{Type: OperandImmediate64, Value: 1000000}, 1, 1),
			expected: 9,
		},
		{
			name:     "relative8",
			instr:    NewInstructionWithOperand(OpJz, Operand{Type: OperandRelative8, Value: 10}, 1, 1),
			expected: 2,
		},
		{
			name:     "relative32",
			instr:    NewInstructionWithOperand(OpJz, Operand{Type: OperandRelative32, Value: 1000}, 1, 1),
			expected: 5,
		},
		{
			name:     "absolute32",
			instr:    NewInstructionWithOperand(OpPush32, Operand{Type: OperandAbsolute32, Value: 1000}, 1, 1),
			expected: 5,
		},
		{
			name:     "absolute64",
			instr:    NewInstructionWithOperand(OpPushU, Operand{Type: OperandAbsolute64, Value: 1000000}, 1, 1),
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
		{name: "JZ", opcode: OpJz, expected: true},
		{name: "JTRUE", opcode: OpJtrue, expected: true},
		{name: "JFALSE", opcode: OpJfalse, expected: true},
		{name: "ITER_NEXT", opcode: OpIterNext, expected: true},
		{name: "NOP", opcode: OpNop, expected: false},
		{name: "PUSH", opcode: OpPush, expected: false},
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
		op   token.Type
	}{
		{name: "AND", op: token.AND},
		{name: "OR", op: token.OR},
		{name: "PLUS", op: token.PLUS},
		{name: "MINUS", op: token.MINUS},
		{name: "MULTIPLY", op: token.MULTIPLY},
		{name: "DIVIDE", op: token.DIVIDE},
		{name: "MODULO", op: token.MODULO},
		{name: "BITWISE_AND", op: token.BitwiseAnd},
		{name: "BITWISE_OR", op: token.BitwiseOr},
		{name: "BITWISE_XOR", op: token.BitwiseXor},
		{name: "LEFT_SHIFT", op: token.LeftShift},
		{name: "RIGHT_SHIFT", op: token.RightShift},
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
		op   token.Type
	}{
		{name: "NOT", op: token.NOT},
		{name: "BITWISE_NOT", op: token.BitwiseNot},
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
	if lastInstr.Opcode != OpHalt {
		t.Errorf("compileCondition() last instruction = %s, want OpHalt", lastInstr.Opcode.String())
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

	program, err := c.compileParseWithContext(context.Background(), source)
	if err != nil {
		t.Errorf("compileParseWithContext() error = %v", err)
	}

	if program == nil {
		t.Errorf("compileParseWithContext() returned nil program")
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

	err := c.compileSemanticWithContext(context.Background(), program)
	if err != nil {
		t.Logf("compileSemanticWithContext() error = %v (this may be expected)", err)
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

func createTestUnaryOpForComplexity(op token.Type, right ast.Expression) *ast.UnaryOp {
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
		{"and_literals", func() *ast.BinaryOp {
			op, _ := createTestBinaryOp(token.AND, true, false)
			return op
		}(), 3},
		{"or_literals", func() *ast.BinaryOp {
			op, _ := createTestBinaryOp(token.OR, true, false)
			return op
		}(), 3},
		{"arithmetic_add", func() *ast.BinaryOp {
			op, _ := createTestBinaryOp(token.PLUS, int64(1), int64(2))
			return op
		}(), 3},
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
			bytecode: []byte{byte(OpHalt)},
			wantErr:  false,
		},
		{
			name:     "nop_halt",
			bytecode: []byte{byte(OpNop), byte(OpHalt)},
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
					Type:  token.IntegerLit,
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
				e.EmitOpcode(OpHalt, 1, 1)
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
				offset := e.EmitJump(JumpConfig{Opcode: OpJz, Target: 1, Line: 1, Pos: 1})
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

// TestCountInRangeEndToEnd tests the full pipeline for "#a in (min..max)"
func TestCountInRangeEndToEnd(t *testing.T) {
	ruleSource := `
rule test_count_in {
    strings:
        $a = "hello"
    condition:
        #a in (1..5)
}`

	compiler := NewCompiler()
	program, err := compiler.CompileSource(ruleSource)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}

	if len(program.Rules) != 1 {
		t.Fatalf("expected 1 compiled rule, got %d", len(program.Rules))
	}

	// Execute against data containing 2 occurrences of "hello"
	data := []byte("hello world hello")
	scanner := NewScanner(program)
	results, err := scanner.Scan(data)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	if len(results.MatchedRules) != 1 {
		t.Errorf("expected 1 match, got %d", len(results.MatchedRules))
	}

	// Test with data that has too many matches (outside range)
	ruleSource2 := `
rule test_count_in_fail {
    strings:
        $a = "a"
    condition:
        #a in (0..2)
}`

	compiler2 := NewCompiler()
	program2, err := compiler2.CompileSource(ruleSource2)
	if err != nil {
		t.Fatalf("CompileSource2() error = %v", err)
	}

	// "a b a b a b" has 3 'a's, which is outside (0..2)
	data2 := []byte("a b a b a b")
	scanner2 := NewScanner(program2)
	results2, err := scanner2.Scan(data2)
	if err != nil {
		t.Fatalf("Scan2() error = %v", err)
	}

	if len(results2.MatchedRules) != 0 {
		t.Errorf("expected 0 matches (count 3 not in range 0..2), got %d", len(results2.MatchedRules))
	}
}

// TestOfPercentEndToEnd tests the full pipeline for "N % of them"
func TestOfPercentEndToEnd(t *testing.T) {
	// Test 1: 50% of them — 2 out of 3 match (66.7% >= 50%)
	ruleSource := `rule test_percent {
		strings:
			$a = "hello"
			$b = "world"
			$c = "foo"
		condition:
			50 % of them
	}`

	data := []byte("hello world")

	compiler := NewCompiler()
	program, err := compiler.CompileSource(ruleSource)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}

	scanner := NewScanner(program)
	results, err := scanner.Scan(data)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	if len(results.MatchedRules) != 1 {
		t.Errorf("expected 1 match (50%% of them, 2/3 = 66.7%%), got %d", len(results.MatchedRules))
	}

	// Test 2: 75% of them — 2 out of 3 match (66.7% < 75%)
	ruleSource2 := `rule test_percent_high {
		strings:
			$a = "hello"
			$b = "world"
			$c = "foo"
		condition:
			75 % of them
	}`

	compiler2 := NewCompiler()
	program2, err := compiler2.CompileSource(ruleSource2)
	if err != nil {
		t.Fatalf("CompileSource2() error = %v", err)
	}

	scanner2 := NewScanner(program2)
	results2, err := scanner2.Scan(data)
	if err != nil {
		t.Fatalf("Scan2() error = %v", err)
	}

	if len(results2.MatchedRules) != 0 {
		t.Errorf("expected 0 matches (75%% of them, 2/3 = 66.7%%), got %d", len(results2.MatchedRules))
	}

	// Test 3: 100% of them — all 3 match
	ruleSource3 := `rule test_percent_100 {
		strings:
			$a = "hello"
			$b = "world"
			$c = "foo"
		condition:
			100 % of them
	}`

	compiler3 := NewCompiler()
	program3, err := compiler3.CompileSource(ruleSource3)
	if err != nil {
		t.Fatalf("CompileSource3() error = %v", err)
	}

	scanner3 := NewScanner(program3)
	results3, err := scanner3.Scan([]byte("hello world foo"))
	if err != nil {
		t.Fatalf("Scan3() error = %v", err)
	}

	if len(results3.MatchedRules) != 1 {
		t.Errorf("expected 1 match (100%% of them, 3/3 = 100%%), got %d", len(results3.MatchedRules))
	}
}

// TestOfFoundInEndToEnd tests "N of ($str*) in (min..max)" end-to-end
func TestOfFoundInEndToEnd(t *testing.T) {
	// Test 1: 2 of ($a, $b, $c) in (0..100) — $a at offset 0, $b at offset 6
	ruleSource1 := `rule test_of_in {
		strings:
			$a = "hello"
			$b = "world"
			$c = "notfound"
		condition:
			2 of ($a, $b, $c) in (0..100)
	}`

	compiler1 := NewCompiler()
	program1, err := compiler1.CompileSource(ruleSource1)
	if err != nil {
		t.Fatalf("CompileSource1() error = %v", err)
	}

	scanner1 := NewScanner(program1)
	results1, err := scanner1.Scan([]byte("hello world"))
	if err != nil {
		t.Fatalf("Scan1() error = %v", err)
	}

	if len(results1.MatchedRules) != 1 {
		t.Errorf("expected 1 match (2 of in range 0..100), got %d", len(results1.MatchedRules))
	}

	// Test 2: 2 of ($a, $b, $c) in (500..600) — no matches in range
	ruleSource2 := `rule test_of_in_no_match {
		strings:
			$a = "hello"
			$b = "world"
			$c = "notfound"
		condition:
			2 of ($a, $b, $c) in (500..600)
	}`

	compiler2 := NewCompiler()
	program2, err := compiler2.CompileSource(ruleSource2)
	if err != nil {
		t.Fatalf("CompileSource2() error = %v", err)
	}

	scanner2 := NewScanner(program2)
	results2, err := scanner2.Scan([]byte("hello world"))
	if err != nil {
		t.Fatalf("Scan2() error = %v", err)
	}

	if len(results2.MatchedRules) != 0 {
		t.Errorf("expected 0 matches (no strings in range 500..600), got %d", len(results2.MatchedRules))
	}
}

// TestCountInOfEndToEnd tests "#a in (min..max) of ($str*)" end-to-end.
// Semantics: at least #a strings from the set are found within offsets [min, max].
func TestCountInOfEndToEnd(t *testing.T) {
	// Test 1: #a in (1..3) of ($a, $b, $c) — $a and $b match at offsets 0 and 6.
	// #a = 1 ("hello" appears once). 1 >= 1 is true, and 2 strings are in range 0..100.
	ruleSource1 := `rule test_count_in_of {
		strings:
			$a = "hello"
			$b = "world"
			$c = "notfound"
		condition:
			#a in (1..3) of ($a, $b, $c)
	}`

	compiler1 := NewCompiler()
	program1, err := compiler1.CompileSource(ruleSource1)
	if err != nil {
		t.Fatalf("CompileSource1() error = %v", err)
	}

	scanner1 := NewScanner(program1)
	results1, err := scanner1.Scan([]byte("hello world"))
	if err != nil {
		t.Fatalf("Scan1() error = %v", err)
	}

	if len(results1.MatchedRules) != 1 {
		t.Errorf("expected 1 match (#a=1, 2 strings in range 0..100, 2 >= 1), got %d", len(results1.MatchedRules))
	}

	// Test 2: #a in (1..3) of them — same as above but with "them"
	ruleSource2 := `rule test_count_in_of_them {
		strings:
			$a = "hello"
			$b = "world"
			$c = "notfound"
		condition:
			#a in (1..3) of them
	}`

	compiler2 := NewCompiler()
	program2, err := compiler2.CompileSource(ruleSource2)
	if err != nil {
		t.Fatalf("CompileSource2() error = %v", err)
	}

	scanner2 := NewScanner(program2)
	results2, err := scanner2.Scan([]byte("hello world"))
	if err != nil {
		t.Fatalf("Scan2() error = %v", err)
	}

	if len(results2.MatchedRules) != 1 {
		t.Errorf("expected 1 match with 'them', got %d", len(results2.MatchedRules))
	}

	// Test 3: #a in (1..3) of ($a, $b, $c) — no strings in range 500..600
	ruleSource3 := `rule test_count_in_of_no_match {
		strings:
			$a = "hello"
			$b = "world"
			$c = "notfound"
		condition:
			#a in (1..3) of ($a, $b, $c) in (500..600)
	}`

	compiler3 := NewCompiler()
	program3, err := compiler3.CompileSource(ruleSource3)
	if err != nil {
		t.Fatalf("CompileSource3() error = %v", err)
	}

	scanner3 := NewScanner(program3)
	results3, err := scanner3.Scan([]byte("hello world"))
	if err != nil {
		t.Fatalf("Scan3() error = %v", err)
	}

	if len(results3.MatchedRules) != 0 {
		t.Errorf("expected 0 matches (no strings in range 500..600), got %d", len(results3.MatchedRules))
	}

	// Test 4: plain "#a in (min..max)" without "of" — should still work
	ruleSource4 := `rule test_count_in_plain {
		strings:
			$a = "hello"
		condition:
			#a in (1..10)
	}`

	compiler4 := NewCompiler()
	program4, err := compiler4.CompileSource(ruleSource4)
	if err != nil {
		t.Fatalf("CompileSource4() error = %v", err)
	}

	scanner4 := NewScanner(program4)
	results4, err := scanner4.Scan([]byte("hello hello"))
	if err != nil {
		t.Fatalf("Scan4() error = %v", err)
	}

	if len(results4.MatchedRules) != 1 {
		t.Errorf("expected 1 match (#a=2 in range 1..10), got %d", len(results4.MatchedRules))
	}
}

// TestOfFoundAtEndToEnd tests "N of ($str*) at offset" end-to-end
func TestOfFoundAtEndToEnd(t *testing.T) {
	// Test 1: 1 of ($a, $b, $c) at 0 — $a at offset 0
	ruleSource1 := `rule test_of_at {
		strings:
			$a = "hello"
			$b = "world"
			$c = "notfound"
		condition:
			1 of ($a, $b, $c) at 0
	}`

	compiler1 := NewCompiler()
	program1, err := compiler1.CompileSource(ruleSource1)
	if err != nil {
		t.Fatalf("CompileSource1() error = %v", err)
	}

	scanner1 := NewScanner(program1)
	results1, err := scanner1.Scan([]byte("hello world"))
	if err != nil {
		t.Fatalf("Scan1() error = %v", err)
	}

	if len(results1.MatchedRules) != 1 {
		t.Errorf("expected 1 match (1 of at offset 0), got %d", len(results1.MatchedRules))
	}

	// Test 2: 1 of ($a, $b, $c) at 50 — no matches at offset 50
	ruleSource2 := `rule test_of_at_no_match {
		strings:
			$a = "hello"
			$b = "world"
			$c = "notfound"
		condition:
			1 of ($a, $b, $c) at 50
	}`

	compiler2 := NewCompiler()
	program2, err := compiler2.CompileSource(ruleSource2)
	if err != nil {
		t.Fatalf("CompileSource2() error = %v", err)
	}

	scanner2 := NewScanner(program2)
	results2, err := scanner2.Scan([]byte("hello world"))
	if err != nil {
		t.Fatalf("Scan2() error = %v", err)
	}

	if len(results2.MatchedRules) != 0 {
		t.Errorf("expected 0 matches (no strings at offset 50), got %d", len(results2.MatchedRules))
	}
}

// TestForLoopInRangeEndToEnd tests "for any of ($str*) in (min..max) : ($"
func TestForLoopInRangeEndToEnd(t *testing.T) {
	// Test 1: for any of ($a, $b, $c) in (0..100) : ($)
	ruleSource1 := `rule test_for_in {
		strings:
			$a = "hello"
			$b = "world"
			$c = "notfound"
		condition:
			for any of ($a, $b, $c) in (0..100) : ($)
	}`

	compiler1 := NewCompiler()
	program1, err := compiler1.CompileSource(ruleSource1)
	if err != nil {
		t.Fatalf("CompileSource1() error = %v", err)
	}

	scanner1 := NewScanner(program1)
	results1, err := scanner1.Scan([]byte("hello world"))
	if err != nil {
		t.Fatalf("Scan1() error = %v", err)
	}

	if len(results1.MatchedRules) != 1 {
		t.Errorf("expected 1 match (for any in range 0..100), got %d", len(results1.MatchedRules))
	}

	// Test 2: for any of ($a, $b, $c) in (500..600) : ($)
	ruleSource2 := `rule test_for_in_no_match {
		strings:
			$a = "hello"
			$b = "world"
			$c = "notfound"
		condition:
			for any of ($a, $b, $c) in (500..600) : ($)
	}`

	compiler2 := NewCompiler()
	program2, err := compiler2.CompileSource(ruleSource2)
	if err != nil {
		t.Fatalf("CompileSource2() error = %v", err)
	}

	scanner2 := NewScanner(program2)
	results2, err := scanner2.Scan([]byte("hello world"))
	if err != nil {
		t.Fatalf("Scan2() error = %v", err)
	}

	if len(results2.MatchedRules) != 0 {
		t.Errorf("expected 0 matches (for any in range 500..600), got %d", len(results2.MatchedRules))
	}
}

// TestForLoopAtOffsetEndToEnd tests "for any of ($str*) at offset : ($"
func TestForLoopAtOffsetEndToEnd(t *testing.T) {
	// Test 1: for any of ($a, $b, $c) at 0 : ($)
	ruleSource1 := `rule test_for_at {
		strings:
			$a = "hello"
			$b = "world"
			$c = "notfound"
		condition:
			for any of ($a, $b, $c) at 0 : ($)
	}`

	compiler1 := NewCompiler()
	program1, err := compiler1.CompileSource(ruleSource1)
	if err != nil {
		t.Fatalf("CompileSource1() error = %v", err)
	}

	scanner1 := NewScanner(program1)
	results1, err := scanner1.Scan([]byte("hello world"))
	if err != nil {
		t.Fatalf("Scan1() error = %v", err)
	}

	if len(results1.MatchedRules) != 1 {
		t.Errorf("expected 1 match (for any at offset 0), got %d", len(results1.MatchedRules))
	}

	// Test 2: for any of ($a, $b, $c) at 50 : ($)
	ruleSource2 := `rule test_for_at_no_match {
		strings:
			$a = "hello"
			$b = "world"
			$c = "notfound"
		condition:
			for any of ($a, $b, $c) at 50 : ($)
	}`

	compiler2 := NewCompiler()
	program2, err := compiler2.CompileSource(ruleSource2)
	if err != nil {
		t.Fatalf("CompileSource2() error = %v", err)
	}

	scanner2 := NewScanner(program2)
	results2, err := scanner2.Scan([]byte("hello world"))
	if err != nil {
		t.Fatalf("Scan2() error = %v", err)
	}

	if len(results2.MatchedRules) != 0 {
		t.Errorf("expected 0 matches (for any at offset 50), got %d", len(results2.MatchedRules))
	}
}

// TestWildcardStringSetEndToEnd tests wildcard string sets like ($a*) in quantifier expressions.
func TestWildcardStringSetEndToEnd(t *testing.T) {
	// Test 1: any of ($a*)
	{
		src := `
rule test {
    strings:
        $a1 = "hello"
        $a2 = "world"
    condition:
        any of ($a*)
}`
		compiler := NewCompiler()
		program, err := compiler.CompileSource(src)
		if err != nil {
			t.Fatalf("CompileSource() error = %v", err)
		}
		scanner := NewScanner(program)
		results, err := scanner.Scan([]byte("hello world"))
		if err != nil {
			t.Fatalf("Scan() error = %v", err)
		}
		if len(results.MatchedRules) != 1 {
			t.Errorf("Test 1 (any of $a*): expected 1 match, got %d", len(results.MatchedRules))
		}
	}

	// Test 2: all of ($a*)
	{
		src := `
rule test {
    strings:
        $a1 = "hello"
        $a2 = "world"
    condition:
        all of ($a*)
}`
		compiler := NewCompiler()
		program, err := compiler.CompileSource(src)
		if err != nil {
			t.Fatalf("CompileSource() error = %v", err)
		}
		scanner := NewScanner(program)
		// Both match
		results, err := scanner.Scan([]byte("hello world"))
		if err != nil {
			t.Fatalf("Scan() error = %v", err)
		}
		if len(results.MatchedRules) != 1 {
			t.Errorf("Test 2 (all of $a*): expected 1 match, got %d", len(results.MatchedRules))
		}
		// Only one matches — should not satisfy "all"
		results, err = scanner.Scan([]byte("hello"))
		if err != nil {
			t.Fatalf("Scan() error = %v", err)
		}
		if len(results.MatchedRules) != 0 {
			t.Errorf("Test 2 (all of $a* partial): expected 0 matches, got %d", len(results.MatchedRules))
		}
	}

	// Test 3: #a in (1..3) of ($a*)
	{
		src := `
rule test {
    strings:
        $a1 = "hello"
        $a2 = "world"
        $a3 = "foo"
        $a4 = "bar"
    condition:
        #a in (1..3) of ($a*)
}`
		compiler := NewCompiler()
		program, err := compiler.CompileSource(src)
		if err != nil {
			t.Fatalf("CompileSource() error = %v", err)
		}
		scanner := NewScanner(program)
		// 2 strings match, in range (1..3)
		results, err := scanner.Scan([]byte("hello world"))
		if err != nil {
			t.Fatalf("Scan() error = %v", err)
		}
		if len(results.MatchedRules) != 1 {
			t.Errorf("Test 3 (count-in-range): expected 1 match (2 in 1..3), got %d", len(results.MatchedRules))
		}
		// 4 strings match, NOT in range (1..3)
		results, err = scanner.Scan([]byte("hello world foo bar"))
		if err != nil {
			t.Fatalf("Scan() error = %v", err)
		}
		if len(results.MatchedRules) != 0 {
			t.Errorf("Test 3 (count-in-range fail): expected 0 matches (4 not in 1..3), got %d", len(results.MatchedRules))
		}
	}

	// Test 4: 2 of ($a*)
	{
		src := `
rule test {
    strings:
        $a1 = "hello"
        $a2 = "world"
    condition:
        2 of ($a*)
}`
		compiler := NewCompiler()
		program, err := compiler.CompileSource(src)
		if err != nil {
			t.Fatalf("CompileSource() error = %v", err)
		}
		scanner := NewScanner(program)
		results, err := scanner.Scan([]byte("hello world"))
		if err != nil {
			t.Fatalf("Scan() error = %v", err)
		}
		if len(results.MatchedRules) != 1 {
			t.Errorf("Test 4 (2 of $a*): expected 1 match, got %d", len(results.MatchedRules))
		}
	}

	// Test 5: multiple wildcards in one rule
	{
		src := `
rule test {
    strings:
        $a1 = "hello"
        $a2 = "world"
        $b1 = "foo"
        $b2 = "bar"
    condition:
        any of ($a*) or any of ($b*)
}`
		compiler := NewCompiler()
		program, err := compiler.CompileSource(src)
		if err != nil {
			t.Fatalf("CompileSource() error = %v", err)
		}
		scanner := NewScanner(program)
		results, err := scanner.Scan([]byte("hello"))
		if err != nil {
			t.Fatalf("Scan() error = %v", err)
		}
		if len(results.MatchedRules) != 1 {
			t.Errorf("Test 5 (multiple wildcards): expected 1 match, got %d", len(results.MatchedRules))
		}
	}

	// Test 6: #a in (0..5) of ($a*) — 0 matches in range
	{
		src := `
rule test {
    strings:
        $a1 = "hello"
        $a2 = "world"
    condition:
        #a in (0..5) of ($a*)
}`
		compiler := NewCompiler()
		program, err := compiler.CompileSource(src)
		if err != nil {
			t.Fatalf("CompileSource() error = %v", err)
		}
		scanner := NewScanner(program)
		results, err := scanner.Scan([]byte("nothing here"))
		if err != nil {
			t.Fatalf("Scan() error = %v", err)
		}
		if len(results.MatchedRules) != 1 {
			t.Errorf("Test 6 (0 in range): expected 1 match (0 in 0..5), got %d", len(results.MatchedRules))
		}
	}
}

// TestLengthOfEndToEnd tests "length of" expressions in YARA conditions.
func TestLengthOfEndToEnd(t *testing.T) {
	// Test 1: length of ($a) with single match
	{
		src := `
rule test {
    strings:
        $a = "hello"
    condition:
        length of ($a) == 5
}`
		compiler := NewCompiler()
		program, err := compiler.CompileSource(src)
		if err != nil {
			t.Fatalf("Test 1 CompileSource() error = %v", err)
		}
		scanner := NewScanner(program)
		results, err := scanner.Scan([]byte("say hello world"))
		if err != nil {
			t.Fatalf("Test 1 Scan() error = %v", err)
		}
		if len(results.MatchedRules) != 1 {
			t.Errorf("Test 1: expected 1 match, got %d", len(results.MatchedRules))
		}
	}

	// Test 2: length of ($a) with multiple matches
	{
		src := `
rule test {
    strings:
        $a = "ab"
    condition:
        length of ($a) == 6
}`
		compiler := NewCompiler()
		program, err := compiler.CompileSource(src)
		if err != nil {
			t.Fatalf("Test 2 CompileSource() error = %v", err)
		}
		scanner := NewScanner(program)
		// "ab" appears 3 times = 6 bytes total
		results, err := scanner.Scan([]byte("ababab"))
		if err != nil {
			t.Fatalf("Test 2 Scan() error = %v", err)
		}
		if len(results.MatchedRules) != 1 {
			t.Errorf("Test 2: expected 1 match, got %d", len(results.MatchedRules))
		}
	}

	// Test 3: length of them
	{
		src := `
rule test {
    strings:
        $a = "hello"
        $b = "world"
    condition:
        length of them >= 10
}`
		compiler := NewCompiler()
		program, err := compiler.CompileSource(src)
		if err != nil {
			t.Fatalf("Test 3 CompileSource() error = %v", err)
		}
		scanner := NewScanner(program)
		results, err := scanner.Scan([]byte("hello world"))
		if err != nil {
			t.Fatalf("Test 3 Scan() error = %v", err)
		}
		if len(results.MatchedRules) != 1 {
			t.Errorf("Test 3: expected 1 match, got %d", len(results.MatchedRules))
		}
	}

	// Test 4: length of them with no matches
	{
		src := `
rule test {
    strings:
        $a = "hello"
        $b = "world"
    condition:
        length of them == 0
}`
		compiler := NewCompiler()
		program, err := compiler.CompileSource(src)
		if err != nil {
			t.Fatalf("Test 4 CompileSource() error = %v", err)
		}
		scanner := NewScanner(program)
		results, err := scanner.Scan([]byte("nothing here"))
		if err != nil {
			t.Fatalf("Test 4 Scan() error = %v", err)
		}
		if len(results.MatchedRules) != 1 {
			t.Errorf("Test 4: expected 1 match, got %d", len(results.MatchedRules))
		}
	}

	// Test 5: length of them*
	{
		src := `
rule test {
    strings:
        $a1 = "hi"
        $a2 = "bye"
    condition:
        length of ($a*) == 5
}`
		compiler := NewCompiler()
		program, err := compiler.CompileSource(src)
		if err != nil {
			t.Fatalf("Test 5 CompileSource() error = %v", err)
		}
		scanner := NewScanner(program)
		// "hi" (2) + "bye" (3) = 5
		results, err := scanner.Scan([]byte("hi bye"))
		if err != nil {
			t.Fatalf("Test 5 Scan() error = %v", err)
		}
		if len(results.MatchedRules) != 1 {
			t.Errorf("Test 5: expected 1 match, got %d", len(results.MatchedRules))
		}
	}

	// Test 6: length of ($a) with no match should be 0
	{
		src := `
rule test {
    strings:
        $a = "hello"
    condition:
        length of ($a) == 0
}`
		compiler := NewCompiler()
		program, err := compiler.CompileSource(src)
		if err != nil {
			t.Fatalf("Test 6 CompileSource() error = %v", err)
		}
		scanner := NewScanner(program)
		results, err := scanner.Scan([]byte("no match here"))
		if err != nil {
			t.Fatalf("Test 6 Scan() error = %v", err)
		}
		if len(results.MatchedRules) != 1 {
			t.Errorf("Test 6: expected 1 match, got %d", len(results.MatchedRules))
		}
	}
}

// TestForLoopStringSet tests for-loop iteration over string sets ($*, them, $a*)
func TestForLoopStringSet(t *testing.T) {
	// Test 1: for any s in ($*) : (s)
	{
		src := `
rule test {
    strings:
        $a = "hello"
        $b = "world"
    condition:
        for any s in ($*) : (
            s
        )
}`
		compiler := NewCompiler()
		program, err := compiler.CompileSource(src)
		if err != nil {
			t.Fatalf("Test 1 CompileSource() error = %v", err)
		}
		scanner := NewScanner(program)
		results, err := scanner.Scan([]byte("say hello world"))
		if err != nil {
			t.Fatalf("Test 1 Scan() error = %v", err)
		}
		if len(results.MatchedRules) != 1 {
			t.Errorf("Test 1: expected 1 match, got %d", len(results.MatchedRules))
		}
	}

	// Test 2: for any s in (them) : (s)
	{
		src := `
rule test {
    strings:
        $a = "hello"
        $b = "world"
    condition:
        for any s in (them) : (
            s
        )
}`
		compiler := NewCompiler()
		program, err := compiler.CompileSource(src)
		if err != nil {
			t.Fatalf("Test 2 CompileSource() error = %v", err)
		}
		scanner := NewScanner(program)
		results, err := scanner.Scan([]byte("say hello world"))
		if err != nil {
			t.Fatalf("Test 2 Scan() error = %v", err)
		}
		if len(results.MatchedRules) != 1 {
			t.Errorf("Test 2: expected 1 match, got %d", len(results.MatchedRules))
		}
	}

	// Test 3: for any s in ($a*) : (s) — wildcard prefix
	{
		src := `
rule test {
    strings:
        $a1 = "hello"
        $a2 = "world"
        $b1 = "foo"
    condition:
        for any s in ($a*) : (
            s
        )
}`
		compiler := NewCompiler()
		program, err := compiler.CompileSource(src)
		if err != nil {
			t.Fatalf("Test 3 CompileSource() error = %v", err)
		}
		scanner := NewScanner(program)
		results, err := scanner.Scan([]byte("say hello world"))
		if err != nil {
			t.Fatalf("Test 3 Scan() error = %v", err)
		}
		if len(results.MatchedRules) != 1 {
			t.Errorf("Test 3: expected 1 match, got %d", len(results.MatchedRules))
		}
		// Verify $b1 is not in the matched strings
		if _, hasB1 := results.MatchedRules[0].Matches["$b1"]; hasB1 {
			t.Errorf("Test 3: $b1 should not be in for-loop matches")
		}
	}

	// Test 4: for all s in ($*) : (s) — all must match
	{
		src := `
rule test {
    strings:
        $a = "hello"
        $b = "world"
    condition:
        for all s in ($*) : (
            s
        )
}`
		compiler := NewCompiler()
		program, err := compiler.CompileSource(src)
		if err != nil {
			t.Fatalf("Test 4 CompileSource() error = %v", err)
		}
		scanner := NewScanner(program)
		// Both present — should match
		results, err := scanner.Scan([]byte("say hello world"))
		if err != nil {
			t.Fatalf("Test 4 Scan() error = %v", err)
		}
		if len(results.MatchedRules) != 1 {
			t.Errorf("Test 4: expected 1 match, got %d", len(results.MatchedRules))
		}
	}

	// Test 5: for any s in ($a*) : (s) — wildcard with simple condition
	{
		src := `
rule test {
    strings:
        $a1 = "hello"
        $a2 = "world"
        $b1 = "foo"
    condition:
        for any s in ($a*) : (
            s
        )
}`
		compiler := NewCompiler()
		program, err := compiler.CompileSource(src)
		if err != nil {
			t.Fatalf("Test 5 CompileSource() error = %v", err)
		}
		scanner := NewScanner(program)
		results, err := scanner.Scan([]byte("say hello world"))
		if err != nil {
			t.Fatalf("Test 5 Scan() error = %v", err)
		}
		if len(results.MatchedRules) != 1 {
			t.Errorf("Test 5: expected 1 match, got %d", len(results.MatchedRules))
		}
	}
}
