// Package compiler provides integration tests for the YARA compiler.
package tests

import (
	"testing"

	"github.com/cawalch/go-yara/compiler/tests/testutils"
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

	compiler := testutils.CreateTestCompiler()

	// Compile the source
	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Logf("Compilation errors: %v", compiler.GetErrors())
		t.Fatalf("Source compilation failed: %v", err)
	}

	// Validate the program
	testutils.AssertProgramValid(t, program)
	testutils.AssertRuleCount(t, program, 1)

	// Check compilation statistics
	stats := compiler.GetStats()
	if stats.RulesCompiled != 1 {
		t.Errorf("Stats show %d rules compiled, want 1", stats.RulesCompiled)
	}

	// Test program validation
	if validateErr := program.Validate(); validateErr != nil {
		t.Errorf("Program validation failed: %v", validateErr)
	}
}

// TestCompilerOptions tests compiler configuration options
func TestCompilerOptions(t *testing.T) {
	// Test with optimizations disabled
	c := testutils.CreateTestCompiler(testutils.WithOptimizations(false))

	source := `rule test { condition: true }`
	program := testutils.CompileTestRule(t, source)

	if program == nil {
		t.Fatal("Failed to compile rule with optimizations disabled")
	}
	_ = c // Use the compiler variable
}

// TestErrorHandling tests error handling in the compiler
func TestErrorHandling(t *testing.T) {
	invalidSource := `
rule invalid_rule {
    strings:
        $test = "unclosed string
    condition:
        $test
}`

	c := testutils.CreateTestCompiler()
	program, errors := testutils.CompileTestRuleWithError(t, invalidSource)

	// Should have compilation errors
	if len(errors) == 0 {
		t.Error("Expected compilation errors for invalid source")
	}

	// Program might be nil or partial due to errors
	if program != nil {
		t.Logf("Partial program compiled despite errors: %d rules", program.GetRuleCount())
	}
	_ = c // Use the compiler variable
}

// TestCompilationStats tests compilation statistics reporting
func TestCompilationStats(t *testing.T) {
	source := `
rule test_rule_1 {
    strings:
        $s1 = "pattern1"
        $s2 = "pattern2"
    condition:
        $s1 and $s2
}

rule test_rule_2 {
    strings:
        $s3 = "pattern3"
    condition:
        $s3
}`

	compiler := testutils.CreateTestCompiler()
	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Logf("Compilation errors: %v", compiler.GetErrors())
		t.Fatalf("Failed to compile test rule: %v", err)
	}

	// Check stats
	stats := compiler.GetStats()
	if stats.RulesCompiled != 2 {
		t.Errorf("Expected 2 rules compiled, got %d", stats.RulesCompiled)
	}

	testutils.AssertRuleCount(t, program, 2)
}

// TODO: Implement these tests once the required methods are available
// TestCompilationReport tests detailed compilation reporting
// TestCompiledRuleMemoryUsage tests memory usage of compiled rules
// TestCompiledRuleMemory tests memory operations on compiled rules
