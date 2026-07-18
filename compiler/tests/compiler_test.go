package tests

import (
	"context"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/compiler"
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

	compiler := createTestCompiler()

	// Compile the source
	program, err := compiler.CompileSourceWithContext(context.Background(), source)
	if err != nil {
		t.Logf("Compilation errors: %v", compiler.GetErrors())
		t.Fatalf("Source compilation failed: %v", err)
	}

	// Validate the program
	assertProgramValid(t, program)
	assertRuleCount(t, program, 1)

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

// TestErrorHandling tests error handling in the compiler
func TestErrorHandling(t *testing.T) {
	invalidSource := `
rule invalid_rule {
    strings:
        $test = "unclosed string
    condition:
        $test
}`

	c := createTestCompiler()
	program, errors := compileTestRuleWithError(t, invalidSource)

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

	compiler := createTestCompiler()
	program, err := compiler.CompileSourceWithContext(context.Background(), source)
	if err != nil {
		t.Logf("Compilation errors: %v", compiler.GetErrors())
		t.Fatalf("Failed to compile test rule: %v", err)
	}

	// Check stats
	stats := compiler.GetStats()
	if stats.RulesCompiled != 2 {
		t.Errorf("Expected 2 rules compiled, got %d", stats.RulesCompiled)
	}

	assertRuleCount(t, program, 2)
}

// TestCompilationReport tests detailed compilation reporting
func TestCompilationReport(t *testing.T) {
	source := `
		rule TestRule1 {
			strings:
				$text1 = "test string"
			condition:
				$text1
		}

		rule TestRule2 {
			condition:
				true
		}
	`

	testCompiler := compiler.NewCompiler()
	_, err := testCompiler.CompileSourceWithContext(context.Background(), source)
	if err != nil {
		t.Fatalf("Failed to compile source: %v", err)
	}

	// Test compilation report generation
	report := testCompiler.GetCompilationReport()
	if report == "" {
		t.Error("Expected non-empty compilation report")
	}

	// Verify report contains expected sections
	expectedSections := []string{
		"Go-YARA Compilation Report",
		"Options:",
		"Timing:",
		"Results:",
		"Rules Compiled:",
	}

	for _, section := range expectedSections {
		if !strings.Contains(report, section) {
			t.Errorf("Expected compilation report to contain '%s', but it doesn't", section)
		}
	}

	// Test report contains timing information
	if !strings.Contains(report, "Total:") {
		t.Error("Expected compilation report to contain total timing information")
	}

	// Test report contains rule compilation count
	if !strings.Contains(report, "2") {
		t.Error("Expected compilation report to indicate 2 rules were compiled")
	}

	// Test report with warnings enabled
	compilerWithWarnings := compiler.NewCompiler(
		compiler.WithWarnings(true),
	)

	sourceWithUnused := `
		rule TestRule {
			strings:
				$unused = "test"
			condition:
				true
		}
	`

	_, err = compilerWithWarnings.CompileSourceWithContext(context.Background(), sourceWithUnused)
	if err != nil {
		t.Fatalf("Failed to compile source with warnings: %v", err)
	}

	reportWithWarnings := compilerWithWarnings.GetCompilationReport()
	if !strings.Contains(reportWithWarnings, "Warnings") {
		t.Error("Expected report to contain warnings section when warnings are enabled")
	}
}

// TestCompiledRuleMemoryUsage tests memory usage of compiled rules
func TestCompiledRuleMemoryUsage(t *testing.T) {
	// Test with a simple rule
	source := `
		rule SimpleRule {
			strings:
				$text = "hello world"
				$hex = { 48 65 6c 6c 6f }
			condition:
				$text and $hex
		}
	`

	program := compileTestRule(t, source)
	rule := program.Rules[0]

	// Test memory usage estimation
	memoryUsage := rule.GetMemoryUsage()
	if memoryUsage <= 0 {
		t.Errorf("Expected positive memory usage, got %d", memoryUsage)
	}

	// Test memory usage increases with more complex rules
	complexSource := `
		rule ComplexRule {
			strings:
				$text1 = "pattern1"
				$text2 = "pattern2"
				$text3 = "pattern3"
				$text4 = "pattern4"
				$text5 = "pattern5"
				$hex1 = { 01 02 03 04 }
				$hex2 = { 05 06 07 08 }
				$regex1 = /test.*pattern/
				$regex2 = /another.*regex/
			condition:
				$text1 and $text2 and $text3 and $text4 and $text5 and
				$hex1 and $hex2 and $regex1 and $regex2
		}
	`

	complexProgram := compileTestRule(t, complexSource)
	complexRule := complexProgram.Rules[0]

	complexMemoryUsage := complexRule.GetMemoryUsage()
	if complexMemoryUsage <= memoryUsage {
		t.Errorf("Expected complex rule to use more memory than simple rule, got %d <= %d",
			complexMemoryUsage, memoryUsage)
	}

	// Test rule with no strings
	noStringSource := `
		rule EmptyRule {
			condition:
				true
		}
	`

	noStringProgram := compileTestRule(t, noStringSource)
	noStringRule := noStringProgram.Rules[0]

	noStringMemoryUsage := noStringRule.GetMemoryUsage()
	if noStringMemoryUsage <= 0 {
		t.Errorf("Expected positive memory usage even for rule with no strings, got %d", noStringMemoryUsage)
	}

	// Test that empty rule uses less memory than rule with strings
	if noStringMemoryUsage >= memoryUsage {
		t.Errorf("Expected empty rule to use less memory than rule with strings, got %d >= %d",
			noStringMemoryUsage, memoryUsage)
	}
}

// TestCompiledProgramMemoryUsage tests memory operations on compiled rules
func TestCompiledProgramMemoryUsage(t *testing.T) {
	// Test with multiple rules
	source := `
		rule Rule1 {
			strings:
				$a = "test1"
			condition:
				$a
		}

		rule Rule2 {
			strings:
				$b = "test2"
				$c = "test3"
			condition:
				$b and $c
		}

		rule Rule3 {
			condition:
				true
		}
	`

	program := compileTestRule(t, source)

	// Test total memory usage
	totalMemoryUsage := program.GetTotalMemoryUsage()
	if totalMemoryUsage <= 0 {
		t.Errorf("Expected positive total memory usage, got %d", totalMemoryUsage)
	}

	// Verify memory usage is sum of individual rules
	expectedTotal := 0
	for _, rule := range program.Rules {
		expectedTotal += rule.GetMemoryUsage()
	}

	if totalMemoryUsage != expectedTotal {
		t.Errorf("Expected total memory usage %d, got %d", expectedTotal, totalMemoryUsage)
	}

	// Test with more rules to verify scaling
	baselineSource := `
		rule BaseRule1 { condition: true }
		rule BaseRule2 { condition: true }
		rule BaseRule3 { condition: true }
	`
	baselineProgram := compileTestRule(t, baselineSource)
	baselineMemoryUsage := baselineProgram.GetTotalMemoryUsage()

	multiRuleSource := `
		rule Rule1 { condition: true }
		rule Rule2 { condition: true }
		rule Rule3 { condition: true }
		rule Rule4 { condition: true }
		rule Rule5 { condition: true }
		rule Rule6 { condition: true }
		rule Rule7 { condition: true }
		rule Rule8 { condition: true }
		rule Rule9 { condition: true }
		rule Rule10 { condition: true }
	`

	multiRuleProgram := compileTestRule(t, multiRuleSource)
	multiRuleMemoryUsage := multiRuleProgram.GetTotalMemoryUsage()

	if multiRuleMemoryUsage <= baselineMemoryUsage {
		t.Errorf("Expected program with 10 rules to use more memory than program with 3 rules, got %d <= %d",
			multiRuleMemoryUsage, baselineMemoryUsage)
	}

	// Test that memory usage scales with number of rules
	ruleCount := len(multiRuleProgram.Rules)
	if ruleCount != 10 {
		t.Errorf("Expected 10 rules in multi-rule program, got %d", ruleCount)
	}

	// Verify memory usage increases with each additional rule
	if len(baselineProgram.Rules) >= 2 {
		singleRuleMemoryUsage := baselineProgram.Rules[0].GetMemoryUsage()
		averagePerRule := float64(multiRuleMemoryUsage) / float64(ruleCount)

		if float64(singleRuleMemoryUsage) > averagePerRule*2 {
			t.Errorf("Memory usage should scale reasonably. Single rule: %d, Average: %f",
				singleRuleMemoryUsage, averagePerRule)
		}
	}
}
