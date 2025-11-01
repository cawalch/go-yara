package tests

import (
	"testing"

	"github.com/cawalch/go-yara/compiler"
	"github.com/cawalch/go-yara/compiler/tests/testutils"
)

// TestRuleCompilerIntegration tests rule compiler integration
func TestRuleCompilerIntegration(t *testing.T) {
	rc := compiler.NewRuleCompiler()

	// Create a test AST node
	testAST := testutils.CreateTestAST()

	// Compile the rule
	compiledRule, err := rc.CompileRule(testAST.Rules[0])
	if err != nil {
		t.Fatalf("Failed to compile rule: %v", err)
	}

	if compiledRule == nil {
		t.Fatal("Compiled rule is nil")
	}

	// Validate compiled rule properties
	if compiledRule.Name == "" {
		t.Error("Compiled rule should have a name")
	}

	// TODO: Add string access methods to CompiledRule
	// if len(compiledRule.Strings) == 0 {
	//     t.Error("Compiled rule should have compiled strings")
	// }

	if compiledRule.Bytecode == nil {
		t.Error("Compiled rule should have bytecode")
	}
	_ = rc // Use the compiler variable
}

// TestRuleCompilerMultipleStrings tests compilation of rules with multiple strings
func TestRuleCompilerMultipleStrings(t *testing.T) {
	// Create a rule with multiple strings
	source := `
rule multi_string_test {
    strings:
        $s1 = "string1"
        $s2 = "string2"
        $s3 = "string3"
        $hex1 = { 48 65 6c 6c 6f }
        $regex1 = /test.*pattern/
    condition:
        $s1 and $s2 and $s3 and $hex1 and $regex1
}`

	c := testutils.CreateTestCompiler()
	program := testutils.CompileTestRule(t, source)

	// TODO: Add string access methods to CompiledProgram
	// Verify we have the expected number of compiled strings
	// if program.GetStringCount() != 5 {
	//     t.Errorf("Expected 5 compiled strings, got %d", program.GetStringCount())
	// }

	// For now, just verify compilation succeeded
	testutils.AssertProgramValid(t, program)
	testutils.AssertRuleCount(t, program, 1)
	_ = c // Use the compiler variable
}

// TestRuleCompilerNoStrings tests compilation of rules without strings
func TestRuleCompilerNoStrings(t *testing.T) {
	// Create a rule without strings (meta only)
	source := `
rule no_strings_test {
    meta:
        author = "test"
        description = "rule with no strings"
    condition:
        true
}`

	c := testutils.CreateTestCompiler()
	program := testutils.CompileTestRule(t, source)

	// But we should still have a valid rule
	testutils.AssertProgramValid(t, program)
	testutils.AssertRuleCount(t, program, 1)
	_ = c // Use the compiler variable
}

// TODO: Implement single string compilation tests once methods are available
// TestRuleCompilerCompileSingleString tests compilation of single string rules

// TODO: Implement complex condition tests
// TestRuleCompilerComplexConditions tests compilation of rules with complex conditions

// TODO: Implement remaining rule compiler tests once required methods are available
// TestRuleCompilerModifiers tests various string modifiers
// TestRuleCompilerMetaInfo tests meta information compilation
// TestRuleCompilerErrorHandling tests error handling in rule compilation
