package compiler

import (
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

// ruleCompilerTestCase represents a single rule compilation test case
type ruleCompilerTestCase struct {
	name string
	rule *ast.Rule
}

// createTestRule creates a basic test rule for compilation testing
func createTestRule(name, identifier, value string) *ast.Rule {
	return &ast.Rule{
		Pos:  token.Position{Line: 1, Column: 1},
		Name: name,
		Strings: []*ast.String{
			{
				Pos:        token.Position{Line: 2, Column: 1},
				Identifier: identifier,
				Pattern: &ast.TextString{
					Pos:   token.Position{Line: 2, Column: 5},
					Value: value,
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
}

// assertCompiledRule validates that a rule was compiled correctly
func assertCompiledRule(t *testing.T, compiledRule *CompiledRule, expectedName string) {
	if compiledRule == nil {
		t.Fatal("Compiled rule is nil")
		return
	}

	if compiledRule.Name != expectedName {
		t.Errorf("Rule name = %v, want %v", compiledRule.Name, expectedName)
	}

	if len(compiledRule.Bytecode) == 0 {
		t.Error("Compiled rule has empty bytecode")
	}

	err := compiledRule.Validate()
	if err != nil {
		t.Errorf("Rule validation failed: %v", err)
	}
}

// compileAndAssertRule compiles a rule and validates the result
func compileAndAssertRule(t *testing.T, rc *RuleCompiler, rule *ast.Rule) *CompiledRule {
	compiledRule, err := rc.CompileRule(rule)
	if err != nil {
		t.Errorf("Failed to compile rule %s: %v", rule.Name, err)
		return nil
	}

	assertCompiledRule(t, compiledRule, rule.Name)
	return compiledRule
}

// runRuleCompilerTests runs multiple rule compilation test cases
func runRuleCompilerTests(t *testing.T, tests []ruleCompilerTestCase) {
	rc := NewRuleCompiler()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			compileAndAssertRule(t, rc, test.rule)
		})
	}
}

// TestRuleCompiler tests the rule compilation system
func TestRuleCompiler(t *testing.T) {
	rc := NewRuleCompiler()

	// Create a simple test rule
	rule := createTestRule("test_rule", "$s1", "test string")

	// Compile the rule
	compiledRule, err := rc.CompileRule(rule)
	if err != nil {
		t.Errorf("Rule compilation failed: %v", err)
	}

	// Validate the compiled rule
	assertCompiledRule(t, compiledRule, "test_rule")
}

// createMultiStringRule creates a rule with multiple strings for testing
func createMultiStringRule(name string, strings []*ast.String) *ast.Rule {
	return &ast.Rule{
		Pos:     token.Position{Line: 1, Column: 1},
		Name:    name,
		Strings: strings,
		Condition: &ast.Literal{
			Pos:   token.Position{Line: 4, Column: 1},
			Type:  token.TRUE,
			Value: true,
		},
	}
}

// createTextString creates a text string pattern for testing
func createTextString(line int, identifier, value string) *ast.String {
	return &ast.String{
		Pos:        token.Position{Line: line, Column: 1},
		Identifier: identifier,
		Pattern: &ast.TextString{
			Pos:   token.Position{Line: line, Column: len(identifier) + 4},
			Value: value,
		},
		Modifiers: []ast.StringModifier{},
	}
}

// createHexString creates a hex string pattern for testing
func createHexString(line int, identifier, value string) *ast.String {
	return &ast.String{
		Pos:        token.Position{Line: line, Column: 1},
		Identifier: identifier,
		Pattern: &ast.HexString{
			Pos:   token.Position{Line: line, Column: len(identifier) + 4},
			Value: value,
		},
		Modifiers: []ast.StringModifier{},
	}
}

// TestRuleCompilerBasic tests basic rule compilation scenarios
func TestRuleCompilerBasic(t *testing.T) {
	tests := []ruleCompilerTestCase{
		{
			name: "rule with single string",
			rule: createTestRule("single_string_rule", "$text", "test"),
		},
		{
			name: "rule with multiple strings",
			rule: createMultiStringRule("multi_string_rule", []*ast.String{
				createTextString(2, "$s1", "hello"),
				createTextString(3, "$s2", "world"),
			}),
		},
		{
			name: "rule with hex string",
			rule: createMultiStringRule("hex_string_rule", []*ast.String{
				createHexString(2, "$hex", "48656c6c6f"),
			}),
		},
	}

	runRuleCompilerTests(t, tests)
}
