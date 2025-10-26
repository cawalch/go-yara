// Package compiler provides tests for rule compilation
package compiler

import (
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

// TestRuleCompiler tests the rule compilation system
func TestRuleCompiler(t *testing.T) {
	rc := NewRuleCompiler()

	// Create a simple test rule
	rule := &ast.Rule{
		Pos:  token.Position{Line: 1, Column: 1},
		Name: "test_rule",
		Strings: []*ast.String{
			{
				Pos:        token.Position{Line: 2, Column: 1},
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

// TestRuleCompilerBasic tests basic rule compilation scenarios
func TestRuleCompilerBasic(t *testing.T) {
	rc := NewRuleCompiler()

	tests := []struct {
		name string
		rule *ast.Rule
	}{
		{
			name: "rule with single string",
			rule: &ast.Rule{
				Pos:  token.Position{Line: 1, Column: 1},
				Name: "single_string_rule",
				Strings: []*ast.String{
					{
						Pos:        token.Position{Line: 2, Column: 1},
						Identifier: "$text",
						Pattern: &ast.TextString{
							Pos:   token.Position{Line: 2, Column: 8},
							Value: "test",
						},
						Modifiers: []ast.StringModifier{},
					},
				},
				Condition: &ast.Literal{
					Pos:   token.Position{Line: 3, Column: 1},
					Type:  token.TRUE,
					Value: true,
				},
			},
		},
		{
			name: "rule with multiple strings",
			rule: &ast.Rule{
				Pos:  token.Position{Line: 1, Column: 1},
				Name: "multi_string_rule",
				Strings: []*ast.String{
					{
						Pos:        token.Position{Line: 2, Column: 1},
						Identifier: "$s1",
						Pattern: &ast.TextString{
							Pos:   token.Position{Line: 2, Column: 5},
							Value: "hello",
						},
						Modifiers: []ast.StringModifier{},
					},
					{
						Pos:        token.Position{Line: 3, Column: 1},
						Identifier: "$s2",
						Pattern: &ast.TextString{
							Pos:   token.Position{Line: 3, Column: 5},
							Value: "world",
						},
						Modifiers: []ast.StringModifier{},
					},
				},
				Condition: &ast.Literal{
					Pos:   token.Position{Line: 4, Column: 1},
					Type:  token.TRUE,
					Value: true,
				},
			},
		},
		{
			name: "rule with hex string",
			rule: &ast.Rule{
				Pos:  token.Position{Line: 1, Column: 1},
				Name: "hex_string_rule",
				Strings: []*ast.String{
					{
						Pos:        token.Position{Line: 2, Column: 1},
						Identifier: "$hex",
						Pattern: &ast.HexString{
							Pos:   token.Position{Line: 2, Column: 6},
							Value: "48656c6c6f",
						},
						Modifiers: []ast.StringModifier{},
					},
				},
				Condition: &ast.Literal{
					Pos:   token.Position{Line: 3, Column: 1},
					Type:  token.TRUE,
					Value: true,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			compiledRule, err := rc.CompileRule(test.rule)
			if err != nil {
				t.Errorf("Failed to compile rule %s: %v", test.name, err)
			}

			if compiledRule == nil {
				t.Fatalf("Compiled rule is nil for %s", test.name)
			}

			if compiledRule.Name != test.rule.Name {
				t.Errorf("Rule name = %v, want %v", compiledRule.Name, test.rule.Name)
			}

			if len(compiledRule.Bytecode) == 0 {
				t.Errorf("Compiled rule has empty bytecode for %s", test.name)
			}

			err = compiledRule.Validate()
			if err != nil {
				t.Errorf("Rule validation failed for %s: %v", test.name, err)
			}
		})
	}
}
