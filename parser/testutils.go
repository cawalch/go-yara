package parser

import (
	"errors"
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/internal/lexer"
)

// ParseRuleString is a helper function that parses a single rule from a string
// This reduces boilerplate in test functions
func ParseRuleString(t *testing.T, source string) *ast.Rule {
	t.Helper()

	l := lexer.New(source)
	p := New(l)
	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("Failed to parse rule: %v", err)
	}

	if len(program.Rules) != 1 {
		t.Fatalf("Expected 1 rule, got %d", len(program.Rules))
	}

	return program.Rules[0]
}

// ParseRulesString is a helper function that parses multiple rules from a string
func ParseRulesString(t *testing.T, source string) *ast.Program {
	t.Helper()

	l := lexer.New(source)
	p := New(l)
	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("Failed to parse rules: %v", err)
	}

	return program
}

// ParseAndExpectError is a helper for testing error conditions
func ParseAndExpectError(t *testing.T, source string) error {
	t.Helper()

	l := lexer.New(source)
	p := New(l)
	_, err := p.ParseRules()
	return err
}

// ParseRuleStringWithErrors is a helper function that parses a rule and expects errors
// This is useful for testing error conditions
func ParseRuleStringWithErrors(t *testing.T, source string) (*ast.Rule, error) {
	t.Helper()

	l := lexer.New(source)
	p := New(l)
	program, err := p.ParseRules()
	if err != nil {
		return nil, err
	}

	if len(program.Rules) == 0 {
		return nil, errors.New("no rules found in source")
	}

	return program.Rules[0], nil
}

// CreateTestRule creates a minimal test rule with basic structure
// This reduces duplication when creating test rules
func CreateTestRule(name, stringID, pattern string) string {
	return `
rule ` + name + ` {
	strings:
		` + stringID + ` = "` + pattern + `"
	condition:
		` + stringID + `
}`
}

// CreateTestRuleWithCondition creates a test rule with a custom condition
func CreateTestRuleWithCondition(name, strings, condition string) string {
	return `
rule ` + name + ` {
	strings:
		` + strings + `
	condition:
		` + condition + `
}`
}

// TestRuleConfig holds configuration for creating test rules
type TestRuleConfig struct {
	Name      string
	Meta      string
	Strings   string
	Condition string
}

// CreateTestRuleWithMeta creates a test rule with meta section
func CreateTestRuleWithMeta(config TestRuleConfig) string {
	return `
rule ` + config.Name + ` {
	meta:
		` + config.Meta + `
	strings:
		` + config.Strings + `
	condition:
		` + config.Condition + `
}`
}

// AssertRuleCount asserts the expected number of rules in a program
func AssertRuleCount(t *testing.T, program *ast.Program, expected int) {
	t.Helper()

	if len(program.Rules) != expected {
		t.Errorf("Expected %d rules, got %d", expected, len(program.Rules))
	}
}

// AssertRuleName asserts that a rule has the expected name
func AssertRuleName(t *testing.T, rule *ast.Rule, expected string) {
	t.Helper()

	if rule.Name != expected {
		t.Errorf("Expected rule name '%s', got '%s'", expected, rule.Name)
	}
}

// AssertStringCount asserts the expected number of strings in a rule
func AssertStringCount(t *testing.T, rule *ast.Rule, expected int) {
	t.Helper()

	if len(rule.Strings) != expected {
		t.Errorf("Expected %d strings, got %d", expected, len(rule.Strings))
	}
}

// AssertMetaCount asserts the expected number of meta entries in a rule
func AssertMetaCount(t *testing.T, rule *ast.Rule, expected int) {
	t.Helper()

	if len(rule.Meta) != expected {
		t.Errorf("Expected %d meta entries, got %d", expected, len(rule.Meta))
	}
}

// AssertStringExists asserts that a string with the given identifier exists
func AssertStringExists(t *testing.T, rule *ast.Rule, identifier string) *ast.String {
	t.Helper()

	for _, str := range rule.Strings {
		if str.Identifier == identifier {
			return str
		}
	}

	t.Errorf("Expected string identifier '%s' not found", identifier)
	return nil
}

// AssertMetaExists asserts that a meta entry with the given key exists
func AssertMetaExists(t *testing.T, rule *ast.Rule, key string) *ast.Meta {
	t.Helper()

	for _, meta := range rule.Meta {
		if meta.Key == key {
			return meta
		}
	}

	t.Errorf("Expected meta key '%s' not found", key)
	return nil
}

// AssertStringValue asserts that a meta entry has the expected string value
func AssertStringValue(t *testing.T, meta *ast.Meta, expected string) {
	t.Helper()

	if meta.AsString() != expected {
		t.Errorf("Expected meta value '%s', got '%s'", expected, meta.AsString())
	}
}

// AssertIntValue asserts that a meta entry has the expected integer value
func AssertIntValue(t *testing.T, meta *ast.Meta, expected int64) {
	t.Helper()

	if meta.AsInt() != expected {
		t.Errorf("Expected meta value %d, got %d", expected, meta.AsInt())
	}
}

// AssertBoolValue asserts that a meta entry has the expected boolean value
func AssertBoolValue(t *testing.T, meta *ast.Meta, expected bool) {
	t.Helper()

	if meta.AsBool() != expected {
		t.Errorf("Expected meta value %t, got %t", expected, meta.AsBool())
	}
}
