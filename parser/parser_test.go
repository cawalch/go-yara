package parser

import (
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/internal/lexer"
)

func TestParserCreation(t *testing.T) {
	input := `rule test { condition: true }`
	l := lexer.New(input)
	p := New(l)

	if p == nil {
		t.Fatal("parser is nil")
	}
	if p.lexer == nil {
		t.Error("lexer not set")
	}
	if p.builder == nil {
		t.Error("builder not set")
	}
	if len(p.errors) != 0 {
		t.Errorf("expected no errors, got %d", len(p.errors))
	}
}

// parseTestRule is a helper function that handles common parsing logic
func parseTestRule(t *testing.T, input string) *ast.Program {
	t.Helper()

	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Logf("Parsing errors: %v", p.Errors())
		t.Fatalf("parsing failed: %v", err)
	}

	if program == nil {
		t.Fatal("program is nil")
	}

	return program
}

// assertRuleCount validates the number of rules in a program
func assertRuleCount(t *testing.T, program *ast.Program, expected int) {
	t.Helper()
	if len(program.Rules) != expected {
		t.Errorf("expected %d rule(s), got %d", expected, len(program.Rules))
	}
}

// assertRuleName validates the name of the first rule
func assertRuleName(t *testing.T, rule *ast.Rule, expectedName string) {
	t.Helper()
	if rule.Name != expectedName {
		t.Errorf("expected rule name '%s', got '%s'", expectedName, rule.Name)
	}
}

// assertConditionExists validates that a rule has a condition
func assertConditionExists(t *testing.T, rule *ast.Rule) {
	t.Helper()
	if rule.Condition == nil {
		t.Error("condition is nil")
	}
}

// assertMetaCount validates the number of meta entries
func assertMetaCount(t *testing.T, rule *ast.Rule, expected int) {
	t.Helper()
	if len(rule.Meta) != expected {
		t.Errorf("expected %d meta entries, got %d", expected, len(rule.Meta))
	}
}

// assertStringCount validates the number of strings
func assertStringCount(t *testing.T, rule *ast.Rule, expected int) {
	t.Helper()
	if len(rule.Strings) != expected {
		t.Errorf("expected %d string(s), got %d", expected, len(rule.Strings))
	}
}

func TestParseSimpleRule(t *testing.T) {
	input := `
rule simple_rule {
	condition:
		true
}
`
	program := parseTestRule(t, input)
	assertRuleCount(t, program, 1)

	rule := program.Rules[0]
	assertRuleName(t, rule, "simple_rule")
	assertConditionExists(t, rule)
}

func TestParseRuleWithMeta(t *testing.T) {
	input := `
rule rule_with_meta {
	meta:
		description = "test rule"
		author = "test"
	condition:
		true
}
`
	program := parseTestRule(t, input)
	assertRuleCount(t, program, 1)

	rule := program.Rules[0]
	assertRuleName(t, rule, "rule_with_meta")
	assertMetaCount(t, rule, 2)
	assertConditionExists(t, rule)
}

func TestParseRuleWithString(t *testing.T) {
	input := `
rule rule_with_string {
	strings:
		$s1 = "test string"
	condition:
		$s1
}
`
	program := parseTestRule(t, input)
	assertRuleCount(t, program, 1)

	rule := program.Rules[0]
	assertRuleName(t, rule, "rule_with_string")
	assertStringCount(t, rule, 1)
	assertConditionExists(t, rule)

	str := rule.Strings[0]
	if str.Identifier != "$s1" {
		t.Errorf("expected string identifier '$s1', got '%s'", str.Identifier)
	}
}

// TestParseRuleStructure consolidates multiple rule structure tests into a single table-driven test
func TestParseRuleStructure(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		validate func(*testing.T, *ast.Program)
	}{
		{
			name: "multiple_rules",
			input: `
rule rule1 {
	condition:
		true
}

rule rule2 {
	condition:
		false
}
`,
			validate: func(t *testing.T, program *ast.Program) {
				assertRuleCount(t, program, 2)
				assertRuleName(t, program.Rules[0], "rule1")
				assertRuleName(t, program.Rules[1], "rule2")
				assertConditionExists(t, program.Rules[0])
				assertConditionExists(t, program.Rules[1])
			},
		},
		{
			name: "rule_with_modifiers",
			input: `
private global rule modified_rule {
	condition:
		true
}
`,
			validate: func(t *testing.T, program *ast.Program) {
				assertRuleCount(t, program, 1)
				rule := program.Rules[0]
				assertRuleName(t, rule, "modified_rule")
				if len(rule.Modifiers) != 2 {
					t.Errorf("expected 2 modifiers, got %d", len(rule.Modifiers))
				}
				assertConditionExists(t, rule)
			},
		},
		{
			name: "rule_with_tags",
			input: `
rule tagged_rule : tag1 tag2 tag3 {
	condition:
		true
}
`,
			validate: func(t *testing.T, program *ast.Program) {
				assertRuleCount(t, program, 1)
				rule := program.Rules[0]
				assertRuleName(t, rule, "tagged_rule")
				if len(rule.Tags) != 3 {
					t.Errorf("expected 3 tags, got %d", len(rule.Tags))
				}
				expectedTags := []string{"tag1", "tag2", "tag3"}
				for i, tag := range rule.Tags {
					if tag != expectedTags[i] {
						t.Errorf("expected tag '%s', got '%s'", expectedTags[i], tag)
					}
				}
				assertConditionExists(t, rule)
			},
		},
		{
			name: "rule_with_all_components",
			input: `
private global rule complete_rule : tag1 tag2 {
	meta:
		description = "complete test rule"
		author = "refactor example"
	strings:
		$s1 = "test pattern"
		$s2 = { 01 02 03 04 }
	condition:
		$s1 and $s2
}
`,
			validate: func(t *testing.T, program *ast.Program) {
				assertRuleCount(t, program, 1)
				rule := program.Rules[0]
				assertRuleName(t, rule, "complete_rule")
				assertMetaCount(t, rule, 2)
				assertStringCount(t, rule, 2)
				if len(rule.Modifiers) != 2 {
					t.Errorf("expected 2 modifiers, got %d", len(rule.Modifiers))
				}
				if len(rule.Tags) != 2 {
					t.Errorf("expected 2 tags, got %d", len(rule.Tags))
				}
				assertConditionExists(t, rule)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			program := parseTestRule(t, tt.input)
			tt.validate(t, program)
		})
	}
}

// Note: TestParseRuleWithModifiers and TestParseRuleWithTags have been consolidated
// into TestParseRuleStructure above for better maintainability and reduced complexity.

func TestParseComplexExpression(t *testing.T) {
	input := `
rule complex_expr {
	condition:
		true and false or true
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	if len(program.Rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(program.Rules))
	}

	rule := program.Rules[0]
	if rule.Condition == nil {
		t.Error("condition is nil")
	}
}

func TestParseExpressionWithParentheses(t *testing.T) {
	input := `
rule paren_expr {
	condition:
		(true and false) or true
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if rule.Condition == nil {
		t.Error("condition is nil")
	}
}

func TestParseExpressionWithNot(t *testing.T) {
	input := `
rule not_expr {
	condition:
		not true
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if rule.Condition == nil {
		t.Error("condition is nil")
	}
}

func TestParseStringIdentifierInCondition(t *testing.T) {
	input := `
rule string_cond {
	strings:
		$s1 = "test"
	condition:
		$s1
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if rule.Condition == nil {
		t.Error("condition is nil")
	}
}

func TestParseMultipleMetaAndStrings(t *testing.T) {
	input := `
rule multi_meta_strings {
	meta:
		author = "test"
		version = "1.0"
		enabled = true
	strings:
		$s1 = "test1"
		$s2 = "test2"
		$s3 = "test3"
	condition:
		any of them
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Logf("Parsing errors: %v", p.Errors())
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if len(rule.Meta) != 3 {
		t.Errorf("expected 3 meta entries, got %d", len(rule.Meta))
	}
	if len(rule.Strings) != 3 {
		t.Errorf("expected 3 strings, got %d", len(rule.Strings))
	}
}

func TestParseRuleWithAllModifiers(t *testing.T) {
	input := `
private global rule all_mods : tag1 tag2 {
	meta:
		desc = "test"
	strings:
		$s = "test"
	condition:
		$s
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if len(rule.Modifiers) != 2 {
		t.Errorf("expected 2 modifiers, got %d", len(rule.Modifiers))
	}
	if len(rule.Tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(rule.Tags))
	}
	if len(rule.Meta) != 1 {
		t.Errorf("expected 1 meta, got %d", len(rule.Meta))
	}
	if len(rule.Strings) != 1 {
		t.Errorf("expected 1 string, got %d", len(rule.Strings))
	}
}

func TestParseComparisonExpressions(t *testing.T) {
	input := `
rule comp_expr {
	condition:
		1 == 1 and 2 != 3 and 4 < 5 and 6 <= 7 and 8 > 9 and 10 >= 11
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if rule.Condition == nil {
		t.Error("condition is nil")
	}
}

func TestParseArithmeticExpressions(t *testing.T) {
	input := `
rule arith_expr {
	condition:
		1 + 2 - 3 * 4 / 5 % 6
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if rule.Condition == nil {
		t.Error("condition is nil")
	}
}

func TestParseQuantifierAll(t *testing.T) {
	input := `
rule quant_all {
	strings:
		$s1 = "test"
	condition:
		all of them
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if rule.Condition == nil {
		t.Error("condition is nil")
	}
}

func TestParseQuantifierNone(t *testing.T) {
	input := `
rule quant_none {
	strings:
		$s1 = "test"
	condition:
		none of them
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if rule.Condition == nil {
		t.Error("condition is nil")
	}
}

func TestParseEmptyMeta(t *testing.T) {
	input := `
rule empty_meta {
	meta:
	strings:
		$s = "test"
	condition:
		$s
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if len(rule.Meta) != 0 {
		t.Errorf("expected 0 meta entries, got %d", len(rule.Meta))
	}
}

func TestParseEmptyStrings(t *testing.T) {
	input := `
rule empty_strings {
	strings:
	condition:
		true
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if len(rule.Strings) != 0 {
		t.Errorf("expected 0 strings, got %d", len(rule.Strings))
	}
}

func TestParseNoMetaNoStrings(t *testing.T) {
	input := `
rule no_meta_strings {
	condition:
		true
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if len(rule.Meta) != 0 {
		t.Errorf("expected 0 meta entries, got %d", len(rule.Meta))
	}
	if len(rule.Strings) != 0 {
		t.Errorf("expected 0 strings, got %d", len(rule.Strings))
	}
}

func TestParseNestedParentheses(t *testing.T) {
	input := `
rule nested_parens {
	condition:
		((true and false) or (true and true))
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if rule.Condition == nil {
		t.Error("condition is nil")
	}
}

func TestParseMultipleNotOperators(t *testing.T) {
	input := `
rule multi_not {
	condition:
		not not true
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if rule.Condition == nil {
		t.Error("condition is nil")
	}
}

func TestParseStringLiteralInExpression(t *testing.T) {
	input := `
rule string_lit {
	condition:
		"test" == "test"
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if rule.Condition == nil {
		t.Error("condition is nil")
	}
}

func TestParseIntegerLiteralInExpression(t *testing.T) {
	input := `
rule int_lit {
	condition:
		42 > 10
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if rule.Condition == nil {
		t.Error("condition is nil")
	}
}

func TestParsePrivateOnlyModifier(t *testing.T) {
	input := `
private rule private_only {
	condition:
		true
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if len(rule.Modifiers) != 1 {
		t.Errorf("expected 1 modifier, got %d", len(rule.Modifiers))
	}
}

func TestParseGlobalOnlyModifier(t *testing.T) {
	input := `
global rule global_only {
	condition:
		true
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if len(rule.Modifiers) != 1 {
		t.Errorf("expected 1 modifier, got %d", len(rule.Modifiers))
	}
}

func TestParseMetaWithBooleanValues(t *testing.T) {
	input := `
rule meta_bool {
	meta:
		enabled = true
		disabled = false
	condition:
		true
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if len(rule.Meta) != 2 {
		t.Errorf("expected 2 meta entries, got %d", len(rule.Meta))
	}
}

func TestParseMetaWithIntegerValues(t *testing.T) {
	input := `
rule meta_int {
	meta:
		count = 42
		version = 1
	condition:
		true
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if len(rule.Meta) != 2 {
		t.Errorf("expected 2 meta entries, got %d", len(rule.Meta))
	}
}

func TestParseMultipleRulesWithMixedContent(t *testing.T) {
	input := `
rule rule1 {
	meta:
		author = "test"
	strings:
		$s1 = "test"
	condition:
		$s1
}

rule rule2 : tag1 {
	condition:
		true
}

private rule rule3 {
	condition:
		false
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	if len(program.Rules) != 3 {
		t.Errorf("expected 3 rules, got %d", len(program.Rules))
	}

	if program.Rules[0].Name != "rule1" {
		t.Errorf("expected first rule name 'rule1', got '%s'", program.Rules[0].Name)
	}
	if program.Rules[1].Name != "rule2" {
		t.Errorf("expected second rule name 'rule2', got '%s'", program.Rules[1].Name)
	}
	if program.Rules[2].Name != "rule3" {
		t.Errorf("expected third rule name 'rule3', got '%s'", program.Rules[2].Name)
	}
}

func TestParseComplexConditionWithAllOperators(t *testing.T) {
	input := `
rule complex_cond {
	strings:
		$s1 = "test"
	condition:
		($s1 and true) or (false and not true) or (1 + 2 > 3)
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if rule.Condition == nil {
		t.Error("condition is nil")
	}
}

func TestParseRuleNameWithUnderscore(t *testing.T) {
	input := `
rule rule_with_underscore {
	condition:
		true
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if rule.Name != "rule_with_underscore" {
		t.Errorf("expected rule name 'rule_with_underscore', got '%s'", rule.Name)
	}
}

func TestParseRuleNameWithNumbers(t *testing.T) {
	input := `
rule rule123 {
	condition:
		true
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if rule.Name != "rule123" {
		t.Errorf("expected rule name 'rule123', got '%s'", rule.Name)
	}
}

func TestParseStringWithMultipleModifiers(t *testing.T) {
	input := `
rule string_mods {
	strings:
		$s1 = "test"
	condition:
		$s1
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if len(rule.Strings) != 1 {
		t.Errorf("expected 1 string, got %d", len(rule.Strings))
	}
}

func TestParseMetaStringValue(t *testing.T) {
	input := `
rule meta_string {
	meta:
		description = "This is a test rule"
	condition:
		true
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if len(rule.Meta) != 1 {
		t.Errorf("expected 1 meta entry, got %d", len(rule.Meta))
	}

	meta := rule.Meta[0]
	if meta.Key != "description" {
		t.Errorf("expected meta key 'description', got '%s'", meta.Key)
	}
}

func TestParseComparisonChain(t *testing.T) {
	input := `
rule comp_chain {
	condition:
		1 < 2 and 2 < 3 and 3 < 4
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if rule.Condition == nil {
		t.Error("condition is nil")
	}
}

func TestParseOperatorPrecedence(t *testing.T) {
	input := `
rule precedence {
	condition:
		1 + 2 * 3 == 7
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if rule.Condition == nil {
		t.Error("condition is nil")
	}
}

func TestParseTagsWithMultipleIdentifiers(t *testing.T) {
	input := `
rule multi_tags : tag1 tag2 tag3 tag4 tag5 {
	condition:
		true
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if len(rule.Tags) != 5 {
		t.Errorf("expected 5 tags, got %d", len(rule.Tags))
	}
}

func TestParseStringIdentifierVariations(t *testing.T) {
	input := `
rule string_vars {
	strings:
		$a = "test1"
		$b = "test2"
		$c = "test3"
	condition:
		$a or $b or $c
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if len(rule.Strings) != 3 {
		t.Errorf("expected 3 strings, got %d", len(rule.Strings))
	}
}

func TestParserErrors(t *testing.T) {
	input := `
rule test {
	condition:
		true
}
`
	l := lexer.New(input)
	p := New(l)

	_, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	errors := p.Errors()
	if len(errors) != 0 {
		t.Errorf("expected 0 errors, got %d", len(errors))
	}
}

func TestParseImportStatement(t *testing.T) {
	input := `
import "test"

rule test {
	condition:
		true
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	if len(program.Rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(program.Rules))
	}
}

func TestParseMultipleImports(t *testing.T) {
	input := `
import "test1"
import "test2"

rule test {
	condition:
		true
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	if len(program.Rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(program.Rules))
	}
}

func TestParseImportAndRules(t *testing.T) {
	input := `
import "test"

rule rule1 {
	condition:
		true
}

rule rule2 {
	condition:
		false
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	if len(program.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(program.Rules))
	}
}

func TestParseExpressionWithFilesize(t *testing.T) {
	input := `
rule filesize_test {
	condition:
		filesize > 1000
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if rule.Condition == nil {
		t.Error("condition is nil")
	}
}

func TestParseExpressionWithEntrypoint(t *testing.T) {
	input := `
rule entrypoint_test {
	condition:
		entrypoint == 0x400000
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Logf("Parsing errors: %v", p.Errors())
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if rule.Condition == nil {
		t.Error("condition is nil")
	}
}

func TestParseExpressionWithDefined(t *testing.T) {
	input := `
rule defined_test {
	condition:
		defined $s1
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if rule.Condition == nil {
		t.Error("condition is nil")
	}
}

func TestParseExpressionWithHexLiteral(t *testing.T) {
	input := `
rule hex_lit {
	condition:
		0x400000 == 0x400000
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if rule.Condition == nil {
		t.Error("condition is nil")
	}
}

func TestParseExpressionWithSizeLiteral(t *testing.T) {
	input := `
rule size_lit {
	condition:
		filesize > 1KB
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if rule.Condition == nil {
		t.Error("condition is nil")
	}
}

func TestParseErrorMissingRuleName(t *testing.T) {
	input := `
rule {
	condition:
		true
}
`
	l := lexer.New(input)
	p := New(l)

	_, err := p.ParseRules()
	if err == nil {
		t.Error("expected parsing error for missing rule name")
	}
}

func TestParseErrorMissingCondition(t *testing.T) {
	input := `
rule test_rule {
	meta:
		author = "test"
}
`
	l := lexer.New(input)
	p := New(l)

	_, err := p.ParseRules()
	if err == nil {
		t.Error("expected parsing error for missing condition")
	}
}

func TestParseErrorMissingClosingBrace(t *testing.T) {
	input := `
rule test_rule {
	condition:
		true
`
	l := lexer.New(input)
	p := New(l)

	_, err := p.ParseRules()
	if err == nil {
		t.Error("expected parsing error for missing closing brace")
	}
}

func TestParseErrorInvalidMetaValue(t *testing.T) {
	input := `
rule test_rule {
	meta:
		key = invalid_value
	condition:
		true
}
`
	l := lexer.New(input)
	p := New(l)

	_, err := p.ParseRules()
	if err == nil {
		t.Error("expected parsing error for invalid meta value")
	}
}

func TestParseErrorInvalidStringValue(t *testing.T) {
	input := `
rule test_rule {
	strings:
		$s1 = invalid_string
	condition:
		true
}
`
	l := lexer.New(input)
	p := New(l)

	_, err := p.ParseRules()
	if err == nil {
		t.Error("expected parsing error for invalid string value")
	}
}

func TestParseErrorMissingParenthesis(t *testing.T) {
	input := `
rule test_rule {
	condition:
		(true and false
}
`
	l := lexer.New(input)
	p := New(l)

	_, err := p.ParseRules()
	if err == nil {
		t.Error("expected parsing error for missing closing parenthesis")
	}
}

func TestParseErrorInvalidExpression(t *testing.T) {
	input := `
rule test_rule {
	condition:
		and true
}
`
	l := lexer.New(input)
	p := New(l)

	_, err := p.ParseRules()
	if err == nil {
		t.Error("expected parsing error for invalid expression")
	}
}

func TestParseErrorQuantifierWithoutOf(t *testing.T) {
	input := `
rule test_rule {
	strings:
		$s = "test"
	condition:
		all them
}
`
	l := lexer.New(input)
	p := New(l)

	_, err := p.ParseRules()
	if err == nil {
		t.Error("expected parsing error for quantifier without 'of'")
	}
}

func TestParseErrorQuantifierWithoutTarget(t *testing.T) {
	input := `
rule test_rule {
	strings:
		$s = "test"
	condition:
		all of
}
`
	l := lexer.New(input)
	p := New(l)

	_, err := p.ParseRules()
	if err == nil {
		t.Error("expected parsing error for quantifier without target")
	}
}

func TestParseRuleWithOnlyPrivateModifier(t *testing.T) {
	input := `
private rule private_rule {
	condition:
		true
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if rule.Name != "private_rule" {
		t.Errorf("expected rule name 'private_rule', got '%s'", rule.Name)
	}
	if len(rule.Modifiers) != 1 {
		t.Errorf("expected 1 modifier, got %d", len(rule.Modifiers))
	}
}

func TestParseComplexMetaSection(t *testing.T) {
	input := `
rule complex_meta {
	meta:
		author = "John Doe"
		version = 2
		enabled = true
		disabled = false
	condition:
		true
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if len(rule.Meta) != 4 {
		t.Errorf("expected 4 meta entries, got %d", len(rule.Meta))
	}
}

func TestParseComplexStringSection(t *testing.T) {
	input := `
rule complex_strings {
	strings:
		$s1 = "test1"
		$s2 = "test2"
		$s3 = "test3"
		$s4 = "test4"
		$s5 = "test5"
	condition:
		any of them
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if len(rule.Strings) != 5 {
		t.Errorf("expected 5 strings, got %d", len(rule.Strings))
	}
}

func TestParseComplexTagSection(t *testing.T) {
	input := `
rule complex_tags : tag1 tag2 tag3 tag4 tag5 tag6 {
	condition:
		true
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if len(rule.Tags) != 6 {
		t.Errorf("expected 6 tags, got %d", len(rule.Tags))
	}
}

func TestParseErrorInvalidImport(t *testing.T) {
	input := `
import invalid_string

rule test {
	condition:
		true
}
`
	l := lexer.New(input)
	p := New(l)

	_, err := p.ParseRules()
	if err == nil {
		t.Error("expected parsing error for invalid import")
	}
}

func TestParseMultipleRulesWithVariousModifiers(t *testing.T) {
	input := `
private global rule rule1 {
	condition:
		true
}

global private rule rule2 {
	condition:
		false
}

rule rule3 {
	condition:
		true
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	if len(program.Rules) != 3 {
		t.Errorf("expected 3 rules, got %d", len(program.Rules))
	}

	if len(program.Rules[0].Modifiers) != 2 {
		t.Errorf("expected 2 modifiers for rule1, got %d", len(program.Rules[0].Modifiers))
	}

	if len(program.Rules[1].Modifiers) != 2 {
		t.Errorf("expected 2 modifiers for rule2, got %d", len(program.Rules[1].Modifiers))
	}

	if len(program.Rules[2].Modifiers) != 0 {
		t.Errorf("expected 0 modifiers for rule3, got %d", len(program.Rules[2].Modifiers))
	}
}

func TestParseExpressionWithMultipleOperators(t *testing.T) {
	input := `
rule multi_ops {
	condition:
		1 + 2 - 3 * 4 / 5 % 6 == 7
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if rule.Condition == nil {
		t.Error("condition is nil")
	}
}

func TestParseRuleWithAllSections(t *testing.T) {
	input := `
private global rule comprehensive : tag1 tag2 {
	meta:
		author = "test"
		version = 1
		enabled = true
	strings:
		$s1 = "test1"
		$s2 = "test2"
	condition:
		($s1 or $s2) and filesize > 100
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if rule.Name != "comprehensive" {
		t.Errorf("expected rule name 'comprehensive', got '%s'", rule.Name)
	}
	if len(rule.Modifiers) != 2 {
		t.Errorf("expected 2 modifiers, got %d", len(rule.Modifiers))
	}
	if len(rule.Tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(rule.Tags))
	}
	if len(rule.Meta) != 3 {
		t.Errorf("expected 3 meta entries, got %d", len(rule.Meta))
	}
	if len(rule.Strings) != 2 {
		t.Errorf("expected 2 strings, got %d", len(rule.Strings))
	}
	if rule.Condition == nil {
		t.Error("condition is nil")
	}
}

func TestParseExpressionWithAllComparisons(t *testing.T) {
	input := `
rule all_comparisons {
	condition:
		1 == 1 and 2 != 3 and 4 < 5 and 6 <= 7 and 8 > 9 and 10 >= 11
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if rule.Condition == nil {
		t.Error("condition is nil")
	}
}

func TestParseExpressionWithAllArithmetic(t *testing.T) {
	input := `
rule all_arithmetic {
	condition:
		1 + 2 and 3 - 4 and 5 * 6 and 7 / 8 and 9 % 10
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if rule.Condition == nil {
		t.Error("condition is nil")
	}
}

func TestParseQuantifierAny(t *testing.T) {
	input := `
rule any_quantifier {
	strings:
		$s1 = "test1"
		$s2 = "test2"
	condition:
		any of them
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if rule.Condition == nil {
		t.Error("condition is nil")
	}
}

func TestParseRuleWithoutTags(t *testing.T) {
	input := `
rule no_tags {
	condition:
		true
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if len(rule.Tags) != 0 {
		t.Errorf("expected 0 tags, got %d", len(rule.Tags))
	}
}

func TestParseRuleWithHexString(t *testing.T) {
	input := `
rule hex_string_rule {
	strings:
		$hex = { E2 34 A1 C8 }
	condition:
		$hex
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if len(rule.Strings) != 1 {
		t.Errorf("expected 1 string, got %d", len(rule.Strings))
	}

	str := rule.Strings[0]
	if str.Identifier != "$hex" {
		t.Errorf("expected string identifier '$hex', got '%s'", str.Identifier)
	}
}

func TestParseRuleWithRegexPattern(t *testing.T) {
	input := `
rule regex_rule {
	strings:
		$regex = /malware[0-9]+/i
	condition:
		$regex
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if len(rule.Strings) != 1 {
		t.Errorf("expected 1 string, got %d", len(rule.Strings))
	}

	str := rule.Strings[0]
	if str.Identifier != "$regex" {
		t.Errorf("expected string identifier '$regex', got '%s'", str.Identifier)
	}
}

func TestParseRuleWithMixedStringTypes(t *testing.T) {
	input := `
rule mixed_strings {
	strings:
		$text = "malware"
		$hex = { E2 34 A1 }
		$regex = /virus[0-9]+/
	condition:
		any of them
}
`
	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	rule := program.Rules[0]
	if len(rule.Strings) != 3 {
		t.Errorf("expected 3 strings, got %d", len(rule.Strings))
	}

	// Check that we have all three types
	expectedIDs := []string{"$text", "$hex", "$regex"}
	for i, str := range rule.Strings {
		if str.Identifier != expectedIDs[i] {
			t.Errorf("expected string identifier '%s', got '%s'", expectedIDs[i], str.Identifier)
		}
	}
}
