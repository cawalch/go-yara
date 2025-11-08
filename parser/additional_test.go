package parser

import (
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
)

// TestParserEdgeCases tests edge cases in the parser for comprehensive coverage
func TestParserEdgeCasesAdditional(t *testing.T) {
	t.Run("InputValidation", testParserInputValidation)
	t.Run("RuleStructure", testParserRuleStructure)
	t.Run("RuleFeatures", testParserRuleFeatures)
}

// testParserInputValidation tests parser with various input scenarios
func testParserInputValidation(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		expectRules int
		description string
	}{
		{
			name:        "empty_input",
			input:       "",
			expectError: false,
			expectRules: 0,
			description: "Parser should handle empty input gracefully",
		},
		{
			name:        "whitespace_only",
			input:       "   \n\t  \r\n  ",
			expectError: false,
			expectRules: 0,
			description: "Parser should handle whitespace-only input",
		},
		{
			name:        "comments_only",
			input:       `// This is a comment\n/* This is a block comment */\n// Another comment`,
			expectError: false,
			expectRules: 0,
			description: "Parser should handle comments-only input",
		},
		{
			name:        "invalid_rule_syntax",
			input:       `rule test_rule {\n\tstrings:\n\t\t$test = "test"\n\tcondition:\n\t\t$test\n\t// Missing closing brace`,
			expectError: true,
			expectRules: 0,
			description: "Parser should reject invalid rule syntax",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)
			p := New(l)
			program, err := p.ParseRules()

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but parsing succeeded: %s", tt.description)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected parsing error: %v: %s", err, tt.description)
				return
			}

			if program == nil {
				t.Errorf("Expected program but got nil: %s", tt.description)
				return
			}

			if len(program.Rules) != tt.expectRules {
				t.Errorf("Expected %d rules but got %d: %s", tt.expectRules, len(program.Rules), tt.description)
			}
		})
	}
}

// testParserRuleStructure tests parser with different rule structures
func testParserRuleStructure(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		expectRules int
		description string
	}{
		{
			name: "rule_no_strings",
			input: `rule test_rule {
	condition:
		true
}`,
			expectError: false,
			expectRules: 1,
			description: "Parser should handle rules without strings section",
		},
		{
			name: "rule_no_condition",
			input: `rule test_rule {
	strings:
		$test = "test"
}`,
			expectError: true,
			expectRules: 0,
			description: "Parser should reject rules without condition section",
		},
		{
			name: "multiple_rules",
			input: `rule test_rule_1 {
	strings:
		$test1 = "test1"
	condition:
		$test1
}

rule test_rule_2 {
	strings:
		$test2 = "test2"
	condition:
		$test2
}`,
			expectError: false,
			expectRules: 2,
			description: "Parser should handle multiple rules",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)
			p := New(l)
			program, err := p.ParseRules()

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but parsing succeeded: %s", tt.description)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected parsing error: %v: %s", err, tt.description)
				for _, parseErr := range p.Errors() {
					t.Logf("Parser error: %v", parseErr)
				}
				return
			}

			if program == nil {
				t.Errorf("Expected program but got nil: %s", tt.description)
				return
			}

			if len(program.Rules) != tt.expectRules {
				t.Errorf("Expected %d rules but got %d: %s", tt.expectRules, len(program.Rules), tt.description)
				return
			}

			// Additional validation for specific test cases
			if tt.name == "rule_no_strings" && len(program.Rules) > 0 {
				if len(program.Rules[0].Strings) != 0 {
					t.Errorf("Expected 0 strings but got %d: %s", len(program.Rules[0].Strings), tt.description)
				}
			}
		})
	}
}

// testParserRuleFeatures tests parser with different rule features
func testParserRuleFeatures(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectError  bool
		expectedTags int
		expectedMeta int
		description  string
		validateTags []string
		validateMeta map[string]string
	}{
		{
			name: "rule_with_tags",
			input: `rule test_rule : tag1 tag2 {
	strings:
		$test = "test"
	condition:
		$test
}`,
			expectError:  false,
			expectedTags: 2,
			expectedMeta: 0,
			description:  "Parser should handle rule tags",
			validateTags: []string{"tag1", "tag2"},
		},
		{
			name: "rule_with_meta",
			input: `rule test_rule {
	meta:
		author = "Test Author"
		description = "Test Description"
		date = "2023-01-01"
	strings:
		$test = "test"
	condition:
		$test
}`,
			expectError:  false,
			expectedTags: 0,
			expectedMeta: 3,
			description:  "Parser should handle rule meta information",
			validateMeta: map[string]string{
				"author":      "Test Author",
				"description": "Test Description",
				"date":        "2023-01-01",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)
			p := New(l)
			program, err := p.ParseRules()

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but parsing succeeded: %s", tt.description)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected parsing error: %v: %s", err, tt.description)
				return
			}

			if program == nil {
				t.Errorf("Expected program but got nil: %s", tt.description)
				return
			}

			if len(program.Rules) != 1 {
				t.Errorf("Expected 1 rule but got %d: %s", len(program.Rules), tt.description)
				return
			}

			rule := program.Rules[0]

			// Validate tags
			if len(rule.Tags) != tt.expectedTags {
				t.Errorf("Expected %d tags but got %d: %s", tt.expectedTags, len(rule.Tags), tt.description)
				return
			}

			if len(tt.validateTags) > 0 {
				for i, expectedTag := range tt.validateTags {
					if i >= len(rule.Tags) || rule.Tags[i] != expectedTag {
						t.Errorf("Expected tag %d to be %s but got %s: %s", i, expectedTag, rule.Tags[i], tt.description)
					}
				}
			}

			// Validate meta
			if len(rule.Meta) != tt.expectedMeta {
				t.Errorf("Expected %d meta entries but got %d: %s", tt.expectedMeta, len(rule.Meta), tt.description)
				return
			}

			if len(tt.validateMeta) > 0 {
				for key, expectedValue := range tt.validateMeta {
					var found bool
					var actualValue string
					for _, meta := range rule.Meta {
						if meta.Key == key {
							actualValue = meta.AsString()
							found = true
							break
						}
					}

					if !found {
						t.Errorf("Expected meta %s to be present but it was not found: %s", key, tt.description)
						continue
					}

					if actualValue != expectedValue {
						t.Errorf("Expected meta %s to be %s but got %s: %s", key, expectedValue, actualValue, tt.description)
					}
				}
			}
		})
	}
}

// TestParserAdvancedFeatures tests advanced parser features for comprehensive coverage
func TestParserAdvancedFeaturesAdditional(t *testing.T) {
	t.Run("GlobalAndImportFeatures", testParserGlobalAndImportFeatures)
	t.Run("RuleModifiers", testParserRuleModifiers)
	t.Run("ArithmeticOperations", testParserArithmeticOperations)
	t.Run("LogicAndComparisons", testParserLogicAndComparisons)
	t.Run("StringOperations", testParserStringOperations)
	t.Run("AdvancedFeatures", testParserAdvancedFeatures)
	t.Run("PatternsAndStrings", testParserPatternsAndStrings)
	t.Run("RuleElements", testParserRuleElements)
}

// parseAndValidate is a helper function that reduces repetitive parsing and validation logic
func parseAndValidate(t *testing.T, input string, testName string, expectedRules int) {
	l := lexer.New(input)
	p := New(l)
	program, err := p.ParseRules()

	if err != nil {
		t.Errorf("ParseRules() with %s failed: %v", testName, err)
		for _, parseErr := range p.Errors() {
			t.Logf("Parser error: %v", parseErr)
		}
		return
	}
	if program == nil {
		t.Errorf("ParseRules() with %s returned nil program", testName)
		return
	}
	if len(program.Rules) != expectedRules {
		t.Errorf("ParseRules() with %s should return %d rule(s), got %d", testName, expectedRules, len(program.Rules))
	}
}

// testParserGlobalAndImportFeatures tests global variables, imports, and includes
func testParserGlobalAndImportFeatures(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedRules int
	}{
		{
			name: "global_variables",
			input: `
global int_var = 42
global str_var = "test"
rule test_rule {
	strings:
		$test = "test"
	condition:
		$test and int_var == 42
}`,
			expectedRules: 1,
		},
		{
			name: "imports",
			input: `
import "pe"
import "cuckoo"

rule test_rule {
	strings:
		$test = "test"
	condition:
		$test and pe.entry_point == 0x1000
}`,
			expectedRules: 1,
		},
		{
			name: "includes",
			input: `
include "test.yar"
include "other.yar"

rule test_rule {
	strings:
		$test = "test"
	condition:
		$test
}`,
			expectedRules: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parseAndValidate(t, tt.input, tt.name, tt.expectedRules)
		})
	}
}

// testParserRuleModifiers tests rule and string modifiers
func testParserRuleModifiers(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedRules int
	}{
		{
			name: "rule_modifiers",
			input: `
private rule test_rule_private {
	strings:
		$test = "test"
	condition:
		$test
}

global rule test_rule_global {
	strings:
		$test = "test"
	condition:
		$test
}`,
			expectedRules: 2,
		},
		{
			name: "string_modifiers",
			input: `
rule test_rule {
	strings:
		$test1 = "test" nocase
		$test2 = "test" wide
		$test3 = "test" ascii
	condition:
		$test1 and $test2 and $test3
}`,
			expectedRules: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parseAndValidate(t, tt.input, tt.name, tt.expectedRules)
		})
	}
}

// testParserArithmeticOperations tests arithmetic, bitwise, and shift operations
func testParserArithmeticOperations(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedRules int
	}{
		{
			name: "arithmetic_expressions",
			input: `
rule test_rule {
	strings:
		$test = "test"
	condition:
		$test and (10 + 5) * 2 == 30
}`,
			expectedRules: 1,
		},
		{
			name: "bitwise_operations",
			input: `
rule test_rule {
	strings:
		$test = "test"
	condition:
		$test and (0xFF & 0x0F) == 0x0F
}`,
			expectedRules: 1,
		},
		{
			name: "shift_operations",
			input: `
rule test_rule {
	strings:
		$test = "test"
	condition:
		$test and (0x10 << 2) == 0x40
}`,
			expectedRules: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parseAndValidate(t, tt.input, tt.name, tt.expectedRules)
		})
	}
}

// testParserLogicAndComparisons tests boolean logic and comparison operators
func testParserLogicAndComparisons(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedRules int
	}{
		{
			name: "boolean_logic",
			input: `
rule test_rule {
	strings:
		$test = "test"
	condition:
		$test and true or false
}`,
			expectedRules: 1,
		},
		{
			name: "comparison_operators",
			input: `
rule test_rule {
	strings:
		$test = "test"
	condition:
		$test and 10 > 5 and 5 < 10
}`,
			expectedRules: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parseAndValidate(t, tt.input, tt.name, tt.expectedRules)
		})
	}
}

// testParserStringOperations tests string count, offset, and length operations
func testParserStringOperations(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedRules int
	}{
		{
			name: "string_count",
			input: `
rule test_rule {
	strings:
		$test1 = "test1"
		$test2 = "test2"
		$test3 = "test3"
	condition:
		#test1 == 1 and #test2 == 1 and #test3 == 1
}`,
			expectedRules: 1,
		},
		{
			name: "string_offset",
			input: `
rule test_rule {
	strings:
		$test = "test"
	condition:
		$test and @test == 100
}`,
			expectedRules: 1,
		},
		{
			name: "string_length",
			input: `
rule test_rule {
	strings:
		$test = "test"
	condition:
		$test and !test == 4
}`,
			expectedRules: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parseAndValidate(t, tt.input, tt.name, tt.expectedRules)
		})
	}
}

// testParserAdvancedFeatures tests functions, arrays, of operator, and for loops
func testParserAdvancedFeatures(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedRules int
	}{
		{
			name: "functions",
			input: `
rule test_rule {
	strings:
		$test = "test"
	condition:
		$test and uint8(0) == 0
}`,
			expectedRules: 1,
		},
		{
			name: "arrays",
			input: `
rule test_rule {
	strings:
		$test = "test"
	condition:
		$test and (uint8(0) + uint8(1) + uint8(2)) == 3
}`,
			expectedRules: 1,
		},
		{
			name: "of_operator",
			input: `
rule test_rule {
	strings:
		$test1 = "test1"
		$test2 = "test2"
		$test3 = "test3"
	condition:
		2 of ($test1, $test2, $test3)
}`,
			expectedRules: 1,
		},
		{
			name: "for_loop",
			input: `
rule test_rule {
	strings:
		$test1 = "test1"
		$test2 = "test2"
		$test3 = "test3"
	condition:
		for any i in (1..3) : ( uint8(i) == 0 )
}`,
			expectedRules: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parseAndValidate(t, tt.input, tt.name, tt.expectedRules)
		})
	}
}

// testParserPatternsAndStrings tests regex patterns, hex strings, and anonymous strings
func testParserPatternsAndStrings(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedRules int
	}{
		{
			name: "regex_patterns",
			input: `
rule test_rule {
	strings:
		$test = /test.*pattern/
	condition:
		$test
}`,
			expectedRules: 1,
		},
		{
			name: "hex_strings",
			input: `
rule test_rule {
	strings:
		$test = { 74 65 73 74 }
	condition:
		$test
}`,
			expectedRules: 1,
		},
		{
			name: "anonymous_strings",
			input: `
rule test_rule {
	strings:
		$test1 = "test"
		$ = "anonymous"
	condition:
		$test1 and $
}`,
			expectedRules: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parseAndValidate(t, tt.input, tt.name, tt.expectedRules)
		})
	}
}

// testParserRuleElements tests rule dependencies, time expressions, filesize, and entrypoint
func testParserRuleElements(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedRules int
	}{
		{
			name: "rule_dependencies",
			input: `
rule base_rule {
	strings:
		$test = "base"
	condition:
		$test
}

rule dependent_rule {
	strings:
		$test = "dependent"
	condition:
		$test and base_rule
}`,
			expectedRules: 2,
		},
		{
			name: "time_expressions",
			input: `
rule test_rule {
	strings:
		$test = "test"
	condition:
		$test and now > 0
}`,
			expectedRules: 1,
		},
		{
			name: "filesize",
			input: `
rule test_rule {
	strings:
		$test = "test"
	condition:
		$test and filesize > 1024
}`,
			expectedRules: 1,
		},
		{
			name: "entrypoint",
			input: `
rule test_rule {
	strings:
		$test = "test"
	condition:
		$test and entrypoint == 0x1000
}`,
			expectedRules: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parseAndValidate(t, tt.input, tt.name, tt.expectedRules)
		})
	}
}

// TestParserErrorHandling tests error handling in the parser
func TestParserErrorHandlingAdditional(t *testing.T) {
	// Test parser with lexer errors
	t.Run("lexer_errors", func(t *testing.T) {
		l := lexer.New(`
rule test_rule {
	strings:
		$test = "unclosed string
	condition:
		$test
}
`)
		p := New(l)
		_, err := p.ParseRules()
		if err == nil {
			t.Error("ParseRules() with lexer errors should have failed")
		}
	})

	// Test parser with unexpected token
	t.Run("unexpected_token", func(t *testing.T) {
		l := lexer.New(`
rule test_rule {
	strings:
		$test = "test"
	condition:
		$test
	invalid_token_here
}
`)
		p := New(l)
		_, err := p.ParseRules()
		if err == nil {
			t.Error("ParseRules() with unexpected token should have failed")
		}
	})
}

// TestParserMethods tests parser methods for comprehensive coverage
func TestParserMethodsAdditional(t *testing.T) {
	// Test Errors method
	t.Run("errors_method", func(t *testing.T) {
		l := lexer.New(`
rule test_rule {
	strings:
		$test = "test"
	condition:
		$test
`)
		p := New(l)
		// Parse to potentially generate errors
		_, _ = p.ParseRules()
		errors := p.Errors()
		// Should not panic even if no errors
		if errors == nil {
			t.Error("Errors() should never return nil")
		}
	})

	// Test parser with different string types
	t.Run("different_string_types", func(t *testing.T) {
		l := lexer.New(`
rule test_rule {
	strings:
		$text = "text string"
		$hex = { 48 65 6C 6C 6F }
		$regex = /test/
	condition:
		$text and $hex and $regex
}
`)
		p := New(l)
		program, err := p.ParseRules()
		if err != nil {
			t.Errorf("ParseRules() with different string types failed: %v", err)
		}
		if program == nil {
			t.Error("ParseRules() with different string types returned nil program")
			return
		}
		if len(program.Rules) != 1 {
			t.Errorf("ParseRules() with different string types should return 1 rule, got %d", len(program.Rules))
		}
		if len(program.Rules[0].Strings) != 3 {
			t.Errorf("ParseRules() with different string types should return 3 strings, got %d", len(program.Rules[0].Strings))
		}
	})
}
