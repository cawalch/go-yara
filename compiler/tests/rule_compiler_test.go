package tests

import (
	"context"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/compiler"
)

// TestRuleCompilerIntegration tests rule compiler integration
func TestRuleCompilerIntegration(t *testing.T) {
	rc := compiler.NewRuleCompiler()

	// Create a test AST node
	testAST := createTestAST()

	// Compile the rule
	compiledRule, err := rc.CompileRule(testAST.Rules[0])
	if err != nil {
		t.Fatalf("Failed to compile rule: %v", err)
	}

	if compiledRule == nil {
		t.Fatal("Compiled rule is nil")
		return
	}

	// Validate compiled rule properties
	if compiledRule.Name == "" {
		t.Error("Compiled rule should have a name")
	}

	// Test string access methods
	if len(compiledRule.GetStrings()) == 0 {
		t.Error("Compiled rule should have compiled strings")
	}

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

	c := createTestCompiler()
	program := compileTestRule(t, source)

	// Test string access methods to CompiledProgram
	// Verify we have the expected number of compiled strings
	if program.GetStringCount() != 5 {
		t.Errorf("Expected 5 compiled strings, got %d", program.GetStringCount())
	}

	// Verify compilation succeeds through the public compiler path.
	assertProgramValid(t, program)
	assertRuleCount(t, program, 1)
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

	c := createTestCompiler()
	program := compileTestRule(t, source)

	// But we should still have a valid rule
	assertProgramValid(t, program)
	assertRuleCount(t, program, 1)
	_ = c // Use the compiler variable
}

// TestRuleCompilerSingleStringCompilation tests compilation of rules with single strings
func TestRuleCompilerSingleStringCompilation(t *testing.T) {
	tests := []struct {
		name        string
		source      string
		description string
		shouldError bool
	}{
		{
			name: "single_text_string",
			source: `
				rule TestRule {
					strings:
						$text = "hello world"
					condition:
						$text
				}
			`,
			description: "Rule with single text string",
		},
		{
			name: "single_hex_string",
			source: `
				rule TestRule {
					strings:
						$hex = { 48 65 6C 6C 6F }
					condition:
						$hex
				}
			`,
			description: "Rule with single hex string",
		},
		{
			name: "single_regex_string",
			source: `
				rule TestRule {
					strings:
						$regex = /hello.*/
					condition:
						$regex
				}
			`,
			description: "Rule with single regex string",
		},
		{
			name: "single_string_with_nocase",
			source: `
				rule TestRule {
					strings:
						$text = "Hello" nocase
					condition:
						$text
				}
			`,
			description: "Single text string with nocase modifier",
		},
		{
			name: "single_string_with_multiple_modifiers",
			source: `
				rule TestRule {
					strings:
						$text = "Hello" nocase wide
					condition:
						$text
				}
			`,
			description: "Single text string with multiple modifiers",
		},
		{
			name: "single_private_string",
			source: `
				rule TestRule {
					strings:
						$private = "secret" private
					condition:
						$private
				}
			`,
			description: "Single private string",
		},
		{
			name: "single_hex_with_fullword",
			source: `
				rule TestRule {
					strings:
						$pattern = { 41 42 43 } fullword
					condition:
						$pattern
				}
			`,
			description: "Single hex string with fullword modifier",
		},
		{
			name: "single_string_special_chars",
			source: `
				rule TestRule {
					strings:
						$special = "test\\n\\t\\r\\\\"
					condition:
						$special
				}
			`,
			description: "Single string with escape sequences",
		},
		{
			name: "single_string_unicode",
			source: `
				rule TestRule {
					strings:
						$unicode = "café" wide
					condition:
						$unicode
				}
			`,
			description: "Single Unicode string with wide modifier",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiler := createTestCompiler()

			program, err := compiler.CompileSourceWithContext(context.Background(), tt.source)

			if tt.shouldError {
				if err == nil {
					t.Errorf("Expected compilation to fail for single string test: %s", tt.name)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected compilation error for %s (%s): %v", tt.name, tt.description, err)
				return
			}

			// Validate the program
			assertProgramValid(t, program)
			assertRuleCount(t, program, 1)

			rule := program.Rules[0]
			strings := rule.GetStrings()

			// Should have exactly one string
			if len(strings) != 1 {
				t.Errorf("Expected exactly 1 string for %s, got %d", tt.name, len(strings))
			}

			// Verify string count matches
			if rule.GetStringCount() != 1 {
				t.Errorf("Expected string count 1 for %s, got %d", tt.name, rule.GetStringCount())
			}

			// Verify rule was compiled successfully
			if rule.GetName() == "" {
				t.Errorf("Rule should have a non-empty name for %s", tt.name)
			}

			if rule.GetBytecode() == nil {
				t.Errorf("Rule should have bytecode for %s", tt.name)
			}

			t.Logf("Successfully compiled single string test: %s (%s)", tt.name, tt.description)
		})
	}
}

// TestRuleCompilerComplexConditions tests compilation of rules with complex conditions
func TestRuleCompilerComplexConditions(t *testing.T) {
	tests := []struct {
		name        string
		source      string
		shouldError bool
		description string
	}{
		{
			name: "nested_boolean_conditions",
			source: `
				rule Test {
					strings:
						$a = "pattern1"
						$b = "pattern2"
						$c = "pattern3"
					condition:
						($a or $b) and ($b and $c) or $c
				}
			`,
			shouldError: false,
			description: "Complex nested boolean operations with multiple strings",
		},
		{
			name: "deeply_nested_conditions",
			source: `
				rule Test {
					strings:
						$x = "test"
						$y = "example"
						$z = "sample"
					condition:
						(($x and $y) or ($y and $z)) and (($x or $z) and not ($x and $y and $z))
				}
			`,
			shouldError: false,
			description: "Deeply nested boolean logic with multiple operators",
		},
		{
			name: "complex_and_or_combinations",
			source: `
				rule Test {
					strings:
						$a = "alpha"
						$b = "beta"
						$c = "gamma"
						$d = "delta"
					condition:
						($a and $b) or ($c and $d) or ($a and $d) or ($b and $c)
				}
			`,
			shouldError: false,
			description: "Multiple AND/OR combinations with different string pairs",
		},
		{
			name: "not_operator_complexity",
			source: `
				rule Test {
					strings:
						$positive = "match"
						$negative1 = "not1"
						$negative2 = "not2"
					condition:
						$positive and not $negative1 and not $negative2
				}
			`,
			shouldError: false,
			description: "Complex NOT operator usage with multiple strings",
		},
		{
			name: "chained_boolean_expressions",
			source: `
				rule Test {
					strings:
						$a = "first"
						$b = "second"
						$c = "third"
						$d = "fourth"
					condition:
						$a and $b or $c and $d
				}
			`,
			shouldError: false,
			description: "Chained boolean expressions demonstrating operator precedence",
		},
		{
			name: "large_string_set_conditions",
			source: `
				rule Test {
					strings:
						$s1 = "pattern1"
						$s2 = "pattern2"
						$s3 = "pattern3"
						$s4 = "pattern4"
						$s5 = "pattern5"
						$s6 = "pattern6"
						$s7 = "pattern7"
						$s8 = "pattern8"
					condition:
						($s1 and $s2) or ($s3 and $s4) or ($s5 and $s6) or ($s7 and $s8)
				}
			`,
			shouldError: false,
			description: "Large set of strings in complex boolean expression",
		},
		{
			name: "triple_nested_parentheses",
			source: `
				rule Test {
					strings:
						$x = "x"
						$y = "y"
						$z = "z"
					condition:
						((($x and $y) and $z) or $x) and $y
				}
			`,
			shouldError: false,
			description: "Triple nested parentheses in boolean expression",
		},
		{
			name: "complex_modifiers_in_condition",
			source: `
				rule Test {
					strings:
						$text_nocase = "Hello World" nocase
						$text_wide = "Test" wide
						$hex_private = { 41 42 43 } private
					condition:
						$text_nocase and $text_wide and $hex_private
				}
			`,
			shouldError: false,
			description: "Conditions using strings with various modifiers",
		},
		{
			name: "mixed_string_types_conditions",
			source: `
				rule Test {
					strings:
						$text = "hello"
						$hex = { 48 65 6c 6c 6f }
						$regex = /test.*pattern/
					condition:
						$text and $hex and $regex
				}
			`,
			shouldError: false,
			description: "Conditions with mixed string types (text, hex, regex)",
		},
		{
			name: "simple_true_condition",
			source: `
				rule Test {
					condition:
						true
				}
			`,
			shouldError: false,
			description: "Simple condition that always evaluates to true",
		},
		{
			name: "simple_false_condition",
			source: `
				rule Test {
					condition:
						false
				}
			`,
			shouldError: false,
			description: "Simple condition that always evaluates to false",
		},
		{
			name: "malformed_condition_syntax",
			source: `
				rule Test {
					condition:
						and $a or $b
				}
			`,
			shouldError: true,
			description: "Malformed boolean expression syntax",
		},
		{
			name: "undefined_string_reference",
			source: `
				rule Test {
					condition:
						$undefined_string
				}
			`,
			shouldError: true,
			description: "Reference to undefined string should cause error",
		},
		{
			name: "empty_condition",
			source: `
				rule Test {
					condition:

				}
			`,
			shouldError: true,
			description: "Empty condition should cause error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fresh compiler for each test to avoid interference
			compiler := createTestCompiler()

			program, err := compiler.CompileSourceWithContext(context.Background(), tt.source)

			if tt.shouldError {
				if err == nil {
					t.Errorf("Expected compilation to fail for %s: %s", tt.name, tt.description)
				}
				t.Logf("Expected error occurred: %v", err)
				return
			}

			if err != nil {
				t.Errorf("Unexpected compilation error for %s (%s): %v", tt.name, tt.description, err)
				return
			}

			// Verify program structure for successful compilations
			if program == nil {
				t.Fatalf("Program should not be nil after successful compilation")
				return
			}

			if len(program.Rules) == 0 {
				t.Errorf("Expected at least one rule in compiled program for %s", tt.name)
			}

			// Verify rule metadata
			rule := program.Rules[0]
			if rule.GetName() == "" {
				t.Errorf("Rule should have a non-empty name for %s", tt.name)
			}

			if rule.GetBytecode() == nil {
				t.Errorf("Rule should have bytecode for %s", tt.name)
			}

			// Verify string count matches expectation for rules that should have strings
			if len(program.Rules[0].GetStrings()) == 0 && strings.Contains(tt.source, "strings:") {
				t.Errorf("Expected strings to be compiled for rule with strings in %s", tt.name)
			}

			t.Logf("Successfully compiled complex condition: %s", tt.description)
		})
	}
}

// TestRuleCompilerModifiers tests various string modifiers
func TestRuleCompilerModifiers(t *testing.T) {
	tests := []struct {
		name         string
		source       string
		shouldError  bool
		description  string
		modifierType string
	}{
		{
			name: "nocase_modifier",
			source: `
				rule Test {
					strings:
						$text = "Hello World" nocase
					condition:
						$text
				}
			`,
			shouldError:  false,
			description:  "Case-insensitive string matching",
			modifierType: "nocase",
		},
		{
			name: "wide_modifier",
			source: `
				rule Test {
					strings:
						$text = "test" wide
					condition:
						$text
				}
			`,
			shouldError:  false,
			description:  "Wide character string matching (UTF-16)",
			modifierType: "wide",
		},
		{
			name: "ascii_modifier",
			source: `
				rule Test {
					strings:
						$text = "test" ascii
					condition:
						$text
				}
			`,
			shouldError:  false,
			description:  "ASCII string matching",
			modifierType: "ascii",
		},
		{
			name: "fullword_modifier",
			source: `
				rule Test {
					strings:
						$text = "test" fullword
					condition:
						$text
				}
			`,
			shouldError:  false,
			description:  "Full word string matching",
			modifierType: "fullword",
		},
		{
			name: "private_modifier",
			source: `
				rule Test {
					strings:
						$secret = "password" private
					condition:
						$secret
				}
			`,
			shouldError:  false,
			description:  "Private string (not included in default matching)",
			modifierType: "private",
		},
		{
			name: "multiple_modifiers_nocase_wide",
			source: `
				rule Test {
					strings:
						$text = "Hello World" nocase wide
					condition:
						$text
				}
			`,
			shouldError:  false,
			description:  "Multiple modifiers on same string",
			modifierType: "nocase wide",
		},
		{
			name: "multiple_modifiers_nocase_fullword",
			source: `
				rule Test {
					strings:
						$text = "test" nocase fullword
					condition:
						$text
				}
			`,
			shouldError:  false,
			description:  "Case-insensitive full word matching",
			modifierType: "nocase fullword",
		},
		{
			name: "hex_with_private_modifier",
			source: `
				rule Test {
					strings:
						$hex = { 48 65 6c 6c 6f } private
					condition:
						$hex
				}
			`,
			shouldError:  false,
			description:  "Hex string with private modifier",
			modifierType: "private",
		},
		{
			name: "all_modifier_types",
			source: `
				rule Test {
					strings:
						$text1 = "Hello" nocase
						$text2 = "World" wide
						$text3 = "test" ascii
						$text4 = "pattern" fullword
						$text5 = "secret" private
						$hex = { 48 49 } private
					condition:
						$text1 and $text2 and $text3 and $text4 and $text5 and $hex
				}
			`,
			shouldError:  false,
			description:  "All available modifier types in one rule",
			modifierType: "all",
		},
		{
			name: "invalid_modifier_syntax",
			source: `
				rule Test {
					strings:
						$text = "test" invalid
					condition:
						$text
				}
			`,
			shouldError:  true,
			description:  "Invalid modifier should cause compilation error",
			modifierType: "invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiler := createTestCompiler()

			program, err := compiler.CompileSourceWithContext(context.Background(), tt.source)

			if tt.shouldError {
				if err == nil {
					t.Errorf("Expected compilation to fail for invalid modifier test: %s", tt.name)
				} else {
					t.Logf("Expected error occurred for invalid modifier: %v", err)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected compilation error for %s (%s): %v", tt.name, tt.description, err)
				return
			}

			if program == nil {
				t.Fatalf("Program should not be nil after successful compilation")
			}

			if len(program.Rules) == 0 {
				t.Errorf("Expected at least one rule in compiled program for %s", tt.name)
			}

			rule := program.Rules[0]
			ruleStrings := rule.GetStrings()

			// For rules that should have strings, verify they were compiled
			if strings.Contains(tt.source, "strings:") && len(ruleStrings) == 0 {
				t.Errorf("Expected strings to be compiled for %s", tt.name)
			}

			t.Logf("Successfully compiled modifier test: %s (%s)", tt.name, tt.description)
		})
	}
}

// TestRuleCompilerMetaInfo tests meta information compilation
func TestRuleCompilerMetaInfo(t *testing.T) {
	tests := []struct {
		name        string
		source      string
		shouldError bool
		description string
	}{
		{
			name: "rule_with_tags",
			source: `
				rule TestRule {
					meta:
						author = "Test Author"
						description = "Test description"
						version = "1.0"
						hash = "abc123"
					strings:
						$pattern = "test"
					condition:
						$pattern
				}
			`,
			shouldError: false,
			description: "Rule with meta information",
		},
		{
			name: "rule_with_multiple_tags",
			source: `
				rule TestRule {
					meta:
						author = "Author Name"
						date = "2024-01-01"
						version = "2.1.0"
						license = "MIT"
						comment = "This is a comment"
					strings:
						$text = "signature"
					condition:
						$text
				}
			`,
			shouldError: false,
			description: "Rule with multiple meta tags",
		},
		{
			name: "rule_with_strings_and_meta",
			source: `
				rule MultiTagRule {
					meta:
						author = "Security Team"
						reference = "CVE-2024-1234"
						description = "Malware signature"
					strings:
						$malware = "malicious_code"
						$payload = "payload_data"
						$encrypt = "encrypted_section"
					condition:
						$malware and $payload or $encrypt
				}
			`,
			shouldError: false,
			description: "Complex rule with meta info and multiple strings",
		},
		{
			name: "rule_without_meta",
			source: `
				rule SimpleRule {
					strings:
						$text = "simple"
					condition:
						$text
				}
			`,
			shouldError: false,
			description: "Simple rule without meta information",
		},
		{
			name: "rule_empty_meta_section",
			source: `
				rule EmptyMetaRule {
					meta:
					strings:
						$text = "test"
					condition:
						$text
				}
			`,
			shouldError: false,
			description: "Rule with empty meta section",
		},
		{
			name: "rule_with_special_characters_in_meta",
			source: `
				rule SpecialCharsRule {
					meta:
						description = "Rule with 'quotes' and \"double quotes\""
						tags = "tag1,tag2,tag3"
						references = ["ref1", "ref2"]
					strings:
						$pattern = "test"
					condition:
						$pattern
				}
			`,
			shouldError: true,
			description: "Rule with special characters in meta",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiler := createTestCompiler()

			program, err := compiler.CompileSourceWithContext(context.Background(), tt.source)

			if tt.shouldError {
				if err == nil {
					t.Errorf("Expected compilation to fail for meta test: %s", tt.name)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected compilation error for %s (%s): %v", tt.name, tt.description, err)
				return
			}

			if program == nil {
				t.Fatalf("Program should not be nil after successful compilation")
			}

			if len(program.Rules) == 0 {
				t.Errorf("Expected at least one rule in compiled program for %s", tt.name)
			}

			rule := program.Rules[0]

			// Verify rule was compiled successfully
			if rule.GetName() == "" {
				t.Errorf("Rule should have a non-empty name for %s", tt.name)
			}

			if rule.GetBytecode() == nil {
				t.Errorf("Rule should have bytecode for %s", tt.name)
			}

			// For rules with strings, verify they were compiled
			if strings.Contains(tt.source, "strings:") {
				if len(rule.GetStrings()) == 0 {
					t.Errorf("Expected strings to be compiled for rule with strings in %s", tt.name)
				}
			}

			t.Logf("Successfully compiled meta info test: %s (%s)", tt.name, tt.description)
		})
	}
}

// TestRuleCompilerErrorHandling tests error handling in rule compilation
func TestRuleCompilerErrorHandling(t *testing.T) {
	tests := []struct {
		name        string
		source      string
		description string
		checkError  func(t *testing.T, err error)
	}{
		{
			name: "duplicate_rule_names",
			source: `
				rule TestRule {
					strings:
						$a = "test1"
					condition:
						$a
				}
				rule TestRule {
					strings:
						$b = "test2"
					condition:
						$b
				}
			`,
			description: "Duplicate rule names should cause error",
			checkError: func(t *testing.T, err error) {
				if err == nil {
					t.Error("Expected error for duplicate rule names")
				}
				// Error is expected - the semantic validation correctly catches duplicate rules
			},
		},
		{
			name: "empty_rule_name",
			source: `
				rule {
					strings:
						$text = "test"
					condition:
						$text
				}
			`,
			description: "Empty rule name should cause error",
			checkError: func(t *testing.T, err error) {
				if err == nil {
					t.Error("Expected error for empty rule name")
				}
				// Error is expected - parsing should fail for empty rule name
			},
		},
		{
			name: "invalid_rule_name_with_spaces",
			source: `
				rule "Invalid Rule Name" {
					strings:
						$text = "test"
					condition:
						$text
				}
			`,
			description: "Rule name with spaces should cause error",
			checkError: func(t *testing.T, err error) {
				if err == nil {
					t.Error("Expected error for rule name with spaces")
				}
			},
		},
		{
			name: "invalid_string_identifier",
			source: `
				rule TestRule {
					strings:
						123invalid = "test"
					condition:
						123invalid
				}
			`,
			description: "Invalid string identifier should cause error",
			checkError: func(t *testing.T, err error) {
				if err == nil {
					t.Error("Expected error for invalid string identifier")
				}
				// Error is expected - parsing should fail for invalid string identifiers
			},
		},
		{
			name: "duplicate_string_identifier",
			source: `
				rule TestRule {
					strings:
						$duplicate = "first"
						$duplicate = "second"
					condition:
						$duplicate
				}
			`,
			description: "Duplicate string identifiers should cause error",
			checkError: func(t *testing.T, err error) {
				if err == nil {
					t.Error("Expected error for duplicate string identifiers")
				}
				// Error is expected - semantic validation should catch duplicate identifiers
			},
		},
		{
			name: "invalid_regex",
			source: `
				rule TestRule {
					strings:
						$invalid = /[unclosed bracket
					condition:
						$invalid
				}
			`,
			description: "Invalid regex should cause error",
			checkError: func(t *testing.T, err error) {
				if err == nil {
					t.Error("Expected error for invalid regex")
				}
			},
		},
		{
			name: "empty_rule",
			source: `
				rule EmptyRule {
					condition:
						// No condition provided
				}
			`,
			description: "Rule without condition should cause error",
			checkError: func(t *testing.T, err error) {
				if err == nil {
					t.Error("Expected error for rule without condition")
				}
			},
		},
		{
			name: "malformed_yara_syntax",
			source: `
				rule TestRule {
					strings
						$text = "test"
					condition:
						$text
				}
			`,
			description: "Malformed YARA syntax should cause error",
			checkError: func(t *testing.T, err error) {
				if err == nil {
					t.Error("Expected parsing error for malformed syntax")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiler := createTestCompiler()

			program, err := compiler.CompileSourceWithContext(context.Background(), tt.source)

			// All tests in this function should result in errors
			switch {
			case err == nil:
				t.Errorf("Expected compilation error for %s: %s", tt.name, tt.description)
			case tt.checkError != nil:
				tt.checkError(t, err)
			default:
				t.Logf("Expected error occurred: %v", err)
			}

			// Program should be nil when compilation fails
			if program != nil {
				t.Errorf("Program should be nil when compilation fails for %s", tt.name)
			}
		})
	}
}
