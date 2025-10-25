// Package parser provides additional tests for comprehensive coverage.
package parser

import (
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
)

// TestParserEdgeCases tests edge cases in the parser for comprehensive coverage
func TestParserEdgeCasesAdditional(t *testing.T) {
	// Test parser with empty input
	t.Run("empty_input", func(t *testing.T) {
		l := lexer.New("")
		p := New(l)
		program, err := p.ParseRules()
		if err != nil {
			t.Errorf("ParseRules() with empty input failed: %v", err)
		}
		if program == nil {
			t.Error("ParseRules() with empty input returned nil program")
		}
		if len(program.Rules) != 0 {
			t.Errorf("ParseRules() with empty input should return 0 rules, got %d", len(program.Rules))
		}
	})

	// Test parser with only whitespace
	t.Run("whitespace_only", func(t *testing.T) {
		l := lexer.New("   \n\t  \r\n  ")
		p := New(l)
		program, err := p.ParseRules()
		if err != nil {
			t.Errorf("ParseRules() with whitespace only failed: %v", err)
		}
		if program == nil {
			t.Error("ParseRules() with whitespace only returned nil program")
		}
		if len(program.Rules) != 0 {
			t.Errorf("ParseRules() with whitespace only should return 0 rules, got %d", len(program.Rules))
		}
	})

	// Test parser with comments only
	t.Run("comments_only", func(t *testing.T) {
		l := lexer.New(`
// This is a comment
/* This is a block comment */
// Another comment
`)
		p := New(l)
		program, err := p.ParseRules()
		if err != nil {
			t.Errorf("ParseRules() with comments only failed: %v", err)
		}
		if program == nil {
			t.Error("ParseRules() with comments only returned nil program")
		}
		if len(program.Rules) != 0 {
			t.Errorf("ParseRules() with comments only should return 0 rules, got %d", len(program.Rules))
		}
	})

	// Test parser with invalid rule syntax
	t.Run("invalid_rule_syntax", func(t *testing.T) {
		l := lexer.New(`
rule test_rule {
	strings:
		$test = "test"
	condition:
		$test
	// Missing closing brace
`)
		p := New(l)
		_, err := p.ParseRules()
		if err == nil {
			t.Error("ParseRules() with invalid syntax should have failed")
		}
	})

	// Test parser with rule but no strings section
	t.Run("rule_no_strings", func(t *testing.T) {
		l := lexer.New(`
rule test_rule {
	condition:
		true
}
`)
		p := New(l)
		program, err := p.ParseRules()
		if err != nil {
			t.Errorf("ParseRules() with rule without strings failed: %v", err)
		}
		if program == nil {
			t.Error("ParseRules() with rule without strings returned nil program")
		}
		if len(program.Rules) != 1 {
			t.Errorf("ParseRules() with rule without strings should return 1 rule, got %d", len(program.Rules))
		}
		if len(program.Rules[0].Strings) != 0 {
			t.Errorf("ParseRules() with rule without strings should return 0 strings, got %d", len(program.Rules[0].Strings))
		}
	})

	// Test parser with rule but no condition section
	t.Run("rule_no_condition", func(t *testing.T) {
		l := lexer.New(`
rule test_rule {
	strings:
		$test = "test"
}
`)
		p := New(l)
		_, err := p.ParseRules()
		if err == nil {
			t.Error("ParseRules() with rule without condition should have failed")
		}
	})

	// Test parser with multiple rules
	t.Run("multiple_rules", func(t *testing.T) {
		l := lexer.New(`
rule test_rule_1 {
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
}
`)
		p := New(l)
		program, err := p.ParseRules()
		if err != nil {
			t.Errorf("ParseRules() with multiple rules failed: %v", err)
			for _, parseErr := range p.Errors() {
				t.Logf("Parser error: %v", parseErr)
			}
			return
		}
		if program == nil {
			t.Error("ParseRules() with multiple rules returned nil program")
			return
		}
		if len(program.Rules) != 2 {
			t.Errorf("ParseRules() with multiple rules should return 2 rules, got %d", len(program.Rules))
		}
	})

	// Test parser with rule tags
	t.Run("rule_with_tags", func(t *testing.T) {
		l := lexer.New(`
rule test_rule : tag1 tag2 {
	strings:
		$test = "test"
	condition:
		$test
}
`)
		p := New(l)
		program, err := p.ParseRules()
		if err != nil {
			t.Errorf("ParseRules() with rule tags failed: %v", err)
		}
		if program == nil {
			t.Error("ParseRules() with rule tags returned nil program")
		}
		if len(program.Rules) != 1 {
			t.Errorf("ParseRules() with rule tags should return 1 rule, got %d", len(program.Rules))
		}
		if len(program.Rules[0].Tags) != 2 {
			t.Errorf("ParseRules() with rule tags should return 2 tags, got %d", len(program.Rules[0].Tags))
		}
		if program.Rules[0].Tags[0] != "tag1" || program.Rules[0].Tags[1] != "tag2" {
			t.Errorf("ParseRules() with rule tags returned unexpected tags: %v", program.Rules[0].Tags)
		}
	})

	// Test parser with rule meta
	t.Run("rule_with_meta", func(t *testing.T) {
		l := lexer.New(`
rule test_rule {
	meta:
		author = "Test Author"
		description = "Test Description"
		date = "2023-01-01"
	strings:
		$test = "test"
	condition:
		$test
}
`)
		p := New(l)
		program, err := p.ParseRules()
		if err != nil {
			t.Errorf("ParseRules() with rule meta failed: %v", err)
		}
		if program == nil {
			t.Error("ParseRules() with rule meta returned nil program")
		}
		if len(program.Rules) != 1 {
			t.Errorf("ParseRules() with rule meta should return 1 rule, got %d", len(program.Rules))
		}
		if len(program.Rules[0].Meta) != 3 {
			t.Errorf("ParseRules() with rule meta should return 3 meta entries, got %d", len(program.Rules[0].Meta))
		}
	})
}

// TestParserAdvancedFeatures tests advanced parser features for comprehensive coverage
func TestParserAdvancedFeaturesAdditional(t *testing.T) {
	// Test parser with global variables
	t.Run("global_variables", func(t *testing.T) {
		l := lexer.New(`
global int_var = 42
global str_var = "test"
rule test_rule {
	strings:
		$test = "test"
	condition:
		$test and int_var == 42
}
`)
		p := New(l)
		program, err := p.ParseRules()
		if err != nil {
			t.Errorf("ParseRules() with global variables failed: %v", err)
			for _, parseErr := range p.Errors() {
				t.Logf("Parser error: %v", parseErr)
			}
			return
		}
		if program == nil {
			t.Error("ParseRules() with global variables returned nil program")
			return
		}
		if len(program.Rules) != 1 {
			t.Errorf("ParseRules() with global variables should return 1 rule, got %d", len(program.Rules))
		}
	})

	// Test parser with imports
	t.Run("imports", func(t *testing.T) {
		l := lexer.New(`
import "pe"
import "cuckoo"

rule test_rule {
	strings:
		$test = "test"
	condition:
		$test and pe.entry_point == 0x1000
}
`)
		p := New(l)
		program, err := p.ParseRules()
		if err != nil {
			t.Errorf("ParseRules() with imports failed: %v", err)
			for _, parseErr := range p.Errors() {
				t.Logf("Parser error: %v", parseErr)
			}
			return
		}
		if program == nil {
			t.Error("ParseRules() with imports returned nil program")
			return
		}
		if len(program.Rules) != 1 {
			t.Errorf("ParseRules() with imports should return 1 rule, got %d", len(program.Rules))
		}
	})

	// Test parser with includes
	t.Run("includes", func(t *testing.T) {
		l := lexer.New(`
include "test.yar"
include "other.yar"

rule test_rule {
	strings:
		$test = "test"
	condition:
		$test
}
`)
		p := New(l)
		program, err := p.ParseRules()
		if err != nil {
			t.Errorf("ParseRules() with includes failed: %v", err)
			for _, parseErr := range p.Errors() {
				t.Logf("Parser error: %v", parseErr)
			}
			return
		}
		if program == nil {
			t.Error("ParseRules() with includes returned nil program")
			return
		}
		if len(program.Rules) != 1 {
			t.Errorf("ParseRules() with includes should return 1 rule, got %d", len(program.Rules))
		}
	})

	// Test parser with rule modifiers
	t.Run("rule_modifiers", func(t *testing.T) {
		l := lexer.New(`
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
}
`)
		p := New(l)
		program, err := p.ParseRules()
		if err != nil {
			t.Errorf("ParseRules() with rule modifiers failed: %v", err)
			for _, parseErr := range p.Errors() {
				t.Logf("Parser error: %v", parseErr)
			}
			return
		}
		if program == nil {
			t.Error("ParseRules() with rule modifiers returned nil program")
			return
		}
		if len(program.Rules) != 2 {
			t.Errorf("ParseRules() with rule modifiers should return 2 rules, got %d", len(program.Rules))
		}
	})

	// Test parser with string modifiers
	t.Run("string_modifiers", func(t *testing.T) {
		l := lexer.New(`
rule test_rule {
	strings:
		$text1 = "test" nocase
		$text2 = "test" wide
		$text3 = "test" ascii
		$text4 = "test" fullword
		$hex1 = { 48 65 6C 6C 6F } private
	condition:
		$text1 and $text2 and $text3 and $text4 and $hex1
}
`)
		p := New(l)
		program, err := p.ParseRules()
		if err != nil {
			t.Errorf("ParseRules() with string modifiers failed: %v", err)
		}
		if program == nil {
			t.Error("ParseRules() with string modifiers returned nil program")
		}
		if len(program.Rules) != 1 {
			t.Errorf("ParseRules() with string modifiers should return 1 rule, got %d", len(program.Rules))
		}
		if len(program.Rules[0].Strings) != 5 {
			t.Errorf("ParseRules() with string modifiers should return 5 strings, got %d", len(program.Rules[0].Strings))
		}
	})

	// Test parser with arithmetic expressions
	t.Run("arithmetic_expressions", func(t *testing.T) {
		l := lexer.New(`
rule test_rule {
	strings:
		$test = "test"
	condition:
		$test and (1 + 2 * 3) > 5 and (10 / 2) == 5
}
`)
		p := New(l)
		program, err := p.ParseRules()
		if err != nil {
			t.Errorf("ParseRules() with arithmetic expressions failed: %v", err)
		}
		if program == nil {
			t.Error("ParseRules() with arithmetic expressions returned nil program")
		}
		if len(program.Rules) != 1 {
			t.Errorf("ParseRules() with arithmetic expressions should return 1 rule, got %d", len(program.Rules))
		}
	})

	// Test parser with bitwise operations
	t.Run("bitwise_operations", func(t *testing.T) {
		l := lexer.New(`
rule test_rule {
	strings:
		$test = "test"
	condition:
		$test and (0xFF & 0x0F) == 0x0F and (0x01 | 0x02) == 0x03
}
`)
		p := New(l)
		program, err := p.ParseRules()
		if err != nil {
			t.Errorf("ParseRules() with bitwise operations failed: %v", err)
		}
		if program == nil {
			t.Error("ParseRules() with bitwise operations returned nil program")
		}
		if len(program.Rules) != 1 {
			t.Errorf("ParseRules() with bitwise operations should return 1 rule, got %d", len(program.Rules))
		}
	})

	// Test parser with shift operations
	t.Run("shift_operations", func(t *testing.T) {
		l := lexer.New(`
rule test_rule {
	strings:
		$test = "test"
	condition:
		$test and (0x01 << 4) == 0x10 and (0x10 >> 4) == 0x01
}
`)
		p := New(l)
		program, err := p.ParseRules()
		if err != nil {
			t.Errorf("ParseRules() with shift operations failed: %v", err)
		}
		if program == nil {
			t.Error("ParseRules() with shift operations returned nil program")
		}
		if len(program.Rules) != 1 {
			t.Errorf("ParseRules() with shift operations should return 1 rule, got %d", len(program.Rules))
		}
	})

	// Test parser with boolean logic
	t.Run("boolean_logic", func(t *testing.T) {
		l := lexer.New(`
rule test_rule {
	strings:
		$test1 = "test1"
		$test2 = "test2"
		$test3 = "test3"
	condition:
		($test1 and $test2) or $test3 and not ($test1 and $test3)
}
`)
		p := New(l)
		program, err := p.ParseRules()
		if err != nil {
			t.Errorf("ParseRules() with boolean logic failed: %v", err)
		}
		if program == nil {
			t.Error("ParseRules() with boolean logic returned nil program")
		}
		if len(program.Rules) != 1 {
			t.Errorf("ParseRules() with boolean logic should return 1 rule, got %d", len(program.Rules))
		}
	})

	// Test parser with comparison operators
	t.Run("comparison_operators", func(t *testing.T) {
		l := lexer.New(`
rule test_rule {
	strings:
		$test = "test"
	condition:
		$test and 5 > 3 and 2 < 4 and 7 >= 7 and 8 <= 8 and 9 == 9 and 10 != 11
}
`)
		p := New(l)
		program, err := p.ParseRules()
		if err != nil {
			t.Errorf("ParseRules() with comparison operators failed: %v", err)
		}
		if program == nil {
			t.Error("ParseRules() with comparison operators returned nil program")
		}
		if len(program.Rules) != 1 {
			t.Errorf("ParseRules() with comparison operators should return 1 rule, got %d", len(program.Rules))
		}
	})

	// Test parser with string count
	t.Run("string_count", func(t *testing.T) {
		l := lexer.New(`
rule test_rule {
	strings:
		$test1 = "test1"
		$test2 = "test2"
	condition:
		#test1 == 1 and #test2 == 1 and #test1 + #test2 == 2
}
`)
		p := New(l)
		program, err := p.ParseRules()
		if err != nil {
			t.Errorf("ParseRules() with string count failed: %v", err)
		}
		if program == nil {
			t.Error("ParseRules() with string count returned nil program")
		}
		if len(program.Rules) != 1 {
			t.Errorf("ParseRules() with string count should return 1 rule, got %d", len(program.Rules))
		}
	})

	// Test parser with string offset
	t.Run("string_offset", func(t *testing.T) {
		l := lexer.New(`
rule test_rule {
	strings:
		$test = "test"
	condition:
		$test and $test at 0 and $test in (0..100)
}
`)
		p := New(l)
		program, err := p.ParseRules()
		if err != nil {
			t.Errorf("ParseRules() with string offset failed: %v", err)
			for _, parseErr := range p.Errors() {
				t.Logf("Parser error: %v", parseErr)
			}
			return
		}
		if program == nil {
			t.Error("ParseRules() with string offset returned nil program")
			return
		}
		if len(program.Rules) != 1 {
			t.Errorf("ParseRules() with string offset should return 1 rule, got %d", len(program.Rules))
		}
	})

	// Test parser with string length
	t.Run("string_length", func(t *testing.T) {
		l := lexer.New(`
rule test_rule {
	strings:
		$test = "test"
	condition:
		$test and !($test at 0) and ($test at 0) and ($test length == 4)
}
`)
		p := New(l)
		program, err := p.ParseRules()
		if err != nil {
			t.Errorf("ParseRules() with string length failed: %v", err)
			for _, parseErr := range p.Errors() {
				t.Logf("Parser error: %v", parseErr)
			}
			return
		}
		if program == nil {
			t.Error("ParseRules() with string length returned nil program")
			return
		}
		if len(program.Rules) != 1 {
			t.Errorf("ParseRules() with string length should return 1 rule, got %d", len(program.Rules))
		}
	})

	// Test parser with functions
	t.Run("functions", func(t *testing.T) {
		l := lexer.New(`
rule test_rule {
	strings:
		$test = "test"
	condition:
		$test and uint8(0) == 0x74 and uint16(0) == 0x7465 and uint32(0) == 0x74657374
}
`)
		p := New(l)
		program, err := p.ParseRules()
		if err != nil {
			t.Errorf("ParseRules() with functions failed: %v", err)
		}
		if program == nil {
			t.Error("ParseRules() with functions returned nil program")
		}
		if len(program.Rules) != 1 {
			t.Errorf("ParseRules() with functions should return 1 rule, got %d", len(program.Rules))
		}
	})

	// Test parser with arrays
	t.Run("arrays", func(t *testing.T) {
		l := lexer.New(`
rule test_rule {
	strings:
		$test = "test"
	condition:
		$test and uint8(0)[0] == 0x74 and uint8(0)[1] == 0x65
}
`)
		p := New(l)
		program, err := p.ParseRules()
		if err != nil {
			t.Errorf("ParseRules() with arrays failed: %v", err)
			for _, parseErr := range p.Errors() {
				t.Logf("Parser error: %v", parseErr)
			}
			return
		}
		if program == nil {
			t.Error("ParseRules() with arrays returned nil program")
			return
		}
		if len(program.Rules) != 1 {
			t.Errorf("ParseRules() with arrays should return 1 rule, got %d", len(program.Rules))
		}
	})

	// Test parser with of operator
	t.Run("of_operator", func(t *testing.T) {
		l := lexer.New(`
rule test_rule {
	strings:
		$test1 = "test1"
		$test2 = "test2"
		$test3 = "test3"
	condition:
		1 of ($test1, $test2, $test3) and 2 of them
}
`)
		p := New(l)
		program, err := p.ParseRules()
		if err != nil {
			t.Errorf("ParseRules() with of operator failed: %v", err)
			for _, parseErr := range p.Errors() {
				t.Logf("Parser error: %v", parseErr)
			}
			return
		}
		if program == nil {
			t.Error("ParseRules() with of operator returned nil program")
			return
		}
		if len(program.Rules) != 1 {
			t.Errorf("ParseRules() with of operator should return 1 rule, got %d", len(program.Rules))
		}
	})

	// Test parser with for loop
	t.Run("for_loop", func(t *testing.T) {
		l := lexer.New(`
rule test_rule {
	strings:
		$test = "test"
	condition:
		$test and for all i in (0..9) : (uint8(i) == 0)
}
`)
		p := New(l)
		program, err := p.ParseRules()
		if err != nil {
			t.Errorf("ParseRules() with for loop failed: %v", err)
			for _, parseErr := range p.Errors() {
				t.Logf("Parser error: %v", parseErr)
			}
			return
		}
		if program == nil {
			t.Error("ParseRules() with for loop returned nil program")
			return
		}
		if len(program.Rules) != 1 {
			t.Errorf("ParseRules() with for loop should return 1 rule, got %d", len(program.Rules))
		}
	})

	// Test parser with regex patterns
	t.Run("regex_patterns", func(t *testing.T) {
		l := lexer.New(`
rule test_rule {
	strings:
		$regex1 = /test/
		$regex2 = /test/i
		$regex3 = /test/s
		$regex4 = /test/m
	condition:
		$regex1 and $regex2 and $regex3 and $regex4
}
`)
		p := New(l)
		program, err := p.ParseRules()
		if err != nil {
			t.Errorf("ParseRules() with regex patterns failed: %v", err)
			for _, parseErr := range p.Errors() {
				t.Logf("Parser error: %v", parseErr)
			}
			return
		}
		if program == nil {
			t.Error("ParseRules() with regex patterns returned nil program")
			return
		}
		if len(program.Rules) != 1 {
			t.Errorf("ParseRules() with regex patterns should return 1 rule, got %d", len(program.Rules))
		}
		if len(program.Rules[0].Strings) != 4 {
			t.Errorf("ParseRules() with regex patterns should return 4 strings, got %d", len(program.Rules[0].Strings))
		}
	})

	// Test parser with hex strings
	t.Run("hex_strings", func(t *testing.T) {
		l := lexer.New(`
rule test_rule {
	strings:
		$hex1 = { 48 65 6C 6C 6F }
		$hex2 = { 48 65 6C [5-6] 6F }
		$hex3 = { 48 65 6C (6C|6F) 6F }
		$hex4 = { 48 65 6C 6C 6F } // comment
	condition:
		$hex1 and $hex2 and $hex3 and $hex4
}
`)
		p := New(l)
		program, err := p.ParseRules()
		if err != nil {
			t.Errorf("ParseRules() with hex strings failed: %v", err)
		}
		if program == nil {
			t.Error("ParseRules() with hex strings returned nil program")
		}
		if len(program.Rules) != 1 {
			t.Errorf("ParseRules() with hex strings should return 1 rule, got %d", len(program.Rules))
		}
		if len(program.Rules[0].Strings) != 4 {
			t.Errorf("ParseRules() with hex strings should return 4 strings, got %d", len(program.Rules[0].Strings))
		}
	})

	// Test parser with anonymous strings
	t.Run("anonymous_strings", func(t *testing.T) {
		l := lexer.New(`
rule test_rule {
	strings:
		$ = "anonymous"
	condition:
		$
}
`)
		p := New(l)
		program, err := p.ParseRules()
		if err != nil {
			t.Errorf("ParseRules() with anonymous strings failed: %v", err)
		}
		if program == nil {
			t.Error("ParseRules() with anonymous strings returned nil program")
		}
		if len(program.Rules) != 1 {
			t.Errorf("ParseRules() with anonymous strings should return 1 rule, got %d", len(program.Rules))
		}
		if len(program.Rules[0].Strings) != 1 {
			t.Errorf("ParseRules() with anonymous strings should return 1 string, got %d", len(program.Rules[0].Strings))
		}
	})

	// Test parser with rule dependencies
	t.Run("rule_dependencies", func(t *testing.T) {
		l := lexer.New(`
rule base_rule {
	strings:
		$test = "test"
	condition:
		$test
}

rule dependent_rule {
	strings:
		$dep = "dep"
	condition:
		$dep and base_rule
}
`)
		p := New(l)
		program, err := p.ParseRules()
		if err != nil {
			t.Errorf("ParseRules() with rule dependencies failed: %v", err)
			for _, parseErr := range p.Errors() {
				t.Logf("Parser error: %v", parseErr)
			}
			return
		}
		if program == nil {
			t.Error("ParseRules() with rule dependencies returned nil program")
			return
		}
		if len(program.Rules) != 2 {
			t.Errorf("ParseRules() with rule dependencies should return 2 rules, got %d", len(program.Rules))
		}
	})

	// Test parser with time expressions
	t.Run("time_expressions", func(t *testing.T) {
		l := lexer.New(`
rule test_rule {
	strings:
		$test = "test"
	condition:
		$test and (now - filetime) > 86400
}
`)
		p := New(l)
		program, err := p.ParseRules()
		if err != nil {
			t.Errorf("ParseRules() with time expressions failed: %v", err)
		}
		if program == nil {
			t.Error("ParseRules() with time expressions returned nil program")
		}
		if len(program.Rules) != 1 {
			t.Errorf("ParseRules() with time expressions should return 1 rule, got %d", len(program.Rules))
		}
	})

	// Test parser with filesize
	t.Run("filesize", func(t *testing.T) {
		l := lexer.New(`
rule test_rule {
	strings:
		$test = "test"
	condition:
		$test and filesize > 1024
}
`)
		p := New(l)
		program, err := p.ParseRules()
		if err != nil {
			t.Errorf("ParseRules() with filesize failed: %v", err)
		}
		if program == nil {
			t.Error("ParseRules() with filesize returned nil program")
		}
		if len(program.Rules) != 1 {
			t.Errorf("ParseRules() with filesize should return 1 rule, got %d", len(program.Rules))
		}
	})

	// Test parser with entrypoint
	t.Run("entrypoint", func(t *testing.T) {
		l := lexer.New(`
rule test_rule {
	strings:
		$test = "test"
	condition:
		$test and entrypoint == 0x1000
}
`)
		p := New(l)
		program, err := p.ParseRules()
		if err != nil {
			t.Errorf("ParseRules() with entrypoint failed: %v", err)
		}
		if program == nil {
			t.Error("ParseRules() with entrypoint returned nil program")
		}
		if len(program.Rules) != 1 {
			t.Errorf("ParseRules() with entrypoint should return 1 rule, got %d", len(program.Rules))
		}
	})
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
		p.ParseRules()
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
		}
		if len(program.Rules) != 1 {
			t.Errorf("ParseRules() with different string types should return 1 rule, got %d", len(program.Rules))
		}
		if len(program.Rules[0].Strings) != 3 {
			t.Errorf("ParseRules() with different string types should return 3 strings, got %d", len(program.Rules[0].Strings))
		}
	})
}
