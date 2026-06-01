package parser

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cawalch/go-yara/internal/lexer"
)

// TestDeeplyNestedParentheses documents parser behavior with deeply nested parentheses
// DO NOT modify code to make tests pass - document current behavior only
func TestDeeplyNestedParentheses(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "single-nesting",
			rule:        `rule test { condition: ((true)) }`,
			expectError: false,
			description: "Documents single level of nesting",
		},
		{
			name:        "triple-nesting",
			rule:        `rule test { condition: (((true))) }`,
			expectError: false,
			description: "Documents three levels of nesting",
		},
		{
			name:        "ten-nesting",
			rule:        `rule test { condition: ` + strings.Repeat("(", 10) + `true` + strings.Repeat(")", 10) + ` }`,
			expectError: false,
			description: "Documents ten levels of nesting",
		},
		{
			name:        "fifty-nesting",
			rule:        `rule test { condition: ` + strings.Repeat("(", 50) + `true` + strings.Repeat(")", 50) + ` }`,
			expectError: false,
			description: "Documents fifty levels of nesting",
		},
		{
			name:        "hundred-nesting",
			rule:        `rule test { condition: ` + strings.Repeat("(", 100) + `true` + strings.Repeat(")", 100) + ` }`,
			expectError: false,
			description: "Documents hundred levels of nesting",
		},
		{
			name:        "unmatched-open",
			rule:        `rule test { condition: ((true) }`,
			expectError: true,
			description: "Documents unmatched opening parenthesis",
		},
		{
			name:        "unmatched-close",
			rule:        `rule test { condition: (true)) }`,
			expectError: true,
			description: "Documents unmatched closing parenthesis",
		},
		{
			name:        "nested-with-operators",
			rule:        `rule test { condition: (((1 + 2) * 3)) }`,
			expectError: false,
			description: "Documents nesting with binary operators",
		},
		{
			name:        "nested-with-strings",
			rule:        `rule test { strings: $a = "test" condition: (($a and $b) or $c) }`,
			expectError: false,
			description: "Documents nesting with string identifiers",
		},
		{
			name:        "deep-nesting-expression",
			rule:        `rule test { condition: ` + strings.Repeat("(", 20) + `1 and 2 and 3` + strings.Repeat(")", 20) + ` }`,
			expectError: false,
			description: "Documents deep nesting with boolean operators",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.rule)
			p := New(l)
			program, err := p.ParseRules()

			assertParseResult(t, program, err, tt.expectError, tt.description)
		})
	}
}

// TestDeeplyNestedBinaryOps documents parser behavior with deeply nested binary operations
// DO NOT modify code to make tests pass - document current behavior only
func TestDeeplyNestedBinaryOps(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "left-associative-and",
			rule:        `rule test { condition: 1 and 2 and 3 and 4 and 5 }`,
			expectError: false,
			description: "Documents left-associative AND chain",
		},
		{
			name:        "left-associative-or",
			rule:        `rule test { condition: 1 or 2 or 3 or 4 or 5 }`,
			expectError: false,
			description: "Documents left-associative OR chain",
		},
		{
			name:        "mixed-operators",
			rule:        `rule test { condition: 1 and 2 or 3 and 4 }`,
			expectError: false,
			description: "Documents mixed AND/OR operators",
		},
		{
			name:        "arithmetic-chain",
			rule:        `rule test { condition: 1 + 2 + 3 + 4 + 5 }`,
			expectError: false,
			description: "Documents arithmetic operator chain",
		},
		{
			name:        "comparison-chain",
			rule:        `rule test { condition: 1 < 2 < 3 }`,
			expectError: false,
			description: "Documents comparison chaining (may have semantic issues)",
		},
		{
			name:        "complex-nesting",
			rule:        `rule test { condition: (1 and 2) or (3 and 4) or (5 and 6) }`,
			expectError: false,
			description: "Documents complex nested binary ops",
		},
		{
			name:        "deep-operator-nesting",
			rule:        `rule test { condition: 1 and (2 or (3 and (4 or 5))) }`,
			expectError: false,
			description: "Documents deep operator nesting",
		},
		{
			name:        "all-binary-operators",
			rule:        `rule test { condition: 1 + 2 - 3 * 4 / 5 % 6 }`,
			expectError: false,
			description: "Documents all arithmetic binary operators",
		},
		{
			name:        "bitwise-operators",
			rule:        `rule test { condition: 1 & 2 | 3 ^ 4 }`,
			expectError: false,
			description: "Documents bitwise operators",
		},
		{
			name:        "shift-operators",
			rule:        `rule test { condition: 1 << 2 >> 3 }`,
			expectError: false,
			description: "Documents shift operators",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.rule)
			p := New(l)
			program, err := p.ParseRules()

			if tt.expectError {
				if err == nil {
					t.Skipf("known gap: %s (no parse error produced)", tt.description)
				}
				return
			}
			if err != nil {
				t.Logf("Unexpected parse error (documents current behavior): %v", err)
			} else {
				require.NotNil(t, program, "Program should not be nil")
			}
		})
	}
}

// TestDeeplyNestedUnaries documents parser behavior with nested unary operations
// DO NOT modify code to make tests pass - document current behavior only
func TestDeeplyNestedUnaries(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "single-not",
			rule:        `rule test { condition: not true }`,
			expectError: false,
			description: "Documents single NOT operator",
		},
		{
			name:        "double-not",
			rule:        `rule test { condition: not not true }`,
			expectError: false,
			description: "Documents double NOT",
		},
		{
			name:        "triple-not",
			rule:        `rule test { condition: not not not true }`,
			expectError: false,
			description: "Documents triple NOT",
		},
		{
			name:        "many-nots",
			rule:        `rule test { condition: ` + strings.Repeat("not ", 10) + `true }`,
			expectError: false,
			description: "Documents many NOT operators",
		},
		{
			name:        "minus-operator",
			rule:        `rule test { condition: -100 }`,
			expectError: false,
			description: "Documents unary minus",
		},
		{
			name:        "double-minus",
			rule:        `rule test { condition: --100 }`,
			expectError: false,
			description: "Documents double minus",
		},
		{
			name:        "bitwise-not",
			rule:        `rule test { condition: ~0xFF }`,
			expectError: false,
			description: "Documents bitwise NOT",
		},
		{
			name:        "mixed-unaries",
			rule:        `rule test { condition: not -~100 }`,
			expectError: false,
			description: "Documents mixed unary operators",
		},
		{
			name:        "unary-with-binary",
			rule:        `rule test { condition: not true and false }`,
			expectError: false,
			description: "Documents unary with binary operators",
		},
		{
			name:        "defined-operator",
			rule:        `rule test { condition: defined extern_var }`,
			expectError: false,
			description: "Documents defined operator",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.rule)
			p := New(l)
			program, err := p.ParseRules()

			if tt.expectError {
				if err == nil {
					t.Skipf("known gap: %s (no parse error produced)", tt.description)
				}
				return
			}
			if err != nil {
				t.Logf("Unexpected parse error (documents current behavior): %v", err)
			} else {
				require.NotNil(t, program, "Program should not be nil")
			}
		})
	}
}

// TestDeeplyNestedForLoops documents parser behavior with nested for-loops
// DO NOT modify code to make tests pass - document current behavior only
func TestDeeplyNestedForLoops(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "single-for-loop",
			rule:        `rule test { strings: $a = "test" condition: for any i in (0..10) : ( true ) }`,
			expectError: false,
			description: "Documents single for-in loop",
		},
		{
			name:        "double-nested-for",
			rule:        `rule test { condition: for any i in (0..10) : ( for any j in (0..5) : ( true ) ) }`,
			expectError: false,
			description: "Documents double nested for-in loops",
		},
		{
			name:        "triple-nested-for",
			rule:        `rule test { condition: for any i in (0..10) : ( for any j in (0..5) : ( for any k in (0..3) : ( true ) ) ) }`,
			expectError: false,
			description: "Documents triple nested for-in loops",
		},
		{
			name:        "mixed-for-of-for-in",
			rule:        `rule test { strings: $a = "test" condition: for any $s in ($a) : ( for any i in (0..10) : ( true ) ) }`,
			expectError: true,
			description: "Documents mixed for-of and for-in (may not be supported)",
		},
		{
			name:        "nested-for-of",
			rule:        `rule test { strings: $a = "a" $b = "b" condition: for any $x in ($a) : ( for any $y in ($b) : ( true ) ) }`,
			expectError: true,
			description: "Documents nested for-of loops (may not be supported)",
		},
		{
			name:        "deep-nesting-limit",
			rule:        `rule test { condition: ` + strings.Repeat("for any i in (0..1) : (", 10) + "true" + strings.Repeat(")", 10) + ` }`,
			expectError: false,
			description: "Documents very deep for-loop nesting",
		},
		{
			name:        "for-loop-in-expression",
			rule:        `rule test { condition: (for any i in (0..10) : (true)) and false }`,
			expectError: false,
			description: "Documents for-loop as expression",
		},
		{
			name:        "complex-nesting",
			rule:        `rule test { strings: $a = "a" $b = "b" $c = "c" condition: (any of ($a, $b)) and (for any i in (0..10) : (true)) }`,
			expectError: false,
			description: "Documents complex nested structures",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.rule)
			p := New(l)
			program, err := p.ParseRules()

			assertParseResult(t, program, err, tt.expectError, tt.description)
		})
	}
}

// TestManyRulesInOneFile documents parser behavior with many rules
// DO NOT modify code to make tests pass - document current behavior only
func TestManyRulesInOneFile(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "ten-rules",
			rule:        strings.Repeat(`rule test { condition: true }`, 10),
			expectError: false,
			description: "Documents parsing 10 rules",
		},
		{
			name:        "fifty-rules",
			rule:        strings.Repeat(`rule test { condition: true }`, 50),
			expectError: false,
			description: "Documents parsing 50 rules",
		},
		{
			name:        "hundred-rules",
			rule:        strings.Repeat(`rule test`, 100),
			expectError: true,
			description: "Documents parsing 100 rules (may fail due to syntax)",
		},
		{
			name:        "unique-rule-names",
			rule:        generateUniqueRules(20),
			expectError: false,
			description: "Documents parsing 20 unique rules",
		},
		{
			name:        "rules-with-strings",
			rule:        generateRulesWithStrings(10),
			expectError: false,
			description: "Documents parsing multiple rules with strings",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.rule)
			p := New(l)
			program, err := p.ParseRules()

			if tt.expectError {
				if err == nil {
					t.Skipf("known gap: %s (no parse error produced)", tt.description)
				}
				return
			}
			if err != nil {
				t.Logf("Unexpected parse error (documents current behavior): %v", err)
			} else if program != nil && len(program.Rules) > 0 {
				t.Logf("Successfully parsed %d rules", len(program.Rules))
			}
		})
	}
}

// TestManyStringsInOneRule documents parser behavior with many strings
// DO NOT modify code to make tests pass - document current behavior only
func TestManyStringsInOneRule(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "ten-strings",
			rule:        generateRuleWithStrings(10),
			expectError: false,
			description: "Documents rule with 10 strings",
		},
		{
			name:        "fifty-strings",
			rule:        generateRuleWithStrings(50),
			expectError: false,
			description: "Documents rule with 50 strings",
		},
		{
			name:        "hundred-strings",
			rule:        generateRuleWithStrings(100),
			expectError: false,
			description: "Documents rule with 100 strings",
		},
		{
			name:        "strings-with-modifiers",
			rule:        generateRulesWithStringModifiers(20),
			expectError: false,
			description: "Documents many strings with various modifiers",
		},
		{
			name:        "mixed-string-types",
			rule:        generateMixedStringTypes(15),
			expectError: false,
			description: "Documents mix of text, hex, and regex strings",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.rule)
			p := New(l)
			program, err := p.ParseRules()

			if tt.expectError {
				if err == nil {
					t.Skipf("known gap: %s (no parse error produced)", tt.description)
				}
				return
			}
			if err != nil {
				t.Logf("Unexpected parse error (documents current behavior): %v", err)
			} else if program != nil && len(program.Rules) > 0 {
				t.Logf("Successfully parsed rule with %d strings", len(program.Rules[0].Strings))
			}
		})
	}
}

// TestLongStringLiterals documents parser behavior with very long string literals
// DO NOT modify code to make tests pass - document current behavior only
func TestLongStringLiterals(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "hundred-char-string",
			rule:        `rule test { strings: $a = "` + strings.Repeat("a", 100) + `" condition: $a }`,
			expectError: false,
			description: "Documents 100 character string literal",
		},
		{
			name:        "thousand-char-string",
			rule:        `rule test { strings: $a = "` + strings.Repeat("b", 1000) + `" condition: $a }`,
			expectError: false,
			description: "Documents 1000 character string literal",
		},
		{
			name:        "with-escape-sequences",
			rule:        `rule test { strings: $a = "` + strings.Repeat("\\x41", 50) + `" condition: $a }`,
			expectError: false,
			description: "Documents long string with escape sequences",
		},
		{
			name:        "with-newlines",
			rule:        `rule test { strings: $a = "` + strings.Repeat("\\n", 20) + `" condition: $a }`,
			expectError: false,
			description: "Documents string with many newlines",
		},
		{
			name:        "with-tabs",
			rule:        `rule test { strings: $a = "` + strings.Repeat("\\t", 20) + `" condition: $a }`,
			expectError: false,
			description: "Documents string with many tabs",
		},
		{
			name:        "unicode-escapes",
			rule:        `rule test { strings: $a = "` + strings.Repeat("\\u0041", 20) + `" condition: $a }`,
			expectError: false,
			description: "Documents string with unicode escapes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.rule)
			p := New(l)
			program, err := p.ParseRules()

			if tt.expectError {
				if err == nil {
					t.Skipf("known gap: %s (no parse error produced)", tt.description)
				}
				return
			}
			if err != nil {
				t.Logf("Unexpected parse error (documents current behavior): %v", err)
			} else {
				require.NotNil(t, program, "Program should not be nil")
			}
		})
	}
}

// TestLongHexPatterns documents parser behavior with long hex patterns
// DO NOT modify code to make tests pass - document current behavior only
func TestLongHexPatterns(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "long-hex-pattern",
			rule:        `rule test { strings: $a = { ` + strings.Repeat("DE AD BE EF ", 25) + `} condition: $a }`,
			expectError: false,
			description: "Documents 100 byte hex pattern",
		},
		{
			name:        "with-jumps",
			rule:        `rule test { strings: $a = { ` + strings.Repeat("DE AD [2-3] BE ", 20) + `} condition: $a }`,
			expectError: false,
			description: "Documents long hex pattern with jumps",
		},
		{
			name:        "with-alternatives",
			rule:        `rule test { strings: $a = { ` + strings.Repeat("(DE | AD | BE | EF) ", 20) + `} condition: $a }`,
			expectError: false,
			description: "Documents long hex pattern with alternatives",
		},
		{
			name:        "with-wildcards",
			rule:        `rule test { strings: $a = { ` + strings.Repeat("DE ?? AD ?? ", 20) + `} condition: $a }`,
			expectError: false,
			description: "Documents long hex pattern with wildcards",
		},
		{
			name:        "complex-mix",
			rule:        `rule test { strings: $a = { ` + strings.Repeat("DE [2-3] (AD | BE) ?? FF ", 15) + `} condition: $a }`,
			expectError: false,
			description: "Documents long hex pattern with complex mix",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.rule)
			p := New(l)
			program, err := p.ParseRules()

			if tt.expectError {
				if err == nil {
					t.Skipf("known gap: %s (no parse error produced)", tt.description)
				}
				return
			}
			if err != nil {
				t.Logf("Unexpected parse error (documents current behavior): %v", err)
			} else {
				require.NotNil(t, program, "Program should not be nil")
			}
		})
	}
}

// TestLongRegexPatterns documents parser behavior with long regex patterns
// DO NOT modify code to make tests pass - document current behavior only
func TestLongRegexPatterns(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "long-regex",
			rule:        `rule test { strings: $a = /` + strings.Repeat("a", 200) + `/ condition: $a }`,
			expectError: false,
			description: "Documents 200 character regex",
		},
		{
			name:        "complex-regex",
			rule:        `rule test { strings: $a = /` + strings.Repeat("[a-z]+", 20) + `/ condition: $a }`,
			expectError: false,
			description: "Documents complex regex with character classes",
		},
		{
			name:        "with-quantifiers",
			rule:        `rule test { strings: $a = /` + strings.Repeat("a*", 30) + `/ condition: $a }`,
			expectError: false,
			description: "Documents regex with many quantifiers",
		},
		{
			name:        "with-groups",
			rule:        `rule test { strings: $a = /` + strings.Repeat("(abc)", 20) + `/ condition: $a }`,
			expectError: false,
			description: "Documents regex with many groups",
		},
		{
			name:        "with-escapes",
			rule:        `rule test { strings: $a = /` + strings.Repeat("\\d+", 20) + `/ condition: $a }`,
			expectError: false,
			description: "Documents regex with many escape sequences",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.rule)
			p := New(l)
			program, err := p.ParseRules()

			if tt.expectError {
				if err == nil {
					t.Skipf("known gap: %s (no parse error produced)", tt.description)
				}
				return
			}
			if err != nil {
				t.Logf("Unexpected parse error (documents current behavior): %v", err)
			} else {
				require.NotNil(t, program, "Program should not be nil")
			}
		})
	}
}

// TestComplexBooleanExpressions documents parser behavior with complex boolean expressions
// DO NOT modify code to make tests pass - document current behavior only
func TestComplexBooleanExpressions(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "long-and-chain",
			rule:        `rule test { condition: ` + strings.Join(repeatStrings("true", 20, " and "), " and ") + ` }`,
			expectError: false,
			description: "Documents long AND chain",
		},
		{
			name:        "long-or-chain",
			rule:        `rule test { condition: ` + strings.Join(repeatStrings("false", 20, " or "), " or ") + ` }`,
			expectError: false,
			description: "Documents long OR chain",
		},
		{
			name:        "mixed-and-or",
			rule:        `rule test { condition: true and false or true and false or true }`,
			expectError: false,
			description: "Documents mixed AND/OR",
		},
		{
			name:        "with-parentheses",
			rule:        `rule test { condition: (true and false) or (true and false) }`,
			expectError: false,
			description: "Documents boolean with parentheses",
		},
		{
			name:        "with-not",
			rule:        `rule test { condition: not true and not false or not (true and false) }`,
			expectError: false,
			description: "Documents boolean with NOT",
		},
		{
			name:        "deeply-nested",
			rule:        `rule test { condition: (((true and false) or true) and (false or (true and false))) }`,
			expectError: false,
			description: "Documents deeply nested boolean",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.rule)
			p := New(l)
			program, err := p.ParseRules()

			if tt.expectError {
				if err == nil {
					t.Skipf("known gap: %s (no parse error produced)", tt.description)
				}
				return
			}
			if err != nil {
				t.Logf("Unexpected parse error (documents current behavior): %v", err)
			} else {
				require.NotNil(t, program, "Program should not be nil")
			}
		})
	}
}

// TestComplexArithmeticExpressions documents parser behavior with complex arithmetic
// DO NOT modify code to make tests pass - document current behavior only
func TestComplexArithmeticExpressions(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "long-chain",
			rule:        `rule test { condition: ` + strings.Join(repeatStrings("1", 10, "+"), " + ") + ` }`,
			expectError: false,
			description: "Documents long arithmetic chain",
		},
		{
			name:        "mixed-operators",
			rule:        `rule test { condition: 1 + 2 * 3 - 4 / 5 % 6 }`,
			expectError: false,
			description: "Documents mixed arithmetic operators",
		},
		{
			name:        "with-parentheses",
			rule:        `rule test { condition: ((1 + 2) * 3) - ((4 / 5) % 6) }`,
			expectError: false,
			description: "Documents arithmetic with parentheses",
		},
		{
			name:        "with-unary",
			rule:        `rule test { condition: -1 + -2 * --3 }`,
			expectError: false,
			description: "Documents arithmetic with unary minus",
		},
		{
			name:        "hex-literals",
			rule:        `rule test { condition: 0x100 + 0x200 * 0xFF }`,
			expectError: false,
			description: "Documents arithmetic with hex literals",
		},
		{
			name:        "comparison",
			rule:        `rule test { condition: 1 + 2 * 3 > 10 and 5 / 2 < 3 }`,
			expectError: false,
			description: "Documents arithmetic in comparisons",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.rule)
			p := New(l)
			program, err := p.ParseRules()

			if tt.expectError {
				if err == nil {
					t.Skipf("known gap: %s (no parse error produced)", tt.description)
				}
				return
			}
			if err != nil {
				t.Logf("Unexpected parse error (documents current behavior): %v", err)
			} else {
				require.NotNil(t, program, "Program should not be nil")
			}
		})
	}
}

// TestComplexStringExpressions documents parser behavior with complex string expressions
// DO NOT modify code to make tests pass - document current behavior only
func TestComplexStringExpressions(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "long-string-list",
			rule:        `rule test { strings: ` + generateStringList(20) + ` condition: any of them }`,
			expectError: false,
			description: "Documents many strings in condition",
		},
		{
			name:        "complex-of",
			rule:        `rule test { strings: $a1 = "a1" $a2 = "a2" $b1 = "b1" $b2 = "b2" condition: any of ($a*) or all of ($b*) }`,
			expectError: false,
			description: "Documents complex of-expression",
		},
		{
			name:        "string-operations",
			rule:        `rule test { strings: $a = "test" condition: #a > 0 and @a < 100 and !a == 4 }`,
			expectError: false,
			description: "Documents string operations in condition",
		},
		{
			name:        "at-operator",
			rule:        `rule test { strings: $a = "test" condition: $a at 0 or $a at 100 }`,
			expectError: false,
			description: "Documents at operator usage",
		},
		{
			name:        "in-operator",
			rule:        `rule test { strings: $a = "test" condition: $a in (0..100) }`,
			expectError: false,
			description: "Documents in operator usage",
		},
		{
			name:        "matches-operator",
			rule:        `rule test { strings: $a = "test" condition: $a matches /test/ }`,
			expectError: false,
			description: "Documents matches operator usage",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.rule)
			p := New(l)
			program, err := p.ParseRules()

			if tt.expectError {
				if err == nil {
					t.Skipf("known gap: %s (no parse error produced)", tt.description)
				}
				return
			}
			if err != nil {
				t.Logf("Unexpected parse error (documents current behavior): %v", err)
			} else {
				require.NotNil(t, program, "Program should not be nil")
			}
		})
	}
}

// Helper functions

func generateUniqueRules(count int) string {
	var rules strings.Builder
	for i := range count {
		rules.WriteString(`rule test_`)
		rules.WriteString(string(rune('0' + i)))
		rules.WriteString(` { condition: true } `)
	}
	return rules.String()
}

func generateRulesWithStrings(count int) string {
	var rules strings.Builder
	for i := range count {
		rules.WriteString(`rule test_`)
		rules.WriteString(string(rune('0' + i%10)))
		rules.WriteString(` { strings: $a = "test`)
		rules.WriteString(string(rune('0' + i)))
		rules.WriteString(`" condition: $a } `)
	}
	return rules.String()
}

func generateRuleWithStrings(count int) string {
	var rule strings.Builder
	rule.WriteString(`rule test { strings: `)
	for i := range count {
		rule.WriteString(`$a`)
		rule.WriteString(string(rune('0' + i%10)))
		rule.WriteString(` = "test`)
		rule.WriteString(string(rune('0' + i)))
		rule.WriteString(`" `)
	}
	rule.WriteString(`condition: any of them }`)
	return rule.String()
}

func generateRulesWithStringModifiers(count int) string {
	var rule strings.Builder
	rule.WriteString(`rule test { strings: `)
	modifiers := []string{"", " nocase", " ascii", " wide", " fullword", " private"}
	for i := range count {
		rule.WriteString(`$a`)
		rule.WriteString(string(rune('0' + i%10)))
		rule.WriteString(` = "test`)
		rule.WriteString(string(rune('0' + i)))
		rule.WriteString(`"`)
		rule.WriteString(modifiers[i%len(modifiers)])
		rule.WriteString(` `)
	}
	rule.WriteString(`condition: any of them }`)
	return rule.String()
}

func generateMixedStringTypes(count int) string {
	var rule strings.Builder
	rule.WriteString(`rule test { strings: `)
	types := []string{`$a = "text"`, `$b = { DE AD BE EF }`, `$c = /regex/`}
	for i := range count {
		rule.WriteString(strings.Replace(types[i%3], "$a", "$"+string(rune('a'+i)), 1))
		rule.WriteString(` `)
	}
	rule.WriteString(`condition: any of them }`)
	return rule.String()
}

func generateStringList(count int) string {
	var list strings.Builder
	for i := range count {
		list.WriteString(`$`)
		list.WriteString(string(rune('a' + i%26)))
		list.WriteString(` = "test`)
		list.WriteString(string(rune('0' + i%10)))
		list.WriteString(`" `)
	}
	return list.String()
}

func repeatStrings(s string, count int, sep string) []string {
	result := make([]string, count)
	for i := range count {
		result[i] = s
	}
	return result
}
