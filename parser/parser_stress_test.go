package parser

import (
	"strconv"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
)

// TestDeeplyNestedParentheses documents parser behavior with deeply nested parentheses
func TestDeeplyNestedParentheses(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expect      parseExpectation
		description string
	}{
		{
			name:        "single-nesting",
			rule:        `rule test { condition: ((true)) }`,
			expect:      parseOK,
			description: "Documents single level of nesting",
		},
		{
			name:        "triple-nesting",
			rule:        `rule test { condition: (((true))) }`,
			expect:      parseOK,
			description: "Documents three levels of nesting",
		},
		{
			name:        "ten-nesting",
			rule:        `rule test { condition: ` + strings.Repeat("(", 10) + `true` + strings.Repeat(")", 10) + ` }`,
			expect:      parseOK,
			description: "Documents ten levels of nesting",
		},
		{
			name:        "fifty-nesting",
			rule:        `rule test { condition: ` + strings.Repeat("(", 50) + `true` + strings.Repeat(")", 50) + ` }`,
			expect:      parseOK,
			description: "Documents fifty levels of nesting",
		},
		{
			name:        "hundred-nesting",
			rule:        `rule test { condition: ` + strings.Repeat("(", 100) + `true` + strings.Repeat(")", 100) + ` }`,
			expect:      parseOK,
			description: "Documents hundred levels of nesting",
		},
		{
			name:        "unmatched-open",
			rule:        `rule test { condition: ((true) }`,
			expect:      parseError,
			description: "Documents unmatched opening parenthesis",
		},
		{
			name:        "unmatched-close",
			rule:        `rule test { condition: (true)) }`,
			expect:      parseError,
			description: "Documents unmatched closing parenthesis",
		},
		{
			name:        "nested-with-operators",
			rule:        `rule test { condition: (((1 + 2) * 3)) }`,
			expect:      parseOK,
			description: "Documents nesting with binary operators",
		},
		{
			name:        "nested-with-strings",
			rule:        `rule test { strings: $a = "test" condition: (($a and $b) or $c) }`,
			expect:      parseOK,
			description: "Documents nesting with string identifiers",
		},
		{
			name:        "deep-nesting-expression",
			rule:        `rule test { condition: ` + strings.Repeat("(", 20) + `1 and 2 and 3` + strings.Repeat(")", 20) + ` }`,
			expect:      parseOK,
			description: "Documents deep nesting with boolean operators",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.rule)
			p := New(l)
			program, err := p.ParseRules()

			assertParseResult(t, program, err, tt.expect, tt.description)
		})
	}
}

// TestDeeplyNestedBinaryOps documents parser behavior with deeply nested binary operations
func TestDeeplyNestedBinaryOps(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expect      parseExpectation
		description string
	}{
		{
			name:        "left-associative-and",
			rule:        `rule test { condition: 1 and 2 and 3 and 4 and 5 }`,
			expect:      parseOK,
			description: "Documents left-associative AND chain",
		},
		{
			name:        "left-associative-or",
			rule:        `rule test { condition: 1 or 2 or 3 or 4 or 5 }`,
			expect:      parseOK,
			description: "Documents left-associative OR chain",
		},
		{
			name:        "mixed-operators",
			rule:        `rule test { condition: 1 and 2 or 3 and 4 }`,
			expect:      parseOK,
			description: "Documents mixed AND/OR operators",
		},
		{
			name:        "arithmetic-chain",
			rule:        `rule test { condition: 1 + 2 + 3 + 4 + 5 }`,
			expect:      parseOK,
			description: "Documents arithmetic operator chain",
		},
		{
			name:        "comparison-chain",
			rule:        `rule test { condition: 1 < 2 < 3 }`,
			expect:      parseOK,
			description: "Documents comparison chaining (may have semantic issues)",
		},
		{
			name:        "complex-nesting",
			rule:        `rule test { condition: (1 and 2) or (3 and 4) or (5 and 6) }`,
			expect:      parseOK,
			description: "Documents complex nested binary ops",
		},
		{
			name:        "deep-operator-nesting",
			rule:        `rule test { condition: 1 and (2 or (3 and (4 or 5))) }`,
			expect:      parseOK,
			description: "Documents deep operator nesting",
		},
		{
			name:        "all-binary-operators",
			rule:        `rule test { condition: 1 + 2 - 3 * 4 / 5 % 6 }`,
			expect:      parseOK,
			description: "Documents all arithmetic binary operators",
		},
		{
			name:        "bitwise-operators",
			rule:        `rule test { condition: 1 & 2 | 3 ^ 4 }`,
			expect:      parseOK,
			description: "Documents bitwise operators",
		},
		{
			name:        "shift-operators",
			rule:        `rule test { condition: 1 << 2 >> 3 }`,
			expect:      parseOK,
			description: "Documents shift operators",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.rule)
			p := New(l)
			program, err := p.ParseRules()

			assertParseResult(t, program, err, tt.expect, tt.description)
		})
	}
}

// TestDeeplyNestedUnaries documents parser behavior with nested unary operations
func TestDeeplyNestedUnaries(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expect      parseExpectation
		description string
	}{
		{
			name:        "single-not",
			rule:        `rule test { condition: not true }`,
			expect:      parseOK,
			description: "Documents single NOT operator",
		},
		{
			name:        "double-not",
			rule:        `rule test { condition: not not true }`,
			expect:      parseOK,
			description: "Documents double NOT",
		},
		{
			name:        "triple-not",
			rule:        `rule test { condition: not not not true }`,
			expect:      parseOK,
			description: "Documents triple NOT",
		},
		{
			name:        "many-nots",
			rule:        `rule test { condition: ` + strings.Repeat("not ", 10) + `true }`,
			expect:      parseOK,
			description: "Documents many NOT operators",
		},
		{
			name:        "minus-operator",
			rule:        `rule test { condition: -100 }`,
			expect:      parseOK,
			description: "Documents unary minus",
		},
		{
			name:        "double-minus",
			rule:        `rule test { condition: --100 }`,
			expect:      parseOK,
			description: "Documents double minus",
		},
		{
			name:        "bitwise-not",
			rule:        `rule test { condition: ~0xFF }`,
			expect:      parseOK,
			description: "Documents bitwise NOT",
		},
		{
			name:        "mixed-unaries",
			rule:        `rule test { condition: not -~100 }`,
			expect:      parseOK,
			description: "Documents mixed unary operators",
		},
		{
			name:        "unary-with-binary",
			rule:        `rule test { condition: not true and false }`,
			expect:      parseOK,
			description: "Documents unary with binary operators",
		},
		{
			name:        "defined-operator",
			rule:        `rule test { condition: defined extern_var }`,
			expect:      parseOK,
			description: "Documents defined operator",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.rule)
			p := New(l)
			program, err := p.ParseRules()

			assertParseResult(t, program, err, tt.expect, tt.description)
		})
	}
}

// TestDeeplyNestedForLoops documents parser behavior with nested for-loops
func TestDeeplyNestedForLoops(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expect      parseExpectation
		description string
	}{
		{
			name:        "single-for-loop",
			rule:        `rule test { strings: $a = "test" condition: for any i in (0..10) : ( true ) }`,
			expect:      parseOK,
			description: "Documents single for-in loop",
		},
		{
			name:        "double-nested-for",
			rule:        `rule test { condition: for any i in (0..10) : ( for any j in (0..5) : ( true ) ) }`,
			expect:      parseOK,
			description: "Documents double nested for-in loops",
		},
		{
			name:        "triple-nested-for",
			rule:        `rule test { condition: for any i in (0..10) : ( for any j in (0..5) : ( for any k in (0..3) : ( true ) ) ) }`,
			expect:      parseOK,
			description: "Documents triple nested for-in loops",
		},
		{
			name:        "mixed-for-of-for-in",
			rule:        `rule test { strings: $a = "test" condition: for any $s in ($a) : ( for any i in (0..10) : ( true ) ) }`,
			expect:      parseError,
			description: "Documents mixed for-of and for-in (may not be supported)",
		},
		{
			name:        "nested-for-of",
			rule:        `rule test { strings: $a = "a" $b = "b" condition: for any $x in ($a) : ( for any $y in ($b) : ( true ) ) }`,
			expect:      parseError,
			description: "Documents nested for-of loops (may not be supported)",
		},
		{
			name:        "deep-nesting-limit",
			rule:        `rule test { condition: ` + strings.Repeat("for any i in (0..1) : (", 10) + "true" + strings.Repeat(")", 10) + ` }`,
			expect:      parseOK,
			description: "Documents very deep for-loop nesting",
		},
		{
			name:        "for-loop-in-expression",
			rule:        `rule test { condition: (for any i in (0..10) : (true)) and false }`,
			expect:      parseOK,
			description: "Documents for-loop as expression",
		},
		{
			name:        "complex-nesting",
			rule:        `rule test { strings: $a = "a" $b = "b" $c = "c" condition: (any of ($a, $b)) and (for any i in (0..10) : (true)) }`,
			expect:      parseOK,
			description: "Documents complex nested structures",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.rule)
			p := New(l)
			program, err := p.ParseRules()

			assertParseResult(t, program, err, tt.expect, tt.description)
		})
	}
}

// TestManyRulesInOneFile documents parser behavior with many rules
func TestManyRulesInOneFile(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expect      parseExpectation
		description string
	}{
		{
			name:        "ten-rules",
			rule:        strings.Repeat(`rule test { condition: true }`, 10),
			expect:      parseOK,
			description: "Documents parsing 10 rules",
		},
		{
			name:        "fifty-rules",
			rule:        strings.Repeat(`rule test { condition: true }`, 50),
			expect:      parseOK,
			description: "Documents parsing 50 rules",
		},
		{
			name:        "hundred-rules",
			rule:        strings.Repeat(`rule test`, 100),
			expect:      parseError,
			description: "Documents parsing 100 rules (may fail due to syntax)",
		},
		{
			name:        "unique-rule-names",
			rule:        generateUniqueRules(20),
			expect:      parseOK,
			description: "Documents parsing 20 unique rules",
		},
		{
			name:        "rules-with-strings",
			rule:        generateRulesWithStrings(10),
			expect:      parseOK,
			description: "Documents parsing multiple rules with strings",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.rule)
			p := New(l)
			program, err := p.ParseRules()

			assertParseResult(t, program, err, tt.expect, tt.description)
			if err == nil && program != nil && len(program.Rules) > 0 {
				t.Logf("Successfully parsed %d rules", len(program.Rules))
			}
		})
	}
}

// TestManyStringsInOneRule documents parser behavior with many strings
func TestManyStringsInOneRule(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expect      parseExpectation
		description string
	}{
		{
			name:        "ten-strings",
			rule:        generateRuleWithStrings(10),
			expect:      parseOK,
			description: "Documents rule with 10 strings",
		},
		{
			name:        "fifty-strings",
			rule:        generateRuleWithStrings(50),
			expect:      parseOK,
			description: "Documents rule with 50 strings",
		},
		{
			name:        "hundred-strings",
			rule:        generateRuleWithStrings(100),
			expect:      parseOK,
			description: "Documents rule with 100 strings",
		},
		{
			name:        "strings-with-modifiers",
			rule:        generateRulesWithStringModifiers(20),
			expect:      parseOK,
			description: "Documents many strings with various modifiers",
		},
		{
			name:        "mixed-string-types",
			rule:        generateMixedStringTypes(15),
			expect:      parseOK,
			description: "Documents mix of text, hex, and regex strings",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.rule)
			p := New(l)
			program, err := p.ParseRules()

			assertParseResult(t, program, err, tt.expect, tt.description)
			if err == nil && program != nil && len(program.Rules) > 0 {
				t.Logf("Successfully parsed rule with %d strings", len(program.Rules[0].Strings))
			}
		})
	}
}

// TestLongStringLiterals documents parser behavior with very long string literals
func TestLongStringLiterals(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expect      parseExpectation
		description string
	}{
		{
			name:        "hundred-char-string",
			rule:        `rule test { strings: $a = "` + strings.Repeat("a", 100) + `" condition: $a }`,
			expect:      parseOK,
			description: "Documents 100 character string literal",
		},
		{
			name:        "thousand-char-string",
			rule:        `rule test { strings: $a = "` + strings.Repeat("b", 1000) + `" condition: $a }`,
			expect:      parseOK,
			description: "Documents 1000 character string literal",
		},
		{
			name:        "with-escape-sequences",
			rule:        `rule test { strings: $a = "` + strings.Repeat("\\x41", 50) + `" condition: $a }`,
			expect:      parseOK,
			description: "Documents long string with escape sequences",
		},
		{
			name:        "with-newlines",
			rule:        `rule test { strings: $a = "` + strings.Repeat("\\n", 20) + `" condition: $a }`,
			expect:      parseOK,
			description: "Documents string with many newlines",
		},
		{
			name:        "with-tabs",
			rule:        `rule test { strings: $a = "` + strings.Repeat("\\t", 20) + `" condition: $a }`,
			expect:      parseOK,
			description: "Documents string with many tabs",
		},
		{
			name:        "unicode-escapes",
			rule:        `rule test { strings: $a = "` + strings.Repeat("\\u0041", 20) + `" condition: $a }`,
			expect:      parseError,
			description: "Rejects unsupported Unicode escape sequences",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.rule)
			p := New(l)
			program, err := p.ParseRules()

			assertParseResult(t, program, err, tt.expect, tt.description)
		})
	}
}

// TestLongHexPatterns documents parser behavior with long hex patterns
func TestLongHexPatterns(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expect      parseExpectation
		description string
	}{
		{
			name:        "long-hex-pattern",
			rule:        `rule test { strings: $a = { ` + strings.Repeat("DE AD BE EF ", 25) + `} condition: $a }`,
			expect:      parseOK,
			description: "Documents 100 byte hex pattern",
		},
		{
			name:        "with-jumps",
			rule:        `rule test { strings: $a = { ` + strings.Repeat("DE AD [2-3] BE ", 20) + `} condition: $a }`,
			expect:      parseOK,
			description: "Documents long hex pattern with jumps",
		},
		{
			name:        "with-alternatives",
			rule:        `rule test { strings: $a = { ` + strings.Repeat("(DE | AD | BE | EF) ", 20) + `} condition: $a }`,
			expect:      parseOK,
			description: "Documents long hex pattern with alternatives",
		},
		{
			name:        "with-wildcards",
			rule:        `rule test { strings: $a = { ` + strings.Repeat("DE ?? AD ?? ", 20) + `} condition: $a }`,
			expect:      parseOK,
			description: "Documents long hex pattern with wildcards",
		},
		{
			name:        "complex-mix",
			rule:        `rule test { strings: $a = { ` + strings.Repeat("DE [2-3] (AD | BE) ?? FF ", 15) + `} condition: $a }`,
			expect:      parseOK,
			description: "Documents long hex pattern with complex mix",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.rule)
			p := New(l)
			program, err := p.ParseRules()

			assertParseResult(t, program, err, tt.expect, tt.description)
		})
	}
}

// TestLongRegexPatterns documents parser behavior with long regex patterns
func TestLongRegexPatterns(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expect      parseExpectation
		description string
	}{
		{
			name:        "long-regex",
			rule:        `rule test { strings: $a = /` + strings.Repeat("a", 200) + `/ condition: $a }`,
			expect:      parseOK,
			description: "Documents 200 character regex",
		},
		{
			name:        "complex-regex",
			rule:        `rule test { strings: $a = /` + strings.Repeat("[a-z]+", 20) + `/ condition: $a }`,
			expect:      parseOK,
			description: "Documents complex regex with character classes",
		},
		{
			name:        "with-quantifiers",
			rule:        `rule test { strings: $a = /` + strings.Repeat("a*", 30) + `/ condition: $a }`,
			expect:      parseOK,
			description: "Documents regex with many quantifiers",
		},
		{
			name:        "with-groups",
			rule:        `rule test { strings: $a = /` + strings.Repeat("(abc)", 20) + `/ condition: $a }`,
			expect:      parseOK,
			description: "Documents regex with many groups",
		},
		{
			name:        "with-escapes",
			rule:        `rule test { strings: $a = /` + strings.Repeat("\\d+", 20) + `/ condition: $a }`,
			expect:      parseOK,
			description: "Documents regex with many escape sequences",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.rule)
			p := New(l)
			program, err := p.ParseRules()

			assertParseResult(t, program, err, tt.expect, tt.description)
		})
	}
}

// TestComplexBooleanExpressions documents parser behavior with complex boolean expressions
func TestComplexBooleanExpressions(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expect      parseExpectation
		description string
	}{
		{
			name:        "long-and-chain",
			rule:        `rule test { condition: ` + strings.Join(repeatStrings("true", 20, " and "), " and ") + ` }`,
			expect:      parseOK,
			description: "Documents long AND chain",
		},
		{
			name:        "long-or-chain",
			rule:        `rule test { condition: ` + strings.Join(repeatStrings("false", 20, " or "), " or ") + ` }`,
			expect:      parseOK,
			description: "Documents long OR chain",
		},
		{
			name:        "mixed-and-or",
			rule:        `rule test { condition: true and false or true and false or true }`,
			expect:      parseOK,
			description: "Documents mixed AND/OR",
		},
		{
			name:        "with-parentheses",
			rule:        `rule test { condition: (true and false) or (true and false) }`,
			expect:      parseOK,
			description: "Documents boolean with parentheses",
		},
		{
			name:        "with-not",
			rule:        `rule test { condition: not true and not false or not (true and false) }`,
			expect:      parseOK,
			description: "Documents boolean with NOT",
		},
		{
			name:        "deeply-nested",
			rule:        `rule test { condition: (((true and false) or true) and (false or (true and false))) }`,
			expect:      parseOK,
			description: "Documents deeply nested boolean",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.rule)
			p := New(l)
			program, err := p.ParseRules()

			assertParseResult(t, program, err, tt.expect, tt.description)
		})
	}
}

// TestComplexArithmeticExpressions documents parser behavior with complex arithmetic
func TestComplexArithmeticExpressions(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expect      parseExpectation
		description string
	}{
		{
			name:        "long-chain",
			rule:        `rule test { condition: ` + strings.Join(repeatStrings("1", 10, "+"), " + ") + ` }`,
			expect:      parseOK,
			description: "Documents long arithmetic chain",
		},
		{
			name:        "mixed-operators",
			rule:        `rule test { condition: 1 + 2 * 3 - 4 / 5 % 6 }`,
			expect:      parseOK,
			description: "Documents mixed arithmetic operators",
		},
		{
			name:        "with-parentheses",
			rule:        `rule test { condition: ((1 + 2) * 3) - ((4 / 5) % 6) }`,
			expect:      parseOK,
			description: "Documents arithmetic with parentheses",
		},
		{
			name:        "with-unary",
			rule:        `rule test { condition: -1 + -2 * --3 }`,
			expect:      parseOK,
			description: "Documents arithmetic with unary minus",
		},
		{
			name:        "hex-literals",
			rule:        `rule test { condition: 0x100 + 0x200 * 0xFF }`,
			expect:      parseOK,
			description: "Documents arithmetic with hex literals",
		},
		{
			name:        "comparison",
			rule:        `rule test { condition: 1 + 2 * 3 > 10 and 5 / 2 < 3 }`,
			expect:      parseOK,
			description: "Documents arithmetic in comparisons",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.rule)
			p := New(l)
			program, err := p.ParseRules()

			assertParseResult(t, program, err, tt.expect, tt.description)
		})
	}
}

// TestComplexStringExpressions documents parser behavior with complex string expressions
func TestComplexStringExpressions(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expect      parseExpectation
		description string
	}{
		{
			name:        "long-string-list",
			rule:        `rule test { strings: ` + generateStringList(20) + ` condition: any of them }`,
			expect:      parseOK,
			description: "Documents many strings in condition",
		},
		{
			name:        "complex-of",
			rule:        `rule test { strings: $a1 = "a1" $a2 = "a2" $b1 = "b1" $b2 = "b2" condition: any of ($a*) or all of ($b*) }`,
			expect:      parseOK,
			description: "Documents complex of-expression",
		},
		{
			name:        "string-operations",
			rule:        `rule test { strings: $a = "test" condition: #a > 0 and @a < 100 and !a == 4 }`,
			expect:      parseOK,
			description: "Documents string operations in condition",
		},
		{
			name:        "at-operator",
			rule:        `rule test { strings: $a = "test" condition: $a at 0 or $a at 100 }`,
			expect:      parseOK,
			description: "Documents at operator usage",
		},
		{
			name:        "in-operator",
			rule:        `rule test { strings: $a = "test" condition: $a in (0..100) }`,
			expect:      parseOK,
			description: "Documents in operator usage",
		},
		{
			name:        "matches-operator",
			rule:        `rule test { strings: $a = "test" condition: $a matches /test/ }`,
			expect:      parseOK,
			description: "Documents matches operator usage",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.rule)
			p := New(l)
			program, err := p.ParseRules()

			assertParseResult(t, program, err, tt.expect, tt.description)
		})
	}
}

// Helper functions

func generateUniqueRules(count int) string {
	var rules strings.Builder
	for i := range count {
		rules.WriteString(`rule test_`)
		rules.WriteString(strconv.Itoa(i))
		rules.WriteString(` { condition: true } `)
	}
	return rules.String()
}

func generateRulesWithStrings(count int) string {
	var rules strings.Builder
	for i := range count {
		rules.WriteString(`rule test_`)
		rules.WriteString(strconv.Itoa(i))
		rules.WriteString(` { strings: $a = "test`)
		rules.WriteString(strconv.Itoa(i))
		rules.WriteString(`" condition: $a } `)
	}
	return rules.String()
}

func generateRuleWithStrings(count int) string {
	var rule strings.Builder
	rule.WriteString(`rule test { strings: `)
	for i := range count {
		rule.WriteString(`$a`)
		rule.WriteString(strconv.Itoa(i))
		rule.WriteString(` = "test`)
		rule.WriteString(strconv.Itoa(i))
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
		rule.WriteString(strconv.Itoa(i))
		rule.WriteString(` = "test`)
		rule.WriteString(strconv.Itoa(i))
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
