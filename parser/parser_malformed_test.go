package parser

import (
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
)

// TestUnterminatedStrings documents parser behavior with unterminated string literals
// DO NOT modify code to make tests pass - document current behavior only
func TestUnterminatedStrings(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "no-closing-quote",
			rule:        `rule test { strings: $a = "unclosed condition: true }`,
			expectError: true,
			description: "Documents string literal without closing quote",
		},
		{
			name:        "only-opening-quote",
			rule:        `rule test { strings: $a = " condition: true }`,
			expectError: true,
			description: "Documents string with only opening quote",
		},
		{
			name:        "unclosed-in-meta",
			rule:        `rule test { meta: author = "unclosed condition: true }`,
			expectError: true,
			description: "Documents unclosed string in meta section",
		},
		{
			name:        "multiple-unclosed",
			rule:        `rule test { strings: $a = "unclosed $b = "also condition: true }`,
			expectError: true,
			description: "Documents multiple unclosed strings",
		},
		{
			name:        "unclosed-with-escape",
			rule:        `rule test { strings: $a = "unclosed\x escape condition: true }`,
			expectError: true,
			description: "Documents unclosed string with escape sequence",
		},
		{
			name:        "unclosed-with-newline",
			rule:        "rule test { strings: $a = \"unclosed\nwith newline\" condition: true }",
			expectError: true,
			description: "Documents unclosed string with newline inside",
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

// TestUnterminatedHexPatterns documents parser behavior with unterminated hex patterns
// DO NOT modify code to make tests pass - document current behavior only
func TestUnterminatedHexPatterns(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "no-closing-brace",
			rule:        `rule test { strings: $a = { DE AD BE EF condition: true }`,
			expectError: true,
			description: "Documents hex pattern without closing brace",
		},
		{
			name:        "no-opening-brace",
			rule:        `rule test { strings: $a = DE AD BE EF } condition: true }`,
			expectError: true,
			description: "Documents hex pattern without opening brace",
		},
		{
			name:        "only-opening-brace",
			rule:        `rule test { strings: $a = { condition: true }`,
			expectError: true,
			description: "Documents hex pattern with only opening brace",
		},
		{
			name:        "incomplete-hex-byte",
			rule:        `rule test { strings: $a = { DE AD B condition: true }`,
			expectError: true,
			description: "Documents hex pattern with incomplete byte",
		},
		{
			name:        "invalid-hex-characters",
			rule:        `rule test { strings: $a = { DE GG BE EF } condition: true }`,
			expectError: false,
			description: "Known gap: parser does not validate hex characters (caught at compile time)",
		},
		{
			name:        "unterminated-jump",
			rule:        `rule test { strings: $a = { DE AD [2- condition: true }`,
			expectError: true,
			description: "Documents hex pattern with unterminated jump",
		},
		{
			name:        "unterminated-alternative",
			rule:        `rule test { strings: $a = { DE AD |  condition: true }`,
			expectError: true,
			description: "Documents hex pattern with unterminated alternative",
		},
		{
			name:        "invalid-wildcard",
			rule:        `rule test { strings: $a = { DE AD condition: true }`,
			expectError: true,
			description: "Documents hex pattern with incomplete wildcard",
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

// TestUnterminatedRegex documents parser behavior with unterminated regex patterns
// DO NOT modify code to make tests pass - document current behavior only
func TestUnterminatedRegex(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "no-closing-slash",
			rule:        `rule test { strings: $a = /unclosed pattern condition: true }`,
			expectError: true,
			description: "Documents regex without closing slash",
		},
		{
			name:        "only-opening-slash",
			rule:        `rule test { strings: $a = / condition: true }`,
			expectError: true,
			description: "Documents regex with only opening slash",
		},
		{
			name:        "unterminated-class",
			rule:        `rule test { strings: $a = /[unclosed condition: true }`,
			expectError: true,
			description: "Documents regex with unterminated character class",
		},
		{
			name:        "unterminated-group",
			rule:        `rule test { strings: $a = /(unclosed condition: true }`,
			expectError: true,
			description: "Documents regex with unterminated group",
		},
		{
			name:        "invalid-escape",
			rule:        `rule test { strings: $a = /\ condition: true }`,
			expectError: true,
			description: "Documents regex with trailing escape",
		},
		{
			name:        "unterminated-quantifier",
			rule:        `rule test { strings: $a = /a{ condition: true }`,
			expectError: true,
			description: "Documents regex with unterminated quantifier",
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

// TestUnbalancedBraces documents parser behavior with unbalanced braces
// DO NOT modify code to make tests pass - document current behavior only
func TestUnbalancedBraces(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "missing-closing-brace",
			rule:        `rule test { condition: true `,
			expectError: true,
			description: "Documents rule without closing brace",
		},
		{
			name:        "missing-opening-brace",
			rule:        `rule test condition: true }`,
			expectError: true,
			description: "Documents rule without opening brace",
		},
		{
			name:        "extra-closing-brace",
			rule:        `rule test { condition: true }}`,
			expectError: true,
			description: "Documents rule with extra closing brace",
		},
		{
			name:        "missing-meta-brace",
			rule:        `rule test { meta: author = "test" condition: true }`,
			expectError: false,
			description: "Known gap: parser does not require braces around meta section",
		},
		{
			name:        "missing-strings-brace",
			rule:        `rule test { strings: $a = "test" condition: true }`,
			expectError: false,
			description: "Known gap: parser does not require braces around strings section",
		},
		{
			name:        "nested-braces-error",
			rule:        `rule test { strings: $a = { DE AD BE EF } condition: true }`,
			expectError: false,
			description: "Documents hex pattern braces (should be valid)",
		},
		{
			name:        "multiple-rules-unbalanced",
			rule:        `rule test1 { condition: true } rule test2 { condition: true `,
			expectError: true,
			description: "Documents multiple rules with unbalanced braces",
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

// TestUnbalancedParentheses documents parser behavior with unbalanced parentheses
// DO NOT modify code to make tests pass - document current behavior only
func TestUnbalancedParentheses(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "missing-closing-paren",
			rule:        `rule test { condition: (true }`,
			expectError: true,
			description: "Documents expression without closing paren",
		},
		{
			name:        "missing-opening-paren",
			rule:        `rule test { condition: true) }`,
			expectError: true,
			description: "Documents expression without opening paren",
		},
		{
			name:        "extra-closing-paren",
			rule:        `rule test { condition: (true)) }`,
			expectError: true,
			description: "Documents expression with extra closing paren",
		},
		{
			name:        "extra-opening-paren",
			rule:        `rule test { condition: ((true) }`,
			expectError: true,
			description: "Documents expression with extra opening paren",
		},
		{
			name:        "reverse-parens",
			rule:        `rule test { condition: )true( }`,
			expectError: true,
			description: "Documents expression with reversed parentheses",
		},
		{
			name:        "multiple-unbalanced",
			rule:        `rule test { condition: ((true or false) and true }`,
			expectError: true,
			description: "Documents multiple unbalanced parentheses",
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

// TestInvalidOperators documents parser behavior with invalid operators
// DO NOT modify code to make tests pass - document current behavior only
func TestInvalidOperators(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "double-binary-operator",
			rule:        `rule test { condition: 1 && 2 }`,
			expectError: true,
			description: "Documents invalid && operator (YARA uses 'and')",
		},
		{
			name:        "double-pipe-operator",
			rule:        `rule test { condition: 1 || 2 }`,
			expectError: true,
			description: "Documents invalid || operator (YARA uses 'or')",
		},
		{
			name:        "triple-equals",
			rule:        `rule test { condition: 1 === 2 }`,
			expectError: true,
			description: "Documents invalid === operator",
		},
		{
			name:        "not-equals-alt",
			rule:        `rule test { condition: 1 !== 2 }`,
			expectError: true,
			description: "Documents invalid !== operator",
		},
		{
			name:        "invalid-comparison",
			rule:        `rule test { condition: 1 <> 2 }`,
			expectError: true,
			description: "Documents invalid <> operator",
		},
		{
			name:        "consecutive-operators",
			rule:        `rule test { condition: 1 + + 2 }`,
			expectError: true,
			description: "Documents consecutive binary operators",
		},
		{
			name:        "trailing-operator",
			rule:        `rule test { condition: 1 + }`,
			expectError: true,
			description: "Documents expression with trailing operator",
		},
		{
			name:        "leading-operator",
			rule:        `rule test { condition: + 1 }`,
			expectError: true,
			description: "Documents expression with leading binary operator",
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

// TestInvalidModifiers documents parser behavior with invalid string modifiers
// DO NOT modify code to make tests pass - document current behavior only
func TestInvalidModifiers(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "unknown-modifier",
			rule:        `rule test { strings: $a = "test" unknown condition: $a }`,
			expectError: true,
			description: "Documents unknown string modifier",
		},
		{
			name:        "xor-without-args",
			rule:        `rule test { strings: $a = "test" xor( condition: $a }`,
			expectError: true,
			description: "Documents xor modifier with incomplete args",
		},
		{
			name:        "base64-without-alphabet",
			rule:        `rule test { strings: $a = "test" base64: condition: $a }`,
			expectError: true,
			description: "Documents base64 modifier with incomplete alphabet",
		},
		{
			name:        "invalid-modifier-syntax",
			rule:        `rule test { strings: $a = "test" ! condition: $a }`,
			expectError: true,
			description: "Documents invalid modifier character",
		},
		{
			name:        "xor-invalid-range",
			rule:        `rule test { strings: $a = "test" xor(condition: $a }`,
			expectError: true,
			description: "Documents xor with invalid range syntax",
		},
		{
			name:        "private-in-condition",
			rule:        `rule test { condition: private }`,
			expectError: true,
			description: "Documents private modifier in condition (invalid)",
		},
		{
			name:        "modifier-on-non-string",
			rule:        `rule test { strings: $a = "test" nocase xor condition: nocase }`,
			expectError: true,
			description: "Documents modifier in condition section",
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

// TestDuplicateIdentifiers documents parser behavior with duplicate identifiers
// DO NOT modify code to make tests pass - document current behavior only
func TestDuplicateIdentifiers(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "duplicate-string-identifier",
			rule:        `rule test { strings: $a = "test1" $a = "test2" condition: $a }`,
			expectError: false,
			description: "Documents duplicate string identifiers (may be allowed)",
		},
		{
			name:        "duplicate-meta-key",
			rule:        `rule test { meta: author = "test1" author = "test2" condition: true }`,
			expectError: false,
			description: "Documents duplicate meta keys (may be allowed)",
		},
		{
			name:        "duplicate-rules",
			rule:        `rule test { condition: true } rule test { condition: false }`,
			expectError: false,
			description: "Documents duplicate rule names (may be allowed)",
		},
		{
			name:        "external-and-string-same-name",
			rule:        `rule test { extern: a = 10 strings: $a = "test" condition: $a }`,
			expectError: false,
			description: "Documents same name for external and string",
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

// TestInvalidEscapeSequences documents parser behavior with invalid escape sequences
// DO NOT modify code to make tests pass - document current behavior only
func TestInvalidEscapeSequences(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "invalid-hex-escape",
			rule:        `rule test { strings: $a = "test\xZZ" condition: $a }`,
			expectError: true,
			description: "Rejects invalid hex escape sequence",
		},
		{
			name:        "incomplete-hex-escape",
			rule:        `rule test { strings: $a = "test\xZ" condition: $a }`,
			expectError: true,
			description: "Rejects incomplete hex escape",
		},
		{
			name:        "invalid-unicode-escape",
			rule:        `rule test { strings: $a = "test\uZZZZ" condition: $a }`,
			expectError: true,
			description: "Rejects unsupported unicode escape",
		},
		{
			name:        "invalid-octal-escape",
			rule:        `rule test { strings: $a = "test\999" condition: $a }`,
			expectError: true,
			description: "Rejects unsupported octal escape",
		},
		{
			name:        "backslash-at-end",
			rule:        `rule test { strings: $a = "test\" condition: $a }`,
			expectError: true,
			description: "Documents backslash at end of string",
		},
		{
			name:        "invalid-control-char",
			rule:        `rule test { strings: $a = "test\c" condition: $a }`,
			expectError: true,
			description: "Rejects unsupported control character escape",
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
