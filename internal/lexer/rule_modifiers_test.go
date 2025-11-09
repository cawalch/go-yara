package lexer_test

import (
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func TestRuleModifiers(t *testing.T) {
	t.Run("RuleWithModifiers", testRuleWithModifiers)
	t.Run("ModifierStandalone", testStandaloneModifiers)
}

// testRuleWithModifiers tests various combinations of rule modifiers
func testRuleWithModifiers(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []token.Token
	}{
		{
			name:  "global_rule",
			input: "global rule GlobalRule { condition: true }",
			expected: []token.Token{
				{Type: token.GLOBAL, Literal: "global"},
				{Type: token.RULE, Literal: "rule"},
				{Type: token.IDENTIFIER, Literal: "GlobalRule"},
				{Type: token.LBRACE, Literal: "{"},
				{Type: token.CONDITION, Literal: "condition"},
				{Type: token.COLON, Literal: ":"},
				{Type: token.TRUE, Literal: "true"},
				{Type: token.RBRACE, Literal: "}"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "global_private_rule",
			input: "global private rule GlobalPrivateRule { condition: false }",
			expected: []token.Token{
				{Type: token.GLOBAL, Literal: "global"},
				{Type: token.PRIVATE, Literal: "private"},
				{Type: token.RULE, Literal: "rule"},
				{Type: token.IDENTIFIER, Literal: "GlobalPrivateRule"},
				{Type: token.LBRACE, Literal: "{"},
				{Type: token.CONDITION, Literal: "condition"},
				{Type: token.COLON, Literal: ":"},
				{Type: token.FALSE, Literal: "false"},
				{Type: token.RBRACE, Literal: "}"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "private_rule",
			input: "private rule PrivateRule { condition: true }",
			expected: []token.Token{
				{Type: token.PRIVATE, Literal: "private"},
				{Type: token.RULE, Literal: "rule"},
				{Type: token.IDENTIFIER, Literal: "PrivateRule"},
				{Type: token.LBRACE, Literal: "{"},
				{Type: token.CONDITION, Literal: "condition"},
				{Type: token.COLON, Literal: ":"},
				{Type: token.TRUE, Literal: "true"},
				{Type: token.RBRACE, Literal: "}"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "normal_rule",
			input: "rule NormalRule { condition: true }",
			expected: []token.Token{
				{Type: token.RULE, Literal: "rule"},
				{Type: token.IDENTIFIER, Literal: "NormalRule"},
				{Type: token.LBRACE, Literal: "{"},
				{Type: token.CONDITION, Literal: "condition"},
				{Type: token.COLON, Literal: ":"},
				{Type: token.TRUE, Literal: "true"},
				{Type: token.RBRACE, Literal: "}"},
				{Type: token.EOF, Literal: ""},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRuleModifierTokenSequence(t, tt.input, tt.expected)
		})
	}
}

// testStandaloneModifiers tests standalone modifier keywords
func testStandaloneModifiers(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []token.Token
	}{
		{
			name:  "standalone_global",
			input: "global",
			expected: []token.Token{
				{Type: token.GLOBAL, Literal: "global"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "uppercase_global_as_identifier",
			input: "GLOBAL",
			expected: []token.Token{
				{Type: token.IDENTIFIER, Literal: "GLOBAL"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "standalone_private",
			input: "private",
			expected: []token.Token{
				{Type: token.PRIVATE, Literal: "private"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "uppercase_private_as_identifier",
			input: "PRIVATE",
			expected: []token.Token{
				{Type: token.IDENTIFIER, Literal: "PRIVATE"},
				{Type: token.EOF, Literal: ""},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRuleModifierTokenSequence(t, tt.input, tt.expected)
		})
	}
}

// assertRuleModifierTokenSequence validates that the lexer produces the expected token sequence
func assertRuleModifierTokenSequence(t *testing.T, input string, expected []token.Token) {
	l := lexer.New(input)

	for i, expectedToken := range expected {
		tok := l.NextToken()
		if tok.Type != expectedToken.Type {
			t.Errorf("token %d - type wrong. expected=%q, got=%q", i, expectedToken.Type, tok.Type)
			return
		}
		if tok.Literal != expectedToken.Literal {
			t.Errorf("token %d - literal wrong. expected=%q, got=%q", i, expectedToken.Literal, tok.Literal)
			return
		}
	}
}