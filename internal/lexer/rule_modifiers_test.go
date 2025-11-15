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
	t.Run("GlobalRule", testGlobalRule)
	t.Run("GlobalPrivateRule", testGlobalPrivateRule)
	t.Run("PrivateRule", testPrivateRule)
	t.Run("NormalRule", testNormalRule)
}

// testGlobalRule tests a rule with only the global modifier
func testGlobalRule(t *testing.T) {
	input := "global rule GlobalRule { condition: true }"
	expected := createRuleTokenSequence([]token.Type{token.GLOBAL}, "GlobalRule", true)
	assertRuleModifierTokenSequence(t, input, expected)
}

// testGlobalPrivateRule tests a rule with both global and private modifiers
func testGlobalPrivateRule(t *testing.T) {
	input := "global private rule GlobalPrivateRule { condition: false }"
	expected := createRuleTokenSequence([]token.Type{token.GLOBAL, token.PRIVATE}, "GlobalPrivateRule", false)
	assertRuleModifierTokenSequence(t, input, expected)
}

// testPrivateRule tests a rule with only the private modifier
func testPrivateRule(t *testing.T) {
	input := "private rule PrivateRule { condition: true }"
	expected := createRuleTokenSequence([]token.Type{token.PRIVATE}, "PrivateRule", true)
	assertRuleModifierTokenSequence(t, input, expected)
}

// testNormalRule tests a rule without any modifiers
func testNormalRule(t *testing.T) {
	input := "rule NormalRule { condition: true }"
	expected := createRuleTokenSequence([]token.Type{}, "NormalRule", true)
	assertRuleModifierTokenSequence(t, input, expected)
}

// createRuleTokenSequence builds the expected token sequence for a rule with modifiers
func createRuleTokenSequence(modifiers []token.Type, ruleName string, condition bool) []token.Token {
	// Pre-allocate tokens with estimated capacity (modifiers + rule components + EOF)
	capacity := len(modifiers) + 7 // 7 = rule, identifier, lbrace, condition, colon, value, rbrace
	tokens := make([]token.Token, 0, capacity)

	// Add modifiers
	for _, mod := range modifiers {
		var literal string
		switch mod {
		case token.GLOBAL:
			literal = "global"
		case token.PRIVATE:
			literal = "private"
		default:
			literal = "unknown"
		}
		tokens = append(tokens, token.Token{Type: mod, Literal: literal})
	}

	// Add rule declaration
	tokens = append(tokens,
		token.Token{Type: token.RULE, Literal: "rule"},
		token.Token{Type: token.IDENTIFIER, Literal: ruleName},
		token.Token{Type: token.LBRACE, Literal: "{"},
		token.Token{Type: token.CONDITION, Literal: "condition"},
		token.Token{Type: token.COLON, Literal: ":"},
	)

	// Add condition value
	if condition {
		tokens = append(tokens, token.Token{Type: token.TRUE, Literal: "true"})
	} else {
		tokens = append(tokens, token.Token{Type: token.FALSE, Literal: "false"})
	}

	// Close rule
	tokens = append(tokens,
		token.Token{Type: token.RBRACE, Literal: "}"},
		token.Token{Type: token.EOF, Literal: ""},
	)

	return tokens
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
