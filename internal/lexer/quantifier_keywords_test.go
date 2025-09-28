package lexer_test

import (
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func TestQuantifierKeywords_Basic(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	tests := []struct {
		name     string
		input    string
		expected token.TokenType
	}{
		{"all keyword", "all", token.ALL},
		{"any keyword", "any", token.ANY},
		{"none keyword", "none", token.NONE},
		{"of keyword", "of", token.OF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			helper.AssertSingleToken(tt.input, tt.expected, tt.input)
		})
	}
}

func TestQuantifierKeywords_CaseSensitive(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	// Test that quantifier keywords are case-sensitive (only lowercase should be recognized)
	tests := []struct {
		name     string
		input    string
		expected token.TokenType
	}{
		{"uppercase ALL", "ALL", token.IDENTIFIER},
		{"uppercase ANY", "ANY", token.IDENTIFIER},
		{"uppercase NONE", "NONE", token.IDENTIFIER},
		{"uppercase OF", "OF", token.IDENTIFIER},
		{"mixed case All", "All", token.IDENTIFIER},
		{"mixed case Any", "Any", token.IDENTIFIER},
		{"mixed case None", "None", token.IDENTIFIER},
		{"mixed case Of", "Of", token.IDENTIFIER},
		{"lowercase all", "all", token.ALL},
		{"lowercase any", "any", token.ANY},
		{"lowercase none", "none", token.NONE},
		{"lowercase of", "of", token.OF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			helper.AssertSingleToken(tt.input, tt.expected, tt.input)
		})
	}
}

func TestQuantifierKeywords_InExpressions(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	tests := []struct {
		name     string
		input    string
		expected []token.Token
	}{
		{
			name:  "all of them",
			input: "all of them",
			expected: []token.Token{
				{Type: token.ALL, Literal: "all"},
				{Type: token.OF, Literal: "of"},
				{Type: token.IDENTIFIER, Literal: "them"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "any of them",
			input: "any of them",
			expected: []token.Token{
				{Type: token.ANY, Literal: "any"},
				{Type: token.OF, Literal: "of"},
				{Type: token.IDENTIFIER, Literal: "them"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "none of them",
			input: "none of them",
			expected: []token.Token{
				{Type: token.NONE, Literal: "none"},
				{Type: token.OF, Literal: "of"},
				{Type: token.IDENTIFIER, Literal: "them"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "all of ($a, $b)",
			input: "all of ($a, $b)",
			expected: []token.Token{
				{Type: token.ALL, Literal: "all"},
				{Type: token.OF, Literal: "of"},
				{Type: token.LPAREN, Literal: "("},
				{Type: token.STRING_IDENTIFIER, Literal: "$a"},
				{Type: token.COMMA, Literal: ","},
				{Type: token.STRING_IDENTIFIER, Literal: "$b"},
				{Type: token.RPAREN, Literal: ")"},
				{Type: token.EOF, Literal: ""},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			helper.AssertTokenSequence(tt.input, tt.expected)
		})
	}
}

func TestQuantifierKeywords_InYARARule(t *testing.T) {
	helper := lexer.NewTestHelper(t)
	input := `rule TestRule {
		strings:
			$a = "malware"
			$b = "virus"
			$c = { E2 34 A1 C8 }
		condition:
			all of them and
			any of ($a, $b) and
			none of ($c) and
			2 of them
	}`

	tokens := helper.CollectTokens(input)
	quantifierCount := 0
	quantifiers := []string{}

	for _, tok := range tokens {
		if tok.Type == token.ALL || tok.Type == token.ANY || tok.Type == token.NONE || tok.Type == token.OF {
			quantifierCount++
			quantifiers = append(quantifiers, tok.Literal)
		}
	}

	expectedQuantifiers := []string{"all", "of", "any", "of", "none", "of", "of"}
	if quantifierCount != len(expectedQuantifiers) {
		t.Errorf("Expected %d quantifier tokens, got %d", len(expectedQuantifiers), quantifierCount)
	}

	for i, expected := range expectedQuantifiers {
		if i >= len(quantifiers) || quantifiers[i] != expected {
			t.Errorf("Expected quantifier[%d] to be %q, got %q", i, expected, quantifiers[i])
		}
	}
}

func TestQuantifierKeywords_WithOperators(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	// Test quantifier keywords with various operators
	helper.AssertTokenSequence("all of them and true", lexer.CreateTokenSequence(
		token.ALL, "all",
		token.OF, "of",
		token.IDENTIFIER, "them",
		token.AND, "and",
		token.TRUE, "true",
	))

	helper.AssertTokenSequence("any of ($a, $b) or false", lexer.CreateTokenSequence(
		token.ANY, "any",
		token.OF, "of",
		token.LPAREN, "(",
		token.STRING_IDENTIFIER, "$a",
		token.COMMA, ",",
		token.STRING_IDENTIFIER, "$b",
		token.RPAREN, ")",
		token.OR, "or",
		token.FALSE, "false",
	))

	helper.AssertTokenSequence("not none of them", lexer.CreateTokenSequence(
		token.NOT, "not",
		token.NONE, "none",
		token.OF, "of",
		token.IDENTIFIER, "them",
	))
}

func TestQuantifierKeywords_EdgeCases(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	// Test that quantifier keywords work in various contexts
	tests := []struct {
		name     string
		input    string
		expected []token.Token
	}{
		{
			name:  "quantifiers with parentheses",
			input: "(all of them)",
			expected: []token.Token{
				{Type: token.LPAREN, Literal: "("},
				{Type: token.ALL, Literal: "all"},
				{Type: token.OF, Literal: "of"},
				{Type: token.IDENTIFIER, Literal: "them"},
				{Type: token.RPAREN, Literal: ")"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "quantifiers with comparison",
			input: "2 of them == true",
			expected: []token.Token{
				{Type: token.INTEGER_LIT, Literal: "2"},
				{Type: token.OF, Literal: "of"},
				{Type: token.IDENTIFIER, Literal: "them"},
				{Type: token.EQ, Literal: "=="},
				{Type: token.TRUE, Literal: "true"},
				{Type: token.EOF, Literal: ""},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			helper.AssertTokenSequence(tt.input, tt.expected)
		})
	}
}
