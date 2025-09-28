package lexer_test

import (
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func TestStringIdentifier_Basic(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple", "$a", "$a"},
		{"with_number", "$a1", "$a1"},
		{"with_underscore", "$_test", "$_test"},
		{"mixed", "$test_123", "$test_123"},
		{"single_char", "$x", "$x"},
		{"starts_with_number", "$1test", "$1test"},
		{"starts_with_underscore", "$_", "$_"},
		{"long_name", "$very_long_string_identifier_123", "$very_long_string_identifier_123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			helper.AssertSingleToken(tt.input, token.STRING_IDENTIFIER, tt.expected)
		})
	}
}

func TestStringIdentifier_Invalid(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	// Test invalid string identifiers (just $ without valid identifier chars)
	tests := []struct {
		name     string
		input    string
		expected token.TokenType
	}{
		{"just_dollar", "$", token.STRING_IDENTIFIER},      // Should still be STRING_IDENTIFIER but just "$"
		{"dollar_space", "$ ", token.STRING_IDENTIFIER},    // Should be STRING_IDENTIFIER "$" followed by whitespace
		{"dollar_operator", "$+", token.STRING_IDENTIFIER}, // Should be STRING_IDENTIFIER "$" followed by PLUS
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := helper.CollectTokens(tt.input)
			if len(tokens) < 1 {
				t.Fatalf("Expected at least 1 token, got %d", len(tokens))
			}
			if tokens[0].Type != tt.expected {
				t.Errorf("Expected token type %v, got %v", tt.expected, tokens[0].Type)
			}
			if tokens[0].Literal != "$" {
				t.Errorf("Expected literal '$', got %q", tokens[0].Literal)
			}
		})
	}
}

func TestStringIdentifier_InYARARule(t *testing.T) {
	helper := lexer.NewTestHelper(t)
	input := `rule TestRule {
		strings:
			$a = "test string"
			$hex1 = { E2 34 A1 C8 23 FB }
			$regex1 = /test.*pattern/i
			$_private = "private string"
			$test_123 = "numbered string"
		condition:
			$a and $hex1 and $regex1 and $_private and $test_123
	}`

	tokens := helper.CollectTokens(input)
	stringIdentifierCount := 0
	stringIdentifiers := []string{}

	for _, tok := range tokens {
		if tok.Type == token.STRING_IDENTIFIER {
			stringIdentifierCount++
			stringIdentifiers = append(stringIdentifiers, tok.Literal)
		}
	}

	expectedIdentifiers := []string{"$a", "$hex1", "$regex1", "$_private", "$test_123", "$a", "$hex1", "$regex1", "$_private", "$test_123"}
	if stringIdentifierCount != len(expectedIdentifiers) {
		t.Errorf("Expected %d string identifier tokens, got %d", len(expectedIdentifiers), stringIdentifierCount)
	}

	// Check that we got the expected identifiers
	for i, expected := range expectedIdentifiers {
		if i < len(stringIdentifiers) && stringIdentifiers[i] != expected {
			t.Errorf("Expected identifier %q at position %d, got %q", expected, i, stringIdentifiers[i])
		}
	}
}

func TestStringIdentifier_WithOperators(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	// Test string identifiers with various operators
	helper.AssertTokenSequence("$a == $b", lexer.CreateTokenSequence(
		token.STRING_IDENTIFIER, "$a",
		token.EQ, "==",
		token.STRING_IDENTIFIER, "$b",
	))

	helper.AssertTokenSequence("$test and $other", lexer.CreateTokenSequence(
		token.STRING_IDENTIFIER, "$test",
		token.AND, "and",
		token.STRING_IDENTIFIER, "$other",
	))

	helper.AssertTokenSequence("$a = \"value\"", lexer.CreateTokenSequence(
		token.STRING_IDENTIFIER, "$a",
		token.ASSIGN, "=",
		token.STRING_LIT, "value",
	))
}

func TestStringIdentifier_EdgeCases(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	// Test edge cases
	tests := []struct {
		name     string
		input    string
		expected []struct {
			tokenType token.TokenType
			literal   string
		}
	}{
		{
			name:  "multiple_dollars",
			input: "$a $b $c",
			expected: []struct {
				tokenType token.TokenType
				literal   string
			}{
				{token.STRING_IDENTIFIER, "$a"},
				{token.STRING_IDENTIFIER, "$b"},
				{token.STRING_IDENTIFIER, "$c"},
			},
		},
		{
			name:  "dollar_with_punctuation",
			input: "$test,",
			expected: []struct {
				tokenType token.TokenType
				literal   string
			}{
				{token.STRING_IDENTIFIER, "$test"},
				{token.COMMA, ","},
			},
		},
		{
			name:  "dollar_in_parentheses",
			input: "($var)",
			expected: []struct {
				tokenType token.TokenType
				literal   string
			}{
				{token.LPAREN, "("},
				{token.STRING_IDENTIFIER, "$var"},
				{token.RPAREN, ")"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := helper.CollectTokens(tt.input)

			// Filter out EOF tokens for easier comparison
			var filteredTokens []token.Token
			for _, tok := range tokens {
				if tok.Type != token.EOF {
					filteredTokens = append(filteredTokens, tok)
				}
			}

			if len(filteredTokens) != len(tt.expected) {
				t.Fatalf("Expected %d tokens, got %d", len(tt.expected), len(filteredTokens))
			}

			for i, expected := range tt.expected {
				if filteredTokens[i].Type != expected.tokenType {
					t.Errorf("Token %d: expected type %v, got %v", i, expected.tokenType, filteredTokens[i].Type)
				}
				if filteredTokens[i].Literal != expected.literal {
					t.Errorf("Token %d: expected literal %q, got %q", i, expected.literal, filteredTokens[i].Literal)
				}
			}
		})
	}
}
