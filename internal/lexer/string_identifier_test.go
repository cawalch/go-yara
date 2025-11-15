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
			helper.AssertSingleToken(tt.input, token.StringIdentifier, tt.expected)
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
		{"just_dollar", "$", token.StringIdentifier},      // Should still be StringIdentifier but just "$"
		{"dollar_space", "$ ", token.StringIdentifier},    // Should be StringIdentifier "$" followed by whitespace
		{"dollar_operator", "$+", token.StringIdentifier}, // Should be StringIdentifier "$" followed by PLUS
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
		if tok.Type == token.StringIdentifier {
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
		token.StringIdentifier, "$a",
		token.EQ, "==",
		token.StringIdentifier, "$b",
	))

	helper.AssertTokenSequence("$test and $other", lexer.CreateTokenSequence(
		token.StringIdentifier, "$test",
		token.AND, "and",
		token.StringIdentifier, "$other",
	))

	helper.AssertTokenSequence("$a = \"value\"", lexer.CreateTokenSequence(
		token.StringIdentifier, "$a",
		token.ASSIGN, "=",
		token.StringLit, "value",
	))
}

func TestStringIdentifier_EdgeCases(t *testing.T) {
	t.Run("MultipleIdentifiers", testMultipleStringIdentifiers)
	t.Run("IdentifierWithPunctuation", testStringIdentifierWithPunctuation)
	t.Run("IdentifierInParentheses", testStringIdentifierInParentheses)
}

// testMultipleStringIdentifiers tests multiple dollar-prefixed identifiers in sequence
func testMultipleStringIdentifiers(t *testing.T) {
	helper := lexer.NewTestHelper(t)
	input := "$a $b $c"

	expected := []tokenExpectation{
		{tokenType: token.StringIdentifier, literal: "$a"},
		{tokenType: token.StringIdentifier, literal: "$b"},
		{tokenType: token.StringIdentifier, literal: "$c"},
	}

	assertIdentifierTokenSequence(t, helper, input, expected)
}

// testStringIdentifierWithPunctuation tests string identifiers followed by punctuation
func testStringIdentifierWithPunctuation(t *testing.T) {
	helper := lexer.NewTestHelper(t)
	input := "$test,"

	expected := []tokenExpectation{
		{tokenType: token.StringIdentifier, literal: "$test"},
		{tokenType: token.COMMA, literal: ","},
	}

	assertIdentifierTokenSequence(t, helper, input, expected)
}

// testStringIdentifierInParentheses tests string identifiers within parentheses
func testStringIdentifierInParentheses(t *testing.T) {
	helper := lexer.NewTestHelper(t)
	input := "($var)"

	expected := []tokenExpectation{
		{tokenType: token.LPAREN, literal: "("},
		{tokenType: token.StringIdentifier, literal: "$var"},
		{tokenType: token.RPAREN, literal: ")"},
	}

	assertIdentifierTokenSequence(t, helper, input, expected)
}

// tokenExpectation defines an expected token for testing
type tokenExpectation struct {
	tokenType token.TokenType
	literal   string
}

// assertIdentifierTokenSequence validates that the input produces the expected token sequence for identifiers
func assertIdentifierTokenSequence(t *testing.T, helper *lexer.TestHelper, input string, expected []tokenExpectation) {
	t.Helper()

	tokens := helper.CollectTokens(input)
	filteredTokens := filterEOF(tokens)

	if len(filteredTokens) != len(expected) {
		t.Fatalf("Expected %d tokens, got %d", len(expected), len(filteredTokens))
	}

	for i, exp := range expected {
		if filteredTokens[i].Type != exp.tokenType {
			t.Errorf("Token %d: expected type %v, got %v", i, exp.tokenType, filteredTokens[i].Type)
		}
		if filteredTokens[i].Literal != exp.literal {
			t.Errorf("Token %d: expected literal %q, got %q", i, exp.literal, filteredTokens[i].Literal)
		}
	}
}

// filterEOF removes EOF tokens from the token slice
func filterEOF(tokens []token.Token) []token.Token {
	var filtered []token.Token
	for _, tok := range tokens {
		if tok.Type != token.EOF {
			filtered = append(filtered, tok)
		}
	}
	return filtered
}
