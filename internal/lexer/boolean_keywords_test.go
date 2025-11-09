package lexer_test

import (
	"slices"
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func TestNextToken_BooleanLiterals(t *testing.T) {
	t.Run("BasicLiterals", testBasicBooleanLiterals)
	t.Run("BooleanExpressions", testBooleanExpressions)
	t.Run("ComplexExpressions", testComplexBooleanExpressions)
}

func testBasicBooleanLiterals(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []token.Token
	}{
		{
			name:  "true literal",
			input: "true",
			expected: []token.Token{
				{Type: token.TRUE, Literal: "true"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "false literal",
			input: "false",
			expected: []token.Token{
				{Type: token.FALSE, Literal: "false"},
				{Type: token.EOF, Literal: ""},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertBooleanTokenSequence(t, tt.input, tt.expected)
		})
	}
}

func testBooleanExpressions(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []token.Token
	}{
		{
			name:  "true and false",
			input: "true and false",
			expected: []token.Token{
				{Type: token.TRUE, Literal: "true"},
				{Type: token.AND, Literal: "and"},
				{Type: token.FALSE, Literal: "false"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "boolean expression",
			input: "true or false and true",
			expected: []token.Token{
				{Type: token.TRUE, Literal: "true"},
				{Type: token.OR, Literal: "or"},
				{Type: token.FALSE, Literal: "false"},
				{Type: token.AND, Literal: "and"},
				{Type: token.TRUE, Literal: "true"},
				{Type: token.EOF, Literal: ""},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertBooleanTokenSequence(t, tt.input, tt.expected)
		})
	}
}

func testComplexBooleanExpressions(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []token.Token
	}{
		{
			name:  "boolean with parentheses",
			input: "(true or false) and true",
			expected: []token.Token{
				{Type: token.LPAREN, Literal: "("},
				{Type: token.TRUE, Literal: "true"},
				{Type: token.OR, Literal: "or"},
				{Type: token.FALSE, Literal: "false"},
				{Type: token.RPAREN, Literal: ")"},
				{Type: token.AND, Literal: "and"},
				{Type: token.TRUE, Literal: "true"},
				{Type: token.EOF, Literal: ""},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertBooleanTokenSequence(t, tt.input, tt.expected)
		})
	}
}

// assertBooleanTokenSequence is a helper function to test boolean token sequences
func assertBooleanTokenSequence(t *testing.T, input string, expected []token.Token) {
	l := lexer.New(input)
	got := collectTokens(l)

	if len(got) != len(expected) {
		t.Fatalf("token count mismatch: got %d want %d\n%v", len(got), len(expected), got)
	}

	for i := range expected {
		if got[i].Type != expected[i].Type || got[i].Literal != expected[i].Literal {
			t.Fatalf("tok[%d]: got {%v %q} want {%v %q}", i, got[i].Type, got[i].Literal, expected[i].Type, expected[i].Literal)
		}
	}
}

func TestNextToken_BooleanLiterals_CaseSensitive(t *testing.T) {
	// Test that boolean literals are case-sensitive (only lowercase should be recognized)
	tests := []struct {
		name     string
		input    string
		expected token.TokenType
	}{
		{"uppercase TRUE", "TRUE", token.IDENTIFIER},
		{"uppercase FALSE", "FALSE", token.IDENTIFIER},
		{"mixed case True", "True", token.IDENTIFIER},
		{"mixed case False", "False", token.IDENTIFIER},
		{"mixed case tRuE", "tRuE", token.IDENTIFIER},
		{"mixed case fAlSe", "fAlSe", token.IDENTIFIER},
		{"lowercase true", "true", token.TRUE},
		{"lowercase false", "false", token.FALSE},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)
			tok := l.NextToken()

			if tok.Type != tt.expected {
				t.Fatalf("expected token type %v, got %v", tt.expected, tok.Type)
			}

			if tok.Literal != tt.input {
				t.Fatalf("expected literal %q, got %q", tt.input, tok.Literal)
			}
		})
	}
}

func TestLogicalNot_Keyword(t *testing.T) {
	input := "not true or not false"
	expected := []token.Token{
		{Type: token.NOT, Literal: "not"},
		{Type: token.TRUE, Literal: "true"},
		{Type: token.OR, Literal: "or"},
		{Type: token.NOT, Literal: "not"},
		{Type: token.FALSE, Literal: "false"},
		{Type: token.EOF, Literal: ""},
	}

	assertBooleanTokenSequence(t, input, expected)
}

// countTokensByType is a helper function that counts tokens by type(s)
func countTokensByType(tokens []token.Token, tokenTypes ...token.TokenType) int {
	count := 0
	for _, tok := range tokens {
		if slices.Contains(tokenTypes, tok.Type) {
			count++
		}
	}
	return count
}

// findTokenByTypeAndLiteral is a helper function that finds a token by type and literal value
func findTokenByTypeAndLiteral(tokens []token.Token, tokenType token.TokenType, literal string) bool {
	for _, tok := range tokens {
		if tok.Type == tokenType && tok.Literal == literal {
			return true
		}
	}
	return false
}

// validateBooleanTokens is a helper function that validates boolean and logical tokens in YARA rule
func validateBooleanTokens(t *testing.T, tokens []token.Token) {
	// Count boolean literals
	booleanCount := countTokensByType(tokens, token.TRUE, token.FALSE)
	expectedBooleans := 5 // true, false, true, false, false

	if booleanCount != expectedBooleans {
		t.Fatalf("expected %d boolean literals, got %d\nActual tokens: %v", expectedBooleans, booleanCount, tokens)
	}

	// Verify specific boolean tokens exist
	tokenValidationTests := []struct {
		tokenType token.TokenType
		literal   string
		name      string
	}{
		{token.TRUE, "true", "TRUE"},
		{token.FALSE, "false", "FALSE"},
		{token.NOT, "not", "NOT"},
	}

	for _, test := range tokenValidationTests {
		if !findTokenByTypeAndLiteral(tokens, test.tokenType, test.literal) {
			t.Fatalf("expected to find %s token", test.name)
		}
	}
}

// TestNextToken_BooleanLiterals_InYARARule tests boolean literals in a realistic YARA rule context
func TestNextToken_BooleanLiterals_InYARARule(t *testing.T) {
	input := `rule TestRule {
		meta:
			enabled = true
			debug = false
		strings:
			$a = "test"
		condition:
			$a and (true or false) and not false
	}`

	l := lexer.New(input)
	tokens := collectTokens(l)

	validateBooleanTokens(t, tokens)
}
