package lexer

import (
	"testing"

	"github.com/cawalch/go-yara/token"
)

func TestTestHelper_AssertSingleToken(t *testing.T) {
	h := NewTestHelper(t)

	// Test successful case
	h.AssertSingleToken("rule", token.RULE, "rule")

	// Test that the function works correctly for valid input
	// The function uses t.Fatalf which will fail the test if assertions fail
	// We can't easily test the failure cases without complex setup,
	// but we can verify the success case works
}

func TestTestHelper_AssertPosition(t *testing.T) {
	h := NewTestHelper(t)

	// Create a token with specific position
	tok := token.Token{
		Type:    token.RULE,
		Literal: "rule",
		Pos:     token.Position{Filename: "test", Offset: 0, Line: 5, Column: 10},
	}

	// Test successful case
	h.AssertPosition(tok, 5, 10)

	// Test that the function works correctly for valid input
	// The function uses t.Fatalf which will fail the test if assertions fail
}

func TestTestHelper_AssertLexerErrors(t *testing.T) {
	h := NewTestHelper(t)

	// Create lexer and add some errors
	l := New("invalid input")
	testPos := token.Position{Filename: "test", Offset: 0, Line: 1, Column: 1}
	l.addError(testPos, "error 1")
	l.addError(testPos, "error 2")

	// Test successful case - correct error count
	h.AssertLexerErrors(l, 2)

	// Test that the function works correctly for valid input
}

func TestTestHelper_AssertErrorContains(t *testing.T) {
	h := NewTestHelper(t)

	// Create lexer and add some errors
	l := New("invalid input")
	testPos := token.Position{Filename: "test", Offset: 0, Line: 1, Column: 1}
	l.addError(testPos, "first error message")
	l.addError(testPos, "second error message")

	// Test successful case - error contains substring
	h.AssertErrorContains(l, "first error")

	// Test that the function works correctly for valid input
}

func TestCreateTokenSequence(t *testing.T) {
	// Test successful case
	tokens := CreateTokenSequence(
		token.RULE, "rule",
		token.IDENTIFIER, "test",
	)

	expected := []token.Token{
		{Type: token.RULE, Literal: "rule"},
		{Type: token.IDENTIFIER, Literal: "test"},
		{Type: token.EOF, Literal: ""},
	}

	if len(tokens) != len(expected) {
		t.Fatalf("Expected %d tokens, got %d", len(expected), len(tokens))
	}

	for i, expectedToken := range expected {
		if tokens[i].Type != expectedToken.Type || tokens[i].Literal != expectedToken.Literal {
			t.Errorf("Token %d: expected {%v %q}, got {%v %q}",
				i, expectedToken.Type, expectedToken.Literal, tokens[i].Type, tokens[i].Literal)
		}
	}

	// Test panic case - odd number of arguments
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for odd number of arguments")
			}
		}()
		CreateTokenSequence(token.RULE) // Missing literal
	}()

	// Test panic case - wrong type
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for wrong type")
			}
		}()
		CreateTokenSequence("not a token type", "literal")
	}()

	// Test panic case - wrong literal type
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for wrong literal type")
			}
		}()
		CreateTokenSequence(token.RULE, 123) // Should be string
	}()
}

func Test_findSubstring(t *testing.T) {
	tests := []struct {
		s        string
		substr   string
		expected int
	}{
		{"hello world", "world", 6},
		{"hello world", "hello", 0},
		{"hello world", "o", 4},
		{"hello world", "xyz", -1},
		{"", "hello", -1},
		{"hello", "", 0},
		{"hello", "hello", 0},
		{"hello", "hello world", -1},
	}

	for _, tt := range tests {
		result := findSubstring(tt.s, tt.substr)
		if result != tt.expected {
			t.Errorf("findSubstring(%q, %q) = %d, expected %d", tt.s, tt.substr, result, tt.expected)
		}
	}
}

func Test_containsString(t *testing.T) {
	tests := []struct {
		s        string
		substr   string
		expected bool
	}{
		{"hello world", "world", true},
		{"hello world", "hello", true},
		{"hello world", "o w", true},
		{"hello world", "xyz", false},
		{"", "hello", false},
		{"hello", "", true},
		{"hello", "hello", true},
		{"hello", "hello world", false},
	}

	for _, tt := range tests {
		result := containsString(tt.s, tt.substr)
		if result != tt.expected {
			t.Errorf("containsString(%q, %q) = %v, expected %v", tt.s, tt.substr, result, tt.expected)
		}
	}
}

// Additional test functions for improved AssertPosition coverage

func TestTestHelper_AssertPosition_EdgeCases(t *testing.T) {
	// Helper to create a test token with the given position
	createTestToken := func(line, column int) token.Token {
		return token.Token{
			Type:    token.RULE,
			Literal: "rule",
			Pos:     token.Position{Filename: "test", Offset: 0, Line: line, Column: column},
		}
	}

	// Test cases using a more concise structure
	tests := []struct {
		name           string
		line           int
		column         int
		expectedLine   int
		expectedColumn int
	}{
		{"negative line number", -1, 5, -1, 5},
		{"negative column number", 1, -5, 1, -5},
		{"zero line number", 0, 5, 0, 5},
		{"zero column number", 1, 0, 1, 0},
		{"very large line number", 1000000, 5, 1000000, 5},
		{"very large column number", 1, 1000000, 1, 1000000},
		{"multi-line scenario - line 1", 1, 1, 1, 1},
		{"multi-line scenario - line 100", 100, 15, 100, 15},
		{"multi-line scenario - line 1000", 1000, 8, 1000, 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewTestHelper(t)
			testToken := createTestToken(tt.line, tt.column)
			h.AssertPosition(testToken, tt.expectedLine, tt.expectedColumn)
		})
	}
}

// Additional test functions for improved AssertSingleToken coverage

func TestTestHelper_AssertSingleToken_EdgeCases(t *testing.T) {
	// Test edge cases for AssertSingleToken - only test cases that should pass
	tests := []struct {
		name            string
		input           string
		expectedType    token.TokenType
		expectedLiteral string
	}{
		{
			name:            "input with special characters",
			input:           "{",
			expectedType:    token.HexStringLit,
			expectedLiteral: "{",
		},
		{
			name:            "input with quotes",
			input:           "\"hello\"",
			expectedType:    token.StringLit,
			expectedLiteral: "hello",
		},
		{
			name:            "input with regex pattern",
			input:           "/test/",
			expectedType:    token.RegexLit,
			expectedLiteral: "/test/",
		},
		{
			name:            "input with hex string",
			input:           "{$a = \"test\"}",
			expectedType:    token.HexStringLit,
			expectedLiteral: "{$a = \"test\"}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewTestHelper(t)
			h.AssertSingleToken(tt.input, tt.expectedType, tt.expectedLiteral)
		})
	}
}

func TestTestHelper_AssertSingleToken_TokenTypeCoverage(t *testing.T) {
	t.Run("Keywords", testKeywordTokens)
	t.Run("Literals", testLiteralTokens)
	t.Run("Operators", testOperatorTokens)
	t.Run("Delimiters", testDelimiterTokens)
	t.Run("Identifiers", testIdentifierTokens)
	t.Run("SpecialTokens", testSpecialTokens)
}

func testKeywordTokens(t *testing.T) {
	h := NewTestHelper(t)
	keywords := []struct {
		input     string
		tokenType token.TokenType
	}{
		{"rule", token.RULE},
		{"meta", token.META},
		{"strings", token.STRINGS},
		{"condition", token.CONDITION},
		{"private", token.PRIVATE},
		{"global", token.GLOBAL},
		{"true", token.TRUE},
		{"false", token.FALSE},
		{"and", token.AND},
		{"or", token.OR},
		{"not", token.NOT},
		{"of", token.OF},
		{"them", token.THEM},
		{"for", token.FOR},
		{"all", token.ALL},
		{"any", token.ANY},
		{"none", token.NONE},
		{"in", token.IN},
		{"contains", token.CONTAINS},
		{"matches", token.MATCHES},
		{"import", token.IMPORT},
		{"include", token.INCLUDE},
		{"defined", token.DEFINED},
	}

	for _, tt := range keywords {
		t.Run(tt.input, func(_ *testing.T) {
			h.AssertSingleToken(tt.input, tt.tokenType, tt.input)
		})
	}
}

func testLiteralTokens(t *testing.T) {
	h := NewTestHelper(t)
	literals := []struct {
		input           string
		tokenType       token.TokenType
		expectedLiteral string
	}{
		{"123", token.IntegerLit, "123"},
	}

	for _, tt := range literals {
		t.Run(tt.input, func(_ *testing.T) {
			h.AssertSingleToken(tt.input, tt.tokenType, tt.expectedLiteral)
		})
	}
}

func testOperatorTokens(t *testing.T) {
	h := NewTestHelper(t)
	operators := []struct {
		input     string
		tokenType token.TokenType
	}{
		{"+", token.PLUS},
		{"-", token.MINUS},
		{"*", token.MULTIPLY},
		{"=", token.ASSIGN},
		{"==", token.EQ},
		{"!=", token.NEQ},
		{">", token.GT},
		{"<", token.LT},
		{">=", token.GE},
		{"<=", token.LE},
		{"|", token.BitwiseOr},
		{"&", token.BitwiseAnd},
		{"^", token.BitwiseXor},
		{"~", token.BitwiseNot},
		{"<<", token.LeftShift},
		{">>", token.RightShift},
		{",", token.COMMA},
		{".", token.DOT},
	}

	for _, tt := range operators {
		t.Run(tt.input, func(_ *testing.T) {
			h.AssertSingleToken(tt.input, tt.tokenType, tt.input)
		})
	}
}

func testDelimiterTokens(t *testing.T) {
	h := NewTestHelper(t)
	delimiters := []struct {
		input     string
		tokenType token.TokenType
	}{
		{"(", token.LPAREN},
		{")", token.RPAREN},
		{"}", token.RBRACE},
		{"[", token.LBRACKET},
		{"]", token.RBRACKET},
	}

	for _, tt := range delimiters {
		t.Run(tt.input, func(_ *testing.T) {
			h.AssertSingleToken(tt.input, tt.tokenType, tt.input)
		})
	}
}

func testIdentifierTokens(t *testing.T) {
	h := NewTestHelper(t)
	identifiers := []struct {
		input     string
		tokenType token.TokenType
	}{
		{"$a", token.StringIdentifier},
		{"test_var", token.IDENTIFIER},
		{"_underscore", token.IDENTIFIER},
		{"hello123", token.IDENTIFIER},
	}

	for _, tt := range identifiers {
		t.Run(tt.input, func(_ *testing.T) {
			h.AssertSingleToken(tt.input, tt.tokenType, tt.input)
		})
	}
}

func testSpecialTokens(t *testing.T) {
	h := NewTestHelper(t)
	special := []struct {
		input     string
		tokenType token.TokenType
	}{
		{"at", token.AT},
		{"filesize", token.FILESIZE},
		{"entrypoint", token.ENTRYPOINT},
	}

	for _, tt := range special {
		t.Run(tt.input, func(_ *testing.T) {
			h.AssertSingleToken(tt.input, tt.tokenType, tt.input)
		})
	}
}
