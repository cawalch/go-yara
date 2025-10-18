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
	// Test out-of-bounds positions and multi-line scenarios
	tests := []struct {
		name           string
		token          token.Token
		expectedLine   int
		expectedColumn int
		shouldFail     bool
	}{
		{
			name: "negative line number",
			token: token.Token{
				Type:    token.RULE,
				Literal: "rule",
				Pos:     token.Position{Filename: "test", Offset: 0, Line: -1, Column: 5},
			},
			expectedLine:   -1,
			expectedColumn: 5,
			shouldFail:     false,
		},
		{
			name: "negative column number",
			token: token.Token{
				Type:    token.RULE,
				Literal: "rule",
				Pos:     token.Position{Filename: "test", Offset: 0, Line: 1, Column: -5},
			},
			expectedLine:   1,
			expectedColumn: -5,
			shouldFail:     false,
		},
		{
			name: "zero line number",
			token: token.Token{
				Type:    token.RULE,
				Literal: "rule",
				Pos:     token.Position{Filename: "test", Offset: 0, Line: 0, Column: 5},
			},
			expectedLine:   0,
			expectedColumn: 5,
			shouldFail:     false,
		},
		{
			name: "zero column number",
			token: token.Token{
				Type:    token.RULE,
				Literal: "rule",
				Pos:     token.Position{Filename: "test", Offset: 0, Line: 1, Column: 0},
			},
			expectedLine:   1,
			expectedColumn: 0,
			shouldFail:     false,
		},
		{
			name: "very large line number",
			token: token.Token{
				Type:    token.RULE,
				Literal: "rule",
				Pos:     token.Position{Filename: "test", Offset: 0, Line: 1000000, Column: 5},
			},
			expectedLine:   1000000,
			expectedColumn: 5,
			shouldFail:     false,
		},
		{
			name: "very large column number",
			token: token.Token{
				Type:    token.RULE,
				Literal: "rule",
				Pos:     token.Position{Filename: "test", Offset: 0, Line: 1, Column: 1000000},
			},
			expectedLine:   1,
			expectedColumn: 1000000,
			shouldFail:     false,
		},
		{
			name: "multi-line scenario - line 1",
			token: token.Token{
				Type:    token.RULE,
				Literal: "rule",
				Pos:     token.Position{Filename: "test", Offset: 0, Line: 1, Column: 1},
			},
			expectedLine:   1,
			expectedColumn: 1,
			shouldFail:     false,
		},
		{
			name: "multi-line scenario - line 100",
			token: token.Token{
				Type:    token.RULE,
				Literal: "rule",
				Pos:     token.Position{Filename: "test", Offset: 0, Line: 100, Column: 15},
			},
			expectedLine:   100,
			expectedColumn: 15,
			shouldFail:     false,
		},
		{
			name: "multi-line scenario - line 1000",
			token: token.Token{
				Type:    token.RULE,
				Literal: "rule",
				Pos:     token.Position{Filename: "test", Offset: 0, Line: 1000, Column: 8},
			},
			expectedLine:   1000,
			expectedColumn: 8,
			shouldFail:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewTestHelper(t)

			// Test that the function handles the position correctly
			h.AssertPosition(tt.token, tt.expectedLine, tt.expectedColumn)
		})
	}
}


// Additional test functions for improved AssertSingleToken coverage

func TestTestHelper_AssertSingleToken_EdgeCases(t *testing.T) {
	// Test edge cases for AssertSingleToken - only test cases that should pass
	tests := []struct {
		name           string
		input          string
		expectedType   token.TokenType
		expectedLiteral string
	}{
		{
			name:           "input with special characters",
			input:          "{",
			expectedType:   token.HEX_STRING_LIT,
			expectedLiteral: "{",
		},
		{
			name:           "input with quotes",
			input:          "\"hello\"",
			expectedType:   token.STRING_LIT,
			expectedLiteral: "hello",
		},
		{
			name:           "input with regex pattern",
			input:          "/test/",
			expectedType:   token.REGEX_LIT,
			expectedLiteral: "/test/",
		},
		{
			name:           "input with hex string",
			input:          "{$a = \"test\"}",
			expectedType:   token.HEX_STRING_LIT,
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
	// Test various token types to ensure comprehensive coverage
	tests := []struct {
		input          string
		expectedType   token.TokenType
		expectedLiteral string
	}{
		{"rule", token.RULE, "rule"},
		{"meta", token.META, "meta"},
		{"strings", token.STRINGS, "strings"},
		{"condition", token.CONDITION, "condition"},
		{"private", token.PRIVATE, "private"},
		{"global", token.GLOBAL, "global"},
		{"true", token.TRUE, "true"},
		{"false", token.FALSE, "false"},
		{"and", token.AND, "and"},
		{"or", token.OR, "or"},
		{"not", token.NOT, "not"},
		{"of", token.OF, "of"},
		{"them", token.THEM, "them"},
		{"for", token.FOR, "for"},
		{"all", token.ALL, "all"},
		{"any", token.ANY, "any"},
		{"none", token.NONE, "none"},
		{"in", token.IN, "in"},
		{"contains", token.CONTAINS, "contains"},
		{"matches", token.MATCHES, "matches"},
		{"import", token.IMPORT, "import"},
		{"include", token.INCLUDE, "include"},
		{"defined", token.DEFINED, "defined"},
		{"123", token.INTEGER_LIT, "123"},
		{"$a", token.STRING_IDENTIFIER, "$a"},
		{"test_var", token.IDENTIFIER, "test_var"},
		{"_underscore", token.IDENTIFIER, "_underscore"},
		{"hello123", token.IDENTIFIER, "hello123"},
		{"+", token.PLUS, "+"},
		{"-", token.MINUS, "-"},
		{"*", token.MULTIPLY, "*"},
		{"=", token.ASSIGN, "="},
		{"==", token.EQ, "=="},
		{"!=", token.NEQ, "!="},
		{">", token.GT, ">"},
		{"<", token.LT, "<"},
		{">=", token.GE, ">="},
		{"<=", token.LE, "<="},
		{"(", token.LPAREN, "("},
		{")", token.RPAREN, ")"},
		{"(", token.LPAREN, "("},
		{"}", token.RBRACE, "}"},
		{"[", token.LBRACKET, "["},
		{"]", token.RBRACKET, "]"},
		{"|", token.BITWISE_OR, "|"},
		{"&", token.BITWISE_AND, "&"},
		{"^", token.BITWISE_XOR, "^"},
		{"~", token.BITWISE_NOT, "~"},
		{"<<", token.LEFT_SHIFT, "<<"},
		{">>", token.RIGHT_SHIFT, ">>"},
		{",", token.COMMA, ","},
		{".", token.DOT, "."},
		{"at", token.AT, "at"},
		{"filesize", token.FILESIZE, "filesize"},
		{"entrypoint", token.ENTRYPOINT, "entrypoint"},
		{"all", token.ALL, "all"},
		{"any", token.ANY, "any"},
	}

	for _, tt := range tests {
		t.Run(tt.expectedType.String()+"_"+tt.expectedLiteral, func(t *testing.T) {
			h := NewTestHelper(t)
			h.AssertSingleToken(tt.input, tt.expectedType, tt.expectedLiteral)
		})
	}
}
