// Package lexer provides testing utilities for lexer tests.
package lexer

import (
	"fmt"
	"testing"

	"github.com/cawalch/go-yara/token"
)

// TestHelper provides common testing utilities for lexer tests.
type TestHelper struct {
	t *testing.T
}

// NewTestHelper creates a new test helper instance.
func NewTestHelper(t *testing.T) *TestHelper {
	return &TestHelper{t: t}
}

// CollectTokens tokenizes the input and returns all tokens until EOF.
func (h *TestHelper) CollectTokens(input string) []token.Token {
	l := New(input)
	tokens := make([]token.Token, 0, 16) // Pre-allocate with reasonable capacity
	for {
		tok := l.NextToken()
		tokens = append(tokens, tok)
		if tok.Type == token.EOF {
			break
		}
	}
	return tokens
}

// AssertTokenSequence verifies that the input produces the expected token sequence.
func (h *TestHelper) AssertTokenSequence(input string, expected []token.Token) {
	got := h.CollectTokens(input)

	if len(got) != len(expected) {
		h.t.Fatalf("token count mismatch: got %d want %d\nGot: %v\nExpected: %v",
			len(got), len(expected), got, expected)
	}

	for i := range expected {
		if got[i].Type != expected[i].Type || got[i].Literal != expected[i].Literal {
			h.t.Fatalf("token[%d]: got {%v %q} want {%v %q}",
				i, got[i].Type, got[i].Literal, expected[i].Type, expected[i].Literal)
		}
	}
}

// AssertTokenTypes verifies that the input produces tokens of the expected types.
func (h *TestHelper) AssertTokenTypes(input string, expectedTypes []token.TokenType) {
	got := h.CollectTokens(input)

	if len(got) != len(expectedTypes) {
		h.t.Fatalf("token count mismatch: got %d want %d", len(got), len(expectedTypes))
	}

	for i := range expectedTypes {
		if got[i].Type != expectedTypes[i] {
			h.t.Fatalf("token[%d] type: got %v want %v", i, got[i].Type, expectedTypes[i])
		}
	}
}

// AssertSingleToken verifies that the input produces exactly one token of the expected type and literal.
func (h *TestHelper) AssertSingleToken(input string, expectedType token.TokenType, expectedLiteral string) {
	tokens := h.CollectTokens(input)

	// Should have exactly 2 tokens: the expected token + EOF
	if len(tokens) != 2 {
		h.t.Fatalf("expected 2 tokens (token + EOF), got %d: %v", len(tokens), tokens)
	}

	tok := tokens[0]
	if tok.Type != expectedType {
		h.t.Fatalf("token type: got %v want %v", tok.Type, expectedType)
	}

	if tok.Literal != expectedLiteral {
		h.t.Fatalf("token literal: got %q want %q", tok.Literal, expectedLiteral)
	}

	// Verify EOF token
	if tokens[1].Type != token.EOF {
		h.t.Fatalf("expected EOF token, got %v", tokens[1].Type)
	}
}

// AssertPosition verifies that a token has the expected position information.
func (h *TestHelper) AssertPosition(tok token.Token, expectedLine, expectedColumn int) {
	if tok.Pos.Line != expectedLine {
		h.t.Fatalf("token line: got %d want %d", tok.Pos.Line, expectedLine)
	}

	if tok.Pos.Column != expectedColumn {
		h.t.Fatalf("token column: got %d want %d", tok.Pos.Column, expectedColumn)
	}
}

// AssertLexerErrors verifies that the lexer collected the expected number of errors.
func (h *TestHelper) AssertLexerErrors(l *Lexer, expectedCount int) {
	errors := l.Errors()
	if len(errors) != expectedCount {
		h.t.Fatalf("error count: got %d want %d\nErrors: %v", len(errors), expectedCount, errors)
	}
}

// AssertErrorContains verifies that at least one lexer error contains the expected message.
func (h *TestHelper) AssertErrorContains(l *Lexer, expectedMessage string) {
	errors := l.Errors()
	for _, err := range errors {
		if containsString(err.Message, expectedMessage) {
			return // Found the expected error message
		}
	}
	h.t.Fatalf("expected error containing %q, got errors: %v", expectedMessage, errors)
}

// CreateTokenSequence is a helper to create token sequences more concisely.
func CreateTokenSequence(pairs ...interface{}) []token.Token {
	if len(pairs)%2 != 0 {
		panic("CreateTokenSequence requires an even number of arguments (type, literal pairs)")
	}

	tokens := make([]token.Token, 0, len(pairs)/2+1) // Pre-allocate for pairs + EOF
	for i := 0; i < len(pairs); i += 2 {
		tokenType, ok := pairs[i].(token.TokenType)
		if !ok {
			panic(fmt.Sprintf("expected token.TokenType at index %d, got %T", i, pairs[i]))
		}
		literal, ok := pairs[i+1].(string)
		if !ok {
			panic(fmt.Sprintf("expected string at index %d, got %T", i+1, pairs[i+1]))
		}
		tokens = append(tokens, token.Token{
			Type:    tokenType,
			Literal: literal,
		})
	}

	// Always add EOF token
	tokens = append(tokens, token.Token{Type: token.EOF, Literal: ""})

	return tokens
}

// containsString checks if a string contains a substring (simple helper).
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr) >= 0
}

// findSubstring finds the index of substr in s, returns -1 if not found.
func findSubstring(s, substr string) int {
	if len(substr) == 0 {
		return 0
	}
	if len(substr) > len(s) {
		return -1
	}

	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
