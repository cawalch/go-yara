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
	t.Helper()
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

	if err := validateTokenSequence(got, expected); err != nil {
		h.t.Fatalf("Token sequence validation failed: %v", err)
	}
}

// tokenValidationError represents a token validation error
type tokenValidationError struct {
	message string
	details string
}

func (e *tokenValidationError) Error() string {
	if e.details != "" {
		return fmt.Sprintf("%s: %s", e.message, e.details)
	}
	return e.message
}

// validateTokenSequence validates a token sequence against expected tokens
func validateTokenSequence(got, expected []token.Token) error {
	if len(got) != len(expected) {
		return &tokenValidationError{
			message: "token count mismatch",
			details: fmt.Sprintf("got %d want %d\nGot: %v\nExpected: %v",
				len(got), len(expected), got, expected),
		}
	}

	for i := range expected {
		if err := validateToken(got[i], expected[i], i); err != nil {
			return err
		}
	}

	return nil
}

// validateToken validates a single token against expected token
func validateToken(got, expected token.Token, index int) error {
	// Check token type and literal
	if got.Type != expected.Type || got.Literal != expected.Literal {
		return &tokenValidationError{
			message: "token mismatch",
			details: fmt.Sprintf("token[%d]: got {%v %q} want {%v %q}",
				index, got.Type, got.Literal, expected.Type, expected.Literal),
		}
	}

	// Check position if specified
	if shouldCheckPosition(expected) {
		if got.Pos.Line != expected.Pos.Line || got.Pos.Column != expected.Pos.Column {
			return &tokenValidationError{
				message: "position mismatch",
				details: fmt.Sprintf("token[%d] position: got {%d:%d} want {%d:%d}",
					index, got.Pos.Line, got.Pos.Column, expected.Pos.Line, expected.Pos.Column),
			}
		}
	}

	return nil
}

// shouldCheckPosition determines if position validation should be performed
func shouldCheckPosition(expected token.Token) bool {
	// Don't check position if expected has zero position
	if expected.Pos.Line == 0 && expected.Pos.Column == 0 {
		return false
	}

	return true
}

// AssertTokenTypes verifies that the input produces tokens of the expected types.
func (h *TestHelper) AssertTokenTypes(input string, expectedTypes []token.Type) {
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
func (h *TestHelper) AssertSingleToken(input string, expectedType token.Type, expectedLiteral string) {
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
// Supports both (type, literal) pairs and (type, literal, line, column) position tuples.
func CreateTokenSequence(pairs ...any) []token.Token {
	if len(pairs) == 0 {
		// Empty sequence, just return EOF
		return []token.Token{{Type: token.EOF, Literal: ""}}
	}

	tokens := make([]token.Token, 0, len(pairs)/2+1) // Pre-allocate for pairs + EOF
	tokens = append(tokens, createTokensFromPairs(pairs)...)

	// Always add EOF token
	tokens = append(tokens, token.Token{Type: token.EOF, Literal: ""})

	return tokens
}

// createTokensFromPairs processes the pairs and creates tokens.
func createTokensFromPairs(pairs []any) []token.Token {
	tokens := make([]token.Token, 0, len(pairs)/2) // Pre-allocate for pairs

	for i := 0; i < len(pairs); i += 2 {
		tok := createTokenFromPair(pairs, &i)
		tokens = append(tokens, tok)
	}

	return tokens
}

// createTokenFromPair creates a single token from pairs starting at index i.
func createTokenFromPair(pairs []any, i *int) token.Token {
	tokenType, ok := pairs[*i].(token.Type)
	if !ok {
		panic(fmt.Sprintf("expected token.Type at index %d, got %T", *i, pairs[*i]))
	}

	literal, ok := pairs[*i+1].(string)
	if !ok {
		panic(fmt.Sprintf("expected string at index %d, got %T", *i+1, pairs[*i+1]))
	}

	tok := token.Token{Type: tokenType, Literal: literal}

	// Check if position info follows
	if *i+2 >= len(pairs) {
		return tok
	}

	line, ok1 := pairs[*i+2].(int)
	if !ok1 {
		return tok
	}

	if *i+3 >= len(pairs) {
		panic(fmt.Sprintf("missing column number after line number at index %d", *i+2))
	}

	column, ok2 := pairs[*i+3].(int)
	if !ok2 {
		panic(fmt.Sprintf("expected int column at index %d, got %T", *i+3, pairs[*i+3]))
	}

	tok.Pos = token.Position{Line: line, Column: column}
	*i += 2 // Skip the position info

	return tok
}

// containsString checks if a string contains a substring (simple helper).
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr) >= 0
}

// findSubstring finds the index of substr in s, returns -1 if not found.
func findSubstring(s, substr string) int {
	if substr == "" {
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
