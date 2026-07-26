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
	h.t.Helper()
	l := New(input)
	tokens := make([]token.Token, 0, 16)
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
	h.t.Helper()
	got := h.CollectTokens(input)

	if err := validateTokenSequence(got, expected); err != nil {
		h.t.Fatal(err)
	}
}

func validateTokenSequence(got, expected []token.Token) error {
	if len(got) != len(expected) {
		return fmt.Errorf(
			"token count mismatch: got %d want %d\nGot: %v\nExpected: %v",
			len(got),
			len(expected),
			got,
			expected,
		)
	}

	for i := range expected {
		if got[i].Type != expected[i].Type || got[i].Literal != expected[i].Literal {
			return fmt.Errorf(
				"token[%d]: got {%v %q} want {%v %q}",
				i,
				got[i].Type,
				got[i].Literal,
				expected[i].Type,
				expected[i].Literal,
			)
		}
	}

	return nil
}

// AssertSingleToken verifies that the input produces exactly one token of the expected type and literal.
func (h *TestHelper) AssertSingleToken(input string, expectedType token.Type, expectedLiteral string) {
	h.t.Helper()
	tokens := h.CollectTokens(input)

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

	if tokens[1].Type != token.EOF {
		h.t.Fatalf("expected EOF token, got %v", tokens[1].Type)
	}
}

// CreateTokenSequence is a helper to create token sequences more concisely.
func CreateTokenSequence(pairs ...any) []token.Token {
	if len(pairs)%2 != 0 {
		panic(fmt.Sprintf("expected type/literal pairs, got %d values", len(pairs)))
	}

	tokens := make([]token.Token, 0, len(pairs)/2+1)
	for i := 0; i < len(pairs); i += 2 {
		tokenType, ok := pairs[i].(token.Type)
		if !ok {
			panic(fmt.Sprintf("expected token.Type at index %d, got %T", i, pairs[i]))
		}
		literal, ok := pairs[i+1].(string)
		if !ok {
			panic(fmt.Sprintf("expected string at index %d, got %T", i+1, pairs[i+1]))
		}
		tokens = append(tokens, token.Token{Type: tokenType, Literal: literal})
	}

	return append(tokens, token.Token{Type: token.EOF})
}
