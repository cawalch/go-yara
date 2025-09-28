package lexer_test

import (
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

// Example of how to use the new test helpers to eliminate code duplication.
// This demonstrates the pattern that should be applied to existing tests.

func TestExampleUsingHelpers(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	// Test basic operators - much more concise than the old pattern
	helper.AssertTokenSequence("+ - :", lexer.CreateTokenSequence(
		token.PLUS, "+",
		token.MINUS, "-",
		token.COLON, ":",
	))

	// Test YARA meta section - eliminates the duplication found by linter
	helper.AssertTokenSequence("meta: author = \"test\"", lexer.CreateTokenSequence(
		token.META, "meta",
		token.COLON, ":",
		token.IDENTIFIER, "author",
		token.ASSIGN, "=",
		token.STRING_LIT, "test",
	))

	// Test YARA condition section - eliminates the duplication found by linter
	helper.AssertTokenSequence("condition: 1 == 1", lexer.CreateTokenSequence(
		token.CONDITION, "condition",
		token.COLON, ":",
		token.INTEGER_LIT, "1",
		token.EQ, "==",
		token.INTEGER_LIT, "1",
	))

	// Test single token - useful for simple cases
	helper.AssertSingleToken("rule", token.RULE, "rule")
	helper.AssertSingleToken("123", token.INTEGER_LIT, "123")
	helper.AssertSingleToken("\"hello\"", token.STRING_LIT, "hello")

	// Test just token types when literals don't matter
	helper.AssertTokenTypes("rule test { condition: true }", []token.TokenType{
		token.RULE,
		token.IDENTIFIER,
		token.LBRACE,
		token.CONDITION,
		token.COLON,
		token.TRUE,
		token.RBRACE,
		token.EOF,
	})
}

func TestExampleErrorHandling(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	// Test error collection
	l := lexer.New("\"unterminated string")
	_ = l.NextToken() // This should generate an error

	helper.AssertLexerErrors(l, 1)
	helper.AssertErrorContains(l, "unterminated string")
}

func TestExamplePositionTracking(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	l := lexer.New("rule\n  test")

	// First token: "rule" at line 1, column 1
	tok1 := l.NextToken()
	helper.AssertPosition(tok1, 1, 1)

	// Second token: "test" at line 2, column 3
	tok2 := l.NextToken()
	helper.AssertPosition(tok2, 2, 3)
}

// This shows how the old pattern can be refactored:
//
// OLD PATTERN (found in multiple test functions):
// func TestSomething(t *testing.T) {
//     input := "some input"
//     l := lexer.New(input)
//     got := collectTokens(l)
//     want := []token.Token{
//         {Type: token.SOME_TYPE, Literal: "literal"},
//         {Type: token.EOF, Literal: ""},
//     }
//     if len(got) != len(want) {
//         t.Fatalf("token count mismatch: got %d want %d\n%v", len(got), len(want), got)
//     }
//     for i := range want {
//         if got[i].Type != want[i].Type || got[i].Literal != want[i].Literal {
//             t.Fatalf("tok[%d]: got {%v %q} want {%v %q}", i, got[i].Type, got[i].Literal, want[i].Type, want[i].Literal)
//         }
//     }
// }
//
// NEW PATTERN (using helpers):
// func TestSomething(t *testing.T) {
//     helper := lexer.NewTestHelper(t)
//     helper.AssertTokenSequence("some input", lexer.CreateTokenSequence(
//         token.SOME_TYPE, "literal",
//     ))
// }
//
// This reduces ~20 lines to ~4 lines and eliminates all duplication!
