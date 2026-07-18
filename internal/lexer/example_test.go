package lexer_test

import (
	"fmt"
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
		token.PLUS, "+", 1, 1,
		token.MINUS, "-", 1, 3,
		token.COLON, ":", 1, 5,
	))

	// Test YARA meta section - eliminates the duplication found by linter
	helper.AssertTokenSequence("meta: author = \"test\"", lexer.CreateTokenSequence(
		token.META, "meta", 1, 1,
		token.COLON, ":", 1, 5,
		token.IDENTIFIER, "author", 1, 7,
		token.ASSIGN, "=", 1, 14,
		token.StringLit, "test", 1, 16,
	))

	// Test YARA condition section - eliminates the duplication found by linter
	helper.AssertTokenSequence("condition: 1 == 1", lexer.CreateTokenSequence(
		token.CONDITION, "condition", 1, 1,
		token.COLON, ":", 1, 10,
		token.IntegerLit, "1", 1, 12,
		token.EQ, "==", 1, 14,
		token.IntegerLit, "1", 1, 17,
	))

	// Test single token - useful for simple cases
	helper.AssertSingleToken("rule", token.RULE, "rule")
	helper.AssertSingleToken("123", token.IntegerLit, "123")
	helper.AssertSingleToken("\"hello\"", token.StringLit, "hello")

	// Test just token types when literals don't matter
	helper.AssertTokenTypes("rule test { condition: true }", []token.Type{
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

	// Second token: "test" at line 2, column 4
	tok2 := l.NextToken()
	helper.AssertPosition(tok2, 2, 4)
}

// ExampleNew demonstrates creating a new lexer instance.
func ExampleNew() {
	_ = lexer.New("rule test { condition: true }")
	fmt.Println("Lexer created successfully")
	// Output: Lexer created successfully
}

// ExampleLexer_NextToken demonstrates tokenizing YARA rule syntax.
func ExampleLexer_NextToken() {
	l := lexer.New("rule test { condition: true }")

	// Get tokens one by one
	tok1 := l.NextToken()
	tok2 := l.NextToken()
	tok3 := l.NextToken()

	fmt.Printf("First token: %s\n", tok1.String())
	fmt.Printf("Second token: %s\n", tok2.String())
	fmt.Printf("Third token: %s\n", tok3.String())
	// Output:
	// First token: {RULE "rule" @ 1:1}
	// Second token: {IDENTIFIER "test" @ 1:6}
	// Third token: {LBRACE "{" @ 1:11}
}

// ExampleRecoveryMode demonstrates different error recovery modes.
func ExampleRecoveryMode() {
	// Basic recovery mode (default)
	lexer1 := lexer.New("?")
	_ = lexer1.NextToken() // This will encounter an error

	// Section recovery mode - more aggressive error recovery
	lexer2 := lexer.New("?")
	lexer2.SetRecoveryMode(lexer.RecoverySection)
	_ = lexer2.NextToken()

	fmt.Printf("Basic recovery errors: %d\n", len(lexer1.Errors()))
	fmt.Printf("Section recovery errors: %d\n", len(lexer2.Errors()))
	// Output:
	// Basic recovery errors: 1
	// Section recovery errors: 1
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
