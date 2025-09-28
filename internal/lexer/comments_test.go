package lexer_test

import (
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func TestNextToken_LineComments(t *testing.T) {
	// Test line comments are properly skipped
	input := "rule // this is a comment\nand // another comment\nor"
	l := lexer.New(input)
	got := collectTokens(l)
	want := []token.Token{
		{Type: token.RULE, Literal: "rule"},
		{Type: token.AND, Literal: "and"},
		{Type: token.OR, Literal: "or"},
		{Type: token.EOF, Literal: ""},
	}

	if len(got) != len(want) {
		t.Fatalf("token count mismatch: got %d want %d\n%v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].Type != want[i].Type || got[i].Literal != want[i].Literal {
			t.Fatalf("tok[%d]: got {%v %q} want {%v %q}", i, got[i].Type, got[i].Literal, want[i].Type, want[i].Literal)
		}
	}
}

func TestNextToken_BlockComments(t *testing.T) {
	// Test block comments are properly skipped
	input := "rule /* this is a block comment */ and /* another */ or"
	l := lexer.New(input)
	got := collectTokens(l)
	want := []token.Token{
		{Type: token.RULE, Literal: "rule"},
		{Type: token.AND, Literal: "and"},
		{Type: token.OR, Literal: "or"},
		{Type: token.EOF, Literal: ""},
	}

	if len(got) != len(want) {
		t.Fatalf("token count mismatch: got %d want %d\n%v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].Type != want[i].Type || got[i].Literal != want[i].Literal {
			t.Fatalf("tok[%d]: got {%v %q} want {%v %q}", i, got[i].Type, got[i].Literal, want[i].Type, want[i].Literal)
		}
	}
}

func TestNextToken_MixedComments(t *testing.T) {
	// Test mixed line and block comments
	input := `rule /* block comment */ test {
		// line comment
		condition: true /* another block */ and false
		// final comment
	}`
	l := lexer.New(input)
	got := collectTokens(l)
	want := []token.Token{
		{Type: token.RULE, Literal: "rule"},
		{Type: token.IDENTIFIER, Literal: "test"},
		{Type: token.LBRACE, Literal: "{"},
		{Type: token.CONDITION, Literal: "condition"},
		{Type: token.COLON, Literal: ":"},
		{Type: token.TRUE, Literal: "true"},
		{Type: token.AND, Literal: "and"},
		{Type: token.FALSE, Literal: "false"},
		{Type: token.RBRACE, Literal: "}"},
		{Type: token.EOF, Literal: ""},
	}

	if len(got) != len(want) {
		t.Fatalf("token count mismatch: got %d want %d\nGot: %v\nWant: %v", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i].Type != want[i].Type || got[i].Literal != want[i].Literal {
			t.Fatalf("tok[%d]: got {%v %q} want {%v %q}", i, got[i].Type, got[i].Literal, want[i].Type, want[i].Literal)
		}
	}
}

func TestNextToken_UnterminatedBlockComment(t *testing.T) {
	// Test unterminated block comment - should stop at EOF
	input := "rule /* unterminated comment"
	l := lexer.New(input)
	got := collectTokens(l)
	want := []token.Token{
		{Type: token.RULE, Literal: "rule"},
		{Type: token.EOF, Literal: ""},
	}

	if len(got) != len(want) {
		t.Fatalf("token count mismatch: got %d want %d\n%v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].Type != want[i].Type || got[i].Literal != want[i].Literal {
			t.Fatalf("tok[%d]: got {%v %q} want {%v %q}", i, got[i].Type, got[i].Literal, want[i].Type, want[i].Literal)
		}
	}
}

func TestNextToken_CommentsWithCRLF(t *testing.T) {
	// Test comments with CRLF line endings
	input := "rule // comment\r\nand /* block\r\ncomment */ or"
	l := lexer.New(input)
	got := collectTokens(l)
	want := []token.Token{
		{Type: token.RULE, Literal: "rule"},
		{Type: token.AND, Literal: "and"},
		{Type: token.OR, Literal: "or"},
		{Type: token.EOF, Literal: ""},
	}

	if len(got) != len(want) {
		t.Fatalf("token count mismatch: got %d want %d\n%v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].Type != want[i].Type || got[i].Literal != want[i].Literal {
			t.Fatalf("tok[%d]: got {%v %q} want {%v %q}", i, got[i].Type, got[i].Literal, want[i].Type, want[i].Literal)
		}
	}
}

func TestNextToken_NestedLikeComments(t *testing.T) {
	// Test sequences that look like nested comments but aren't
	input := "rule /* comment // with line comment inside */ and"
	l := lexer.New(input)
	got := collectTokens(l)
	want := []token.Token{
		{Type: token.RULE, Literal: "rule"},
		{Type: token.AND, Literal: "and"},
		{Type: token.EOF, Literal: ""},
	}

	if len(got) != len(want) {
		t.Fatalf("token count mismatch: got %d want %d\n%v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].Type != want[i].Type || got[i].Literal != want[i].Literal {
			t.Fatalf("tok[%d]: got {%v %q} want {%v %q}", i, got[i].Type, got[i].Literal, want[i].Type, want[i].Literal)
		}
	}
}
