package lexer_test

import (
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func TestNextToken_BooleanLiterals(t *testing.T) {
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
			l := lexer.New(tt.input)
			got := collectTokens(l)

			if len(got) != len(tt.expected) {
				t.Fatalf("token count mismatch: got %d want %d\n%v", len(got), len(tt.expected), got)
			}

			for i := range tt.expected {
				if got[i].Type != tt.expected[i].Type || got[i].Literal != tt.expected[i].Literal {
					t.Fatalf("tok[%d]: got {%v %q} want {%v %q}", i, got[i].Type, got[i].Literal, tt.expected[i].Type, tt.expected[i].Literal)
				}
			}
		})
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
	l := lexer.New("not true or not false")
	got := collectTokens(l)
	want := []token.Token{
		{Type: token.NOT, Literal: "not"},
		{Type: token.TRUE, Literal: "true"},
		{Type: token.OR, Literal: "or"},
		{Type: token.NOT, Literal: "not"},
		{Type: token.FALSE, Literal: "false"},
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

func TestNextToken_BooleanLiterals_InYARARule(t *testing.T) {
	// Test boolean literals in a realistic YARA rule context
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
	got := collectTokens(l)

	// Count boolean literals
	booleanCount := 0
	for _, tok := range got {
		if tok.Type == token.TRUE || tok.Type == token.FALSE {
			booleanCount++
		}
	}

	// Should have 4 boolean literals: true, false, true, false, false
	expectedBooleans := 5
	if booleanCount != expectedBooleans {
		t.Fatalf("expected %d boolean literals, got %d\nActual tokens: %v", expectedBooleans, booleanCount, got)
	}

	// Verify specific boolean tokens exist
	foundTrue := false
	foundFalse := false
	foundNot := false
	for _, tok := range got {
		if tok.Type == token.TRUE && tok.Literal == "true" {
			foundTrue = true
		}
		if tok.Type == token.FALSE && tok.Literal == "false" {
			foundFalse = true
		}
		if tok.Type == token.NOT && tok.Literal == "not" {
			foundNot = true
		}
	}

	if !foundTrue {
		t.Fatal("expected to find TRUE token")
	}
	if !foundFalse {
		t.Fatal("expected to find FALSE token")
	}
	if !foundNot {
		t.Fatal("expected to find NOT token")
	}
}
