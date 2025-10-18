package lexer_test

import (
	"fmt"
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func TestIllegalRunAndSynchronization(t *testing.T) {
	input := "foo ?? bar\nrule r { condition: true }"
	l := lexer.New(input)
	got := collectTokens(l)

	// Should have: IDENTIFIER(foo), ILLEGAL(@@), IDENTIFIER(bar), RULE(rule), IDENTIFIER(r), LBRACE({), CONDITION(condition), COLON(:), TRUE(true), RBRACE(}), EOF
	want := []token.Token{
		{Type: token.IDENTIFIER, Literal: "foo"},
		{Type: token.ILLEGAL, Literal: "??"},
		{Type: token.IDENTIFIER, Literal: "bar"},
		{Type: token.RULE, Literal: "rule"},
		{Type: token.IDENTIFIER, Literal: "r"},
		{Type: token.LBRACE, Literal: "{"},
		{Type: token.CONDITION, Literal: "condition"},
		{Type: token.COLON, Literal: ":"},
		{Type: token.TRUE, Literal: "true"},
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

func TestErrorRecoveryAfterIllegalTokens(t *testing.T) {
	// Test that lexer continues properly after encountering ILLEGAL tokens
	tests := []struct {
		name     string
		input    string
		expected []token.Token
	}{
		{
			name:  "single illegal character",
			input: "rule ? condition",
			expected: []token.Token{
				{Type: token.RULE, Literal: "rule"},
				{Type: token.ILLEGAL, Literal: "?"},
				{Type: token.CONDITION, Literal: "condition"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "multiple illegal characters",
			input: "rule ??? condition",
			expected: []token.Token{
				{Type: token.RULE, Literal: "rule"},
				{Type: token.ILLEGAL, Literal: "???"},
				{Type: token.CONDITION, Literal: "condition"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "illegal at start",
			input: "??? rule condition",
			expected: []token.Token{
				{Type: token.ILLEGAL, Literal: "???"},
				{Type: token.RULE, Literal: "rule"},
				{Type: token.CONDITION, Literal: "condition"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "illegal at end",
			input: "rule condition ???",
			expected: []token.Token{
				{Type: token.RULE, Literal: "rule"},
				{Type: token.CONDITION, Literal: "condition"},
				{Type: token.ILLEGAL, Literal: "???"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "mixed illegal and valid",
			input: "rule ? and ??? or # condition",
			expected: []token.Token{
				{Type: token.RULE, Literal: "rule"},
				{Type: token.ILLEGAL, Literal: "?"},
				{Type: token.AND, Literal: "and"},
				{Type: token.ILLEGAL, Literal: "???"},
				{Type: token.OR, Literal: "or"},
				{Type: token.HASH, Literal: "#"},
				{Type: token.CONDITION, Literal: "condition"},
				{Type: token.EOF, Literal: ""},
			},
		},
	}

	for _, tt := range tests {
		l := lexer.New(tt.input)
		got := collectTokens(l)

		// Debug output
		fmt.Printf("Input: %q\n", tt.input)
		fmt.Printf("Got tokens:\n")
		for i, tok := range got {
			fmt.Printf("  [%d] %v\n", i, tok)
		}
		fmt.Printf("Expected tokens:\n")
		for i, tok := range tt.expected {
			fmt.Printf("  [%d] %v\n", i, tok)
		}

		if len(got) != len(tt.expected) {
			t.Fatalf("token count mismatch: got %d want %d\nGot: %v\nExpected: %v", len(got), len(tt.expected), got, tt.expected)
		}

		for i := range tt.expected {
			if got[i].Type != tt.expected[i].Type || got[i].Literal != tt.expected[i].Literal {
				t.Fatalf("tok[%d]: got {%v %q} want {%v %q}", i, got[i].Type, got[i].Literal, tt.expected[i].Type, tt.expected[i].Literal)
			}
		}
		t.Run(tt.name, func(t *testing.T) {
			l2 := lexer.New(tt.input)
			got2 := collectTokens(l2)

			if len(got2) != len(tt.expected) {
				t.Fatalf("token count mismatch: got %d want %d\nGot: %v\nExpected: %v", len(got2), len(tt.expected), got2, tt.expected)
			}

			for i := range tt.expected {
				if got2[i].Type != tt.expected[i].Type || got2[i].Literal != tt.expected[i].Literal {
					t.Fatalf("tok[%d]: got {%v %q} want {%v %q}", i, got2[i].Type, got2[i].Literal, tt.expected[i].Type, tt.expected[i].Literal)
				}
			}
		})
	}
}

func TestLexerErrorCollection(t *testing.T) {
	// Test that lexer collects errors during tokenization
	tests := []struct {
		name         string
		input        string
		expectErrors bool
		errorCount   int
	}{
		{
			name:         "valid input",
			input:        "rule test { condition: true }",
			expectErrors: false,
			errorCount:   0,
		},
		{
			name:         "unterminated string",
			input:        "rule test { strings: $a = \"unterminated }",
			expectErrors: true,
			errorCount:   1,
		},
		{
			name:         "invalid escape sequence",
			input:        "rule test { strings: $a = \"test\\z\" }",
			expectErrors: true,
			errorCount:   1,
		},
		{
			name:         "multiple errors",
			input:        "rule test { strings: $a = \"test\\z\" $b = \"unterminated }",
			expectErrors: true,
			errorCount:   2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)

			// Consume all tokens to trigger error collection
			for {
				tok := l.NextToken()
				if tok.Type == token.EOF {
					break
				}
			}

			errors := l.Errors()

			if tt.expectErrors {
				if len(errors) == 0 {
					t.Fatalf("expected %d errors, got none", tt.errorCount)
				}
				if len(errors) != tt.errorCount {
					t.Fatalf("expected %d errors, got %d: %v", tt.errorCount, len(errors), errors)
				}
			} else if len(errors) > 0 {
				t.Fatalf("expected no errors, got %d: %v", len(errors), errors)
			}
		})
	}
}

func TestFastForwardRecovery(t *testing.T) {
	// Test section recovery mode
	input := "??? illegal ??? rule test { condition: true }"

	// Test basic recovery mode (default)
	l1 := lexer.New(input)
	tokens1 := collectTokens(l1)

	// Should tokenize everything including illegal tokens
	if len(tokens1) < 5 {
		t.Fatalf("basic recovery should tokenize all content, got %d tokens", len(tokens1))
	}

	// Test section recovery mode
	l2 := lexer.NewWithRecovery(input, lexer.RecoverySection)
	tokens2 := collectTokens(l2)

	// Should have fewer tokens due to fast-forward recovery
	if len(tokens2) >= len(tokens1) {
		t.Fatalf("section recovery should have fewer tokens than basic recovery: got %d vs %d", len(tokens2), len(tokens1))
	}

	// Should still find the 'rule' keyword
	foundRule := false
	for _, tok := range tokens2 {
		if tok.Type == token.RULE {
			foundRule = true
			break
		}
	}
	if !foundRule {
		t.Fatal("section recovery should still find 'rule' keyword")
	}
}

func TestRecoveryModeConfiguration(t *testing.T) {
	input := "@@@ illegal @@@"

	// Test default recovery mode
	l := lexer.New(input)
	if l.RecoveryMode() != lexer.RecoveryBasic {
		t.Fatalf("expected default recovery mode to be RecoveryBasic, got %v", l.RecoveryMode())
	}

	// Test setting recovery mode
	l.SetRecoveryMode(lexer.RecoverySection)
	if l.RecoveryMode() != lexer.RecoverySection {
		t.Fatalf("expected recovery mode to be RecoverySection, got %v", l.RecoveryMode())
	}

	// Test creating with recovery mode
	l2 := lexer.NewWithRecovery(input, lexer.RecoverySection)
	if l2.RecoveryMode() != lexer.RecoverySection {
		t.Fatalf("expected recovery mode to be RecoverySection, got %v", l2.RecoveryMode())
	}
}
