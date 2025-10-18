package lexer_test

import (
	"fmt"
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func TestRuleModifiers(t *testing.T) {
	tests := []struct {
		input    string
		expected []token.Token
	}{
		{
			input: "global rule GlobalRule { condition: true }",
			expected: []token.Token{
				{Type: token.GLOBAL, Literal: "global"},
				{Type: token.RULE, Literal: "rule"},
				{Type: token.IDENTIFIER, Literal: "GlobalRule"},
				{Type: token.LBRACE, Literal: "{"},
				{Type: token.CONDITION, Literal: "condition"},
				{Type: token.COLON, Literal: ":"},
				{Type: token.TRUE, Literal: "true"},
				{Type: token.RBRACE, Literal: "}"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			input: "global private rule GlobalPrivateRule { condition: false }",
			expected: []token.Token{
				{Type: token.GLOBAL, Literal: "global"},
				{Type: token.PRIVATE, Literal: "private"},
				{Type: token.RULE, Literal: "rule"},
				{Type: token.IDENTIFIER, Literal: "GlobalPrivateRule"},
				{Type: token.LBRACE, Literal: "{"},
				{Type: token.CONDITION, Literal: "condition"},
				{Type: token.COLON, Literal: ":"},
				{Type: token.FALSE, Literal: "false"},
				{Type: token.RBRACE, Literal: "}"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			input: "private rule PrivateRule { condition: true }",
			expected: []token.Token{
				{Type: token.PRIVATE, Literal: "private"},
				{Type: token.RULE, Literal: "rule"},
				{Type: token.IDENTIFIER, Literal: "PrivateRule"},
				{Type: token.LBRACE, Literal: "{"},
				{Type: token.CONDITION, Literal: "condition"},
				{Type: token.COLON, Literal: ":"},
				{Type: token.TRUE, Literal: "true"},
				{Type: token.RBRACE, Literal: "}"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			input: "rule NormalRule { condition: true }",
			expected: []token.Token{
				{Type: token.RULE, Literal: "rule"},
				{Type: token.IDENTIFIER, Literal: "NormalRule"},
				{Type: token.LBRACE, Literal: "{"},
				{Type: token.CONDITION, Literal: "condition"},
				{Type: token.COLON, Literal: ":"},
				{Type: token.TRUE, Literal: "true"},
				{Type: token.RBRACE, Literal: "}"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			input: "global",
			expected: []token.Token{
				{Type: token.GLOBAL, Literal: "global"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			input: "GLOBAL",
			expected: []token.Token{
				{Type: token.IDENTIFIER, Literal: "GLOBAL"},
				{Type: token.EOF, Literal: ""},
			},
		},
	}

	for i, tt := range tests {
		t.Run(fmt.Sprintf("test_%d", i), func(t *testing.T) {
			l := lexer.New(tt.input)
			for i, expectedToken := range tt.expected {
				tok := l.NextToken()
				if tok.Type != expectedToken.Type {
					t.Fatalf("tests[%d] - token type wrong. expected=%q, got=%q", i, expectedToken.Type, tok.Type)
				}
				if tok.Literal != expectedToken.Literal {
					t.Fatalf("tests[%d] - literal wrong. expected=%q, got=%q", i, expectedToken.Literal, tok.Literal)
				}
			}
		})
	}
}
