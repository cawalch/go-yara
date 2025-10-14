package lexer_test

import (
	"fmt"
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func TestControlFlowKeywords(t *testing.T) {
	tests := []struct {
		input    string
		expected []token.Token
	}{
		{
			input: "for all of them : ( $ at pe.entry_point )",
			expected: []token.Token{
				{Type: token.FOR, Literal: "for"},
				{Type: token.ALL, Literal: "all"},
				{Type: token.OF, Literal: "of"},
				{Type: token.THEM, Literal: "them"},
				{Type: token.COLON, Literal: ":"},
				{Type: token.LPAREN, Literal: "("},
				{Type: token.STRING_IDENTIFIER, Literal: "$"},
				{Type: token.AT, Literal: "at"},
				{Type: token.IDENTIFIER, Literal: "pe"},
				{Type: token.DOT, Literal: "."},
				{Type: token.IDENTIFIER, Literal: "entry_point"},
				{Type: token.RPAREN, Literal: ")"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			input: "for all i in (1..#s) : ( uint32(@s[i]) == 0x5A4D )",
			expected: []token.Token{
				{Type: token.FOR, Literal: "for"},
				{Type: token.ALL, Literal: "all"},
				{Type: token.IDENTIFIER, Literal: "i"},
				{Type: token.IN, Literal: "in"},
				{Type: token.LPAREN, Literal: "("},
				{Type: token.INTEGER_LIT, Literal: "1"},
				{Type: token.DOT, Literal: "."},
				{Type: token.DOT, Literal: "."},
				{Type: token.HASH, Literal: "#"},
				{Type: token.IDENTIFIER, Literal: "s"},
				{Type: token.RPAREN, Literal: ")"},
				{Type: token.COLON, Literal: ":"},
				{Type: token.LPAREN, Literal: "("},
				{Type: token.UINT32, Literal: "uint32"},
				{Type: token.LPAREN, Literal: "("},
				{Type: token.ILLEGAL, Literal: "@"},
				{Type: token.IDENTIFIER, Literal: "s"},
				{Type: token.LBRACKET, Literal: "["},
				{Type: token.IDENTIFIER, Literal: "i"},
				{Type: token.RBRACKET, Literal: "]"},
				{Type: token.RPAREN, Literal: ")"},
				{Type: token.EQ, Literal: "=="},
				{Type: token.HEX_INTEGER_LIT, Literal: "0x5A4D"},
				{Type: token.RPAREN, Literal: ")"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			input: "defined pe.entry_point and them",
			expected: []token.Token{
				{Type: token.DEFINED, Literal: "defined"},
				{Type: token.IDENTIFIER, Literal: "pe"},
				{Type: token.DOT, Literal: "."},
				{Type: token.IDENTIFIER, Literal: "entry_point"},
				{Type: token.AND, Literal: "and"},
				{Type: token.THEM, Literal: "them"},
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
