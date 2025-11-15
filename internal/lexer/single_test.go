package lexer_test

import (
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func TestSingleControlFlow(t *testing.T) {
	input := "for all of them : ( $ at pe.entry_point )"
	expected := []token.Token{
		{Type: token.FOR, Literal: "for"},
		{Type: token.ALL, Literal: "all"},
		{Type: token.OF, Literal: "of"},
		{Type: token.THEM, Literal: "them"},
		{Type: token.COLON, Literal: ":"},
		{Type: token.LPAREN, Literal: "("},
		{Type: token.StringIdentifier, Literal: "$"},
		{Type: token.AT, Literal: "at"},
		{Type: token.IDENTIFIER, Literal: "pe"},
		{Type: token.DOT, Literal: "."},
		{Type: token.IDENTIFIER, Literal: "entry_point"},
		{Type: token.RPAREN, Literal: ")"},
		{Type: token.EOF, Literal: ""},
	}

	l := lexer.New(input)
	for i, expectedToken := range expected {
		tok := l.NextToken()
		if tok.Type != expectedToken.Type {
			t.Fatalf("tests[%d] - token type wrong. expected=%q, got=%q", i, expectedToken.Type, tok.Type)
		}
		if tok.Literal != expectedToken.Literal {
			t.Fatalf("tests[%d] - literal wrong. expected=%q, got=%q", i, expectedToken.Literal, tok.Literal)
		}
	}
}
