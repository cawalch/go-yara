package parser

import (
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func TestCoordinatorTokenSynchronization(t *testing.T) {
	for _, source := range []string{
		"",
		`rule r { strings: $a = "abc" condition: for any of them : ($ at 1) }`,
		"import \"pe\"\nrule broken { condition: ( }\nrule next { condition: true }",
	} {
		p := New(lexer.New(source))
		for {
			want := [2]token.Token{p.current, p.peek}
			for name, got := range map[string][2]token.Token{
				"expression":  {p.exprParser.current, p.exprParser.peek},
				"declaration": {p.declParser.current, p.declParser.peek},
				"quantifier":  {p.quantParser.current, p.quantParser.peek},
				"rule":        {p.ruleParser.current, p.ruleParser.peek},
			} {
				if got != want {
					t.Fatalf("%s tokens = %v, want %v", name, got, want)
				}
			}
			if p.current.Type == token.EOF {
				break
			}
			p.nextToken()
		}
	}
}

func TestDelegatingTokenSetters(t *testing.T) {
	p := New(lexer.New(""))
	current := token.Token{Type: token.IDENTIFIER, Literal: "example", Pos: token.Position{Line: 3, Column: 5}}
	peek := token.Token{Type: token.LPAREN, Literal: "(", Pos: token.Position{Line: 3, Column: 12}}
	p.ruleParser.SetCurrentTokens(current, peek)
	if p.ruleParser.current != current || p.ruleParser.peek != peek ||
		p.exprParser.current != current || p.exprParser.peek != peek ||
		p.declParser.current != current || p.declParser.peek != peek {
		t.Fatal("rule setter did not propagate tokens to its children")
	}
	current, peek = peek, current
	p.quantParser.SetCurrentTokens(current, peek)
	if p.quantParser.current != current || p.quantParser.peek != peek ||
		p.exprParser.current != current || p.exprParser.peek != peek {
		t.Fatal("quantifier setter did not propagate tokens to its child")
	}
}
