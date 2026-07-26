package lexer_test

import (
	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func collectTokens(l *lexer.Lexer) []token.Token {
	toks := make([]token.Token, 0, 16)
	for {
		t := l.NextToken()
		toks = append(toks, t)
		if t.Type == token.EOF {
			break
		}
	}
	return toks
}
