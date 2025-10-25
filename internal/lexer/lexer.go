package lexer

import (
	"github.com/cawalch/go-yara/token"
)

// NextToken returns the next token from the input
func (l *Lexer) NextToken() token.Token {
	return NextTokenImpl(l)
}

// Implement TokenCreator interface methods
func (l *Lexer) getCurrentPosition() token.Position {
	return l.reader.CurrentPosition()
}

func (l *Lexer) getCurrentChar() byte {
	return l.reader.Current()
}

func (l *Lexer) getPeekChar() byte {
	return l.reader.PeekChar()
}
