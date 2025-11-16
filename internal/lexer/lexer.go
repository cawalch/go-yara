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

// isStringLengthContext checks if the current ! should be treated as StringLength operator
// This is true when the next non-whitespace character starts an identifier that represents a string
func (l *Lexer) isStringLengthContext() bool {
	// Save current position
	snapshot := l.reader.SavePosition()
	defer l.reader.RestorePosition(snapshot)

	// Skip whitespace
	for l.reader.PeekChar() == ' ' || l.reader.PeekChar() == '\t' ||
		l.reader.PeekChar() == '\n' || l.reader.PeekChar() == '\r' {
		l.reader.ReadChar()
	}

	// Check if next non-whitespace character starts an identifier
	peekChar := l.reader.PeekChar()
	return peekChar == '$' || (peekChar >= 'a' && peekChar <= 'z') || (peekChar >= 'A' && peekChar <= 'Z') || peekChar == '_'
}
