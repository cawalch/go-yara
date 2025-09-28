package lexer

// Identifier scanning functions

// readIdentifier reads an identifier (letters, digits, underscores)
func (l *Lexer) readIdentifier() string {
	start := l.position()
	for isLetter(l.ch()) || isDigit(l.ch()) || l.ch() == '_' {
		l.readChar()
	}
	return l.reader.Slice(start)
}

// readStringIdentifier reads a string identifier starting with '$'
func (l *Lexer) readStringIdentifier() string {
	// current l.ch() is '$'
	start := l.position()
	l.readChar() // skip '$'

	// Read the identifier part (letters, digits, underscores, wildcards)
	for isLetter(l.ch()) || isDigit(l.ch()) || l.ch() == '_' || l.ch() == '*' {
		l.readChar()
	}

	return l.reader.Slice(start)
}
