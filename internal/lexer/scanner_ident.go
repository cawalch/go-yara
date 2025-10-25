package lexer

// Identifier scanning functions

// readIdentifier reads an identifier (letters, digits, underscores)
func (l *Lexer) readIdentifier() string {
	return l.reader.ReadIdentifierFast()
}

// readStringIdentifier reads a string identifier starting with '$'
func (l *Lexer) readStringIdentifier() string {
	// current l.ch() is '$'
	start := l.reader.Position()
	l.reader.ReadChar() // skip '$'

	// Read the identifier part (letters, digits, underscores, wildcards, #, @)
	for isLetter(l.reader.Current()) || isDigit(l.reader.Current()) || l.reader.Current() == '_' || l.reader.Current() == '*' || l.reader.Current() == '#' || l.reader.Current() == '@' {
		l.reader.ReadChar()
	}

	return l.reader.Slice(start)
}
