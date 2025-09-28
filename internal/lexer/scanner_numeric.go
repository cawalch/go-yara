package lexer

// Numeric literal scanning functions

// readNumber reads a numeric literal
func (l *Lexer) readNumber() string {
	start := l.position()
	for isDigit(l.ch()) {
		l.readChar()
	}
	return l.reader.Slice(start)
}

// readHexInteger reads a hexadecimal integer literal (0x prefix)
func (l *Lexer) readHexInteger() string {
	start := l.position()
	l.readChar() // skip '0'
	l.readChar() // skip 'x' or 'X'

	// Read hex digits
	for isHexDigit(l.ch()) {
		l.readChar()
	}
	return l.reader.Slice(start)
}

// hasSizeSuffix checks if the current position has a size suffix (KB, MB)
func (l *Lexer) hasSizeSuffix() bool {
	ch1 := l.ch()
	ch2 := l.peekChar()

	// Check for KB (case insensitive)
	if (ch1 == 'K' || ch1 == 'k') && (ch2 == 'B' || ch2 == 'b') {
		return true
	}

	// Check for MB (case insensitive)
	if (ch1 == 'M' || ch1 == 'm') && (ch2 == 'B' || ch2 == 'b') {
		return true
	}

	return false
}

// readSizeSuffix reads a size suffix and combines it with the number literal
func (l *Lexer) readSizeSuffix(numberLit string) string {
	start := l.position() - len(numberLit) // Start from beginning of number
	l.readChar()                           // skip first letter (K/M)
	l.readChar()                           // skip 'B'
	return l.reader.Slice(start)
}
