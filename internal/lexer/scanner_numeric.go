package lexer

// Numeric literal scanning functions

// readNumber reads a numeric literal
func (l *Lexer) readNumber() string {
	start := l.reader.Position()
	for isDigit(l.reader.Current()) {
		l.reader.ReadChar()
	}
	return l.reader.Slice(start)
}

// readFloatFraction reads fractional part of a float literal (. followed by digits)
func (l *Lexer) readFloatFraction() string {
	start := l.reader.Position()
	l.reader.ReadChar() // skip '.'

	for isDigit(l.reader.Current()) {
		l.reader.ReadChar()
	}

	return l.reader.Slice(start)
}

// readHexInteger reads a hexadecimal integer literal (0x prefix)
func (l *Lexer) readHexInteger() string {
	start := l.reader.Position()
	l.reader.ReadChar() // skip '0'
	l.reader.ReadChar() // skip 'x' or 'X'

	// Read hex digits
	for isHexDigit(l.reader.Current()) {
		l.reader.ReadChar()
	}

	return l.reader.Slice(start)
}

// readOctalInteger reads an octal integer literal (0o prefix)
func (l *Lexer) readOctalInteger() string {
	start := l.reader.Position()
	l.reader.ReadChar() // skip '0'
	l.reader.ReadChar() // skip 'o' or 'O'

	// Read octal digits (0-7)
	for isOctalDigit(l.reader.Current()) {
		l.reader.ReadChar()
	}

	return l.reader.Slice(start)
}

// hasSizeSuffix checks if the current position has a size suffix (KB, MB)
func (l *Lexer) hasSizeSuffix() bool {
	ch1 := l.reader.Current()
	ch2 := l.reader.PeekChar()

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
	start := l.reader.Position() - len(numberLit) // Start from beginning of number
	l.reader.ReadChar()                           // skip first letter (K/M)
	l.reader.ReadChar()                           // skip 'B'
	return l.reader.Slice(start)
}
