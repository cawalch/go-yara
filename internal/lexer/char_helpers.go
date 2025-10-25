package lexer

// Character reading and manipulation helper functions

// readChar advances to lexer to the next character
func (l *Lexer) readChar() {
	l.reader.ReadChar()
}

// peekChar returns the next character without advancing the lexer
func (l *Lexer) peekChar() byte {
	return l.reader.PeekChar()
}

// ch returns the current character
func (l *Lexer) ch() byte {
	return l.reader.Current()
}

// position returns the current position in the input
func (l *Lexer) position() int {
	return l.reader.Position()
}

// readIllegalSequence reads a sequence of illegal characters
func (l *Lexer) readIllegalSequence() string {
	start := l.reader.Position()

	// Check for specific multi-character illegal sequences first
	if l.reader.Current() == '*' && l.reader.PeekChar() == '/' {
		// Stray closing block comment
		l.reader.ReadChar()
		l.reader.ReadChar()
		return l.reader.Slice(start)
	}

	// Default behavior: basic illegal sequence reading
	for {
		next := l.reader.PeekChar()
		switch {
		case next == 0 || next == ' ' || next == '\t' || next == '\r' || next == '\n':
			l.reader.ReadChar() // include current illegal char
			return l.reader.Slice(start)
		case l.reader.Current() == '*' && next == '/':
			// Coalesce stray closing block comment token "*/"
			l.reader.ReadChar()
			l.reader.ReadChar()
			return l.reader.Slice(start)
		case startsKnownToken(next) || isLetter(next) || isDigit(next):
			l.reader.ReadChar()
			return l.reader.Slice(start)
		default:
			// Otherwise consume current and continue growing the illegal run
			l.reader.ReadChar()
		}
	}
}

// Character classification helper functions

// isHexDigit returns true if the character is a hexadecimal digit
func isHexDigit(ch byte) bool {
	return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')
}

// isLetter returns true if the character is a letter or underscore
func isLetter(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_'
}

// isDigit returns true if the character is a digit
func isDigit(ch byte) bool {
	return ch >= '0' && ch <= '9'
}

// startsKnownToken returns true if the character can start a known token
func startsKnownToken(ch byte) bool {
	switch ch {
	case '+', '-', ':', ',', '.', '(', ')', '{', '}', '=', '!', '<', '>', '"', '/', '$', '#':
		return true
	default:
		return false
	}
}
