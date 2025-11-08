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

// isWhitespace returns true if the character is whitespace
func isWhitespace(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n'
}

// isTokenDelimiter returns true if the character marks the end of an illegal sequence
func (l *Lexer) isTokenDelimiter(ch byte) bool {
	return startsKnownToken(ch) || isLetter(ch) || isDigit(ch)
}

// shouldTerminateIllegalSequence checks if the illegal sequence should terminate
func (l *Lexer) shouldTerminateIllegalSequence() bool {
	next := l.reader.PeekChar()

	if next == 0 || isWhitespace(next) {
		return true
	}

	if l.reader.Current() == '*' && next == '/' {
		return true
	}

	if l.isTokenDelimiter(next) {
		return true
	}

	return false
}

// handleStrayClosingComment handles stray closing block comment
func (l *Lexer) handleStrayClosingComment(start int) string {
	l.reader.ReadChar()
	l.reader.ReadChar()
	return l.reader.Slice(start)
}

// readIllegalSequence reads a sequence of illegal characters
func (l *Lexer) readIllegalSequence() string {
	start := l.reader.Position()

	// Check for specific multi-character illegal sequences first
	if l.reader.Current() == '*' && l.reader.PeekChar() == '/' {
		// Stray closing block comment
		return l.handleStrayClosingComment(start)
	}

	// Default behavior: basic illegal sequence reading
	for {
		if l.shouldTerminateIllegalSequence() {
			l.reader.ReadChar() // include current illegal char
			return l.reader.Slice(start)
		}

		if l.reader.Current() == '*' && l.reader.PeekChar() == '/' {
			// Coalesce stray closing block comment token "*/"
			return l.handleStrayClosingComment(start)
		}

		// Otherwise consume current and continue growing the illegal run
		l.reader.ReadChar()
	}
}

// Character classification helper functions

// isHexDigit returns true if the character is a hexadecimal digit
func isHexDigit(ch byte) bool {
	return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')
}

// isOctalDigit returns true if the character is an octal digit
func isOctalDigit(ch byte) bool {
	return ch >= '0' && ch <= '7'
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
