package lexer

import "github.com/cawalch/go-yara/token"

// Error handling and recovery functions

// SetRecoveryMode sets the error recovery mode
func (l *Lexer) SetRecoveryMode(mode RecoveryMode) {
	l.recoveryMode = mode
}

// RecoveryMode returns the current recovery mode
func (l *Lexer) RecoveryMode() RecoveryMode {
	return l.recoveryMode
}

// Errors returns a copy of all collected errors
func (l *Lexer) Errors() []Error {
	result := make([]Error, len(l.errors))
	copy(result, l.errors)
	return result
}

// ClearErrors clears all collected errors
func (l *Lexer) ClearErrors() {
	l.errors = l.errors[:0]
}

// addError adds an error to the error collection
func (l *Lexer) addError(pos token.Position, message string) {
	l.errors = append(l.errors, Error{
		Position: pos,
		Message:  message,
	})
}

// isWhitespaceChar returns true if the character is whitespace
func (l *Lexer) isWhitespaceChar() bool {
	ch := l.reader.Current()
	return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n'
}

// skipLineComment skips line comments (// comment)
func (l *Lexer) skipLineComment() bool {
	if l.reader.Current() == '/' && l.reader.PeekChar() == '/' {
		// Check if this might be an empty regex before treating as comment
		if l.isEmptyRegex() {
			// This is an empty regex, don't consume it here
			return false
		}
		// Skip line comment: // comment text
		l.reader.ReadChar() // skip first '/'
		l.reader.ReadChar() // skip second '/'
		for l.reader.Current() != '\n' && l.reader.Current() != 0 {
			l.reader.ReadChar()
		}
		return true
	}
	return false
}

// skipBlockComment skips block comments (/* comment */)
func (l *Lexer) skipBlockComment() bool {
	if l.reader.Current() == '/' && l.reader.PeekChar() == '*' {
		// Skip block comment: /* comment text */
		l.reader.ReadChar() // skip '/'
		l.reader.ReadChar() // skip '*'
		for l.reader.Current() != 0 {
			if l.reader.Current() == '*' && l.reader.PeekChar() == '/' {
				l.reader.ReadChar() // skip '*'
				l.reader.ReadChar() // skip '/'
				break
			}
			l.reader.ReadChar()
		}
		return true
	}
	return false
}

// skipWhitespace skips whitespace characters and comments
func (l *Lexer) skipWhitespace() {
	for {
		if l.isWhitespaceChar() {
			l.reader.ReadChar()
		} else if l.skipLineComment() {
			// Continue loop to handle post-comment whitespace
			continue
		} else if l.skipBlockComment() {
			// Continue loop to handle post-comment whitespace
			continue
		} else {
			return
		}
	}
}

// fastForward advances the lexer's position to the next potential start of a
// recognizable token. This is used in RecoverySection mode to skip over
// sections of input that are not valid, until something that looks like a
// keyword or identifier is found.
func (l *Lexer) fastForward() {
	// Skip whitespace first
	for l.reader.Current() != 0 {
		ch := l.reader.Current()

		if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' {
			l.reader.ReadChar()
			continue
		}
		// Stop at first letter or end of input
		if isLetter(ch) || ch == 0 {
			return
		}
		// Skip non-whitespace, non-letter characters
		l.reader.ReadChar()
	}
}
