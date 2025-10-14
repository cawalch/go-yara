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

// skipWhitespace skips whitespace characters and comments
func (l *Lexer) skipWhitespace() {
	for {
		switch {
		case l.ch() == ' ' || l.ch() == '\t' || l.ch() == '\r' || l.ch() == '\n':
			l.readChar()
		case l.ch() == '/' && l.peekChar() == '/':
			// Check if this might be an empty regex before treating as comment
			if l.isEmptyRegex() {
				// This is an empty regex, don't consume it here
				return
			}
			// Skip line comment: // comment text
			l.readChar() // skip first '/'
			l.readChar() // skip second '/'
			for l.ch() != '\n' && l.ch() != 0 {
				l.readChar()
			}
			// Don't skip the newline here - let the whitespace loop handle it
		case l.ch() == '/' && l.peekChar() == '*':
			// Skip block comment: /* comment text */
			l.readChar() // skip '/'
			l.readChar() // skip '*'
			for l.ch() != 0 {
				if l.ch() == '*' && l.peekChar() == '/' {
					l.readChar() // skip '*'
					l.readChar() // skip '/'
					break
				}
				l.readChar()
			}
		default:
			return
		}
	}
}

// fastForward advances the lexer's position to the next potential start of a
// recognizable token. This is used in RecoverySection mode to skip over
// sections of input that are not valid, until something that looks like a
// keyword or identifier is found.
func (l *Lexer) fastForward() {
	for l.ch() != 0 {
		ch := l.ch()
		if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || isLetter(ch) {
			return
		}
		l.readChar()
	}
}
