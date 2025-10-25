package lexer

// String literal and regex pattern scanning functions.
// This module handles the parsing of quoted string literals and regular expression patterns,
// including complex disambiguation between regex patterns and comments.

// readString reads a string literal and returns the content and whether it was properly closed
func (l *Lexer) readString() (string, bool) {
	// current l.ch() is '"'
	start := l.position()
	l.readChar() // skip opening quote

	for l.ch() != '"' && l.ch() != 0 {
		if l.ch() == '\\' {
			l.readChar() // skip backslash
			if l.ch() != 0 {
				l.readChar() // skip escaped character
			}
		} else {
			l.readChar()
		}
	}

	if l.ch() == 0 {
		// Unterminated string - return the entire sequence including the opening quote
		return l.reader.Slice(start), false
	}

	// Extract content between quotes (excluding the quotes themselves)
	content := l.reader.Slice(start + 1) // +1 to skip opening quote
	l.readChar()                         // skip closing quote

	// Process escape sequences in the content
	return processEscapeSequences(content), true
}

// readRegex reads a regular expression literal
func (l *Lexer) readRegex() string {
	// current l.ch() is '/'
	start := l.position()
	l.readChar() // skip opening '/'

	for l.ch() != '/' && l.ch() != 0 && l.ch() != '\n' {
		if l.ch() == '\\' {
			l.readChar() // skip backslash
			if l.ch() != 0 && l.ch() != '\n' {
				l.readChar() // skip escaped character
			}
		} else {
			l.readChar()
		}
	}

	if l.ch() == '/' {
		l.readChar() // skip closing '/'

		// Read flags (i, s, m, etc.)
		for l.ch() == 'i' || l.ch() == 's' || l.ch() == 'm' {
			l.readChar()
		}
	}

	return l.reader.Slice(start)
}

// isEmptyRegex checks if the current position starts an empty regex pattern
func (l *Lexer) isEmptyRegex() bool {
	// Save current position
	savedPos := l.reader.Position()
	defer l.reader.SetPosition(savedPos)

	// We're at the first '/', advance to check the second
	if l.ch() != '/' {
		return false
	}
	l.readChar()

	// Check if next character is also '/'
	if l.ch() != '/' {
		return false
	}
	l.readChar()

	// Check for optional flags after //
	for l.ch() == 'i' || l.ch() == 's' || l.ch() == 'm' {
		l.readChar()
	}

	// For empty regex, we should only see end of input or expression delimiters
	// NOT whitespace followed by text (which would be a comment)
	ch := l.ch()
	if ch == 0 || ch == ')' || ch == '}' || ch == ']' || ch == ',' || ch == ';' {
		return true
	}

	// If followed by whitespace, check what comes after
	if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
		// Look ahead to see what's after whitespace
		for ch == ' ' || ch == '\t' {
			l.readChar()
			ch = l.ch()
		}

		// If we hit newline or end of input after whitespace, it's an empty regex
		if ch == '\n' || ch == '\r' || ch == 0 {
			return true
		}

		// Check if the next word is a YARA keyword (like "nocase", "wide", etc.)
		// If so, this is likely an empty regex followed by modifiers
		if isLetter(ch) {
			wordStart := l.reader.Position()
			for isLetter(l.ch()) || isDigit(l.ch()) || l.ch() == '_' {
				l.readChar()
			}
			word := l.reader.Slice(wordStart)

			// Check if it's a known YARA modifier keyword
			if isYARAModifier(word) {
				return true
			}
		}

		// Otherwise, it's likely a comment
		return false
	}

	return false
}

// isYARAModifier checks if a word is a YARA string modifier keyword
func isYARAModifier(word string) bool {
	switch word {
	case "nocase", "wide", "ascii", "fullword", "private", "xor", "base64", "base64wide":
		return true
	default:
		return false
	}
}

// looksLikeRegex determines if a '/' character starts a regex rather than division
func (l *Lexer) looksLikeRegex() bool {
	// Check the character after the '/' to determine if it looks like a regex
	next := l.peekChar()

	// Definitely comments
	if next == '/' || next == '*' {
		return false
	}

	// End of input or whitespace - likely division operator
	if next == 0 || next == ' ' || next == '\t' || next == '\n' || next == '\r' {
		return false
	}

	// Common regex starting characters
	if (next >= 'a' && next <= 'z') || (next >= 'A' && next <= 'Z') ||
		(next >= '0' && next <= '9') || next == '_' || next == '\\' ||
		next == '[' || next == '(' || next == '.' || next == '^' || next == '$' ||
		next == '|' || next == '?' {
		return true
	}

	// For other characters, be conservative and assume division
	return false
}
