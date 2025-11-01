package lexer

// String literal and regex pattern scanning functions.
// This module handles parsing of quoted string literals and regular expression patterns,
// including complex disambiguation between regex patterns and comments.

// readString reads a string literal and returns content and whether it was properly closed
func (l *Lexer) readString() (string, bool) {
	// current l.ch() is '"'
	start := l.reader.Position()
	l.reader.ReadChar() // skip opening quote

	for l.reader.Current() != '"' && l.reader.Current() != 0 {
		if l.reader.Current() == '\\' {
			l.reader.ReadChar() // skip backslash
			if l.reader.Current() != 0 {
				l.reader.ReadChar() // skip escaped character
			}
		} else {
			l.reader.ReadChar()
		}
	}

	if l.reader.Current() == 0 {
		// Unterminated string - return the entire sequence including the opening quote
		return l.reader.Slice(start), false
	}

	// Extract content between quotes (excluding the quotes themselves)
	content := l.reader.Slice(start + 1) // +1 to skip opening quote
	l.reader.ReadChar()                  // skip closing quote

	// Process escape sequences in the content
	return processEscapeSequences(content), true
}

// readRegex reads a regular expression literal
func (l *Lexer) readRegex() string {
	start := l.reader.Position()
	l.reader.ReadChar() // skip opening '/'

	for l.reader.Current() != '/' && l.reader.Current() != 0 && l.reader.Current() != '\n' {
		if l.reader.Current() == '\\' {
			l.reader.ReadChar() // skip backslash
			if l.reader.Current() != 0 && l.reader.Current() != '\n' {
				l.reader.ReadChar() // skip escaped character
			}
		} else {
			l.reader.ReadChar()
		}
	}

	if l.reader.Current() == '/' {
		l.reader.ReadChar() // skip closing '/'

		// Read flags (i, s, m, etc.)
		for l.reader.Current() == 'i' || l.reader.Current() == 's' || l.reader.Current() == 'm' {
			l.reader.ReadChar()
		}
	}

	return l.reader.Slice(start)
}

// isEmptyRegex checks if the current position starts an empty regex pattern
func (l *Lexer) isEmptyRegex() bool {
	return isEmptyRegexImpl(l)
}

// GetPosition implements regexReader interface for Lexer
// GetPosition returns the current position in the input
func (l *Lexer) GetPosition() int {
	return l.reader.Position()
}

// SetPosition sets the current position in the input
func (l *Lexer) SetPosition(pos int) {
	l.reader.SetPosition(pos)
}

// GetCurrent returns the current character
func (l *Lexer) GetCurrent() byte {
	return l.reader.Current()
}

// ReadChar advances to the next character
func (l *Lexer) ReadChar() {
	l.reader.ReadChar()
}

// Slice returns a substring from the given start position
func (l *Lexer) Slice(start int) string {
	return l.reader.Slice(start)
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
	return looksLikeRegexImpl(l.reader.PeekChar)
}

// regexReader provides the interface needed for regex pattern checking
type regexReader interface {
	GetPosition() int
	SetPosition(int)
	GetCurrent() byte
	ReadChar()
	Slice(int) string
}

// isEmptyRegexImpl is a shared implementation for checking empty regex patterns
func isEmptyRegexImpl(r regexReader) bool {
	// Save current position
	savedPos := r.GetPosition()
	defer r.SetPosition(savedPos)

	// We're at the first '/', advance to check the second
	if r.GetCurrent() != '/' {
		return false
	}
	r.ReadChar()

	// Check if next character is also '/'
	if r.GetCurrent() != '/' {
		return false
	}
	r.ReadChar()

	// Check for optional flags after //
	for r.GetCurrent() == 'i' || r.GetCurrent() == 's' || r.GetCurrent() == 'm' {
		r.ReadChar()
	}

	// For empty regex, we should only see end of input or expression delimiters
	// NOT whitespace followed by text (which would be a comment)
	ch := r.GetCurrent()
	if ch == 0 || ch == ')' || ch == '}' || ch == ']' || ch == ',' || ch == ';' {
		return true
	}

	// If followed by whitespace, check what comes after
	if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
		// Look ahead to see what's after whitespace
		for ch == ' ' || ch == '\t' {
			r.ReadChar()
			ch = r.GetCurrent()
		}

		// If we hit newline or end of input after whitespace, it's an empty regex
		if ch == '\n' || ch == '\r' || ch == 0 {
			return true
		}

		// Check if the next word is a YARA keyword (like "nocase", "wide", etc.)
		// If so, this is likely an empty regex followed by modifiers
		if isLetter(ch) {
			wordStart := r.GetPosition()
			for isLetter(r.GetCurrent()) || isDigit(r.GetCurrent()) || r.GetCurrent() == '_' {
				r.ReadChar()
			}
			word := r.Slice(wordStart)

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

// looksLikeRegexImpl is a shared implementation for determining if '/' starts a regex
func looksLikeRegexImpl(peekChar func() byte) bool {
	// Check the character after the '/' to determine if it looks like a regex
	next := peekChar()

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
