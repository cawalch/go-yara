package lexer

// Hexadecimal string scanning functions.
// This module handles the complex logic for detecting and parsing hex string literals,
// including disambiguation between hex strings and regular rule body braces.

// readHexString reads a hexadecimal string literal
func (l *Lexer) readHexString() string {
	// current l.ch() is '{'
	start := l.position()
	l.readChar() // skip opening '{'

	braceCount := 1 // We've already seen the opening brace
	for braceCount > 0 && l.ch() != 0 {
		if l.ch() == '{' {
			braceCount++
		} else if l.ch() == '}' {
			braceCount--
		}
		l.readChar()
	}

	return l.reader.Slice(start)
}

// isHexStringStart checks if the current position starts a hex string
// Optimized fast-path with bounded lookahead and minimal scanning.
func (l *Lexer) isHexStringStart() bool {
	savedPos := l.reader.Position()
	defer l.reader.SetPosition(savedPos)

	// Move past '{' and skip immediate whitespace
	l.readChar()
	l.skipWhitespace()

	// Empty hex: "{ }"
	if l.ch() == '}' {
		return true
	}

	// Bounded scan ahead for rule structure keywords followed by ':'
	// Check this first to prioritize rule body detection over tags context
	startScan := l.reader.Position()
	for (l.reader.Position()-startScan) < 128 && l.ch() != 0 && l.ch() != '}' {
		if isLetter(l.ch()) {
			wordStart := l.position()
			for isLetter(l.ch()) {
				l.readChar()
			}
			word := l.reader.Slice(wordStart)
			l.skipWhitespace()
			if l.ch() == ':' && isRuleKeyword(word) {
				return false // Regular rule body
			}
		} else {
			l.readChar()
		}
	}

	// Context hint: tags before brace (e.g., strings: $a = { ... })
	hasTagsContext := l.hasTagsBeforeBrace()

	if hasTagsContext {
		// In a strings/tags context, braces typically denote a hex string
		return true
	}

	// Fast path: First non-space character heuristics
	// If it looks like hex content or hex operators, treat as hex string immediately.
	switch ch := l.ch(); ch {
	case '?', '~', '(', '[':
		return true
	default:
		if isHexDigit(ch) {
			// Disambiguate identifiers starting with [a-f] (e.g., "condition")
			next := l.peekChar()
			if isHexDigit(next) || next == ' ' || next == '\t' || next == '\n' || next == '\r' || next == '}' || next == '?' || next == '~' || next == '(' || next == '[' {
				return true
			}
			// Otherwise, could be an identifier; fall through to default
		}
	}

	// Default to hex when no rule-structure detected
	return true
}

// hasTagsBeforeBrace checks if there are tags before the current brace
func (l *Lexer) hasTagsBeforeBrace() bool {
	input := l.reader.Input()
	currentPos := l.reader.Position()

	colonPos := l.findRecentColon(input, currentPos)
	if colonPos < 0 {
		return false
	}

	return l.hasTagsAfterColon(input, colonPos, currentPos)
}

// findRecentColon looks for a colon within a reasonable distance backwards
func (l *Lexer) findRecentColon(input string, currentPos int) int {
	maxLookback := 100
	startPos := currentPos - maxLookback
	if startPos < 0 {
		startPos = 0
	}

	for pos := currentPos - 1; pos >= startPos; pos-- {
		if input[pos] == ':' {
			return pos
		}
	}
	return -1
}

// hasTagsAfterColon checks if there are identifiers (tags) between colon and current position
func (l *Lexer) hasTagsAfterColon(input string, colonPos, currentPos int) bool {
	checkPos := colonPos + 1
	foundIdentifiers := false

	// Skip whitespace after colon
	checkPos = l.skipWhitespaceInRange(input, checkPos, currentPos)

	// Look for identifiers (tags)
	for checkPos < currentPos {
		if !isLetter(input[checkPos]) {
			break
		}

		foundIdentifiers = true
		checkPos = l.skipIdentifierInRange(input, checkPos, currentPos)
		checkPos = l.skipWhitespaceInRange(input, checkPos, currentPos)
	}

	return foundIdentifiers && checkPos == currentPos
}

// skipWhitespaceInRange skips whitespace characters within a range
func (l *Lexer) skipWhitespaceInRange(input string, start, end int) int {
	pos := start
	for pos < end && (input[pos] == ' ' || input[pos] == '\t' || input[pos] == '\n' || input[pos] == '\r') {
		pos++
	}
	return pos
}

// skipIdentifierInRange skips an identifier within a range
func (l *Lexer) skipIdentifierInRange(input string, start, end int) int {
	pos := start
	for pos < end && (isLetter(input[pos]) || isDigit(input[pos]) || input[pos] == '_') {
		pos++
	}
	return pos
}

// isRuleKeyword checks if a word is a YARA rule structure keyword
func isRuleKeyword(word string) bool {
	return word == "condition" || word == "meta" || word == "strings"
}
