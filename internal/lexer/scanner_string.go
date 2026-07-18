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
		if l.reader.Current() == '\n' || l.reader.Current() == '\r' {
			// Unterminated string before line end; stop to allow recovery.
			return l.reader.Slice(start), false
		}
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

	// Extract raw content between quotes (excluding the quotes themselves)
	content := l.reader.Slice(start + 1) // +1 to skip opening quote
	l.reader.ReadChar()                  // skip closing quote

	return content, true
}

// readRegex reads a regular expression literal
func (l *Lexer) readRegex() string {
	start := l.reader.Position()
	l.reader.ReadChar() // skip opening '/'

	l.readRegexBody()

	if l.reader.Current() == '/' {
		l.reader.ReadChar() // skip closing '/'
		l.readRegexFlags()
	}

	return l.reader.Slice(start)
}

// readRegexBody reads the regex body content
func (l *Lexer) readRegexBody() {
	for !l.isAtRegexEnd() {
		if l.reader.Current() == '\\' {
			l.reader.ReadChar() // skip backslash
			if l.reader.Current() != 0 && l.reader.Current() != '\n' {
				l.reader.ReadChar() // skip escaped character
			}
		} else {
			l.reader.ReadChar()
		}
	}
}

// isAtRegexEnd checks if we've reached the end of regex body
func (l *Lexer) isAtRegexEnd() bool {
	return l.reader.Current() == '/' || l.reader.Current() == 0 || l.reader.Current() == '\n'
}

// readRegexFlags reads regex flags (i, s, m, etc.)
func (l *Lexer) readRegexFlags() {
	for l.isRegexFlag(l.reader.Current()) {
		l.reader.ReadChar()
	}
}

// isRegexFlag checks if character is a valid regex flag
func (l *Lexer) isRegexFlag(ch byte) bool {
	return ch == 'i' || ch == 's' || ch == 'm'
}

// isEmptyRegex checks if the current position starts an empty regex pattern
func (l *Lexer) isEmptyRegex() bool {
	return isEmptyRegexImpl(l)
}

// GetPosition implements regexReader interface for Lexer
func (l *Lexer) GetPosition() int {
	return l.reader.Position()
}

// SetPosition implements regexReader interface for Lexer
func (l *Lexer) SetPosition(pos int) {
	l.reader.SetPosition(pos)
}

// GetCurrent implements regexReader interface for Lexer
func (l *Lexer) GetCurrent() byte {
	return l.reader.Current()
}

// ReadChar implements regexReader interface for Lexer
func (l *Lexer) ReadChar() {
	l.reader.ReadChar()
}

// slice implements regexReader interface for Lexer
func (l *Lexer) slice(start int) string {
	return l.reader.Slice(start)
}

// isYARAModifier checks if a word is a YARA string modifier keyword
func isYARAModifier(word string) bool {
	switch word {
	case "nocase", "wide", "ascii", "fullword", "private", "xor", "base64", "base64wide", "capture":
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
	slice(int) string
}

// isEmptyRegexImpl is a shared implementation for checking empty regex patterns
func isEmptyRegexImpl(r regexReader) bool {
	savedPos := r.GetPosition()
	defer r.SetPosition(savedPos)

	if !hasDoubleSlash(r) {
		return false
	}

	skipRegexFlags(r)

	return isEmptyRegexEnd(r)
}

// hasDoubleSlash checks if reader has "//" pattern
func hasDoubleSlash(r regexReader) bool {
	if r.GetCurrent() != '/' {
		return false
	}
	r.ReadChar()
	return r.GetCurrent() == '/'
}

// skipRegexFlags skips regex flags (i, s, m)
func skipRegexFlags(r regexReader) {
	r.ReadChar() // skip second '/'
	for isRegexFlag(r) {
		r.ReadChar()
	}
}

// isRegexFlag checks if current char is a regex flag
func isRegexFlag(r regexReader) bool {
	ch := r.GetCurrent()
	return ch == 'i' || ch == 's' || ch == 'm'
}

// isEmptyRegexEnd checks if we're at valid end of empty regex
func isEmptyRegexEnd(r regexReader) bool {
	ch := r.GetCurrent()
	if isRegexEndDelimiter(ch) {
		return true
	}

	if isAnyWhitespace(ch) {
		return handleWhitespaceAfterRegex(r)
	}

	return false
}

// isRegexEndDelimiter checks if char is a regex end delimiter
func isRegexEndDelimiter(ch byte) bool {
	return ch == 0 || ch == ')' || ch == '}' || ch == ']' || ch == ',' || ch == ';'
}

// isAnyWhitespace checks if char is whitespace
func isAnyWhitespace(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r'
}

// handleWhitespaceAfterRegex handles whitespace after empty regex
func handleWhitespaceAfterRegex(r regexReader) bool {
	skipHorizontalWhitespace(r)
	ch := r.GetCurrent()

	if isLineEndOrEOF(ch) {
		return true
	}

	if isLetter(ch) {
		return checkYARAModifier(r)
	}

	return false
}

// skipHorizontalWhitespace skips spaces and tabs
func skipHorizontalWhitespace(r regexReader) {
	for r.GetCurrent() == ' ' || r.GetCurrent() == '\t' {
		r.ReadChar()
	}
}

// isLineEndOrEOF checks if char is line end or EOF
func isLineEndOrEOF(ch byte) bool {
	return ch == '\n' || ch == '\r' || ch == 0
}

// checkYARAModifier checks if current word is a YARA modifier
func checkYARAModifier(r regexReader) bool {
	wordStart := r.GetPosition()
	for isWordChar(r) {
		r.ReadChar()
	}
	word := r.slice(wordStart)
	return isYARAModifier(word)
}

// isWordChar checks if char can be part of a word
func isWordChar(r regexReader) bool {
	ch := r.GetCurrent()
	return isLetter(ch) || isDigit(ch) || ch == '_'
}

// looksLikeRegexImpl is a shared implementation for determining if '/' starts a regex
func looksLikeRegexImpl(peekChar func() byte) bool {
	next := peekChar()

	if isCommentStart(next) {
		return false
	}

	if isEndOrWhitespace(next) {
		return false
	}

	return isRegexStartChar(next)
}

// isCommentStart checks if character starts a comment
func isCommentStart(ch byte) bool {
	return ch == '/' || ch == '*'
}

// isEndOrWhitespace checks if character is end of input or whitespace
func isEndOrWhitespace(ch byte) bool {
	return ch == 0 || isAnyWhitespace(ch)
}

// isRegexStartChar checks if character commonly starts regex patterns
func isRegexStartChar(ch byte) bool {
	if isBasicRegexChar(ch) {
		return true
	}
	return isSpecialRegexChar(ch)
}

// isBasicRegexChar checks for basic regex characters
func isBasicRegexChar(ch byte) bool {
	return isLetter(ch) || isDigit(ch) || ch == '_' || ch == '\\'
}

// isSpecialRegexChar checks for special regex characters
func isSpecialRegexChar(ch byte) bool {
	return ch == '[' || ch == '(' || ch == '.' || ch == '^' || ch == '$' ||
		ch == '|' || ch == '?'
}
