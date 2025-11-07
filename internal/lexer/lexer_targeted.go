package lexer

import (
	"github.com/cawalch/go-yara/token"
)

// Targeted provides targeted optimizations based on profiling data
// This focuses on the actual bottlenecks identified in CPU profiling
type Targeted struct {
	reader       *ReaderFast
	errors       []Error
	recoveryMode RecoveryMode
}

// NewTargeted creates a new targeted lexer for the given input string.
func NewTargeted(input string) *Targeted {
	return &Targeted{
		reader:       NewReaderFast(input),
		recoveryMode: RecoveryBasic,
	}
}

// NewTargetedWithRecovery creates a new targeted lexer with specified recovery mode.
func NewTargetedWithRecovery(input string, mode RecoveryMode) *Targeted {
	return &Targeted{
		reader:       NewReaderFast(input),
		recoveryMode: mode,
	}
}

// NextToken returns the next token from the input using targeted optimizations.
func (l *Targeted) NextToken() token.Token {
	return NextTokenImpl(l)
}

// Implement TokenCreator interface methods
func (l *Targeted) getCurrentPosition() token.Position {
	return l.reader.CurrentPosition()
}

func (l *Targeted) getCurrentChar() byte {
	return l.reader.Current()
}

func (l *Targeted) getPeekChar() byte {
	return l.reader.PeekChar()
}

func (l *Targeted) readChar() {
	l.reader.ReadChar()
}

func (l *Targeted) makeSimpleToken(tokenType token.TokenType, literal string, pos token.Position) token.Token {
	return l.makeSimpleTokenTargeted(tokenType, literal, pos)
}

func (l *Targeted) makeTwoCharToken(tokenType token.TokenType, literal string, pos token.Position) token.Token {
	return l.makeTwoCharTokenTargeted(tokenType, literal, pos)
}

func (l *Targeted) makeToken(tokenType token.TokenType, literal string, pos token.Position) token.Token {
	return l.makeTokenTargeted(tokenType, literal, pos)
}

func (l *Targeted) handleStringToken(pos token.Position) token.Token {
	return l.handleStringTokenTargeted(pos)
}

func (l *Targeted) handleSlashToken(pos token.Position) token.Token {
	return l.handleSlashTokenTargeted(pos)
}

func (l *Targeted) handleStringIdentifierToken(pos token.Position) token.Token {
	return l.handleStringIdentifierTokenTargeted(pos)
}

func (l *Targeted) handleBraceToken(pos token.Position) token.Token {
	return l.handleBraceTokenTargeted(pos)
}

func (l *Targeted) handleDefaultToken(pos token.Position) token.Token {
	return l.handleDefaultTokenTargeted(pos)
}

func (l *Targeted) skipWhitespace() {
	l.skipWhitespaceTargeted()
}

// skipWhitespaceTargeted efficiently skips whitespace using the fast reader.
func (l *Targeted) skipWhitespaceTargeted() {
	l.reader.SkipWhitespace()
}

// makeSimpleTokenTargeted creates a simple token.
func (l *Targeted) makeSimpleTokenTargeted(tokenType token.TokenType, literal string, pos token.Position) token.Token {
	l.reader.ReadChar()
	return token.Token{
		Type:    tokenType,
		Literal: literal,
		Pos:     pos,
	}
}

// makeTwoCharTokenTargeted creates a two-character token.
func (l *Targeted) makeTwoCharTokenTargeted(tokenType token.TokenType, literal string, pos token.Position) token.Token {
	l.reader.ReadChar() // advance past second character
	return token.Token{
		Type:    tokenType,
		Literal: literal,
		Pos:     pos,
	}
}

// makeTokenTargeted creates a token.
func (l *Targeted) makeTokenTargeted(tokenType token.TokenType, literal string, pos token.Position) token.Token {
	return token.Token{
		Type:    tokenType,
		Literal: literal,
		Pos:     pos,
	}
}

// makeErrorTokenTargeted creates an error token.
func (l *Targeted) makeErrorTokenTargeted(pos token.Position, literal, message string) token.Token {
	l.addErrorTargeted(pos, message)
	return l.makeTokenTargeted(token.ILLEGAL, literal, pos)
}

// handleStringTokenTargeted handles string literals with optimized processing.
func (l *Targeted) handleStringTokenTargeted(pos token.Position) token.Token {
	lit, closed := l.reader.ReadStringFast()
	if !closed {
		return l.makeErrorTokenTargeted(pos, lit, "unterminated string literal")
	}

	// Validate escape sequences and collect any errors
	errors := ValidateStringEscapes(lit, pos)
	for _, err := range errors {
		l.addErrorTargeted(err.Position, err.Message)
	}

	return l.makeTokenTargeted(token.STRING_LIT, lit, pos)
}

// handleSlashTokenTargeted handles slash tokens with optimized logic.
func (l *Targeted) handleSlashTokenTargeted(pos token.Position) token.Token {
	// Check if it's an empty regex first
	if l.reader.PeekChar() == '/' && l.isEmptyRegexTargeted() {
		return l.makeRegexTokenTargeted(pos)
	}

	// Check if it looks like a regex
	if l.looksLikeRegexTargeted() {
		return l.makeRegexTokenTargeted(pos)
	}

	// Division operator
	return l.makeSimpleTokenTargeted(token.DIVIDE, "/", pos)
}

// handleBraceTokenTargeted handles brace tokens with optimized logic.
func (l *Targeted) handleBraceTokenTargeted(pos token.Position) token.Token {
	if l.isHexStringStartTargeted() {
		return l.makeHexStringTokenTargeted(pos)
	}

	return l.makeSimpleTokenTargeted(token.LBRACE, "{", pos)
}

// handleDefaultTokenTargeted handles default cases with optimized processing.
func (l *Targeted) handleDefaultTokenTargeted(pos token.Position) token.Token {
	if isLetter(l.reader.Current()) {
		return l.makeIdentifierTokenTargeted(pos)
	}

	if isDigit(l.reader.Current()) {
		return l.makeNumericTokenTargeted(pos)
	}

	// Generate an error for illegal characters
	tok := l.makeIllegalTokenTargeted(pos)

	if l.recoveryMode == RecoverySection {
		l.fastForwardTargeted()
		return l.NextToken()
	}

	return tok
}

// handleStringIdentifierTokenTargeted handles string identifiers with optimization.
func (l *Targeted) handleStringIdentifierTokenTargeted(pos token.Position) token.Token {
	lit := l.reader.ReadIdentifierFast()
	return l.makeTokenTargeted(token.STRING_IDENTIFIER, lit, pos)
}

// isEmptyRegexTargeted checks if the current position starts an empty regex pattern
func (l *Targeted) isEmptyRegexTargeted() bool {
	return isEmptyRegexImpl(l)
}

// GetPosition implements regexReader interface for Targeted
// GetPosition returns the current position in the input
func (l *Targeted) GetPosition() int {
	return l.reader.Position()
}

// SetPosition sets the current position in the input
func (l *Targeted) SetPosition(pos int) {
	l.reader.SetPosition(pos)
}

// GetCurrent returns the current character
func (l *Targeted) GetCurrent() byte {
	return l.reader.Current()
}

// ReadChar advances to the next character
func (l *Targeted) ReadChar() {
	l.reader.ReadChar()
}

// Slice returns a substring from the given start position
func (l *Targeted) Slice(start int) string {
	return l.reader.Slice(start)
}

// looksLikeRegexTargeted determines if a '/' character starts a regex rather than division
func (l *Targeted) looksLikeRegexTargeted() bool {
	return looksLikeRegexImpl(l.reader.PeekChar)
}

// isHexStringStartTargeted checks if the current position starts a hex string
func (l *Targeted) isHexStringStartTargeted() bool {
	savedPos := l.reader.Position()
	defer l.reader.SetPosition(savedPos)

	// Move past '{' and skip immediate whitespace
	l.reader.ReadChar()
	l.reader.SkipWhitespace()

	// Empty hex: "{ }"
	if l.reader.Current() == '}' {
		return true
	}

	// Bounded scan ahead for rule structure keywords followed by ':'
	// Check this first to prioritize rule body detection over tags context
	startScan := l.reader.Position()
	for (l.reader.Position()-startScan) < 128 && l.reader.Current() != 0 && l.reader.Current() != '}' {
		if isLetter(l.reader.Current()) {
			wordStart := l.reader.Position()
			for isLetter(l.reader.Current()) {
				l.reader.ReadChar()
			}
			word := l.reader.Slice(wordStart)
			l.reader.SkipWhitespace()
			if l.reader.Current() == ':' && isRuleKeyword(word) {
				return false // Regular rule body
			}
		} else {
			l.reader.ReadChar()
		}
	}

	// Context hint: tags before brace (e.g., strings: $a = { ... })
	hasTagsContext := l.hasTagsBeforeBraceTargeted()

	if hasTagsContext {
		// In a strings/tags context, braces typically denote a hex string
		return true
	}

	// Fast path: First non-space character heuristics
	// If it looks like hex content or hex operators, treat as hex string immediately.
	switch ch := l.reader.Current(); ch {
	case '?', '~', '(', '[':
		return true
	default:
		if isHexDigit(ch) {
			// Disambiguate identifiers starting with [a-f] (e.g., "condition")
			next := l.reader.PeekChar()
			if isHexDigit(next) || next == ' ' || next == '\t' || next == '\n' || next == '\r' || next == '}' || next == '?' || next == '~' || next == '(' || next == '[' {
				return true
			}
			// Otherwise, could be an identifier; fall through to default
		}
	}

	// Default to hex when no rule-structure detected
	return true
}

// hasTagsBeforeBraceTargeted checks if there are tags before the current brace
func (l *Targeted) hasTagsBeforeBraceTargeted() bool {
	input := l.reader.Input()
	currentPos := l.reader.Position()

	colonPos := l.findRecentColonTargeted(input, currentPos)
	if colonPos < 0 {
		return false
	}

	return l.hasTagsAfterColonTargeted(input, colonPos, currentPos)
}

// findRecentColonTargeted looks for a colon within a reasonable distance backwards
func (l *Targeted) findRecentColonTargeted(input string, currentPos int) int {
	maxLookback := 100
	startPos := max(currentPos-maxLookback, 0)

	// Ensure we don't go beyond input bounds
	if currentPos > len(input) {
		currentPos = len(input)
	}

	for pos := currentPos - 1; pos >= startPos; pos-- {
		if pos >= 0 && pos < len(input) && input[pos] == ':' {
			return pos
		}
	}
	return -1
}

// hasTagsAfterColonTargeted checks if there are identifiers (tags) between colon and current position
func (l *Targeted) hasTagsAfterColonTargeted(input string, colonPos, currentPos int) bool {
	checkPos := colonPos + 1
	foundIdentifiers := false

	// Skip whitespace after colon
	checkPos = l.skipWhitespaceInRangeTargeted(input, checkPos, currentPos)

	// Look for identifiers (tags)
	for checkPos < currentPos {
		if !isLetter(input[checkPos]) {
			break
		}

		foundIdentifiers = true
		checkPos = l.skipIdentifierInRangeTargeted(input, checkPos, currentPos)
		checkPos = l.skipWhitespaceInRangeTargeted(input, checkPos, currentPos)
	}

	return foundIdentifiers && checkPos == currentPos
}

// skipWhitespaceInRangeTargeted skips whitespace characters within a range
func (l *Targeted) skipWhitespaceInRangeTargeted(input string, start, end int) int {
	pos := start
	for pos < end && (input[pos] == ' ' || input[pos] == '\t' || input[pos] == '\n' || input[pos] == '\r') {
		pos++
	}
	return pos
}

// skipIdentifierInRangeTargeted skips an identifier within a range
func (l *Targeted) skipIdentifierInRangeTargeted(input string, start, end int) int {
	pos := start
	for pos < end && (isLetter(input[pos]) || isDigit(input[pos]) || input[pos] == '_') {
		pos++
	}
	return pos
}

// makeNumericTokenTargeted creates a numeric token with optimized parsing
func (l *Targeted) makeNumericTokenTargeted(pos token.Position) token.Token {
	start := l.reader.Position()

	// Check for hexadecimal prefix
	if l.reader.Current() == '0' {
		next := l.reader.PeekChar()
		if next == 'x' || next == 'X' {
			// Hexadecimal integer
			l.reader.ReadChar() // skip '0'
			l.reader.ReadChar() // skip 'x'

			for isHexDigit(l.reader.Current()) {
				l.reader.ReadChar()
			}

			// Check for size suffix
			if l.reader.Current() == 'K' || l.reader.Current() == 'k' ||
				l.reader.Current() == 'M' || l.reader.Current() == 'm' {
				if l.reader.PeekChar() == 'B' || l.reader.PeekChar() == 'b' {
					l.reader.ReadChar() // skip first letter
					l.reader.ReadChar() // skip 'B'
				}
			}

			return l.makeTokenTargeted(token.INTEGER_LIT, l.reader.Slice(start), pos)
		}
	}

	// Decimal integer or float
	for isDigit(l.reader.Current()) {
		l.reader.ReadChar()
	}

	// Check for float
	if l.reader.Current() == '.' && isDigit(l.reader.PeekChar()) {
		l.reader.ReadChar() // skip '.'
		for isDigit(l.reader.Current()) {
			l.reader.ReadChar()
		}
		return l.makeTokenTargeted(token.FLOAT_LIT, l.reader.Slice(start), pos)
	}

	// Check for size suffix
	if l.reader.Current() == 'K' || l.reader.Current() == 'k' ||
		l.reader.Current() == 'M' || l.reader.Current() == 'm' {
		if l.reader.PeekChar() == 'B' || l.reader.PeekChar() == 'b' {
			l.reader.ReadChar() // skip first letter
			l.reader.ReadChar() // skip 'B'
		}
	}

	return l.makeTokenTargeted(token.INTEGER_LIT, l.reader.Slice(start), pos)
}

// makeRegexTokenTargeted creates a regex token with optimized parsing
func (l *Targeted) makeRegexTokenTargeted(pos token.Position) token.Token {
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

	return l.makeTokenTargeted(token.REGEX_LIT, l.reader.Slice(start), pos)
}

// makeHexStringTokenTargeted creates a hex string token with optimized parsing
func (l *Targeted) makeHexStringTokenTargeted(pos token.Position) token.Token {
	start := l.reader.Position()
	l.reader.ReadChar() // skip opening '{'

	braceCount := 1 // We've already seen the opening brace
	for braceCount > 0 && l.reader.Current() != 0 {
		if l.reader.Current() == '{' {
			braceCount++
		} else if l.reader.Current() == '}' {
			braceCount--
		}
		l.reader.ReadChar()
	}

	return l.makeTokenTargeted(token.HEX_STRING_LIT, l.reader.Slice(start), pos)
}

// makeIllegalTokenTargeted creates an illegal token with optimized processing
func (l *Targeted) makeIllegalTokenTargeted(pos token.Position) token.Token {
	start := l.reader.Position()

	// Check for specific multi-character illegal sequences first
	if l.reader.Current() == '*' && l.reader.PeekChar() == '/' {
		// Stray closing block comment
		l.reader.ReadChar()
		l.reader.ReadChar()
		return l.makeTokenTargeted(token.ILLEGAL, l.reader.Slice(start), pos)
	}

	// Default behavior: basic illegal sequence reading
	for {
		next := l.reader.PeekChar()
		switch {
		case next == 0 || next == ' ' || next == '\t' || next == '\r' || next == '\n':
			l.reader.ReadChar() // include current illegal char
			return l.makeTokenTargeted(token.ILLEGAL, l.reader.Slice(start), pos)
		case l.reader.Current() == '*' && next == '/':
			// Coalesce stray closing block comment token "*/"
			l.reader.ReadChar()
			l.reader.ReadChar()
			return l.makeTokenTargeted(token.ILLEGAL, l.reader.Slice(start), pos)
		case startsKnownToken(next) || isLetter(next) || isDigit(next):
			l.reader.ReadChar()
			return l.makeTokenTargeted(token.ILLEGAL, l.reader.Slice(start), pos)
		default:
			// Otherwise consume current and continue growing the illegal run
			l.reader.ReadChar()
		}
	}
}

// fastForwardTargeted advances past the current line for error recovery
func (l *Targeted) fastForwardTargeted() {
	for l.reader.Current() != 0 && l.reader.Current() != '\n' {
		l.reader.ReadChar()
	}
}

// makeIdentifierTokenTargeted creates an identifier token using fast lookup
func (l *Targeted) makeIdentifierTokenTargeted(pos token.Position) token.Token {
	literal := l.reader.ReadIdentifierFast()

	// Use fast keyword lookup
	tokenType := lookupIdent(literal)

	return token.Token{
		Type:    tokenType,
		Literal: literal,
		Pos:     pos,
	}
}

// addErrorTargeted adds an error to the error list
func (l *Targeted) addErrorTargeted(pos token.Position, message string) {
	l.errors = append(l.errors, Error{
		Position: pos,
		Message:  message,
	})
}

// GetErrors returns all collected errors.
func (l *Targeted) GetErrors() []Error {
	return l.errors
}

// Reset resets the lexer state for reuse.
func (l *Targeted) Reset() {
	l.errors = l.errors[:0]
	// Reset reader position if needed
	// This would be implemented based on ReaderFast capabilities
}
