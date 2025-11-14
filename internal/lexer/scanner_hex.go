package lexer

import (
	"strings"
)

// Section keywords that should be treated as constants
const (
	sectionKeywordCondition = "condition"
	sectionKeywordMeta      = "meta"
	sectionKeywordStrings   = "strings"
)

// Hexadecimal string scanning functions.
// This module handles the complex logic for detecting and parsing hex string literals,
// including disambiguation between hex strings and regular rule body braces.

// readHexString reads a hexadecimal string literal
func (l *Lexer) readHexString() string {
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

	return l.reader.Slice(start)
}

// isHexStringStart checks if the current position starts a hex string
// More sophisticated logic to distinguish between hex strings and rule body braces
func (l *Lexer) isHexStringStart() bool {
	savedPos := l.reader.Position()
	defer l.reader.SetPosition(savedPos)

	l.reader.ReadChar()
	l.reader.SkipWhitespace()

	if l.isEmptyHexString() {
		return true
	}

	if l.hasTagsBeforeBrace() {
		return true
	}

	if l.isInRuleDeclarationContext() {
		return l.handleRuleDeclarationContext()
	}

	if l.isInStringsSection() {
		return true
	}

	if l.hasObviousHexPatterns() {
		return true
	}

	if l.hasHexDigitWithContext() {
		return !l.looksLikeRuleBody() && !l.looksLikeArithmeticExpression()
	}

	return l.isQuickClosingBrace()
}

// isEmptyHexString checks if this is an empty hex string like "{ }" or "{EOF}"
func (l *Lexer) isEmptyHexString() bool {
	return l.reader.Current() == '}' || l.reader.Current() == 0
}

// handleRuleDeclarationContext handles hex string detection in rule declaration context
func (l *Lexer) handleRuleDeclarationContext() bool {
	if l.isEmptyHexString() {
		return true
	}

	if l.hasSectionKeywordsAhead() {
		return false
	}

	if l.startsWithRuleKeyword() {
		return false
	}

	return l.startsWithHexContent()
}

// hasSectionKeywordsAhead checks for section keywords ahead in the current context
func (l *Lexer) hasSectionKeywordsAhead() bool {
	quickCheckPos := l.reader.Position()
	lookaheadLimit := 50

	defer l.reader.SetPosition(quickCheckPos)

	for i := 0; i < lookaheadLimit && l.reader.Current() != 0; i++ {
		ch := l.reader.Current()
		if ch == ':' {
			if l.hasSectionKeywordBeforeColon(quickCheckPos) {
				return true
			}
		}
		if ch == '}' {
			break
		}
		l.reader.ReadChar()
	}

	return false
}

// hasSectionKeywordBeforeColon checks if there's a section keyword before the current colon
func (l *Lexer) hasSectionKeywordBeforeColon(startPos int) bool {
	contextStart := max(startPos, 0)
	contextEnd := l.reader.Position()
	if contextEnd-contextStart > 20 {
		contextStart = contextEnd - 20
	}
	context := l.reader.Input()[contextStart:contextEnd]
	return l.containsSectionKeyword(context)
}

// startsWithRuleKeyword checks if current position starts with a rule keyword
func (l *Lexer) startsWithRuleKeyword() bool {
	currentChar := l.reader.Current()
	if !isLetter(currentChar) {
		return false
	}

	ident := l.readIdentifierAtPosition()
	return l.isRuleSectionKeyword(ident)
}

// readIdentifierAtPosition reads the identifier at current position
func (l *Lexer) readIdentifierAtPosition() string {
	identStart := l.reader.Position()
	identEnd := identStart
	input := l.reader.Input()

	for identEnd < len(input) && isLetter(input[identEnd]) {
		identEnd++
	}

	return input[identStart:identEnd]
}

// isRuleSectionKeyword checks if identifier is a rule section keyword
func (l *Lexer) isRuleSectionKeyword(ident string) bool {
	return ident == sectionKeywordCondition || ident == sectionKeywordMeta || ident == sectionKeywordStrings
}

// startsWithHexContent checks if current position starts with hex-specific content
func (l *Lexer) startsWithHexContent() bool {
	currentChar := l.reader.Current()
	return isHexDigit(currentChar) || currentChar == '?' || currentChar == '~'
}

// hasObviousHexPatterns checks for obvious hex string pattern characters
func (l *Lexer) hasObviousHexPatterns() bool {
	switch ch := l.reader.Current(); ch {
	case '?', '~', '(', '[':
		return true
	default:
		return false
	}
}

// hasHexDigitWithContext checks if hex digit is followed by hex string context
func (l *Lexer) hasHexDigitWithContext() bool {
	ch := l.reader.Current()
	if !isHexDigit(ch) {
		return false
	}

	next := l.reader.PeekChar()
	return l.isValidHexNextChar(next)
}

// isValidHexNextChar checks if the next character is valid in hex string context
func (l *Lexer) isValidHexNextChar(next byte) bool {
	return isHexDigit(next) || next == ' ' || next == '\t' || next == '\n' ||
		next == '\r' || next == '}' || next == '?' || next == '~' || next == '(' || next == '['
}

// isQuickClosingBrace checks if we quickly hit a closing brace (simple "{ }" case)
func (l *Lexer) isQuickClosingBrace() bool {
	quickCheckPos := l.reader.Position()
	defer l.reader.SetPosition(quickCheckPos)

	for i := 0; i < 10 && l.reader.Current() != 0 && l.reader.Current() != '}'; i++ {
		l.reader.ReadChar()
	}

	return l.reader.Current() == '}'
}

// isInStringsSection checks if the current context appears to be in a strings section
func (l *Lexer) isInStringsSection() bool {
	input := l.reader.Input()
	currentPos := l.reader.Position()

	// Look backwards for "strings:" keyword
	maxLookback := 500
	startPos := max(currentPos-maxLookback, 0)

	// Extract the text before this position for analysis
	contextText := input[startPos:currentPos]

	// Look for "strings:" pattern
	return l.containsStringsKeyword(contextText)
}

// containsStringsKeyword checks if the context contains "strings:" keyword
func (l *Lexer) containsStringsKeyword(text string) bool {
	return l.findKeywordWithColon(text, "strings")
}

// findKeywordWithColon looks for a keyword followed by optional whitespace and a colon
func (l *Lexer) findKeywordWithColon(text, keyword string) bool {
	for i := 0; i <= len(text)-len(keyword); i++ {
		if text[i:i+len(keyword)] == keyword {
			if l.isWordBoundary(text, i) && l.hasColonAfter(text, i+len(keyword)) {
				return true
			}
		}
	}
	return false
}

// isWordBoundary checks if position is at a word boundary
func (l *Lexer) isWordBoundary(text string, pos int) bool {
	return pos == 0 || !isLetter(text[pos-1])
}

// hasColonAfter checks if there's a colon after optional whitespace
func (l *Lexer) hasColonAfter(text string, pos int) bool {
	if pos >= len(text) {
		return false
	}

	// Skip whitespace
	after := pos
	for after < len(text) && (text[after] == ' ' || text[after] == '\t') {
		after++
	}

	return after < len(text) && text[after] == ':'
}

// looksLikeRuleBody checks if the current context appears to be a rule body
func (l *Lexer) looksLikeRuleBody() bool {
	input := l.reader.Input()
	currentPos := l.reader.Position()

	// Look backwards for rule structure keywords
	maxLookback := 200
	startPos := max(currentPos-maxLookback, 0)

	// Extract the text before this position for analysis
	contextText := input[startPos:currentPos]

	// Check for rule body keywords
	return l.containsRuleKeyword(contextText)
}

// containsRuleKeyword checks if the context contains rule structure keywords
func (l *Lexer) containsRuleKeyword(text string) bool {
	return l.containsRuleKeywordPattern(text) || l.containsSectionKeywords(text)
}

// containsRuleKeywordPattern checks for "rule" keyword patterns
func (l *Lexer) containsRuleKeywordPattern(text string) bool {
	if len(text) < 4 {
		return false
	}

	for i := 0; i <= len(text)-4; i++ {
		if text[i:i+4] == KeywordRule {
			if l.isValidRuleKeyword(text, i) {
				return true
			}
		}
	}
	return false
}

// isValidRuleKeyword checks if "rule" at position i is valid
func (l *Lexer) isValidRuleKeyword(text string, i int) bool {
	before := i == 0 || !isLetter(text[i-1])
	if !before {
		return false
	}

	after := i + 4
	if after >= len(text) || !isLetter(text[after]) {
		// Standalone "rule" keyword
		return true
	}

	if text[after] == ' ' || text[after] == '\t' {
		// "rule" followed by whitespace - check for identifier
		return l.hasIdentifierAfter(text, after)
	}

	return false
}

// hasIdentifierAfter checks if there's an identifier after whitespace
func (l *Lexer) hasIdentifierAfter(text string, pos int) bool {
	identStart := pos + 1
	for identStart < len(text) && (text[identStart] == ' ' || text[identStart] == '\t') {
		identStart++
	}
	return identStart < len(text) && isLetter(text[identStart])
}

// containsSectionKeywords checks for section declaration keywords
func (l *Lexer) containsSectionKeywords(text string) bool {
	keywords := []string{"condition:", "meta:", "strings:"}
	for _, keyword := range keywords {
		if l.endsWithKeyword(text, keyword) {
			return true
		}
	}
	return false
}

// endsWithKeyword checks if text ends with the given keyword
func (l *Lexer) endsWithKeyword(text, keyword string) bool {
	return len(text) >= len(keyword) && text[len(text)-len(keyword):] == keyword
}

// containsSectionKeyword checks if context contains section declaration keywords (with colons)
func (l *Lexer) containsSectionKeyword(text string) bool {
	// Look for section keywords with colons
	keywords := []string{"condition:", "meta:", "strings:"}
	for _, keyword := range keywords {
		if len(text) >= len(keyword) {
			// Check if keyword appears at the end
			if text[len(text)-len(keyword):] == keyword {
				return true
			}
		}
	}
	return false
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
	startPos := max(currentPos-maxLookback, 0)

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

// looksLikeArithmeticExpression checks if current context appears to be an arithmetic expression
func (l *Lexer) looksLikeArithmeticExpression() bool {
	input := l.reader.Input()
	currentPos := l.reader.Position()

	// Look backwards for arithmetic patterns
	maxLookback := 100
	startPos := max(currentPos-maxLookback, 0)

	// Extract text before this position for analysis
	contextText := input[startPos:currentPos]

	// Check for arithmetic operators or patterns that suggest this is not a hex string
	arithmeticPatterns := []string{"==", "!=", ">=", "<=", ">", "<", "+", "-", "*", "/", "and ", " or ", "not ", "condition:", "meta:", "strings:"}

	for _, pattern := range arithmeticPatterns {
		if len(contextText) >= len(pattern) {
			// Check if pattern appears near the end of context
			if len(contextText) >= len(pattern) && contextText[len(contextText)-len(pattern):] == pattern {
				return true
			}
		}
	}

	// Check for numbers separated by spaces (like "90 9 19") which is more likely arithmetic than hex
	// when not in a strings section
	if !l.isInStringsSection() {
		// Look for pattern of numbers with spaces
		words := strings.Fields(contextText)
		if len(words) >= 2 {
			numberCount := 0
			for _, word := range words {
				// Check if word looks like a decimal number (not hex)
				if l.looksLikeDecimalNumber(word) {
					numberCount++
				}
			}
			// If we have multiple decimal numbers, likely arithmetic
			if numberCount >= 2 {
				return true
			}
		}
	}

	return false
}

// looksLikeDecimalNumber checks if a string looks like a decimal number (not hex)
func (l *Lexer) looksLikeDecimalNumber(s string) bool {
	if s == "" {
		return false
	}

	// Check if all characters are digits (no hex letters A-F)
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return false
		}
	}

	return true
}

// isInRuleDeclarationContext checks if we're in a rule declaration (after "rule" but before first section)
func (l *Lexer) isInRuleDeclarationContext() bool {
	contextText := l.getLookbackContext()

	if !l.hasRuleKeyword(contextText) {
		return false
	}

	return !l.hasSectionKeywordAfterRule(contextText)
}

// getLookbackContext gets text context for analysis
func (l *Lexer) getLookbackContext() string {
	input := l.reader.Input()
	currentPos := l.reader.Position()
	maxLookback := 200
	startPos := max(currentPos-maxLookback, 0)
	return input[startPos:currentPos]
}

// hasRuleKeyword checks if context has "rule" keyword with word boundaries
func (l *Lexer) hasRuleKeyword(contextText string) bool {
	for i := 0; i <= len(contextText)-len(KeywordRule); i++ {
		if contextText[i:i+len(KeywordRule)] == KeywordRule {
			if l.isRuleKeywordBounded(contextText, i) {
				return true
			}
		}
	}
	return false
}

// isRuleKeywordBounded checks if "rule" at position i has proper word boundaries
func (l *Lexer) isRuleKeywordBounded(contextText string, i int) bool {
	before := i == 0 || !isLetter(contextText[i-1])
	after := i + len(KeywordRule)
	return before || (after >= len(contextText) || !isLetter(contextText[after]))
}

// hasSectionKeywordAfterRule checks if section keywords appear after rule
func (l *Lexer) hasSectionKeywordAfterRule(contextText string) bool {
	sectionKeywords := []string{"meta", "strings", "condition"}
	rulePos := strings.LastIndex(contextText, KeywordRule)

	for _, keyword := range sectionKeywords {
		if l.keywordAppearsAfter(contextText, keyword, rulePos) {
			return true
		}
	}
	return false
}

// keywordAppearsAfter checks if keyword appears after given position
func (l *Lexer) keywordAppearsAfter(contextText, keyword string, afterPos int) bool {
	if len(contextText) < len(keyword) {
		return false
	}
	keywordPos := strings.LastIndex(contextText, keyword)
	return keywordPos > afterPos
}
