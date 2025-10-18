package lexer

import "github.com/cawalch/go-yara/token"

// Token handler functions for specific character types

// handleStringToken handles string literal tokens starting with '"'
func (l *Lexer) handleStringToken(pos token.Position) token.Token {
	return l.makeStringToken(pos)
}

// handleSlashToken handles tokens starting with '/' (comments, regex, division)
func (l *Lexer) handleSlashToken(pos token.Position) token.Token {
	// Check if it's an empty regex first (handles // and //flags)
	if l.peekChar() == '/' && l.isEmptyRegex() {
		return l.makeRegexToken(pos)
	}

	// Check if it looks like a regex (not a comment)
	if l.looksLikeRegex() {
		return l.makeRegexToken(pos)
	}

	// If we get here, it's a division operator
	// Comments should have been handled by skipWhitespace
	return l.makeSimpleToken(token.DIVIDE, "/", pos)
}

// handleBraceToken handles tokens starting with '{' (hex strings or regular braces)
func (l *Lexer) handleBraceToken(pos token.Position) token.Token {
	if l.isHexStringStart() {
		return l.makeHexStringToken(pos)
	}

	// If we're not in a rule body, this is a regular brace
	return l.makeSimpleToken(token.LBRACE, "{", pos)
}

// handleDefaultToken handles identifiers, numbers, and other default cases
func (l *Lexer) handleDefaultToken(pos token.Position) token.Token {
	if isLetter(l.ch()) {
		return l.makeIdentifierToken(pos)
	}

	if isDigit(l.ch()) {
		return l.makeNumericToken(pos)
	}

	// Generate an error for illegal characters even in recovery mode
	tok := l.makeIllegalToken(pos)

	if l.recoveryMode == RecoverySection {
		l.fastForward()
		return l.NextToken()
	}

	return tok
}

// handleStringIdentifierToken handles string identifiers starting with '$'
func (l *Lexer) handleStringIdentifierToken(pos token.Position) token.Token {
	lit := l.readStringIdentifier()
	return l.makeToken(token.STRING_IDENTIFIER, lit, pos)
}
