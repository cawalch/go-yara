package lexer

import "github.com/cawalch/go-yara/token"

// Token emission and creation functions

// makeSimpleToken creates a token for single-character operators and advances the lexer
func (l *Lexer) makeSimpleToken(tokenType token.Type, literal string, pos token.Position) token.Token {
	tok := token.Token{Type: tokenType, Literal: literal, Pos: pos}
	l.readChar()
	return tok
}

// makeTwoCharToken creates a token for two-character operators and advances the lexer
func (l *Lexer) makeTwoCharToken(tokenType token.Type, literal string, pos token.Position) token.Token {
	tok := token.Token{Type: tokenType, Literal: literal, Pos: pos}
	l.readChar() // advance past second character
	return tok
}

// makeToken creates a token with the given type, literal, and position
func (l *Lexer) makeToken(tokenType token.Type, literal string, pos token.Position) token.Token {
	return token.Token{Type: tokenType, Literal: literal, Pos: pos}
}

// makeErrorToken creates an ILLEGAL token and adds an error to the lexer
func (l *Lexer) makeErrorToken(pos token.Position, literal, message string) token.Token {
	l.addError(pos, message)
	return l.makeToken(token.ILLEGAL, literal, pos)
}

// makeStringToken creates a string literal token with validation
func (l *Lexer) makeStringToken(pos token.Position) token.Token {
	lit, closed := l.readString()
	if !closed {
		// Unterminated string - emit ILLEGAL token and add error
		return l.makeErrorToken(pos, lit, "unterminated string literal")
	}

	// Validate escape sequences and collect any errors
	errors := ValidateStringEscapes(lit, pos)
	for _, err := range errors {
		l.addError(err.Position, err.Message)
	}

	return l.makeToken(token.StringLit, lit, pos)
}

// makeRegexToken creates a regex literal token
func (l *Lexer) makeRegexToken(pos token.Position) token.Token {
	lit := l.readRegex()
	return l.makeToken(token.RegexLit, lit, pos)
}

// makeHexStringToken creates a hex string literal token
func (l *Lexer) makeHexStringToken(pos token.Position) token.Token {
	lit := l.readHexString()
	return l.makeToken(token.HexStringLit, lit, pos)
}

// makeIdentifierToken creates an identifier or keyword token
func (l *Lexer) makeIdentifierToken(pos token.Position) token.Token {
	lit := l.readIdentifier()
	tokenType := lookupIdent(lit)
	return l.makeToken(tokenType, lit, pos)
}

// makeNumericToken creates a numeric literal token (integer, hex, octal, float, or size)
func (l *Lexer) makeNumericToken(pos token.Position) token.Token {
	// Check for prefixed numbers (hex, octal)
	if token, ok := l.tryPrefixedNumber(pos); ok {
		return token
	}

	// Read regular number
	lit := l.readNumber()

	// Check for float literal (digit+ "." digit+)
	if l.ch() == '.' && isDigit(l.peekChar()) {
		lit += l.readFloatFraction()
		return l.makeToken(token.FloatLit, lit, pos)
	}

	return l.finalizeNumberToken(lit, pos)
}

// tryPrefixedNumber attempts to parse hex or octal numbers with prefixes
func (l *Lexer) tryPrefixedNumber(pos token.Position) (token.Token, bool) {
	if l.ch() != '0' {
		return token.Token{}, false
	}

	switch l.peekChar() {
	case 'x', 'X':
		lit := l.readHexInteger()
		return l.makeNumberTokenWithSize(lit, token.HexIntegerLit, pos), true

	case 'o', 'O':
		lit := l.readOctalInteger()
		return l.makeNumberTokenWithSize(lit, token.OctalIntegerLit, pos), true

	default:
		return token.Token{}, false
	}
}

// makeNumberTokenWithSize creates a numeric token and checks for size suffix
func (l *Lexer) makeNumberTokenWithSize(lit string, baseType token.Type, pos token.Position) token.Token {
	if l.hasSizeSuffix() {
		sizeLit := l.readSizeSuffix(lit)
		return l.makeToken(token.SizeLit, sizeLit, pos)
	}
	return l.makeToken(baseType, lit, pos)
}

// finalizeNumberToken finalizes a regular number token (integer or size)
func (l *Lexer) finalizeNumberToken(lit string, pos token.Position) token.Token {
	if l.hasSizeSuffix() {
		sizeLit := l.readSizeSuffix(lit)
		return l.makeToken(token.SizeLit, sizeLit, pos)
	}
	return l.makeToken(token.IntegerLit, lit, pos)
}

// makeIllegalToken creates an illegal token for unrecognized characters
func (l *Lexer) makeIllegalToken(pos token.Position) token.Token {
	lit := l.readIllegalSequence()
	return l.makeErrorToken(pos, lit, "illegal character sequence")
}
