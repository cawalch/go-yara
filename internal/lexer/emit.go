package lexer

import "github.com/cawalch/go-yara/token"

// Token emission and creation functions

// makeSimpleToken creates a token for single-character operators and advances the lexer
func (l *Lexer) makeSimpleToken(tokenType token.TokenType, literal string, pos token.Position) token.Token {
	tok := token.Token{Type: tokenType, Literal: literal, Pos: pos}
	l.readChar()
	return tok
}

// makeTwoCharToken creates a token for two-character operators and advances the lexer
func (l *Lexer) makeTwoCharToken(tokenType token.TokenType, literal string, pos token.Position) token.Token {
	tok := token.Token{Type: tokenType, Literal: literal, Pos: pos}
	l.readChar() // advance past second character
	return tok
}

// makeToken creates a token with the given type, literal, and position
func (l *Lexer) makeToken(tokenType token.TokenType, literal string, pos token.Position) token.Token {
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

	return l.makeToken(token.STRING_LIT, lit, pos)
}

// makeRegexToken creates a regex literal token
func (l *Lexer) makeRegexToken(pos token.Position) token.Token {
	lit := l.readRegex()
	return l.makeToken(token.REGEX_LIT, lit, pos)
}

// makeHexStringToken creates a hex string literal token
func (l *Lexer) makeHexStringToken(pos token.Position) token.Token {
	lit := l.readHexString()
	return l.makeToken(token.HEX_STRING_LIT, lit, pos)
}

// makeIdentifierToken creates an identifier or keyword token
func (l *Lexer) makeIdentifierToken(pos token.Position) token.Token {
	lit := l.readIdentifier()
	tokenType := lookupIdent(lit)
	return l.makeToken(tokenType, lit, pos)
}

// makeNumericToken creates a numeric literal token (integer, hex, float, or size)
func (l *Lexer) makeNumericToken(pos token.Position) token.Token {
	// Check for hexadecimal integer (0x prefix)
	if l.ch() == '0' && (l.peekChar() == 'x' || l.peekChar() == 'X') {
		lit := l.readHexInteger()
		// Check for size suffix after hex integer
		if l.hasSizeSuffix() {
			sizeLit := l.readSizeSuffix(lit)
			return l.makeToken(token.SIZE_LIT, sizeLit, pos)
		}
		return l.makeToken(token.HEX_INTEGER_LIT, lit, pos)
	}

	// Read regular number
	lit := l.readNumber()

	// Check for float literal (digit+ "." digit+)
	if l.ch() == '.' && isDigit(l.peekChar()) {
		lit += l.readFloatFraction()
		return l.makeToken(token.FLOAT_LIT, lit, pos)
	}

	// Check for size suffix after decimal integer
	if l.hasSizeSuffix() {
		sizeLit := l.readSizeSuffix(lit)
		return l.makeToken(token.SIZE_LIT, sizeLit, pos)
	}

	return l.makeToken(token.INTEGER_LIT, lit, pos)
}

// makeIllegalToken creates an illegal token for unrecognized characters
func (l *Lexer) makeIllegalToken(pos token.Position) token.Token {
	lit := l.readIllegalSequence()
	return l.makeErrorToken(pos, lit, "illegal character sequence")
}
