package lexer

import (
	"github.com/cawalch/go-yara/token"
)

// TokenMethods defines the common token creation operations
// This replaces the TokenCreator interface with concrete methods
type TokenMethods interface {
	makeSimpleToken(tokenType token.Type, literal string, pos token.Position) token.Token
	makeTwoCharToken(tokenType token.Type, literal string, pos token.Position) token.Token
	makeToken(tokenType token.Type, literal string, pos token.Position) token.Token
	handleStringToken(pos token.Position) token.Token
	handleSlashToken(pos token.Position) token.Token
	handleStringIdentifierToken(pos token.Position) token.Token
	handleBraceToken(pos token.Position) token.Token
	handleDefaultToken(pos token.Position) token.Token
	skipWhitespace()
	getCurrentPosition() token.Position
	getCurrentChar() byte
	getPeekChar() byte
	readChar()
}

// NextTokenImpl is a shared implementation for NextToken logic
// Uses generic type constraint to work with any type that implements the token methods
func NextTokenImpl[T TokenMethods](lexer T) token.Token {
	lexer.skipWhitespace()
	pos := lexer.getCurrentPosition()
	ch := lexer.getCurrentChar()

	if token, ok := trySimpleToken(ch, pos, lexer); ok {
		return token
	}

	if token, ok := tryMultiCharToken(ch, pos, lexer); ok {
		return token
	}

	if token, ok := tryComplexToken(ch, pos, lexer); ok {
		return token
	}

	if ch == 0 {
		return lexer.makeToken(token.EOF, "", pos)
	}

	return lexer.handleDefaultToken(pos)
}

// simpleTokenMapping maps characters to their token types
var simpleTokenMapping = map[byte]token.Type{
	'+':  token.PLUS,
	'-':  token.MINUS,
	'*':  token.MULTIPLY,
	'%':  token.MODULO,
	'\\': token.IntDivide,
	':':  token.COLON,
	',':  token.COMMA,
	'.':  token.DOT,
	'(':  token.LPAREN,
	')':  token.RPAREN,
	'[':  token.LBRACKET,
	']':  token.RBRACKET,
	'#':  token.HASH,
	'}':  token.RBRACE,
	'&':  token.BitwiseAnd,
	'|':  token.BitwiseOr,
	'^':  token.BitwiseXor,
	'~':  token.BitwiseNot,
	'@':  token.AT,
}

// trySimpleToken attempts to create a simple single-character token
func trySimpleToken[T TokenMethods](ch byte, pos token.Position, lexer T) (token.Token, bool) {
	if tokenType, exists := simpleTokenMapping[ch]; exists {
		return lexer.makeSimpleToken(tokenType, string(ch), pos), true
	}
	return token.Token{}, false
}

// tryMultiCharToken attempts to create multi-character operator tokens
func tryMultiCharToken[T TokenMethods](ch byte, pos token.Position, lexer T) (token.Token, bool) {
	switch ch {
	case '=':
		return tryEqualsToken(lexer, pos)
	case '!':
		return tryNotEqualsToken(lexer, pos)
	case '<':
		return tryLessThanToken(lexer, pos)
	case '>':
		return tryGreaterThanToken(lexer, pos)
	default:
		return token.Token{}, false
	}
}

// tryEqualsToken handles = and == tokens
func tryEqualsToken[T TokenMethods](lexer T, pos token.Position) (token.Token, bool) {
	if lexer.getPeekChar() == '=' {
		lexer.readChar()
		return lexer.makeTwoCharToken(token.EQ, "==", pos), true
	}
	return lexer.makeSimpleToken(token.ASSIGN, "=", pos), true
}

// tryNotEqualsToken handles ! and != tokens
func tryNotEqualsToken[T TokenMethods](lexer T, pos token.Position) (token.Token, bool) {
	if lexer.getPeekChar() == '=' {
		lexer.readChar()
		return lexer.makeTwoCharToken(token.NEQ, "!=", pos), true
	}
	return lexer.makeSimpleToken(token.NOT, "!", pos), true
}

// tryLessThanToken handles <, <=, and << tokens
func tryLessThanToken[T TokenMethods](lexer T, pos token.Position) (token.Token, bool) {
	switch lexer.getPeekChar() {
	case '=':
		lexer.readChar()
		return lexer.makeTwoCharToken(token.LE, "<=", pos), true
	case '<':
		lexer.readChar()
		return lexer.makeTwoCharToken(token.LeftShift, "<<", pos), true
	default:
		return lexer.makeSimpleToken(token.LT, "<", pos), true
	}
}

// tryGreaterThanToken handles >, >=, and >> tokens
func tryGreaterThanToken[T TokenMethods](lexer T, pos token.Position) (token.Token, bool) {
	switch lexer.getPeekChar() {
	case '=':
		lexer.readChar()
		return lexer.makeTwoCharToken(token.GE, ">=", pos), true
	case '>':
		lexer.readChar()
		return lexer.makeTwoCharToken(token.RightShift, ">>", pos), true
	default:
		return lexer.makeSimpleToken(token.GT, ">", pos), true
	}
}

// tryComplexToken attempts to create tokens that require special handling
func tryComplexToken[T TokenMethods](ch byte, pos token.Position, lexer T) (token.Token, bool) {
	switch ch {
	case '{':
		return lexer.handleBraceToken(pos), true
	case '"':
		return lexer.handleStringToken(pos), true
	case '/':
		return lexer.handleSlashToken(pos), true
	case '$':
		return lexer.handleStringIdentifierToken(pos), true
	default:
		return token.Token{}, false
	}
}
