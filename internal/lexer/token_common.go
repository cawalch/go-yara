package lexer

import (
	"github.com/cawalch/go-yara/token"
)

// TokenCreator interface defines methods for creating tokens
type TokenCreator interface {
	makeSimpleToken(tokenType token.TokenType, literal string, pos token.Position) token.Token
	makeTwoCharToken(tokenType token.TokenType, literal string, pos token.Position) token.Token
	makeToken(tokenType token.TokenType, literal string, pos token.Position) token.Token
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
func NextTokenImpl(creator TokenCreator) token.Token {
	creator.skipWhitespace()
	pos := creator.getCurrentPosition()
	ch := creator.getCurrentChar()

	if token, ok := trySimpleToken(ch, pos, creator); ok {
		return token
	}

	if token, ok := tryMultiCharToken(ch, pos, creator); ok {
		return token
	}

	if token, ok := tryComplexToken(ch, pos, creator); ok {
		return token
	}

	if ch == 0 {
		return creator.makeToken(token.EOF, "", pos)
	}

	return creator.handleDefaultToken(pos)
}

// simpleTokenMapping maps characters to their token types
var simpleTokenMapping = map[byte]token.TokenType{
	'+':  token.PLUS,
	'-':  token.MINUS,
	'*':  token.MULTIPLY,
	'%':  token.MODULO,
	'\\': token.INT_DIVIDE,
	':':  token.COLON,
	',':  token.COMMA,
	'.':  token.DOT,
	'(':  token.LPAREN,
	')':  token.RPAREN,
	'[':  token.LBRACKET,
	']':  token.RBRACKET,
	'#':  token.HASH,
	'}':  token.RBRACE,
	'&':  token.BITWISE_AND,
	'|':  token.BITWISE_OR,
	'^':  token.BITWISE_XOR,
	'~':  token.BITWISE_NOT,
	'@':  token.AT,
}

// trySimpleToken attempts to create a simple single-character token
func trySimpleToken(ch byte, pos token.Position, creator TokenCreator) (token.Token, bool) {
	if tokenType, exists := simpleTokenMapping[ch]; exists {
		return creator.makeSimpleToken(tokenType, string(ch), pos), true
	}
	return token.Token{}, false
}

// tryMultiCharToken attempts to create multi-character operator tokens
func tryMultiCharToken(ch byte, pos token.Position, creator TokenCreator) (token.Token, bool) {
	switch ch {
	case '=':
		return tryEqualsToken(creator, pos)
	case '!':
		return tryNotEqualsToken(creator, pos)
	case '<':
		return tryLessThanToken(creator, pos)
	case '>':
		return tryGreaterThanToken(creator, pos)
	default:
		return token.Token{}, false
	}
}

// tryEqualsToken handles = and == tokens
func tryEqualsToken(creator TokenCreator, pos token.Position) (token.Token, bool) {
	if creator.getPeekChar() == '=' {
		creator.readChar()
		return creator.makeTwoCharToken(token.EQ, "==", pos), true
	}
	return creator.makeSimpleToken(token.ASSIGN, "=", pos), true
}

// tryNotEqualsToken handles ! and != tokens
func tryNotEqualsToken(creator TokenCreator, pos token.Position) (token.Token, bool) {
	if creator.getPeekChar() == '=' {
		creator.readChar()
		return creator.makeTwoCharToken(token.NEQ, "!=", pos), true
	}
	return creator.makeSimpleToken(token.NOT, "!", pos), true
}

// tryLessThanToken handles <, <=, and << tokens
func tryLessThanToken(creator TokenCreator, pos token.Position) (token.Token, bool) {
	switch creator.getPeekChar() {
	case '=':
		creator.readChar()
		return creator.makeTwoCharToken(token.LE, "<=", pos), true
	case '<':
		creator.readChar()
		return creator.makeTwoCharToken(token.LEFT_SHIFT, "<<", pos), true
	default:
		return creator.makeSimpleToken(token.LT, "<", pos), true
	}
}

// tryGreaterThanToken handles >, >=, and >> tokens
func tryGreaterThanToken(creator TokenCreator, pos token.Position) (token.Token, bool) {
	switch creator.getPeekChar() {
	case '=':
		creator.readChar()
		return creator.makeTwoCharToken(token.GE, ">=", pos), true
	case '>':
		creator.readChar()
		return creator.makeTwoCharToken(token.RIGHT_SHIFT, ">>", pos), true
	default:
		return creator.makeSimpleToken(token.GT, ">", pos), true
	}
}

// tryComplexToken attempts to create tokens that require special handling
func tryComplexToken(ch byte, pos token.Position, creator TokenCreator) (token.Token, bool) {
	switch ch {
	case '{':
		return creator.handleBraceToken(pos), true
	case '"':
		return creator.handleStringToken(pos), true
	case '/':
		return creator.handleSlashToken(pos), true
	case '$':
		return creator.handleStringIdentifierToken(pos), true
	default:
		return token.Token{}, false
	}
}
