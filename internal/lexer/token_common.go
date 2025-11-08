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
func NextTokenImpl(creator TokenCreator) token.Token { //nolint:gocyclo // high complexity is inherent to comprehensive tokenization
	creator.skipWhitespace()

	pos := creator.getCurrentPosition()

	switch creator.getCurrentChar() {
	case '+':
		return creator.makeSimpleToken(token.PLUS, "+", pos)
	case '-':
		return creator.makeSimpleToken(token.MINUS, "-", pos)
	case '*':
		return creator.makeSimpleToken(token.MULTIPLY, "*", pos)
	case '%':
		return creator.makeSimpleToken(token.MODULO, "%", pos)
	case '\\':
		return creator.makeSimpleToken(token.INT_DIVIDE, "\\", pos)
	case ':':
		return creator.makeSimpleToken(token.COLON, ":", pos)
	case ',':
		return creator.makeSimpleToken(token.COMMA, ",", pos)
	case '.':
		return creator.makeSimpleToken(token.DOT, ".", pos)
	case '(':
		return creator.makeSimpleToken(token.LPAREN, "(", pos)
	case ')':
		return creator.makeSimpleToken(token.RPAREN, ")", pos)
	case '[':
		return creator.makeSimpleToken(token.LBRACKET, "[", pos)
	case ']':
		return creator.makeSimpleToken(token.RBRACKET, "]", pos)
	case '#':
		return creator.makeSimpleToken(token.HASH, "#", pos)
	case '{':
		return creator.handleBraceToken(pos)
	case '}':
		return creator.makeSimpleToken(token.RBRACE, "}", pos)
	case '=':
		if creator.getPeekChar() == '=' {
			creator.readChar()
			return creator.makeTwoCharToken(token.EQ, "==", pos)
		}
		return creator.makeSimpleToken(token.ASSIGN, "=", pos)
	case '!':
		if creator.getPeekChar() == '=' {
			creator.readChar()
			return creator.makeTwoCharToken(token.NEQ, "!=", pos)
		}
		return creator.makeSimpleToken(token.NOT, "!", pos)
	case '<':
		if creator.getPeekChar() == '=' {
			creator.readChar()
			return creator.makeTwoCharToken(token.LE, "<=", pos)
		}
		if creator.getPeekChar() == '<' {
			creator.readChar()
			return creator.makeTwoCharToken(token.LEFT_SHIFT, "<<", pos)
		}
		return creator.makeSimpleToken(token.LT, "<", pos)
	case '>':
		if creator.getPeekChar() == '=' {
			creator.readChar()
			return creator.makeTwoCharToken(token.GE, ">=", pos)
		}
		if creator.getPeekChar() == '>' {
			creator.readChar()
			return creator.makeTwoCharToken(token.RIGHT_SHIFT, ">>", pos)
		}
		return creator.makeSimpleToken(token.GT, ">", pos)
	case '"':
		return creator.handleStringToken(pos)
	case '/':
		return creator.handleSlashToken(pos)
	case '$':
		return creator.handleStringIdentifierToken(pos)
	case '&':
		return creator.makeSimpleToken(token.BITWISE_AND, "&", pos)
	case '|':
		return creator.makeSimpleToken(token.BITWISE_OR, "|", pos)
	case '^':
		return creator.makeSimpleToken(token.BITWISE_XOR, "^", pos)
	case '~':
		return creator.makeSimpleToken(token.BITWISE_NOT, "~", pos)
	case '@':
		// Position operator '@' (AT)
		return creator.makeSimpleToken(token.AT, "@", pos)
	case 0:
		return creator.makeToken(token.EOF, "", pos)
	default:
		return creator.handleDefaultToken(pos)
	}
}
