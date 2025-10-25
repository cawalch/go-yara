package lexer

import (
	"github.com/cawalch/go-yara/token"
)

// NextToken returns the next token from the input
func (l *Lexer) NextToken() token.Token {
	l.skipWhitespace()

	pos := l.reader.CurrentPosition()

	switch l.ch() {
	case '+':
		return l.makeSimpleToken(token.PLUS, "+", pos)
	case '-':
		return l.makeSimpleToken(token.MINUS, "-", pos)
	case '*':
		return l.makeSimpleToken(token.MULTIPLY, "*", pos)
	case '%':
		return l.makeSimpleToken(token.MODULO, "%", pos)
	case ':':
		return l.makeSimpleToken(token.COLON, ":", pos)
	case ',':
		return l.makeSimpleToken(token.COMMA, ",", pos)
	case '.':
		return l.makeSimpleToken(token.DOT, ".", pos)
	case '(':
		return l.makeSimpleToken(token.LPAREN, "(", pos)
	case ')':
		return l.makeSimpleToken(token.RPAREN, ")", pos)
	case '[':
		return l.makeSimpleToken(token.LBRACKET, "[", pos)
	case ']':
		return l.makeSimpleToken(token.RBRACKET, "]", pos)
	case '#':
		return l.makeSimpleToken(token.HASH, "#", pos)
	case '{':
		return l.handleBraceToken(pos)
	case '}':
		return l.makeSimpleToken(token.RBRACE, "}", pos)
	case '=':
		if l.peekChar() == '=' {
			l.readChar()
			return l.makeTwoCharToken(token.EQ, "==", pos)
		}
		return l.makeSimpleToken(token.ASSIGN, "=", pos)
	case '!':
		if l.peekChar() == '=' {
			l.readChar()
			return l.makeTwoCharToken(token.NEQ, "!=", pos)
		}
		return l.makeSimpleToken(token.NOT, "!", pos)
	case '<':
		if l.peekChar() == '=' {
			l.readChar()
			return l.makeTwoCharToken(token.LE, "<=", pos)
		}
		if l.peekChar() == '<' {
			l.readChar()
			return l.makeTwoCharToken(token.LEFT_SHIFT, "<<", pos)
		}
		return l.makeSimpleToken(token.LT, "<", pos)
	case '>':
		if l.peekChar() == '=' {
			l.readChar()
			return l.makeTwoCharToken(token.GE, ">=", pos)
		}
		if l.peekChar() == '>' {
			l.readChar()
			return l.makeTwoCharToken(token.RIGHT_SHIFT, ">>", pos)
		}
		return l.makeSimpleToken(token.GT, ">", pos)
	case '"':
		return l.handleStringToken(pos)
	case '/':
		return l.handleSlashToken(pos)
	case '$':
		return l.handleStringIdentifierToken(pos)
	case '&':
		return l.makeSimpleToken(token.BITWISE_AND, "&", pos)
	case '|':
		return l.makeSimpleToken(token.BITWISE_OR, "|", pos)
	case '^':
		return l.makeSimpleToken(token.BITWISE_XOR, "^", pos)
	case '~':
		return l.makeSimpleToken(token.BITWISE_NOT, "~", pos)
	case '@':
		// Position operator '@' (AT)
		return l.makeSimpleToken(token.AT, "@", pos)
	case 0:
		return l.makeToken(token.EOF, "", pos)
	default:
		return l.handleDefaultToken(pos)
	}
}
