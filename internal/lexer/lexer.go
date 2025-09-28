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
		return l.makeSimpleToken(token.PLUS, "+")
	case '-':
		return l.makeSimpleToken(token.MINUS, "-")
	case '*':
		return l.makeSimpleToken(token.MULTIPLY, "*")
	case '%':
		return l.makeSimpleToken(token.MODULO, "%")
	case ':':
		return l.makeSimpleToken(token.COLON, ":")
	case ',':
		return l.makeSimpleToken(token.COMMA, ",")
	case '.':
		return l.makeSimpleToken(token.DOT, ".")
	case '(':
		return l.makeSimpleToken(token.LPAREN, "(")
	case ')':
		return l.makeSimpleToken(token.RPAREN, ")")
	case '{':
		return l.handleBraceToken(pos)
	case '}':
		return l.makeSimpleToken(token.RBRACE, "}")
	case '=':
		if l.peekChar() == '=' {
			l.readChar()
			return l.makeTwoCharToken(token.EQ, "==")
		}
		return l.makeSimpleToken(token.ASSIGN, "=")
	case '!':
		if l.peekChar() == '=' {
			l.readChar()
			return l.makeTwoCharToken(token.NEQ, "!=")
		}
		return l.makeSimpleToken(token.ILLEGAL, "!")
	case '<':
		if l.peekChar() == '=' {
			l.readChar()
			return l.makeTwoCharToken(token.LE, "<=")
		}
		if l.peekChar() == '<' {
			l.readChar()
			return l.makeTwoCharToken(token.LEFT_SHIFT, "<<")
		}
		return l.makeSimpleToken(token.LT, "<")
	case '>':
		if l.peekChar() == '=' {
			l.readChar()
			return l.makeTwoCharToken(token.GE, ">=")
		}
		if l.peekChar() == '>' {
			l.readChar()
			return l.makeTwoCharToken(token.RIGHT_SHIFT, ">>")
		}
		return l.makeSimpleToken(token.GT, ">")
	case '"':
		return l.handleStringToken(pos)
	case '/':
		return l.handleSlashToken(pos)
	case '$':
		return l.handleStringIdentifierToken(pos)
	case '&':
		return l.makeSimpleToken(token.BITWISE_AND, "&")
	case '|':
		return l.makeSimpleToken(token.BITWISE_OR, "|")
	case '^':
		return l.makeSimpleToken(token.BITWISE_XOR, "^")
	case '~':
		return l.makeSimpleToken(token.BITWISE_NOT, "~")
	case 0:
		return l.makeToken(token.EOF, "", pos)
	default:
		return l.handleDefaultToken(pos)
	}
}
