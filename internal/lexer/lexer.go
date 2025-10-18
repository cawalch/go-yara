package lexer

import (
	"github.com/cawalch/go-yara/token"
)

// NextToken returns the next token from the input
func (l *Lexer) NextToken() token.Token {
	l.skipWhitespace()

	pos := l.reader.CurrentPosition()

	// If we're inside a rule body, handle rule body parsing
	if l.insideRuleBody {
		return l.nextRuleBodyToken(pos)
	}

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
	case '[':
		return l.makeSimpleToken(token.LBRACKET, "[")
	case ']':
		return l.makeSimpleToken(token.RBRACKET, "]")
	case '#':
		return l.makeSimpleToken(token.HASH, "#")
	case '{':
		return l.handleBraceToken(pos)
	case '}':
		// Exiting rule body when we encounter closing brace
		if l.insideRuleBody {
			l.insideRuleBody = false
		}
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

// nextRuleBodyToken handles tokenization when inside a rule body
func (l *Lexer) nextRuleBodyToken(pos token.Position) token.Token {
	// Handle section keywords (meta, strings, condition) first
	if isLetter(l.ch()) {
		wordStart := l.position()
		for isLetter(l.ch()) {
			l.readChar()
		}
		word := l.reader.Slice(wordStart)

		// Check if this is a section keyword followed by ':'
		if l.ch() == ':' {
			switch word {
			case "meta":
				return l.makeToken(token.META, "meta:", pos)
			case "strings":
				return l.makeToken(token.STRINGS, "strings:", pos)
			case "condition":
				return l.makeToken(token.CONDITION, "condition:", pos)
			}
		}

		// Not a section keyword, rewind and handle as regular identifier
		l.reader.SetPosition(wordStart)
		l.readChar() // Restore the first character
		return l.handleDefaultToken(pos)
	}

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
	case '[':
		return l.makeSimpleToken(token.LBRACKET, "[")
	case ']':
		return l.makeSimpleToken(token.RBRACKET, "]")
	case '#':
		return l.makeSimpleToken(token.HASH, "#")
	case '{':
		return l.handleBraceToken(pos)
	case '}':
		// Exiting rule body when we encounter closing brace
		l.insideRuleBody = false
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
