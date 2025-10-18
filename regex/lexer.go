package regex

// Minimal lexer for Phase 2 (incremental). Handles:
// - literals (ASCII bytes)
// - dot '.'
// - grouping '(', ')'
// - alternation '|'
// - anchors '^', '$'
// - simple escapes for metacharacters: \\ . | ( ) ^ $
// Character classes and quantifiers will be added incrementally.

type tokenKind int

const (
	tEOF tokenKind = iota
	tChar
	tDot
	tLParen
	tRParen
	tBar
	tCaret
	tDollar
	tLBracket
	tRBracket
	tStar
	tPlus
	tQMark
	tLBrace
	tRBrace
	tComma
	// Shorthand classes and boundaries
	tWord
	tNonWord
	tSpace
	tNonSpace
	tDigit
	tNonDigit
	tWordBoundary
	tNonWordBoundary
)

type token struct {
	kind tokenKind
	ch   byte // for tChar
}

type lexer struct {
	s   string
	i   int
	len int
}

func newLexer(s string) *lexer {
	return &lexer{s: s, len: len(s)}
}

func (l *lexer) next() token {
	if l.i >= l.len {
		return token{kind: tEOF}
	}
	c := l.s[l.i]
	l.i++
	switch c {
	case '.':
		return token{kind: tDot}
	case '(':
		return token{kind: tLParen}
	case ')':
		return token{kind: tRParen}
	case '|':
		return token{kind: tBar}
	case '^':
		return token{kind: tCaret}
	case '$':
		return token{kind: tDollar}
	case '[':
		return token{kind: tLBracket}
	case ']':
		return token{kind: tRBracket}
	case '*':
		return token{kind: tStar}
	case '+':
		return token{kind: tPlus}
	case '?':
		return token{kind: tQMark}
	case '{':
		return token{kind: tLBrace}
	case '}':
		return token{kind: tRBrace}
	case ',':
		return token{kind: tComma}
	case '\\':
		if l.i >= l.len {
			// Trailing backslash; treat as literal
			return token{kind: tChar, ch: '\\'}
		}
		e := l.s[l.i]
		l.i++
		// Recognize shorthand classes and boundaries; otherwise pass escapes as literals
		switch e {
		case 'w':
			return token{kind: tWord}
		case 'W':
			return token{kind: tNonWord}
		case 's':
			return token{kind: tSpace}
		case 'S':
			return token{kind: tNonSpace}
		case 'd':
			return token{kind: tDigit}
		case 'D':
			return token{kind: tNonDigit}
		case 'b':
			return token{kind: tWordBoundary}
		case 'B':
			return token{kind: tNonWordBoundary}
		case '\\', '.', '|', '(', ')', '^', '$', '[', ']', '*', '+', '?', '{', '}', ',':
			return token{kind: tChar, ch: e}
		default:
			// For now, pass through unknown escapes as literal character (non-strict)
			return token{kind: tChar, ch: e}
		}
	default:
		return token{kind: tChar, ch: c}
	}
}

