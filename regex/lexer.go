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

// simpleTokenMapping maps simple regex characters to token types
var simpleTokenMapping = map[byte]tokenKind{
	'.': tDot,
	'(': tLParen,
	')': tRParen,
	'|': tBar,
	'^': tCaret,
	'$': tDollar,
	'[': tLBracket,
	']': tRBracket,
	'*': tStar,
	'+': tPlus,
	'?': tQMark,
	'{': tLBrace,
	'}': tRBrace,
	',': tComma,
}

// escapeTokenMapping maps escaped characters to token types
var escapeTokenMapping = map[byte]tokenKind{
	'w': tWord,
	'W': tNonWord,
	's': tSpace,
	'S': tNonSpace,
	'd': tDigit,
	'D': tNonDigit,
	'b': tWordBoundary,
	'B': tNonWordBoundary,
}

// literalEscapeChars are characters that should be treated as literals when escaped
var literalEscapeChars = map[byte]bool{
	'\\': true, '.': true, '|': true, '(': true, ')': true, '^': true,
	'$': true, '[': true, ']': true, '*': true, '+': true, '?': true,
	'{': true, '}': true, ',': true, '-': true, '/': true,
}

func (l *lexer) next() token {
	if l.i >= l.len {
		return token{kind: tEOF}
	}
	c := l.s[l.i]
	l.i++

	if tokenKind, exists := simpleTokenMapping[c]; exists {
		return token{kind: tokenKind}
	}

	if c == '\\' {
		return l.handleEscapeSequence()
	}

	return token{kind: tChar, ch: c}
}

// handleEscapeSequence processes escaped characters in regex
func (l *lexer) handleEscapeSequence() token {
	if l.i >= l.len {
		// Trailing backslash; treat as literal
		return token{kind: tChar, ch: '\\'}
	}
	e := l.s[l.i]
	l.i++

	if e == 'x' && l.i+1 < l.len {
		if h1, ok1 := parseHexDigit(l.s[l.i]); ok1 {
			if h2, ok2 := parseHexDigit(l.s[l.i+1]); ok2 {
				l.i += 2
				return token{kind: tChar, ch: (h1 << 4) | h2}
			}
		}
	}

	if tokenKind, exists := escapeTokenMapping[e]; exists {
		return token{kind: tokenKind}
	}

	if mapped, isStandard := getStandardEscape(e); isStandard {
		return token{kind: tChar, ch: mapped}
	}

	if literalEscapeChars[e] {
		return token{kind: tChar, ch: e}
	}

	// For now, pass through unknown escapes as literal character (non-strict)
	return token{kind: tChar, ch: e}
}

// parseHexDigit parses a single hex digit (0-9, a-f, A-F)
func parseHexDigit(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
