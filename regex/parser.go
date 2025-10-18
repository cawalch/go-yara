package regex

import (
	"errors"
	"fmt"
)

// Parser provides a hand-written lexer+parser pipeline (incremental).
type Parser struct {
	lx           *lexer
	cur          token
	strictEscape bool // validate escape sequences strictly (ParserFlagEnableStrictEscapeSequences)
}
 // ErrNotImplemented is returned for parser features not yet implemented.
var ErrNotImplemented = errors.New("regex: parser not implemented yet")

 // NewParser constructs a Parser. Flags are accepted for future use.
func NewParser(flags ParserFlags) *Parser {
 p := &Parser{}
 if flags&ParserFlagEnableStrictEscapeSequences != 0 {
 	p.strictEscape = true
 }
 return p
}

// Parse parses the provided pattern into an AST (minimal subset: alt, concat, primary).
func (p *Parser) Parse(pattern string) (*AST, error) {
	p.lx = newLexer(pattern)
	p.cur = p.lx.next()
	root, err := p.parseAlternative()
	if err != nil {
		return nil, err
	}
	if p.cur.kind != tEOF {
		return nil, fmt.Errorf("unexpected input after parse")
	}
	return &AST{Flags: 0, Root: root}, nil
}

// alternative := concatenation ( '|' concatenation )*
func (p *Parser) parseAlternative() (*Node, error) {
	left, err := p.parseConcat()
	if err != nil {
		return nil, err
	}
	for p.cur.kind == tBar {
		p.next()
		var right *Node
		right, err = p.parseConcat()
		if err != nil {
			return nil, err
		}
		left = &Node{Kind: NodeAlt, Children: []*Node{left, right}, Greedy: true}
	}
	return left, nil
}

// concatenation := primary+
func (p *Parser) parseConcat() (*Node, error) {
	var nodes []*Node
	for {
		n, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		if n == nil {
			break
		}
		nodes = append(nodes, n)
		// Continue while next token starts a primary
		if p.cur.kind != tChar && p.cur.kind != tDot && p.cur.kind != tLParen && p.cur.kind != tCaret && p.cur.kind != tDollar && p.cur.kind != tLBracket &&
			p.cur.kind != tWord && p.cur.kind != tNonWord && p.cur.kind != tSpace && p.cur.kind != tNonSpace && p.cur.kind != tDigit && p.cur.kind != tNonDigit &&
			p.cur.kind != tWordBoundary && p.cur.kind != tNonWordBoundary {
			break
		}
	}
	if len(nodes) == 0 {
		// empty concatenation is allowed in some alternation positions; represent as empty
		return &Node{Kind: NodeEmpty, Greedy: true}, nil
	}
	if len(nodes) == 1 {
		return nodes[0], nil
	}
	return &Node{Kind: NodeConcat, Children: nodes, Greedy: true}, nil
}

// primary := base ( quantifier )*
func (p *Parser) parsePrimary() (*Node, error) {
	base, err := p.parseBase()
	if err != nil || base == nil {
		return base, err
	}
	for {
		switch p.cur.kind {
		case tStar:
			p.next()
			n := &Node{Kind: NodeStar, Children: []*Node{base}, Greedy: true}
			if p.cur.kind == tQMark {
				n.Greedy = false
				p.next()
			}
			base = n
		case tPlus:
			p.next()
			n := &Node{Kind: NodePlus, Children: []*Node{base}, Greedy: true}
			if p.cur.kind == tQMark {
				n.Greedy = false
				p.next()
			}
			base = n
		case tQMark:
			// '?' quantifier (0 or 1)
			p.next()
			n := &Node{Kind: NodeRange, Children: []*Node{base}, Start: 0, End: 1, Greedy: true}
			if p.cur.kind == tQMark {
				n.Greedy = false
				p.next()
			}
			base = n
		case tLBrace:
			min, max, err2 := p.parseBound()
			if err2 != nil {
				return nil, err2
			}
			n := &Node{Kind: NodeRange, Children: []*Node{base}, Start: min, End: max, Greedy: true}
			if p.cur.kind == tQMark {
				n.Greedy = false
				p.next()
			}
			base = n
		default:
			return base, nil
		}
	}
}

// base := literal | '.' | '^' | '$' | '(' alternative ')' | '[' class ']' | shorthand classes | word boundaries
func (p *Parser) parseBase() (*Node, error) {
	switch p.cur.kind {
	case tChar:
		ch := p.cur.ch
		p.next()
		return &Node{Kind: NodeLiteral, Value: ch, Greedy: true}, nil
	case tDot:
		p.next()
		return &Node{Kind: NodeAny, Greedy: true}, nil
	case tCaret:
		p.next()
		return &Node{Kind: NodeAnchorStart, Greedy: true}, nil
	case tDollar:
		p.next()
		return &Node{Kind: NodeAnchorEnd, Greedy: true}, nil
	case tLParen:
		p.next()
		n, err := p.parseAlternative()
		if err != nil {
			return nil, err
		}
		if p.cur.kind != tRParen {
			return nil, fmt.Errorf("missing ')' in group")
		}
		p.next()
		return n, nil
	case tLBracket:
		return p.parseClass()
	case tWord:
		p.next()
		return &Node{Kind: NodeWordChar, Greedy: true}, nil
	case tNonWord:
		p.next()
		return &Node{Kind: NodeNonWordChar, Greedy: true}, nil
	case tSpace:
		p.next()
		return &Node{Kind: NodeSpace, Greedy: true}, nil
	case tNonSpace:
		p.next()
		return &Node{Kind: NodeNonSpace, Greedy: true}, nil
	case tDigit:
		p.next()
		return &Node{Kind: NodeDigit, Greedy: true}, nil
	case tNonDigit:
		p.next()
		return &Node{Kind: NodeNonDigit, Greedy: true}, nil
	case tWordBoundary:
		p.next()
		return &Node{Kind: NodeWordBoundary, Greedy: true}, nil
	case tNonWordBoundary:
		p.next()
		return &Node{Kind: NodeNonWordBoundary, Greedy: true}, nil
	default:
		return nil, nil
	}
}

func (p *Parser) next() { p.cur = p.lx.next() }

// parseBound parses {m}, {m,}, or {m,n}. After '}', it advances p.cur to the next meaningful token.
func (p *Parser) parseBound() (uint16, uint16, error) {
	l := p.lx // current index is just after '{'
	readNum := func() (uint16, error) {
		if l.i >= l.len || l.s[l.i] < '0' || l.s[l.i] > '9' {
			return 0, fmt.Errorf("expected number in bound")
		}
		val := 0
		for l.i < l.len && l.s[l.i] >= '0' && l.s[l.i] <= '9' {
			val = val*10 + int(l.s[l.i]-'0')
			if val > 65535 {
				val = 65535
			} // clamp
			l.i++
		}
		return uint16(val), nil //nolint:gosec // val is clamped to <= 65535
	}
	min, err := readNum()
	if err != nil {
		return 0, 0, err
	}
	var max uint16
	if l.i < l.len && l.s[l.i] == ',' {
		l.i++
		if l.i < l.len && l.s[l.i] == '}' {
			max = 65535 // unbounded
		} else {
			m, err2 := readNum()
			if err2 != nil {
				return 0, 0, err2
			}
			max = m
		}
	} else {
		max = min
	}
	if l.i >= l.len || l.s[l.i] != '}' {
		return 0, 0, fmt.Errorf("missing '}' in bound")
	}
	l.i++
	p.cur = p.lx.next() // advance to token after '}'
	return min, max, nil
}

// parseClass consumes a character class from the underlying lexer state.
// Supports: negation ^, ranges a-z, escaped metachars (\\, \-, \]).
func (p *Parser) parseClass() (*Node, error) {
	// We have just seen '[' as current token; the lexer's index is already positioned
	// right after '['. Work directly with the underlying input index.
	l := p.lx
	cls := &Class{}
	neg := false
	// Negation if first char is '^'
	if l.i < l.len && l.s[l.i] == '^' {
		neg = true
		l.i++
	}
	// If first char is ']' or '-' treat as literal
	if l.i < l.len && (l.s[l.i] == ']' || l.s[l.i] == '-') {
		c := l.s[l.i]
		l.i++
		classSet(cls, c)
	}
	for {
		if l.i >= l.len {
			return nil, fmt.Errorf("unterminated character class")
		}
		if l.s[l.i] == ']' {
			l.i++
			break
		}
		// read first char (with simple escapes)
		c, err := readEscaped(l, p.strictEscape)
		if err != nil {
			return nil, err
		}
		// range?
		if l.i+1 < l.len && l.s[l.i] == '-' && l.s[l.i+1] != ']' {
			// consume '-'
			l.i++
			end, err2 := readEscaped(l, p.strictEscape)
			if err2 != nil {
				return nil, err2
			}
			start, finish := c, end
			if start > finish {
				start, finish = finish, start
			}
			for v := start; v <= finish; v++ {
				classSet(cls, v)
			}
			continue
		}
		classSet(cls, c)
	}
	// Set negation and set current token properly to next token after ']'
	cls.Negated = neg
	p.cur = p.lx.next()
	return &Node{Kind: NodeClass, Class: cls, Greedy: true}, nil
}

func readEscaped(l *lexer, strict bool) (byte, error) {
	if l.i >= l.len {
		return 0, fmt.Errorf("unexpected end in escape")
	}
	c := l.s[l.i]
	l.i++
	if c != '\\' {
		return c, nil
	}
	if l.i >= l.len { // trailing backslash
		return '\\', nil
	}
	e := l.s[l.i]
	l.i++
	switch e {
	case 'n':
		return '\n', nil
	case 't':
		return '\t', nil
	case 'r':
		return '\r', nil
	case 'f':
		return '\f', nil
	case 'a':
		return '\a', nil
	case 'b':
		return '\b', nil
	default:
		if strict {
			return 0, fmt.Errorf("unknown escape \\%c", e)
		}
		return e, nil
	}
}

func classSet(c *Class, b byte) {
	idx := b / 8
	bit := b % 8
	c.Bitmap[idx] |= 1 << bit
}
