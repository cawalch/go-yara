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
		return nil, errors.New("unexpected input after parse")
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
		if !isPrimaryStart(p.cur.kind) {
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
			p.maybeMakeUngreedy(n)
			base = n
		case tPlus:
			p.next()
			n := &Node{Kind: NodePlus, Children: []*Node{base}, Greedy: true}
			p.maybeMakeUngreedy(n)
			base = n
		case tQMark:
			// '?' quantifier (0 or 1)
			p.next()
			n := &Node{Kind: NodeRange, Children: []*Node{base}, Start: 0, End: 1, Greedy: true}
			p.maybeMakeUngreedy(n)
			base = n
		case tLBrace:
			minVal, maxVal, err2 := p.parseBound()
			if err2 != nil {
				return nil, err2
			}
			n := &Node{Kind: NodeRange, Children: []*Node{base}, Start: minVal, End: maxVal, Greedy: true}
			p.maybeMakeUngreedy(n)
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
	case tLParen:
		p.next()
		n, err := p.parseAlternative()
		if err != nil {
			return nil, err
		}
		if p.cur.kind != tRParen {
			return nil, errors.New("missing ')' in group")
		}
		p.next()
		return n, nil
	case tLBracket:
		return p.parseClass()
	}

	// Simple one-token constructs (dot, anchors, shorthands, boundaries)
	if nk, ok := tokenToSimpleNode[p.cur.kind]; ok {
		p.next()
		return &Node{Kind: nk, Greedy: true}, nil
	}

	// Returning nil, nil is intentional here - it indicates that this token
	// is not a base expression, and the caller should handle it appropriately.
	return nil, nil //nolint:nilnil // intentional: nil,nil indicates "not a base expression" not an error
}

func (p *Parser) next() { p.cur = p.lx.next() }

// tokenToSimpleNode maps lexer tokens that directly translate to simple AST nodes.
var tokenToSimpleNode = map[tokenKind]NodeKind{
	tDot:             NodeAny,
	tCaret:           NodeAnchorStart,
	tDollar:          NodeAnchorEnd,
	tWord:            NodeWordChar,
	tNonWord:         NodeNonWordChar,
	tSpace:           NodeSpace,
	tNonSpace:        NodeNonSpace,
	tDigit:           NodeDigit,
	tNonDigit:        NodeNonDigit,
	tWordBoundary:    NodeWordBoundary,
	tNonWordBoundary: NodeNonWordBoundary,
}

// isPrimaryStart reports whether a token can start a primary expression.
func isPrimaryStart(k tokenKind) bool {
	if k == tChar || k == tLParen || k == tLBracket {
		return true
	}
	_, ok := tokenToSimpleNode[k]
	return ok
}

// maybeMakeUngreedy consumes an optional '?' after a quantifier to mark it ungreedy.
func (p *Parser) maybeMakeUngreedy(n *Node) {
	if p.cur.kind == tQMark {
		n.Greedy = false
		p.next()
	}
}

// parseBound parses {m}, {m,}, or {m,n}. After '}', it advances p.cur to the next meaningful token.
func (p *Parser) parseBound() (minVal, maxVal uint16, err error) {
	l := p.lx // current index is just after '{'

	minVal, err = p.readBoundNumber(l)
	if err != nil {
		return 0, 0, err
	}

	maxVal, err = p.parseMaxBound(l, minVal)
	if err != nil {
		return 0, 0, err
	}

	if err := p.finalizeBound(l); err != nil {
		return 0, 0, err
	}

	return minVal, maxVal, nil
}

// readBoundNumber reads a numeric value from the bound specification
func (p *Parser) readBoundNumber(l *lexer) (uint16, error) {
	if l.i >= l.len || l.s[l.i] < '0' || l.s[l.i] > '9' {
		return 0, errors.New("expected number in bound")
	}

	val := 0
	for l.i < l.len && l.s[l.i] >= '0' && l.s[l.i] <= '9' {
		newVal := val*10 + int(l.s[l.i]-'0')
		if newVal > 65535 { //nolint:modernize // avoiding min() to prevent shadowing issues
			newVal = 65535
		}
		val = newVal // clamp
		l.i++
	}

	return p.clampToUint16(val), nil
}

// parseMaxBound parses the maximum value part of a bound specification
func (p *Parser) parseMaxBound(l *lexer, minVal uint16) (uint16, error) {
	if l.i >= l.len || l.s[l.i] != ',' {
		return minVal, nil
	}

	l.i++ // skip comma

	if l.i < l.len && l.s[l.i] == '}' {
		return 65535, nil // unbounded
	}

	return p.readBoundNumber(l)
}

// finalizeBound validates and finalizes bound parsing
func (p *Parser) finalizeBound(l *lexer) error {
	if l.i >= l.len || l.s[l.i] != '}' {
		return errors.New("missing '}' in bound")
	}

	l.i++
	p.cur = p.lx.next() // advance to token after '}'
	return nil
}

// clampToUint16 safely converts an int to uint16 with bounds checking
func (p *Parser) clampToUint16(val int) uint16 {
	if val > 65535 {
		val = 65535
	} else if val < 0 {
		val = 0
	}
	// Safe conversion with explicit truncation
	return uint16(val & 0xFFFF) // #nosec G115 - safe conversion with explicit masking
}

// parseClass consumes a character class from the underlying lexer state.
// Supports: negation ^, ranges a-z, escaped metachars (\\, \-, \]).
func (p *Parser) parseClass() (*Node, error) {
	l := p.lx
	cls := &Class{}
	neg := p.parseClassNegation(l)
	p.parseInitialLiteral(l, cls)

	if err := p.parseClassContent(l, cls); err != nil {
		return nil, err
	}

	cls.Negated = neg
	p.cur = p.lx.next()
	return &Node{Kind: NodeClass, Class: cls, Greedy: true}, nil
}

// parseClassNegation handles negation ^ at the start of a character class
func (p *Parser) parseClassNegation(l *lexer) bool {
	if l.i < l.len && l.s[l.i] == '^' {
		l.i++
		return true
	}
	return false
}

// parseInitialLiteral handles literal ']' or '-' at the start of a character class
func (p *Parser) parseInitialLiteral(l *lexer, cls *Class) {
	if l.i < l.len && (l.s[l.i] == ']' || l.s[l.i] == '-') {
		c := l.s[l.i]
		l.i++
		classSet(cls, c)
	}
}

// parseClassContent parses the main content of a character class
func (p *Parser) parseClassContent(l *lexer, cls *Class) error {
	for {
		if l.i >= l.len {
			return errors.New("unterminated character class")
		}

		if l.s[l.i] == ']' {
			l.i++
			break
		}

		c, err := readEscaped(l, p.strictEscape)
		if err != nil {
			return err
		}

		if p.isRangePattern(l) {
			if err := p.parseRange(l, cls, c); err != nil {
				return err
			}
			continue
		}

		classSet(cls, c)
	}
	return nil
}

// isRangePattern checks if current position represents a range pattern
func (p *Parser) isRangePattern(l *lexer) bool {
	return l.i+1 < l.len && l.s[l.i] == '-' && l.s[l.i+1] != ']'
}

// parseRange handles character range patterns like a-z
func (p *Parser) parseRange(l *lexer, cls *Class, start byte) error {
	l.i++ // consume '-'

	end, err := readEscaped(l, p.strictEscape)
	if err != nil {
		return err
	}

	if start > end {
		start, end = end, start
	}

	for i := int(start); i <= int(end); i++ {
		classSet(cls, byte(i))
	}
	return nil
}

func readEscaped(l *lexer, strict bool) (byte, error) {
	if l.i >= l.len {
		return 0, errors.New("unexpected end in escape")
	}
	c := l.s[l.i]
	l.i++
	if c != '\\' {
		return c, nil
	}
	return readEscapeSequence(l, strict)
}

// readEscapeSequence handles escape sequences after a backslash
func readEscapeSequence(l *lexer, strict bool) (byte, error) {
	if l.i >= l.len { // trailing backslash
		return '\\', nil
	}
	e := l.s[l.i]
	l.i++

	if mapped, isStandard := getStandardEscape(e); isStandard {
		return mapped, nil
	}

	return handleUnknownEscape(e, strict)
}

// getStandardEscape returns the character for standard escape sequences
func getStandardEscape(e byte) (byte, bool) {
	switch e {
	case 'n':
		return '\n', true
	case 't':
		return '\t', true
	case 'r':
		return '\r', true
	case 'f':
		return '\f', true
	case 'a':
		return '\a', true
	case 'b':
		return '\b', true
	default:
		return e, false
	}
}

// handleUnknownEscape handles unknown escape characters
func handleUnknownEscape(e byte, strict bool) (byte, error) {
	if strict {
		return 0, fmt.Errorf("unknown escape \\%c", e)
	}
	return e, nil
}

func classSet(c *Class, b byte) {
	idx := b / 8
	bit := b % 8
	c.Bitmap[idx] |= 1 << bit
}
