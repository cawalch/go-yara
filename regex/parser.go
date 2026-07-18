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
	groupCount   int
}

// NewParser constructs a parser with the requested validation flags.
func NewParser(flags ParserFlags) *Parser {
	p := &Parser{}
	if flags&ParserFlagEnableStrictEscapeSequences != 0 {
		p.strictEscape = true
	}
	return p
}

// Parse parses the provided pattern into an AST (minimal subset: alt, concat, primary).
func (p *Parser) Parse(pattern string) (*AST, error) {
	if p.strictEscape {
		if err := validateStrictEscapes(pattern); err != nil {
			return nil, err
		}
	}
	p.lx = newLexer(pattern)
	p.cur = p.lx.next()
	p.groupCount = 0
	root, err := p.parseAlternative()
	if err != nil {
		return nil, err
	}
	if p.cur.kind != tEOF {
		return nil, errors.New("unexpected input after parse")
	}
	return &AST{Flags: 0, Root: root, GroupCount: p.groupCount}, nil
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
		p.groupCount++
		group := p.groupCount
		p.next()
		n, err := p.parseAlternative()
		if err != nil {
			return nil, err
		}
		if p.cur.kind != tRParen {
			return nil, errors.New("missing ')' in group")
		}
		p.next()
		return &Node{Kind: NodeGroup, Group: group, Children: []*Node{n}, Greedy: true}, nil
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
		newVal := min(val*10+int(l.s[l.i]-'0'),
			//nolint:modernize // avoiding min() to prevent shadowing issues
			65535)
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

		// Check for POSIX class like [:alnum:]
		if p.isPOSIXClass(l) {
			if err := p.parsePOSIXClass(l, cls); err != nil {
				return err
			}
			continue
		}

		// Check for shorthand class like \w
		if l.s[l.i] == '\\' && l.i+1 < l.len {
			e := l.s[l.i+1]
			if isShorthandClass(e) {
				l.i += 2
				applyShorthandClass(cls, e)
				continue
			}
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

func isShorthandClass(e byte) bool {
	switch e {
	case 'w', 'W', 's', 'S', 'd', 'D':
		return true
	}
	return false
}

func applyShorthandClass(cls *Class, e byte) {
	switch e {
	case 'w':
		for i := range 256 {
			if isWord(byte(i)) {
				classSet(cls, byte(i))
			}
		}
	case 'W':
		for i := range 256 {
			if !isWord(byte(i)) {
				classSet(cls, byte(i))
			}
		}
	case 's':
		for i := range 256 {
			if isSpace(byte(i)) {
				classSet(cls, byte(i))
			}
		}
	case 'S':
		for i := range 256 {
			if !isSpace(byte(i)) {
				classSet(cls, byte(i))
			}
		}
	case 'd':
		for i := range 256 {
			if isDigit(byte(i)) {
				classSet(cls, byte(i))
			}
		}
	case 'D':
		for i := range 256 {
			if !isDigit(byte(i)) {
				classSet(cls, byte(i))
			}
		}
	}
}

// isPOSIXClass checks if the current position starts a POSIX class like [:alnum:]
func (p *Parser) isPOSIXClass(l *lexer) bool {
	if l.i+1 < l.len && l.s[l.i] == '[' && l.s[l.i+1] == ':' {
		return true
	}
	return false
}

// parsePOSIXClass parses a POSIX class inside a character class
func (p *Parser) parsePOSIXClass(l *lexer, cls *Class) error {
	l.i += 2 // skip '[:'

	negated := false
	if l.i < l.len && l.s[l.i] == '^' {
		negated = true
		l.i++
	}

	start := l.i
	end := -1
	for i := l.i; i+1 < l.len; i++ {
		if l.s[i] == ':' && l.s[i+1] == ']' {
			end = i
			break
		}
	}

	if end == -1 {
		return errors.New("unterminated POSIX class")
	}

	className := l.s[start:end]
	l.i = end + 2 // skip ':]'

	return applyPOSIXClass(cls, className, negated)
}

func applyPOSIXClass(cls *Class, name string, negated bool) error {
	var matchFunc func(byte) bool

	switch name {
	case "alnum":
		matchFunc = func(b byte) bool { return isWord(b) && b != '_' }
	case "alpha":
		matchFunc = func(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }
	case "ascii":
		matchFunc = func(b byte) bool { return b <= 0x7F }
	case "blank":
		matchFunc = func(b byte) bool { return b == ' ' || b == '\t' }
	case "cntrl":
		matchFunc = func(b byte) bool { return b <= 0x1F || b == 0x7F }
	case "digit":
		matchFunc = isDigit
	case "graph":
		matchFunc = func(b byte) bool { return b >= 0x21 && b <= 0x7E }
	case "lower":
		matchFunc = func(b byte) bool { return b >= 'a' && b <= 'z' }
	case "print":
		matchFunc = func(b byte) bool { return b >= 0x20 && b <= 0x7E }
	case "punct":
		matchFunc = func(b byte) bool {
			return (b >= 0x21 && b <= 0x2F) ||
				(b >= 0x3A && b <= 0x40) ||
				(b >= 0x5B && b <= 0x60) ||
				(b >= 0x7B && b <= 0x7E)
		}
	case "space":
		matchFunc = isSpace
	case "upper":
		matchFunc = func(b byte) bool { return b >= 'A' && b <= 'Z' }
	case "word":
		matchFunc = isWord
	case "xdigit":
		matchFunc = func(b byte) bool {
			return isDigit(b) || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
		}
	default:
		return fmt.Errorf("unknown POSIX class: %s", name)
	}

	for i := range 256 {
		if matchFunc(byte(i)) != negated {
			classSet(cls, byte(i))
		}
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
		if strict {
			return 0, errors.New("trailing backslash in escape")
		}
		return '\\', nil
	}
	e := l.s[l.i]
	l.i++

	if e == 'x' && l.i+1 < l.len {
		if h1, ok1 := parseHexDigit(l.s[l.i]); ok1 {
			if h2, ok2 := parseHexDigit(l.s[l.i+1]); ok2 {
				l.i += 2
				return (h1 << 4) | h2, nil
			}
		}
	}

	if mapped, isStandard := getStandardEscape(e); isStandard {
		return mapped, nil
	}

	if literalEscapeChars[e] {
		return e, nil
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

func validateStrictEscapes(pattern string) error {
	for i := 0; i < len(pattern); i++ {
		if pattern[i] != '\\' {
			continue
		}
		i++
		if i >= len(pattern) {
			return errors.New("trailing backslash in escape")
		}
		e := pattern[i]
		if e == 'x' {
			if i+2 >= len(pattern) {
				return errors.New("incomplete hex escape")
			}
			if _, ok := parseHexDigit(pattern[i+1]); !ok {
				return fmt.Errorf("invalid hex escape \\x%c%c", pattern[i+1], pattern[i+2])
			}
			if _, ok := parseHexDigit(pattern[i+2]); !ok {
				return fmt.Errorf("invalid hex escape \\x%c%c", pattern[i+1], pattern[i+2])
			}
			i += 2
			continue
		}
		if isStrictEscape(e) {
			continue
		}
		return fmt.Errorf("unknown escape \\%c", e)
	}
	return nil
}

func isStrictEscape(e byte) bool {
	if _, exists := escapeTokenMapping[e]; exists {
		return true
	}
	if _, exists := getStandardEscape(e); exists {
		return true
	}
	return literalEscapeChars[e]
}

func classSet(c *Class, b byte) {
	idx := b / 8
	bit := b % 8
	c.Bitmap[idx] |= 1 << bit
}
