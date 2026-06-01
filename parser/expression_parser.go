package parser

import (
	"fmt"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

// tokenSource is the minimal interface the expression parser needs from a lexer.
type tokenSource interface {
	NextToken() token.Token
}

// ExpressionParser parses YARA expression syntax using a Pratt parser.
type ExpressionParser struct {
	quantifierParser  *QuantifierParser
	current           token.Token
	peek              token.Token
	emitter           any
	depth             int
	depthStack        []int
	src               tokenSource
	maxRecursionDepth int
	// External token management for synchronization with parent parser
	externalNextToken func()
	externalAddError  func(error)
	useExternalTokens bool
}

// NewExpressionParser creates a new expression parser.
// The first argument can be a tokenSource or *lexer.Lexer (for legacy callers).
func NewExpressionParser(first any, second any) *ExpressionParser {
	var src tokenSource
	if s, ok := first.(tokenSource); ok {
		src = s
	}

	return &ExpressionParser{
		quantifierParser: nil,
		depth:            0,
		depthStack:       make([]int, 0),
		emitter:          second,
		src:              src,
	}
}

// ParseExpression parses an expression using a Pratt (precedence climbing) parser.
func (p *ExpressionParser) ParseExpression() (ast.Expression, error) {
	if err := p.incrementDepth(); err != nil {
		return nil, err
	}
	defer p.decrementDepth()

	// Initialize tokens if not already done
	if p.current.Type == token.EOF && p.src != nil {
		p.InitializeTokens()
	}

	return p.parseBinaryExpressionWithPrecedence(0)
}

// ---------- operator classification helpers ----------

func isBinaryOperator(tok token.Type) bool {
	switch tok {
	case token.AND, token.OR:
		return true
	case token.EQ, token.NEQ, token.LT, token.LE, token.GT, token.GE,
		token.CONTAINS, token.ICONTAINS, token.STARTSWITH, token.ISTARTSWITH,
		token.ENDSWITH, token.IENDSWITH, token.IEQUALS, token.MATCHES,
		token.AT, token.IN:
		return true
	case token.PLUS, token.MINUS, token.MULTIPLY, token.DIVIDE, token.MODULO:
		return true
	case token.BitwiseAnd, token.BitwiseOr, token.BitwiseXor,
		token.LeftShift, token.RightShift:
		return true
	default:
		return false
	}
}

// operatorPrecedence returns (precedence, leftAssociative).
// Higher number = binds tighter.
func operatorPrecedence(tok token.Type) (prec int, leftAssoc bool) {
	switch tok {
	case token.AND, token.OR:
		return 1, true
	case token.OF:
		return 2, true
	case token.EQ, token.NEQ, token.LT, token.LE, token.GT, token.GE,
		token.CONTAINS, token.ICONTAINS, token.STARTSWITH, token.ISTARTSWITH,
		token.ENDSWITH, token.IENDSWITH, token.IEQUALS, token.MATCHES,
		token.AT, token.IN:
		return 3, true
	case token.BitwiseAnd, token.BitwiseOr, token.BitwiseXor,
		token.LeftShift, token.RightShift:
		return 4, true
	case token.PLUS, token.MINUS, token.MULTIPLY, token.DIVIDE, token.MODULO:
		return 5, true
	default:
		return 0, false
	}
}

func isUnaryOperator(tok token.Type) bool {
	switch tok {
	case token.NOT, token.BitwiseNot, token.MINUS, token.DEFINED:
		return true
	default:
		return false
	}
}

// ---------- Pratt parser core ----------

// parseBinaryExpressionWithPrecedence parses binary expressions with operator precedence climbing.
func (p *ExpressionParser) parseBinaryExpressionWithPrecedence(minPrecedence int) (ast.Expression, error) {
	left, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}

	for isBinaryOperator(p.current.Type) {
		op := p.current.Type
		opPrec, leftAssoc := operatorPrecedence(op)
		if opPrec < minPrecedence {
			break
		}

		rightPrec := opPrec
		if leftAssoc {
			rightPrec++
		}

		// Special case: "N % of" — percent quantifier
		// When left is an integer literal and op is MODULO and next token is OF,
		// this is a percent quantifier, not a modulo operation.
		if op == token.MODULO && p.peekTokenIs(token.OF) {
			if intLit, ok := left.(*ast.Literal); ok &&
				(intLit.Type == token.IntegerLit || intLit.Type == token.HexIntegerLit || intLit.Type == token.OctalIntegerLit) {
				p.nextToken() // consume '%'
				p.nextToken() // consume 'of'
				// Parse the target (string set)
				target, err := p.parseQuantifierTarget(intLit.Pos)
				if err != nil {
					return nil, err
				}
				percentExpr := &ast.PercentExpression{
					Pos:   intLit.Pos,
					Value: intLit,
				}
				left = &ast.OfExpression{
					Pos:     intLit.Pos,
					Count:   percentExpr,
					Strings: target,
				}
				continue
			}
		}

		p.nextToken() // consume operator

		right, err := p.parseBinaryExpressionWithPrecedence(rightPrec)
		if err != nil {
			return nil, err
		}

		left = &ast.BinaryOp{
			Left:  left,
			Op:    op,
			Right: right,
			Pos:   p.current.Pos,
		}
	}

	return left, nil
}

// ---------- primary expressions ----------

// parsePrimary parses primary expressions (literals, identifiers, parenthesized exprs, unary ops, etc.).
func (p *ExpressionParser) parsePrimary() (ast.Expression, error) {
	pos := p.current.Pos

	// Handle unary operators
	if isUnaryOperator(p.current.Type) {
		op := p.current.Type
		p.nextToken()
		operand, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		return &ast.UnaryOp{
			Op:    op,
			Right: operand,
			Pos:   pos,
		}, nil
	}

	// Handle quantifier expressions: "N of ...", "any/all/none of ...", "for ..."
	if p.isQuantifierExpression() {
		return p.parseQuantifierPrimary()
	}

	// Handle parenthesized expressions
	if p.currentTokenIs(token.LPAREN) {
		return p.parseParenthesizedExpression()
	}

	// Handle literals
	if p.isLiteral() {
		return p.parseLiteral()
	}

	// Handle data type functions (uint8, int16be, concat, etc.)
	if p.isDataTypeFunction() {
		return p.parseDataTypeFunction()
	}

	// Handle YARA built-ins (entrypoint, filesize, etc.)
	if p.isYaraBuiltIn() {
		return p.parseYaraBuiltIn()
	}

	// Handle string operations (!, @, #)
	if p.currentTokenIs(token.StringLength) || p.currentTokenIs(token.AT) || p.currentTokenIs(token.HASH) {
		return p.parseStringOperation()
	}

	// Handle identifiers (including string identifiers like $a)
	if p.currentTokenIs(token.IDENTIFIER) || p.currentTokenIs(token.StringIdentifier) {
		return p.parseIdentifier()
	}

	// Handle quantifier keywords as standalone identifiers
	if p.currentTokenIs(token.ANY) || p.currentTokenIs(token.ALL) || p.currentTokenIs(token.NONE) ||
		p.currentTokenIs(token.FOR) || p.currentTokenIs(token.THEM) {
		ident := &ast.Identifier{
			Name: p.current.Literal,
			Pos:  pos,
		}
		p.nextToken()
		return ident, nil
	}

	return nil, fmt.Errorf("unexpected token %s at %v", p.current.Type, pos)
}

func (p *ExpressionParser) isQuantifierExpression() bool {
	if (p.currentTokenIs(token.IntegerLit) || p.currentTokenIs(token.HexIntegerLit) || p.currentTokenIs(token.OctalIntegerLit)) && p.peekTokenIs(token.OF) {
		return true
	}
	if (p.currentTokenIs(token.ANY) || p.currentTokenIs(token.ALL) || p.currentTokenIs(token.NONE)) && p.peekTokenIs(token.OF) {
		return true
	}
	if p.currentTokenIs(token.FOR) {
		return true
	}
	return false
}

// parseQuantifierTarget parses the target of a quantifier ("them", string identifiers, parenthesized list).
func (p *ExpressionParser) parseQuantifierTarget(pos token.Position) (ast.Expression, error) {
	switch {
	case p.currentTokenIs(token.THEM):
		ident := &ast.Identifier{Name: "them", Pos: pos}
		p.nextToken()
		return ident, nil
	case p.currentTokenIs(token.StringIdentifier):
		ident := &ast.Identifier{Name: p.current.Literal, Pos: pos}
		p.nextToken()
		return ident, nil
	case p.currentTokenIs(token.LPAREN):
		return p.parseParenthesizedTarget(pos)
	default:
		return nil, fmt.Errorf("expected 'them', string pattern, or '(' after 'of'")
	}
}

// parseParenthesizedTarget parses a parenthesized target like ($a, $b) or ($a*)
func (p *ExpressionParser) parseParenthesizedTarget(pos token.Position) (ast.Expression, error) {
	p.nextToken() // consume '('
	first, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	// Check for comma-separated list
	if p.currentTokenIs(token.COMMA) {
		// Build a comma-separated BinaryOp chain
		list := first
		for p.currentTokenIs(token.COMMA) {
			p.nextToken() // consume ','
			next, err := p.parsePrimary()
			if err != nil {
				return nil, err
			}
			list = &ast.BinaryOp{Left: list, Op: token.COMMA, Right: next, Pos: pos}
		}
		if !p.currentTokenIs(token.RPAREN) {
			return nil, fmt.Errorf("expected ')' after target list")
		}
		p.nextToken() // consume ')'
		return list, nil
	}
	if !p.currentTokenIs(token.RPAREN) {
		return nil, fmt.Errorf("expected ')' after target")
	}
	p.nextToken() // consume ')'
	return first, nil
}

func (p *ExpressionParser) parseQuantifierPrimary() (ast.Expression, error) {
	if p.quantifierParser != nil {
		p.quantifierParser.SetCurrentTokens(p.current, p.peek)
		expr, err := p.quantifierParser.ParseQuantifier(p.current.Pos)
		if err != nil {
			return nil, err
		}
		p.current = p.quantifierParser.current
		p.peek = p.quantifierParser.peek
		return expr, nil
	}
	// Fallback: treat as identifier
	ident := &ast.Identifier{
		Name: p.current.Literal,
		Pos:  p.current.Pos,
	}
	p.nextToken()
	return ident, nil
}

func (p *ExpressionParser) parseParenthesizedExpression() (ast.Expression, error) {
	p.nextToken() // consume '('

	expr, err := p.ParseExpression()
	if err != nil {
		return nil, fmt.Errorf("error in parenthesized expression: %w", err)
	}

	// Support range expressions like (0..10)
	if p.currentTokenIs(token.DOT) && p.peekTokenIs(token.DOT) {
		dotPos := p.current.Pos
		p.nextToken() // consume first '.'
		p.nextToken() // consume second '.'

		right, err := p.parsePrimaryExcludingUnary()
		if err != nil {
			return nil, fmt.Errorf("error parsing range expression: %w", err)
		}

		expr = &ast.BinaryOp{
			Left:  expr,
			Op:    token.DOT,
			Right: right,
			Pos:   dotPos,
		}
	}

	if !p.currentTokenIs(token.RPAREN) {
		return nil, fmt.Errorf("expected ')' at %v", p.current.Pos)
	}
	p.nextToken() // consume ')'
	return expr, nil
}

func (p *ExpressionParser) isLiteral() bool {
	switch p.current.Type {
	case token.IntegerLit, token.HexIntegerLit, token.OctalIntegerLit,
		token.FloatLit, token.StringLit, token.TRUE, token.FALSE,
		token.RegexLit, token.SizeLit:
		return true
	default:
		return false
	}
}

func (p *ExpressionParser) parseLiteral() (ast.Expression, error) {
	lit := &ast.Literal{
		Type:  p.current.Type,
		Value: p.current.Literal,
		Pos:   p.current.Pos,
	}
	p.nextToken()
	return lit, nil
}

func (p *ExpressionParser) isDataTypeFunction() bool {
	switch p.current.Type {
	case token.UINT8, token.UINT16, token.UINT32, token.UINT64, token.INT8, token.INT16, token.INT32, token.INT64,
		token.UINT8BE, token.UINT16BE, token.UINT32BE, token.UINT64BE, token.INT8BE, token.INT16BE, token.INT32BE, token.INT64BE:
		return true
	case token.IDENTIFIER:
		switch p.current.Literal {
		case "uint8", "uint16", "uint32", "int8", "int16", "int32",
			"uint8be", "uint16be", "uint32be", "int8be", "int16be", "int32be",
			"concat":
			return true
		}
		return false
	default:
		return false
	}
}

func (p *ExpressionParser) parseDataTypeFunction() (ast.Expression, error) {
	pos := p.current.Pos
	functionName := mapDataTypeToken(p.current.Type, p.current.Literal)
	if functionName == "" {
		return nil, fmt.Errorf("unsupported data type function: %s", p.current.Literal)
	}
	p.nextToken() // consume function name

	if !p.currentTokenIs(token.LPAREN) {
		return nil, fmt.Errorf("expected '(' after function %s", functionName)
	}
	p.nextToken() // consume '('

	var args []ast.Expression
	for !p.currentTokenIs(token.RPAREN) {
		arg, err := p.ParseExpression()
		if err != nil {
			return nil, fmt.Errorf("error parsing function argument: %w", err)
		}
		args = append(args, arg)

		if p.currentTokenIs(token.COMMA) {
			p.nextToken()
		} else if !p.currentTokenIs(token.RPAREN) {
			return nil, fmt.Errorf("expected ',' or ')' in function arguments")
		}
	}
	p.nextToken() // consume ')'

	return &ast.FunctionCall{
		Function: functionName,
		Args:     args,
		Pos:      pos,
	}, nil
}

func mapDataTypeToken(tok token.Type, literal string) string {
	switch tok {
	case token.UINT8:
		return "uint8"
	case token.UINT16:
		return "uint16"
	case token.UINT32:
		return "uint32"
	case token.UINT64:
		return "uint64"
	case token.INT8:
		return "int8"
	case token.INT16:
		return "int16"
	case token.INT32:
		return "int32"
	case token.INT64:
		return "int64"
	case token.UINT8BE:
		return "uint8be"
	case token.UINT16BE:
		return "uint16be"
	case token.UINT32BE:
		return "uint32be"
	case token.UINT64BE:
		return "uint64be"
	case token.INT8BE:
		return "int8be"
	case token.INT16BE:
		return "int16be"
	case token.INT32BE:
		return "int32be"
	case token.INT64BE:
		return "int64be"
	case token.IDENTIFIER:
		return literal
	default:
		return ""
	}
}

func (p *ExpressionParser) isYaraBuiltIn() bool {
	switch p.current.Type {
	case token.ENTRYPOINT, token.DEFINED, token.SizeLit, token.FILESIZE:
		return true
	default:
		return false
	}
}

func (p *ExpressionParser) parseYaraBuiltIn() (ast.Expression, error) {
	lit := &ast.Literal{
		Type:  p.current.Type,
		Value: p.current.Literal,
		Pos:   p.current.Pos,
	}
	p.nextToken()
	return lit, nil
}

func (p *ExpressionParser) parseStringOperation() (ast.Expression, error) {
	op := p.current.Type
	pos := p.current.Pos
	p.nextToken()

	if !p.currentTokenIs(token.StringIdentifier) && !p.currentTokenIs(token.IDENTIFIER) {
		return nil, fmt.Errorf("string operations require a string identifier, got token: %v", p.current.Type)
	}

	stringIdent := &ast.Identifier{
		Name: p.current.Literal,
		Pos:  p.current.Pos,
	}
	p.nextToken()

	// Handle optional index [i]
	var index ast.Expression
	if p.currentTokenIs(token.LBRACKET) {
		p.nextToken()
		var err error
		index, err = p.parsePrimary()
		if err != nil {
			return nil, fmt.Errorf("error parsing string operation index: %w", err)
		}
		if !p.currentTokenIs(token.RBRACKET) {
			return nil, fmt.Errorf("expected ']' after string operation index")
		}
		p.nextToken()
	}

	switch op {
	case token.StringLength:
		return &ast.StringLength{String: stringIdent, Index: index, Pos: pos}, nil
	case token.AT:
		return &ast.StringOffset{String: stringIdent, Index: index, Pos: pos}, nil
	case token.HASH:
		return &ast.StringCount{String: stringIdent, Index: index, Pos: pos}, nil
	default:
		return nil, fmt.Errorf("unsupported string operation: %v", op)
	}
}

func (p *ExpressionParser) parseIdentifier() (ast.Expression, error) {
	pos := p.current.Pos
	name := p.current.Literal
	p.nextToken()

	// Handle member access (dot notation) like pe.entry_point
	if p.currentTokenIs(token.DOT) {
		result, err := p.parseMemberAccess(pos, name)
		if err != nil {
			return nil, err
		}
		// Handle postfix operations on the result
		return p.parsePostfix(result)
	}

	result := &ast.Identifier{Name: name, Pos: pos}
	// Handle postfix operations (function calls, array indexing)
	return p.parsePostfix(result)
}

func (p *ExpressionParser) parseMemberAccess(pos token.Position, baseName string) (ast.Expression, error) {
	var left ast.Expression = &ast.Identifier{Name: baseName, Pos: pos}

	for p.currentTokenIs(token.DOT) {
		p.nextToken() // consume '.'
		if !p.currentTokenIs(token.IDENTIFIER) {
			return nil, fmt.Errorf("expected identifier after '.' at %v", p.current.Pos)
		}
		memberName := p.current.Literal
		memberPos := p.current.Pos
		p.nextToken()
		left = &ast.BinaryOp{
			Left:  left,
			Op:    token.DOT,
			Right: &ast.Identifier{Name: memberName, Pos: memberPos},
			Pos:   pos,
		}
	}
	return left, nil
}

// ---------- postfix ----------

// parsePostfix handles postfix operations (function calls).
func (p *ExpressionParser) parsePostfix(base ast.Expression) (ast.Expression, error) {
	if p.currentTokenIs(token.LPAREN) {
		return p.parseFunctionCall(base)
	}
	if p.currentTokenIs(token.LBRACKET) {
		return nil, fmt.Errorf("invalid syntax: array indexing $a[i] is not supported in YARA. Use @a[i] for string offset or #a[i] for string count")
	}
	return base, nil
}

func (p *ExpressionParser) parseFunctionCall(base ast.Expression) (ast.Expression, error) {
	functionName, ok := extractFunctionName(base)
	if !ok {
		return nil, fmt.Errorf("cannot call non-identifier at %v", base.Position())
	}
	p.nextToken() // consume '('

	var args []ast.Expression
	for !p.currentTokenIs(token.RPAREN) {
		arg, err := p.ParseExpression()
		if err != nil {
			return nil, fmt.Errorf("error parsing function argument: %w", err)
		}
		args = append(args, arg)

		if p.currentTokenIs(token.COMMA) {
			p.nextToken()
		} else if !p.currentTokenIs(token.RPAREN) {
			return nil, fmt.Errorf("expected ',' or ')' in function arguments at %v", p.current.Pos)
		}
	}
	p.nextToken() // consume ')'

	return &ast.FunctionCall{
		Function: functionName,
		Args:     args,
		Pos:      base.Position(),
	}, nil
}

// extractFunctionName flattens identifiers and dotted member access into a function name.
func extractFunctionName(expr ast.Expression) (string, bool) {
	switch node := expr.(type) {
	case *ast.Identifier:
		return node.Name, true
	case *ast.BinaryOp:
		if node.Op != token.DOT {
			return "", false
		}
		left, ok := extractFunctionName(node.Left)
		if !ok {
			return "", false
		}
		rightIdent, ok := node.Right.(*ast.Identifier)
		if !ok {
			return "", false
		}
		if left == "" {
			return rightIdent.Name, true
		}
		return left + "." + rightIdent.Name, true
	default:
		return "", false
	}
}

// ---------- token management ----------

func (p *ExpressionParser) nextToken() {
	if p.useExternalTokens && p.externalNextToken != nil {
		p.externalNextToken()
		return
	}
	p.current = p.peek
	if p.src != nil {
		p.peek = p.src.NextToken()
	}
}

func (p *ExpressionParser) currentTokenIs(tok token.Type) bool {
	return p.current.Type == tok
}

func (p *ExpressionParser) peekTokenIs(tok token.Type) bool {
	return p.peek.Type == tok
}

// SetTokens sets the current and peek tokens.
func (p *ExpressionParser) SetTokens(current, peek token.Token) {
	p.current = current
	p.peek = peek
}

// InitializeTokens sets up the initial tokens from the lexer source.
func (p *ExpressionParser) InitializeTokens() {
	if p.useExternalTokens && p.externalNextToken != nil {
		p.nextToken()
	} else if p.src != nil {
		p.current = p.src.NextToken()
		p.peek = p.src.NextToken()
	}
}

// parsePrimaryExcludingUnary parses primary expressions excluding unary operators.
// Used by quantifier parser to avoid consuming unary prefixes.
// NOTE: This intentionally does NOT dispatch quantifier expressions to avoid
// infinite recursion when called from within the quantifier parser.
func (p *ExpressionParser) parsePrimaryExcludingUnary() (ast.Expression, error) {
	pos := p.current.Pos

	// Handle parenthesized expressions
	if p.currentTokenIs(token.LPAREN) {
		return p.parseParenthesizedExpression()
	}

	// Handle literals
	if p.isLiteral() {
		return p.parseLiteral()
	}

	// Handle data type functions
	if p.isDataTypeFunction() {
		return p.parseDataTypeFunction()
	}

	// Handle YARA built-ins
	if p.isYaraBuiltIn() {
		return p.parseYaraBuiltIn()
	}

	// Handle string operations
	if p.currentTokenIs(token.StringLength) || p.currentTokenIs(token.AT) || p.currentTokenIs(token.HASH) {
		return p.parseStringOperation()
	}

	// Handle identifiers
	if p.currentTokenIs(token.IDENTIFIER) || p.currentTokenIs(token.StringIdentifier) {
		return p.parseIdentifier()
	}

	// Handle quantifier keywords as standalone identifiers
	if p.currentTokenIs(token.ANY) || p.currentTokenIs(token.ALL) || p.currentTokenIs(token.NONE) ||
		p.currentTokenIs(token.FOR) || p.currentTokenIs(token.THEM) {
		ident := &ast.Identifier{
			Name: p.current.Literal,
			Pos:  pos,
		}
		p.nextToken()
		return ident, nil
	}

	return nil, fmt.Errorf("unexpected token %s at %v", p.current.Type, pos)
}

// SetTokenHandler sets the token handling functions for compatibility.
func (p *ExpressionParser) SetTokenHandler(nextToken func(), addError func(error)) {
	p.externalNextToken = nextToken
	p.externalAddError = addError
	p.useExternalTokens = true
}

// SetCurrentTokens sets the current and peek tokens (alias for SetTokens).
func (p *ExpressionParser) SetCurrentTokens(current, peek token.Token) {
	p.SetTokens(current, peek)
}

// GetDepth returns the current parsing depth.
func (p *ExpressionParser) GetDepth() int {
	return p.depth
}

// SetMaxRecursionDepth sets the maximum allowed recursion depth.
func (p *ExpressionParser) SetMaxRecursionDepth(maxDepth int) {
	p.maxRecursionDepth = maxDepth
}

func (p *ExpressionParser) incrementDepth() error {
	p.depth++
	if p.maxRecursionDepth > 0 && p.depth > p.maxRecursionDepth {
		return fmt.Errorf("recursion depth %d exceeds maximum allowed %d", p.depth, p.maxRecursionDepth)
	}
	return nil
}

func (p *ExpressionParser) decrementDepth() {
	if p.depth > 0 {
		p.depth--
	}
}

// SetQuantifierParser sets the quantifier parser (for dependencies).
func (p *ExpressionParser) SetQuantifierParser(qp *QuantifierParser) {
	p.quantifierParser = qp
}

// GetQuantifierParser returns the quantifier parser.
func (p *ExpressionParser) GetQuantifierParser() *QuantifierParser {
	return p.quantifierParser
}
