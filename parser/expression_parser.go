package parser

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/cawalch/go-yara/ast"
	internal "github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

// ExpressionParser handles parsing of expressions in YARA rules
type ExpressionParser struct {
	lexer            *internal.Lexer
	current          token.Token
	peek             token.Token
	errors           []error
	builder          *ast.Builder
	nextToken        func()
	addError         func(error)
	quantifierParser *QuantifierParser
}

// NewExpressionParser creates a new expression parser instance
func NewExpressionParser(lexer *internal.Lexer, builder *ast.Builder) *ExpressionParser {
	return &ExpressionParser{
		lexer:   lexer,
		errors:  make([]error, 0),
		builder: builder,
	}
}

// SetTokenHandler sets the token handling functions for the parser
func (p *ExpressionParser) SetTokenHandler(nextToken func(), addError func(error)) {
	p.nextToken = nextToken
	p.addError = addError
}

// SetCurrentTokens sets the current and peek tokens
func (p *ExpressionParser) SetCurrentTokens(current, peek token.Token) {
	p.current = current
	p.peek = peek
}

// ParseExpression parses expressions using operator precedence
func (p *ExpressionParser) ParseExpression() (ast.Expression, error) {
	return p.parseLogicalOr()
}

// parseLogicalOr parses logical OR expressions with left-associative binding
func (p *ExpressionParser) parseLogicalOr() (ast.Expression, error) {
	left, err := p.parseLogicalAnd()
	if err != nil {
		return nil, err
	}

	return p.parseBinaryExpression(left, p.parseLogicalAnd, []token.TokenType{token.OR})
}

// parseLogicalAnd parses logical AND expressions with left-associative binding
func (p *ExpressionParser) parseLogicalAnd() (ast.Expression, error) {
	left, err := p.parseLogicalNot()
	if err != nil {
		return nil, err
	}

	return p.parseBinaryExpression(left, p.parseLogicalNot, []token.TokenType{token.AND})
}

// parseLogicalNot parses logical NOT expressions
func (p *ExpressionParser) parseLogicalNot() (ast.Expression, error) {
	if p.currentTokenIs(token.NOT) {
		// Check if this is a string length operation (!string)
		if p.peekTokenIs(token.STRING_IDENTIFIER) || p.peekTokenIs(token.IDENTIFIER) {
			pos := p.current.Pos
			p.nextToken() // consume '!'

			// Parse the identifier
			if !p.currentTokenIs(token.STRING_IDENTIFIER) && !p.currentTokenIs(token.IDENTIFIER) {
				return nil, fmt.Errorf("expected identifier after '!' at %v", p.current.Pos)
			}

			ident := p.current.Literal
			identPos := p.current.Pos
			p.nextToken() // consume identifier

			// For string operators, ensure identifier is treated as string
			if !strings.HasPrefix(ident, "$") {
				ident = "$" + ident
			}

			stringLengthExpr := p.builder.StringLength(pos, p.builder.Identifier(identPos, ident))

			// Check for comparison operator after string length expression
			if p.isComparisonOp(p.current.Type) {
				op := p.current.Type
				opPos := p.current.Pos
				p.nextToken()

				right, cmpErr := p.parseBitwiseOr()
				if cmpErr != nil {
					return nil, cmpErr
				}

				return p.builder.BinaryOp(opPos, stringLengthExpr, op, right), nil
			}

			return stringLengthExpr, nil
		}

		// Logical NOT operation
		op := p.current.Type
		pos := p.current.Pos
		p.nextToken()

		right, err := p.parseLogicalNot()
		if err != nil {
			return nil, err
		}

		return p.builder.UnaryOp(pos, op, right), nil
	}

	return p.parseQuantifierExpression()
}

// parseQuantifierExpression parses quantifier expressions (of operator)
func (p *ExpressionParser) parseQuantifierExpression() (ast.Expression, error) {
	if expr, err := p.parseQuantifier(p.current.Pos); expr != nil || err != nil {
		if errors.Is(err, ErrNotQuantifier) {
			return p.parseComparison()
		}
		return expr, err
	}

	return p.parseComparison()
}

// parseComparison parses comparison expressions
func (p *ExpressionParser) parseComparison() (ast.Expression, error) {
	left, err := p.parseBitwiseOr()
	if err != nil {
		return nil, err
	}

	// Check for range expression (..)
	if p.currentTokenIs(token.DOT) && p.peekTokenIs(token.DOT) {
		dotPos := p.current.Pos
		p.nextToken() // consume first DOT
		p.nextToken() // consume second DOT

		right, rangeErr := p.parseBitwiseOr()
		if rangeErr != nil {
			return nil, rangeErr
		}

		return p.builder.BinaryOp(dotPos, left, token.DOT, right), nil
	}

	for p.isComparisonOp(p.current.Type) {
		op := p.current.Type
		pos := p.current.Pos
		p.nextToken()

		right, cmpErr := p.parseBitwiseOr()
		if cmpErr != nil {
			return nil, cmpErr
		}

		left = p.builder.BinaryOp(pos, left, op, right)
	}

	return left, nil
}

// parseAdditive parses addition and subtraction
func (p *ExpressionParser) parseAdditive() (ast.Expression, error) {
	left, err := p.parseMultiplicative()
	if err != nil {
		return nil, err
	}

	return p.parseBinaryExpression(left, p.parseMultiplicative, []token.TokenType{token.PLUS, token.MINUS})
}

// parseMultiplicative parses multiplication, division, and modulo
func (p *ExpressionParser) parseMultiplicative() (ast.Expression, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}

	return p.parseBinaryExpression(left, p.parseUnary, []token.TokenType{token.MULTIPLY, token.DIVIDE, token.MODULO, token.INT_DIVIDE})
}

// parseUnary parses unary expressions (unary minus, bitwise NOT)
func (p *ExpressionParser) parseUnary() (ast.Expression, error) {
	if p.currentTokenIs(token.MINUS) || p.currentTokenIs(token.BITWISE_NOT) {
		op := p.current.Type
		pos := p.current.Pos
		p.nextToken()

		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}

		return p.builder.UnaryOp(pos, op, right), nil
	}

	return p.parsePrimary()
}

// parseBitwiseShift parses bitwise shift operations
func (p *ExpressionParser) parseBitwiseShift() (ast.Expression, error) {
	left, err := p.parseAdditive()
	if err != nil {
		return nil, err
	}

	return p.parseBinaryExpression(left, p.parseAdditive, []token.TokenType{token.LEFT_SHIFT, token.RIGHT_SHIFT})
}

// parseBitwiseAnd parses bitwise AND operations
func (p *ExpressionParser) parseBitwiseAnd() (ast.Expression, error) {
	left, err := p.parseBitwiseShift()
	if err != nil {
		return nil, err
	}

	return p.parseBinaryExpression(left, p.parseBitwiseShift, []token.TokenType{token.BITWISE_AND})
}

// parseBitwiseXor parses bitwise XOR operations
func (p *ExpressionParser) parseBitwiseXor() (ast.Expression, error) {
	left, err := p.parseBitwiseAnd()
	if err != nil {
		return nil, err
	}

	return p.parseBinaryExpression(left, p.parseBitwiseAnd, []token.TokenType{token.BITWISE_XOR})
}

// parseBitwiseOr parses bitwise OR operations
func (p *ExpressionParser) parseBitwiseOr() (ast.Expression, error) {
	left, err := p.parseBitwiseXor()
	if err != nil {
		return nil, err
	}

	return p.parseBinaryExpression(left, p.parseBitwiseXor, []token.TokenType{token.BITWISE_OR})
}

// parsePrimary parses primary expressions
// ParsePrimary parses primary expressions (public method)
func (p *ExpressionParser) ParsePrimary() (ast.Expression, error) {
	return p.parsePrimary()
}

func (p *ExpressionParser) parsePrimary() (ast.Expression, error) {
	pos := p.current.Pos

	// Try simple token-based parsing first
	if expr, err := p.trySimpleTokenParsing(pos); expr != nil || err != nil {
		return expr, err
	}

	// Try complex parsing attempts
	if expr, err := p.tryComplexParsing(pos); expr != nil || err != nil {
		return expr, err
	}

	return nil, fmt.Errorf("unexpected token %s at %v", p.current.Type, p.current.Pos)
}

// trySimpleTokenParsing attempts to parse expressions based on simple token checks
func (p *ExpressionParser) trySimpleTokenParsing(pos token.Position) (ast.Expression, error) {
	switch {
	case p.currentTokenIs(token.STRING_IDENTIFIER):
		return p.parseStringIdentifierExpression(pos)
	case p.isDataTypeFunction(p.current.Type):
		return p.parseDataTypeFunction(pos)
	case p.currentTokenIs(token.LPAREN):
		return p.parseParenthesizedExpression()
	case p.isUnaryOperator(p.current.Type):
		return p.parseUnaryWithArrayIndex(pos)
	case p.currentTokenIs(token.IDENTIFIER):
		return p.parseIdentifierExpression(pos)
	default:
		return nil, nil
	}
}

// tryComplexParsing attempts to parse expressions using more complex logic
func (p *ExpressionParser) tryComplexParsing(pos token.Position) (ast.Expression, error) {
	if expr, err := p.parseLiteral(pos); expr != nil || (err != nil && !errors.Is(err, ErrNotLiteral)) {
		return expr, err
	}

	if expr, err := p.parseQuantifier(pos); expr != nil || (err != nil && !errors.Is(err, ErrNotQuantifier)) {
		return expr, err
	}

	if expr := p.parseSpecialKeyword(pos); expr != nil {
		return expr, nil
	}

	return nil, nil
}

// Helper methods
func (p *ExpressionParser) currentTokenIs(t token.TokenType) bool {
	return p.current.Type == t
}

func (p *ExpressionParser) peekTokenIs(t token.TokenType) bool {
	return p.peek.Type == t
}

func (p *ExpressionParser) isAnyToken(tokenTypes []token.TokenType) bool {
	return slices.ContainsFunc(tokenTypes, p.currentTokenIs)
}

func (p *ExpressionParser) isComparisonOp(t token.TokenType) bool {
	comparisonOps := map[token.TokenType]bool{
		token.EQ:          true,
		token.NEQ:         true,
		token.LT:          true,
		token.LE:          true,
		token.GT:          true,
		token.GE:          true,
		token.MATCHES:     true,
		token.CONTAINS:    true,
		token.ICONTAINS:   true,
		token.STARTSWITH:  true,
		token.ISTARTSWITH: true,
		token.ENDSWITH:    true,
		token.IENDSWITH:   true,
		token.IEQUALS:     true,
	}
	return comparisonOps[t]
}

func (p *ExpressionParser) isDataTypeFunction(t token.TokenType) bool {
	switch t {
	case token.INT8, token.INT16, token.INT32, token.UINT8, token.UINT16, token.UINT32,
		token.INT8BE, token.INT16BE, token.INT32BE, token.UINT8BE, token.UINT16BE, token.UINT32BE:
		return true
	default:
		return false
	}
}

func (p *ExpressionParser) isUnaryOperator(tokenType token.TokenType) bool {
	switch tokenType {
	case token.DEFINED, token.AT, token.IN, token.HASH:
		return true
	default:
		return false
	}
}

// parseBinaryExpression parses binary expressions with left-associative binding
func (p *ExpressionParser) parseBinaryExpression(
	left ast.Expression,
	parseRightOperand func() (ast.Expression, error),
	operatorTypes []token.TokenType,
) (ast.Expression, error) {
	for p.isAnyToken(operatorTypes) {
		op := p.current.Type
		pos := p.current.Pos
		p.nextToken()

		right, err := parseRightOperand()
		if err != nil {
			return nil, err
		}

		left = p.builder.BinaryOp(pos, left, op, right)
	}

	return left, nil
}

// Remaining parsing methods (simplified versions extracted from original parser)
func (p *ExpressionParser) parseStringIdentifierExpression(pos token.Position) (ast.Expression, error) {
	ident := p.current.Literal
	p.nextToken()

	// Check for string offset operators (at, in)
	if p.currentTokenIs(token.AT) || p.currentTokenIs(token.IN) {
		op := p.current.Type
		opPos := p.current.Pos
		p.nextToken()

		offsetExpr, err := p.ParseExpression()
		if err != nil {
			return nil, err
		}

		return p.builder.BinaryOp(opPos, p.builder.Identifier(pos, ident), op, offsetExpr), nil
	}

	// Check for string length operator
	if p.currentTokenIs(token.LENGTH) {
		lengthPos := p.current.Pos
		p.nextToken()
		return p.builder.StringLength(lengthPos, p.builder.Identifier(pos, ident)), nil
	}

	return p.builder.Identifier(pos, ident), nil
}

func (p *ExpressionParser) parseDataTypeFunction(_ token.Position) (ast.Expression, error) {
	functionName := p.current.Literal
	funcPos := p.current.Pos
	p.nextToken()

	if p.currentTokenIs(token.LPAREN) {
		return p.parseFunctionCall(funcPos, functionName)
	}

	return nil, fmt.Errorf("expected '(' after data type function %s", functionName)
}

func (p *ExpressionParser) parseParenthesizedExpression() (ast.Expression, error) {
	p.nextToken()
	expr, err := p.ParseExpression()
	if err != nil {
		return nil, err
	}
	if !p.expectToken(token.RPAREN) {
		return nil, errors.New("expected ')' after expression")
	}
	return expr, nil
}

func (p *ExpressionParser) parseUnaryWithArrayIndex(pos token.Position) (ast.Expression, error) {
	expr, err := p.parseUnaryOperator(pos)
	if err != nil {
		return nil, err
	}

	if p.currentTokenIs(token.LBRACKET) {
		p.nextToken()

		indexExpr, indexErr := p.ParseExpression()
		if indexErr != nil {
			return nil, indexErr
		}

		if !p.expectToken(token.RBRACKET) {
			return nil, errors.New("expected ']' after array index")
		}

		return p.builder.ArrayIndex(pos, expr, indexExpr), nil
	}

	return expr, nil
}

func (p *ExpressionParser) parseIdentifierExpression(pos token.Position) (ast.Expression, error) {
	ident := p.current.Literal
	p.nextToken()

	// Handle member access for enums
	if p.currentTokenIs(token.DOT) {
		p.nextToken()
		memberIdent := p.current.Literal
		if !p.currentTokenIs(token.IDENTIFIER) {
			return nil, errors.New("expected identifier after '.' for enum member access")
		}
		p.nextToken()

		return p.builder.BinaryOp(
			pos,
			p.builder.Identifier(pos, ident),
			token.DOT,
			p.builder.Identifier(pos, memberIdent),
		), nil
	}

	return p.builder.Identifier(pos, ident), nil
}

func (p *ExpressionParser) parseLiteral(pos token.Position) (ast.Expression, error) {
	switch {
	case p.currentTokenIs(token.TRUE):
		p.nextToken()
		return p.builder.Literal(pos, token.TRUE, true), nil
	case p.currentTokenIs(token.FALSE):
		p.nextToken()
		return p.builder.Literal(pos, token.FALSE, false), nil
	case p.currentTokenIs(token.INTEGER_LIT):
		value := p.parseIntLiteral()
		p.nextToken()
		return p.builder.Literal(pos, token.INTEGER_LIT, value), nil
	case p.currentTokenIs(token.HEX_INTEGER_LIT):
		value := p.parseHexIntegerLiteral()
		p.nextToken()
		return p.builder.Literal(pos, token.HEX_INTEGER_LIT, value), nil
	case p.currentTokenIs(token.OCTAL_INTEGER_LIT):
		value := p.parseOctalIntegerLiteral()
		p.nextToken()
		return p.builder.Literal(pos, token.OCTAL_INTEGER_LIT, value), nil
	case p.currentTokenIs(token.FLOAT_LIT):
		value := p.parseFloatLiteral()
		p.nextToken()
		return p.builder.Literal(pos, token.FLOAT_LIT, value), nil
	case p.currentTokenIs(token.SIZE_LIT):
		literal := p.current.Literal
		p.nextToken()
		return p.builder.Literal(pos, token.SIZE_LIT, literal), nil
	case p.currentTokenIs(token.STRING_LIT):
		literal := p.current.Literal
		p.nextToken()
		return p.builder.Literal(pos, token.STRING_LIT, literal), nil
	case p.currentTokenIs(token.REGEX_LIT):
		literal := p.current.Literal
		p.nextToken()
		return p.builder.Literal(pos, token.REGEX_LIT, literal), nil
	default:
		return nil, ErrNotLiteral
	}
}

func (p *ExpressionParser) parseSpecialKeyword(pos token.Position) ast.Expression {
	if p.currentTokenIs(token.FILESIZE) {
		p.nextToken()
		return p.builder.Identifier(pos, "filesize")
	}
	if p.currentTokenIs(token.ENTRYPOINT) {
		p.nextToken()
		return p.builder.Identifier(pos, "entrypoint")
	}
	return nil
}

func (p *ExpressionParser) parseUnaryOperator(pos token.Position) (ast.Expression, error) {
	op, err := p.parseUnaryOperatorToken()
	if err != nil {
		return nil, err
	}

	p.nextToken()

	expr, err := p.parseUnaryOperand(op)
	if err != nil {
		return nil, err
	}

	return p.handleUnaryOperatorPostfix(pos, op, expr)
}

func (p *ExpressionParser) parseUnaryOperatorToken() (token.TokenType, error) {
	switch {
	case p.currentTokenIs(token.DEFINED):
		return token.DEFINED, nil
	case p.currentTokenIs(token.AT):
		return token.AT, nil
	case p.currentTokenIs(token.IN):
		return token.IN, nil
	case p.currentTokenIs(token.HASH):
		return token.HASH, nil
	default:
		return 0, fmt.Errorf("expected unary operator at %v", p.current.Pos)
	}
}

func (p *ExpressionParser) parseUnaryOperand(op token.TokenType) (ast.Expression, error) {
	if p.currentTokenIs(token.STRING_IDENTIFIER) || p.currentTokenIs(token.IDENTIFIER) {
		return p.parseIdentifierOperand(op)
	}
	return p.parsePrimaryExcludingUnary()
}

func (p *ExpressionParser) parseIdentifierOperand(op token.TokenType) (ast.Expression, error) {
	ident := p.current.Literal
	identPos := p.current.Pos
	p.nextToken()

	// For string operators (#, @), ensure identifier is treated as string
	if op == token.HASH || op == token.AT {
		if !strings.HasPrefix(ident, "$") {
			ident = "$" + ident
		}
	}

	return p.builder.Identifier(identPos, ident), nil
}

func (p *ExpressionParser) handleUnaryOperatorPostfix(pos token.Position, op token.TokenType, expr ast.Expression) (ast.Expression, error) {
	if p.currentTokenIs(token.LBRACKET) {
		return p.handleArrayIndexing(pos, op, expr)
	}

	if p.currentTokenIs(token.LENGTH) {
		return p.handleStringLength(pos, op, expr)
	}

	return p.builder.UnaryOp(pos, op, expr), nil
}

func (p *ExpressionParser) handleArrayIndexing(pos token.Position, op token.TokenType, expr ast.Expression) (ast.Expression, error) {
	p.nextToken()

	indexExpr, err := p.ParseExpression()
	if err != nil {
		return nil, err
	}

	if !p.expectToken(token.RBRACKET) {
		return nil, errors.New("expected ']' after array index")
	}

	arrayExpr := p.builder.UnaryOp(pos, op, expr)
	return p.builder.ArrayIndex(pos, arrayExpr, indexExpr), nil
}

func (p *ExpressionParser) handleStringLength(pos token.Position, op token.TokenType, expr ast.Expression) (ast.Expression, error) {
	p.nextToken()
	stringExpr := p.builder.UnaryOp(pos, op, expr)
	return p.builder.StringLength(pos, stringExpr), nil
}

// parsePrimaryExcludingUnary parses primary expressions but excludes unary operators
// This is used to avoid infinite recursion when parsing unary operator operands
func (p *ExpressionParser) parsePrimaryExcludingUnary() (ast.Expression, error) {
	pos := p.current.Pos

	if expr, err := p.trySimpleTokenParsingExcludingUnary(pos); expr != nil || err != nil {
		return expr, err
	}

	if expr, err := p.tryComplexParsing(pos); expr != nil || err != nil {
		return expr, err
	}

	return nil, fmt.Errorf("unexpected token %s at %v", p.current.Type, p.current.Pos)
}

func (p *ExpressionParser) trySimpleTokenParsingExcludingUnary(pos token.Position) (ast.Expression, error) {
	switch {
	case p.currentTokenIs(token.STRING_IDENTIFIER):
		return p.parseStringIdentifierExpression(pos)
	case p.isDataTypeFunction(p.current.Type):
		return p.parseDataTypeFunction(pos)
	case p.currentTokenIs(token.LPAREN):
		return p.parseParenthesizedExpression()
	case p.currentTokenIs(token.IDENTIFIER):
		return p.parseIdentifierExpression(pos)
	default:
		return nil, nil
	}
}

func (p *ExpressionParser) parseIntLiteral() int64 {
	return p.parseIntLiteralWithBase(10, nil, "")
}

func (p *ExpressionParser) parseHexIntegerLiteral() int64 {
	return p.parseIntLiteralWithBase(16, []string{"0x"}, "hex")
}

func (p *ExpressionParser) parseOctalIntegerLiteral() int64 {
	return p.parseIntLiteralWithBase(8, []string{"0o"}, "octal")
}

func (p *ExpressionParser) parseFloatLiteral() float64 {
	literal := p.current.Literal

	if value, err := strconv.ParseFloat(literal, 64); err == nil {
		return value
	}

	p.errors = append(
		p.errors,
		fmt.Errorf("invalid float literal: %s at %v", literal, p.current.Pos),
	)
	return 0
}

func (p *ExpressionParser) parseIntLiteralWithBase(base int, prefixes []string, literalType string) int64 {
	literal := p.current.Literal

	// Remove specified prefixes
	for _, prefix := range prefixes {
		literal = strings.TrimPrefix(literal, prefix)
		literal = strings.TrimPrefix(literal, strings.ToUpper(prefix))
	}

	if value, err := strconv.ParseInt(literal, base, 64); err == nil {
		return value
	}

	if literalType == "" {
		p.errors = append(p.errors, fmt.Errorf("invalid integer literal: %s at %v", p.current.Literal, p.current.Pos))
	} else {
		p.errors = append(p.errors, fmt.Errorf("invalid %s integer literal: %s at %v", literalType, p.current.Literal, p.current.Pos))
	}
	return 0
}

func (p *ExpressionParser) expectToken(t token.TokenType) bool {
	if p.currentTokenIs(t) {
		p.nextToken()
		return true
	}
	return false
}

func (p *ExpressionParser) parseFunctionCall(pos token.Position, functionName string) (ast.Expression, error) {
	if !p.expectToken(token.LPAREN) {
		return nil, errors.New("expected '(' after function name")
	}

	var args []ast.Expression

	if !p.currentTokenIs(token.RPAREN) {
		arg, err := p.ParseExpression()
		if err != nil {
			return nil, err
		}
		args = append(args, arg)

		for p.currentTokenIs(token.COMMA) {
			p.nextToken()
			nextArg, parseErr := p.ParseExpression()
			if parseErr != nil {
				return nil, parseErr
			}
			args = append(args, nextArg)
		}
	}

	if !p.expectToken(token.RPAREN) {
		return nil, errors.New("expected ')' after function arguments")
	}

	funcCall := p.builder.FunctionCall(pos, functionName, args)

	if p.currentTokenIs(token.LBRACKET) {
		p.nextToken()

		indexExpr, indexErr := p.ParseExpression()
		if indexErr != nil {
			return nil, indexErr
		}

		if !p.expectToken(token.RBRACKET) {
			return nil, errors.New("expected ']' after array index")
		}

		return p.builder.ArrayIndex(pos, funcCall, indexExpr), nil
	}

	return funcCall, nil
}

// parseQuantifier delegates to the quantifier parser
func (p *ExpressionParser) parseQuantifier(pos token.Position) (ast.Expression, error) {
	if p.quantifierParser != nil {
		return p.quantifierParser.ParseQuantifier(pos)
	}
	return nil, ErrNotQuantifier
}

// SetQuantifierParser sets the quantifier parser instance
func (p *ExpressionParser) SetQuantifierParser(qp *QuantifierParser) {
	p.quantifierParser = qp
}
