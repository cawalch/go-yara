package parser

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/cawalch/go-yara/ast"
	internal "github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

// QuantifierParser handles parsing of quantifier expressions in YARA rules
type QuantifierParser struct {
	lexer      *internal.Lexer
	current    token.Token
	peek       token.Token
	errors     []error
	builder    *ast.Builder
	nextToken  func()
	addError   func(error)
	exprParser *ExpressionParser
}

// forLoopFields groups the components of a for-loop quantifier.
type forLoopFields struct {
	pos           token.Position
	quantifierStr string
	variables     []string
	target        ast.Expression
	constraint    ast.Expression
	isRange       bool
}

// NewQuantifierParser creates a new quantifier parser instance
func NewQuantifierParser(lexer *internal.Lexer, builder *ast.Builder, exprParser *ExpressionParser) *QuantifierParser {
	qp := &QuantifierParser{
		lexer:      lexer,
		errors:     make([]error, 0),
		builder:    builder,
		exprParser: exprParser,
	}

	// Set up expression parser delegation
	exprParser.SetTokenHandler(qp.nextToken, qp.addError)

	return qp
}

// SetTokenHandler sets the token handling functions for the parser
func (p *QuantifierParser) SetTokenHandler(nextToken func(), addError func(error)) {
	p.nextToken = nextToken
	p.addError = addError
	p.exprParser.SetTokenHandler(nextToken, addError)
}

// SetCurrentTokens sets the current and peek tokens
func (p *QuantifierParser) SetCurrentTokens(current, peek token.Token) {
	p.current = current
	p.peek = peek
	p.exprParser.SetCurrentTokens(current, peek)
}

// ParseQuantifier parses quantifier expressions (all/any/none of them, for any of them)
func (p *QuantifierParser) ParseQuantifier(pos token.Position) (ast.Expression, error) {
	// Handle "for" quantifier syntax
	if p.CurrentTokenIs(token.FOR) {
		p.nextToken() // consume 'for'
		return p.parseForQuantifier(pos)
	}

	if !p.isQuantifierToken() {
		return nil, ErrNotQuantifier
	}

	// Handle standard quantifier syntax (all/any/none of them) and numeric quantifiers
	return p.parseStandardQuantifier(pos)
}

// parseForQuantifier parses "for" quantifier expressions with optional variables and ranges
func (p *QuantifierParser) parseForQuantifier(pos token.Position) (ast.Expression, error) {
	var quantifierExpr ast.Expression
	var quantifierStr string

	// Parse the quantifier after 'for' - could be keyword (all/any/none) or numeric
	switch {
	case p.CurrentTokenIs(token.ALL) || p.CurrentTokenIs(token.ANY) ||
		p.CurrentTokenIs(token.NONE):
		// Keyword quantifier
		quantifierStr = p.current.Literal
		quantifierExpr = p.builder.Identifier(pos, quantifierStr)
		p.nextToken()
	case p.isNumericLiteral():
		// Numeric quantifier like "for 2 of them" or "for 2 i in (1..3)".
		quantifierStr = p.current.Literal
		if parsed, err := strconv.ParseInt(quantifierStr, 0, 64); err == nil {
			quantifierStr = strconv.FormatInt(parsed, 10)
		}
		numericExpr, err := p.exprParser.parsePrimaryExcludingUnary()
		if err != nil {
			return nil, fmt.Errorf("error parsing numeric quantifier: %w", err)
		}
		quantifierExpr = numericExpr
	default:
		return nil, errors.New("expected quantifier (all/any/none) or number after 'for'")
	}

	// A variable after either a keyword or numeric quantifier starts a range loop.
	if p.CurrentTokenIs(token.IDENTIFIER) {
		return p.parseForLoopWithVariable(pos, quantifierStr)
	}

	// Standard string-set quantifiers use "of".
	if !p.expectToken(token.OF) {
		return nil, errors.New("expected 'of' after quantifier")
	}

	// Parse the target (them, string patterns, etc.)
	target, err := p.parseQuantifierTarget(pos)
	if err != nil {
		return nil, err
	}

	// Check for "in (range)" or "at offset" constraints
	constraint, isRange, err := p.parseQuantifierConstraint()
	if err != nil {
		return nil, err
	}
	if constraint != nil {
		if p.CurrentTokenIs(token.COLON) {
			return p.parseForLoopWithConstraint(forLoopFields{pos, quantifierStr, nil, target, constraint, isRange})
		}
		return p.parseOfExpressionWithConstraint(pos, quantifierExpr, target, constraint, isRange), nil
	}

	// Check for colon syntax in "for" quantifiers
	if p.CurrentTokenIs(token.COLON) {
		p.nextToken() // consume ':'

		// Parse the expression after colon
		expr, parseErr := p.exprParser.ParseExpression()
		if parseErr != nil {
			return nil, parseErr
		}

		// Create a ForLoop node for "for" quantifiers with colon
		return p.builder.ForLoop(pos, quantifierStr, "", target, expr), nil
	}

	return p.builder.OfExpression(pos, quantifierExpr, target), nil
}

// parseForLoopWithVariable parses for loops with variables like "for all i in (0..9) : ..." or "for any k,v in dict : ..."
func (p *QuantifierParser) parseForLoopWithVariable(pos token.Position, quantifier string) (ast.Expression, error) {
	var variables []string

	for {
		if !p.CurrentTokenIs(token.IDENTIFIER) {
			return nil, fmt.Errorf("expected identifier as loop variable, got %s", p.current.Type)
		}
		variables = append(variables, p.current.Literal)
		p.nextToken()

		if !p.CurrentTokenIs(token.COMMA) {
			break
		}
		p.nextToken() // consume ','
	}

	if !p.expectToken(token.IN) {
		return nil, errors.New("expected 'in' after variable name in for loop")
	}

	// Parse the range expression
	rangeExpr, err := p.parseRangeExpression()
	if err != nil {
		return nil, err
	}

	// Check for colon syntax in "for" quantifiers
	if p.CurrentTokenIs(token.COLON) {
		p.nextToken() // consume ':'

		// Parse the expression after colon
		expr, parseErr := p.exprParser.ParseExpression()
		if parseErr != nil {
			return nil, parseErr
		}

		// Create a ForLoopMultiVar node for "for" quantifiers with colon
		return p.builder.ForLoopMultiVar(pos, quantifier, variables, rangeExpr, expr), nil
	}

	return nil, errors.New("expected ':' after for loop range")
}

// parseRangeExpression parses range expressions, handling both parenthesized ranges and regular expressions
func (p *QuantifierParser) parseRangeExpression() (ast.Expression, error) {
	if p.CurrentTokenIs(token.LPAREN) {
		return p.parseParenthesizedRangeExpression()
	}
	return p.exprParser.parsePrimaryExcludingUnary()
}

// parseParenthesizedRangeExpression parses a parenthesized range expression like (0..9)
func (p *QuantifierParser) parseParenthesizedRangeExpression() (ast.Expression, error) {
	pos := p.current.Pos // Store position of '('
	p.nextToken()        // consume '('

	// Handle single expression parenthesized or comma separated tuple
	left, err := p.exprParser.parsePrimaryExcludingUnary()
	if err != nil {
		return nil, err
	}

	// If we see a comma, this is a tuple e.g., (1, 2, 3) or ("a", "b")
	if p.CurrentTokenIs(token.COMMA) {
		tupleElements := []ast.Expression{left}
		for p.CurrentTokenIs(token.COMMA) {
			p.nextToken() // consume ','
			nextElem, err := p.exprParser.parsePrimaryExcludingUnary()
			if err != nil {
				return nil, err
			}
			tupleElements = append(tupleElements, nextElem)
		}

		if !p.expectToken(token.RPAREN) {
			return nil, errors.New("expected ')' after tuple elements")
		}

		return &ast.StringTuple{
			Pos:      pos,
			Elements: tupleElements,
		}, nil
	}

	rangeExpr, err := p.parseRangeSuffix(left)
	if err != nil {
		return nil, err
	}

	if !p.expectToken(token.RPAREN) {
		return nil, errors.New("expected ')' after range expression")
	}

	return rangeExpr, nil
}

// parseRangeSuffix parses the optional range suffix (..right) or returns the left expression as-is
func (p *QuantifierParser) parseRangeSuffix(left ast.Expression) (ast.Expression, error) {
	if p.CurrentTokenIs(token.DOT) && p.PeekTokenIs(token.DOT) {
		return p.parseFullRange(left)
	}
	return left, nil
}

// parseFullRange parses a complete range expression with left .. right
func (p *QuantifierParser) parseFullRange(left ast.Expression) (ast.Expression, error) {
	dotPos := p.current.Pos
	p.nextToken() // consume first DOT
	p.nextToken() // consume second DOT

	right, err := p.exprParser.parsePrimaryExcludingUnary()
	if err != nil {
		return nil, err
	}

	return p.builder.BinaryOp(dotPos, left, token.DOT, right), nil
}

// parseStandardQuantifier parses standard quantifiers (all/any/none of them) and numeric quantifiers
func (p *QuantifierParser) parseStandardQuantifier(pos token.Position) (ast.Expression, error) {
	quantifierExpr, err := p.parseQuantifierExpressionPart(pos)
	if err != nil {
		return nil, err
	}

	// Parse the target (them, string patterns, etc.)
	target, err := p.parseQuantifierTarget(pos)
	if err != nil {
		return nil, err
	}

	ofExpr := p.builder.OfExpression(pos, quantifierExpr, target)

	// Check for "in (range)" or "at offset" constraints
	if p.CurrentTokenIs(token.IN) {
		p.nextToken() // consume 'in'
		rangeExpr, err := p.parseRangeExpression()
		if err != nil {
			return nil, err
		}
		ofExpr.InRange = rangeExpr
	} else if p.CurrentTokenIs(token.AT) {
		p.nextToken() // consume 'at'
		offsetExpr, err := p.exprParser.ParseExpression()
		if err != nil {
			return nil, err
		}
		ofExpr.AtOffset = offsetExpr
	}

	return ofExpr, nil
}

// parseForLoopWithConstraint creates a ForLoop with the given constraint.
func (p *QuantifierParser) parseForLoopWithConstraint(fields forLoopFields) (*ast.ForLoop, error) {
	p.nextToken() // consume ':'
	expr, err := p.exprParser.ParseExpression()
	if err != nil {
		return nil, err
	}
	var forLoop *ast.ForLoop
	if len(fields.variables) > 0 {
		forLoop = p.builder.ForLoopMultiVar(fields.pos, fields.quantifierStr, fields.variables, fields.target, expr)
	} else {
		forLoop = p.builder.ForLoop(fields.pos, fields.quantifierStr, "", fields.target, expr)
	}
	if fields.isRange {
		forLoop.InRange = fields.constraint
	} else {
		forLoop.AtOffset = fields.constraint
	}
	return forLoop, nil
}

// parseOfExpressionWithConstraint creates an OfExpression with the given constraint.
//
//nolint:revive // argument-limit: parser method
func (p *QuantifierParser) parseOfExpressionWithConstraint(
	pos token.Position,
	quantifierExpr, target ast.Expression,
	constraint ast.Expression,
	isRange bool,
) *ast.OfExpression {
	ofExpr := p.builder.OfExpression(pos, quantifierExpr, target)
	if isRange {
		ofExpr.InRange = constraint
	} else {
		ofExpr.AtOffset = constraint
	}
	return ofExpr
}

// parseQuantifierConstraint parses an optional "in (range)" or "at offset" constraint
// and returns (expression, isRange, nil) or (nil, false, nil) if no constraint.
func (p *QuantifierParser) parseQuantifierConstraint() (ast.Expression, bool, error) {
	if p.CurrentTokenIs(token.IN) {
		p.nextToken() // consume 'in'
		rangeExpr, err := p.parseRangeExpression()
		if err != nil {
			return nil, false, err
		}
		return rangeExpr, true, nil
	} else if p.CurrentTokenIs(token.AT) {
		p.nextToken() // consume 'at'
		offsetExpr, err := p.exprParser.ParseExpression()
		if err != nil {
			return nil, false, err
		}
		return offsetExpr, false, nil
	}
	return nil, false, nil
}

// parseQuantifierExpressionPart parses the quantifier part of a standard quantifier
func (p *QuantifierParser) parseQuantifierExpressionPart(pos token.Position) (ast.Expression, error) {
	if p.isNumericQuantifier() {
		return p.parseNumericQuantifier()
	}

	if p.isKeywordQuantifier() {
		return p.parseKeywordQuantifier(pos)
	}

	return nil, fmt.Errorf("invalid quantifier token %s at %v", p.current.Type, p.current.Pos)
}

// isNumericQuantifier checks if current token is a numeric quantifier
func (p *QuantifierParser) isNumericQuantifier() bool {
	isNumber := p.CurrentTokenIs(token.IntegerLit) ||
		p.CurrentTokenIs(token.HexIntegerLit) ||
		p.CurrentTokenIs(token.OctalIntegerLit)
	return isNumber && p.PeekTokenIs(token.OF)
}

// isNumericLiteral checks if current token is a numeric literal
func (p *QuantifierParser) isNumericLiteral() bool {
	return p.CurrentTokenIs(token.IntegerLit) ||
		p.CurrentTokenIs(token.HexIntegerLit) ||
		p.CurrentTokenIs(token.OctalIntegerLit)
}

// isKeywordQuantifier checks if current token is a keyword quantifier
func (p *QuantifierParser) isKeywordQuantifier() bool {
	return p.CurrentTokenIs(token.ALL) ||
		p.CurrentTokenIs(token.ANY) ||
		p.CurrentTokenIs(token.NONE)
}

// parseNumericQuantifier parses numeric quantifiers like "1 of", "2 of"
func (p *QuantifierParser) parseNumericQuantifier() (ast.Expression, error) {
	quantifierExpr, err := p.exprParser.parsePrimaryExcludingUnary()
	if err != nil {
		return nil, err
	}

	if !p.expectToken(token.OF) {
		return nil, errors.New("expected 'of' after count")
	}

	return quantifierExpr, nil
}

// parseKeywordQuantifier parses keyword quantifiers like "all of", "any of", "none of"
func (p *QuantifierParser) parseKeywordQuantifier(pos token.Position) (ast.Expression, error) {
	quantifier := p.current.Literal
	p.nextToken()

	if !p.expectToken(token.OF) {
		return nil, errors.New("expected 'of' after quantifier")
	}

	return p.builder.Identifier(pos, quantifier), nil
}

// parseQuantifierTarget parses the target part of quantifier expressions (them, string patterns, etc.)
func (p *QuantifierParser) parseQuantifierTarget(pos token.Position) (ast.Expression, error) {
	switch {
	case p.CurrentTokenIs(token.THEM):
		target := p.builder.Identifier(pos, "them")
		p.nextToken()
		return target, nil
	case p.CurrentTokenIs(token.StringIdentifier):
		target := p.builder.Identifier(pos, p.current.Literal)
		p.nextToken()
		return target, nil
	case p.CurrentTokenIs(token.LPAREN):
		return p.parseParenthesizedTarget(pos)
	default:
		return nil, errors.New("expected 'them', string pattern, or '(' after 'of'")
	}
}

// parseParenthesizedTarget parses parenthesized expressions in quantifier targets
func (p *QuantifierParser) parseParenthesizedTarget(pos token.Position) (ast.Expression, error) {
	p.nextToken() // consume '('

	// Parse the first expression
	firstExpr, err := p.parseFirstParenthesizedExpression(pos)
	if err != nil {
		return nil, err
	}

	// Parse additional comma-separated expressions if any
	expressions, err := p.parseCommaSeparatedExpressions(pos, firstExpr)
	if err != nil {
		return nil, err
	}

	if !p.expectToken(token.RPAREN) {
		return nil, errors.New("expected ')' after expression")
	}

	return p.createCommaExpression(pos, expressions), nil
}

// parseFirstParenthesizedExpression parses the first expression in parentheses
func (p *QuantifierParser) parseFirstParenthesizedExpression(pos token.Position) (ast.Expression, error) {
	switch {
	case p.CurrentTokenIs(token.StringIdentifier) && p.current.Literal == "$":
		p.nextToken()
		return p.builder.Identifier(pos, "$"), nil
	case p.CurrentTokenIs(token.StringIdentifier):
		expr := p.builder.Identifier(pos, p.current.Literal)
		p.nextToken()
		return expr, nil
	default:
		return p.exprParser.ParseExpression()
	}
}

// parseCommaSeparatedExpressions parses comma-separated expressions after the first one
func (p *QuantifierParser) parseCommaSeparatedExpressions(pos token.Position, firstExpr ast.Expression) ([]ast.Expression, error) {
	expressions := []ast.Expression{firstExpr}

	for p.CurrentTokenIs(token.COMMA) {
		p.nextToken() // consume ','
		nextExpr, err := p.parseNextParenthesizedExpression(pos)
		if err != nil {
			return nil, err
		}
		expressions = append(expressions, nextExpr)
	}

	return expressions, nil
}

// parseNextParenthesizedExpression parses subsequent expressions in a comma-separated list
func (p *QuantifierParser) parseNextParenthesizedExpression(pos token.Position) (ast.Expression, error) {
	if p.CurrentTokenIs(token.StringIdentifier) {
		expr := p.builder.Identifier(pos, p.current.Literal)
		p.nextToken()
		return expr, nil
	}
	return p.exprParser.ParseExpression()
}

// createCommaExpression creates a comma expression from multiple expressions
func (p *QuantifierParser) createCommaExpression(pos token.Position, expressions []ast.Expression) ast.Expression {
	if len(expressions) == 1 {
		return expressions[0]
	}

	// Represent the comma-separated list as left-associated binary nodes.
	target := expressions[0]
	for i := 1; i < len(expressions); i++ {
		target = p.builder.BinaryOp(pos, target, token.COMMA, expressions[i])
	}
	return target
}

// isQuantifierToken checks if current token could be part of a quantifier
func (p *QuantifierParser) isQuantifierToken() bool {
	return p.isKeywordQuantifier() || p.isNumericQuantifierToken()
}

// isNumericQuantifierToken checks if current token is a numeric quantifier
func (p *QuantifierParser) isNumericQuantifierToken() bool {
	isNumber := p.CurrentTokenIs(token.IntegerLit) ||
		p.CurrentTokenIs(token.HexIntegerLit) ||
		p.CurrentTokenIs(token.OctalIntegerLit)
	return isNumber && p.PeekTokenIs(token.OF)
}

// Helper methods
func (p *QuantifierParser) CurrentTokenIs(t token.Type) bool {
	return p.current.Type == t
}

func (p *QuantifierParser) PeekTokenIs(t token.Type) bool {
	return p.peek.Type == t
}

func (p *QuantifierParser) expectToken(t token.Type) bool {
	if p.CurrentTokenIs(t) {
		p.nextToken()
		return true
	}
	p.addError(fmt.Errorf("expected token %s, got %s at line %d, col %d",
		t, p.current.Type, p.current.Pos.Line, p.current.Pos.Column))
	return false
}
