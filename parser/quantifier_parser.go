package parser

import (
	"errors"
	"fmt"

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
	if p.currentTokenIs(token.FOR) {
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
	// Parse the quantifier after 'for'
	if !p.currentTokenIs(token.ALL) && !p.currentTokenIs(token.ANY) &&
		!p.currentTokenIs(token.NONE) {
		return nil, errors.New("expected quantifier (all/any/none) after 'for'")
	}

	quantifier := p.current.Literal
	p.nextToken()

	// Check if this is a for loop with variable (for all i in (0..9) : ...)
	if p.currentTokenIs(token.IDENTIFIER) {
		return p.parseForLoopWithVariable(pos, quantifier)
	}

	// For standard "for" quantifiers without variables, we expect 'of'
	if !p.expectToken(token.OF) {
		return nil, errors.New("expected 'of' after quantifier")
	}

	// Parse the target (them, string patterns, etc.)
	target, err := p.parseQuantifierTarget(pos)
	if err != nil {
		return nil, err
	}

	// Check for colon syntax in "for" quantifiers
	if p.currentTokenIs(token.COLON) {
		p.nextToken() // consume ':'

		// Parse the expression after colon
		expr, parseErr := p.exprParser.ParseExpression()
		if parseErr != nil {
			return nil, parseErr
		}

		// Create a ForLoop node for "for" quantifiers with colon
		return p.builder.ForLoop(pos, quantifier, "", target, expr), nil
	}

	return p.builder.OfExpression(pos, p.builder.Identifier(pos, quantifier), target), nil
}

// parseForLoopWithVariable parses for loops with variables like "for all i in (0..9) : ..."
func (p *QuantifierParser) parseForLoopWithVariable(pos token.Position, quantifier string) (ast.Expression, error) {
	variableName := p.current.Literal
	p.nextToken()

	if !p.expectToken(token.IN) {
		return nil, errors.New("expected 'in' after variable name in for loop")
	}

	// Parse the range expression
	rangeExpr, err := p.parseRangeExpression()
	if err != nil {
		return nil, err
	}

	// Check for colon syntax in "for" quantifiers
	if p.currentTokenIs(token.COLON) {
		p.nextToken() // consume ':'

		// Parse the expression after colon
		expr, parseErr := p.exprParser.ParseExpression()
		if parseErr != nil {
			return nil, parseErr
		}

		// Create a ForLoop node for "for" quantifiers with colon
		return p.builder.ForLoop(pos, quantifier, variableName, rangeExpr, expr), nil
	}

	return nil, errors.New("expected ':' after for loop range")
}

// parseRangeExpression parses range expressions, handling both parenthesized ranges and regular expressions
func (p *QuantifierParser) parseRangeExpression() (ast.Expression, error) {
	var rangeExpr ast.Expression
	var err error

	// Check if this is a parenthesized range expression like (0..9)
	if p.currentTokenIs(token.LPAREN) {
		p.nextToken() // consume '('

		// Parse the left operand of the range
		left, leftErr := p.exprParser.parsePrimaryExcludingUnary()
		if leftErr != nil {
			return nil, leftErr
		}

		// Check for range expression (..)
		if p.currentTokenIs(token.DOT) && p.peekTokenIs(token.DOT) {
			dotPos := p.current.Pos
			p.nextToken() // consume first DOT
			p.nextToken() // consume second DOT

			// Parse the right operand of the range
			right, rightErr := p.exprParser.parsePrimaryExcludingUnary()
			if rightErr != nil {
				return nil, rightErr
			}

			// Create a binary operation to represent the range
			rangeExpr = p.builder.BinaryOp(dotPos, left, token.DOT, right)
		} else {
			// Not a range expression, parse the rest as a regular expression
			rangeExpr = left
		}

		if !p.expectToken(token.RPAREN) {
			return nil, errors.New("expected ')' after range expression")
		}
	} else {
		// Parse regular expression
		rangeExpr, err = p.exprParser.parsePrimaryExcludingUnary()
		if err != nil {
			return nil, err
		}
	}

	return rangeExpr, nil
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

	// Create an OfExpression node
	return p.builder.OfExpression(pos, quantifierExpr, target), nil
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
	isNumber := p.currentTokenIs(token.IntegerLit) ||
		p.currentTokenIs(token.HexIntegerLit) ||
		p.currentTokenIs(token.OctalIntegerLit)
	return isNumber && p.peekTokenIs(token.OF)
}

// isKeywordQuantifier checks if current token is a keyword quantifier
func (p *QuantifierParser) isKeywordQuantifier() bool {
	return p.currentTokenIs(token.ALL) ||
		p.currentTokenIs(token.ANY) ||
		p.currentTokenIs(token.NONE)
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
	case p.currentTokenIs(token.THEM):
		target := p.builder.Identifier(pos, "them")
		p.nextToken()
		return target, nil
	case p.currentTokenIs(token.StringIdentifier):
		target := p.builder.Identifier(pos, p.current.Literal)
		p.nextToken()
		return target, nil
	case p.currentTokenIs(token.LPAREN):
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
	case p.currentTokenIs(token.StringIdentifier) && p.current.Literal == "$":
		p.nextToken()
		return p.builder.Identifier(pos, "$"), nil
	case p.currentTokenIs(token.StringIdentifier):
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

	for p.currentTokenIs(token.COMMA) {
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
	if p.currentTokenIs(token.StringIdentifier) {
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

	// Create a temporary representation for comma-separated list
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
	isNumber := p.currentTokenIs(token.IntegerLit) ||
		p.currentTokenIs(token.HexIntegerLit) ||
		p.currentTokenIs(token.OctalIntegerLit)
	return isNumber && p.peekTokenIs(token.OF)
}

// Helper methods
func (p *QuantifierParser) currentTokenIs(t token.Type) bool {
	return p.current.Type == t
}

func (p *QuantifierParser) peekTokenIs(t token.Type) bool {
	return p.peek.Type == t
}

func (p *QuantifierParser) expectToken(t token.Type) bool {
	if p.currentTokenIs(t) {
		p.nextToken()
		return true
	}
	return false
}
