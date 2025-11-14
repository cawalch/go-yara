package parser

import (
	"fmt"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

// Quantifier constants
const (
	QuantifierAny  = "any"
	QuantifierAll  = "all"
	QuantifierNone = "none"
)

// QuantifierStrategy defines the interface for parsing quantifier expressions
type QuantifierStrategy interface {
	// CanHandle determines if this strategy can handle the current token combination
	CanHandle(currentToken, peekToken token.TokenType) bool

	// Parse attempts to parse the quantifier using this strategy
	Parse(parser *QuantifierParser, context ParseContext) ParseResult

	// Name returns the name of this strategy for debugging
	Name() string

	// Priority returns the priority (lower number = higher priority) for strategy selection
	Priority() int
}

// ForLoopQuantifierStrategy handles "for" loop quantifiers (for i in (0..9), for any of them, etc.)
type ForLoopQuantifierStrategy struct{}

// NewForLoopQuantifierStrategy creates a new for-loop quantifier strategy
func NewForLoopQuantifierStrategy() *ForLoopQuantifierStrategy {
	return &ForLoopQuantifierStrategy{}
}

func (flqs *ForLoopQuantifierStrategy) CanHandle(currentToken, peekToken token.TokenType) bool {
	return currentToken == token.FOR
}

func (flqs *ForLoopQuantifierStrategy) Parse(parser *QuantifierParser, context ParseContext) ParseResult {
	parser.nextToken() // consume 'for'

	// Handle different "for" quantifier forms
	if parser.currentTokenIs(token.ANY) {
		return flqs.parseAnyOfThem(parser, context)
	}

	if parser.currentTokenIs(token.ALL) {
		return flqs.parseAllOfThem(parser, context)
	}

	if parser.currentTokenIs(token.NONE) {
		return flqs.parseNoneOfThem(parser, context)
	}

	// Handle "for variable in range" format
	if parser.currentTokenIs(token.IDENTIFIER) && parser.peekTokenIs(token.IN) {
		return flqs.parseForInRange(parser, context)
	}

	// Handle "for i in (0..n)" format
	if parser.currentTokenIs(token.IDENTIFIER) && parser.peekTokenIs(token.IN) {
		variable := parser.current.Literal
		return flqs.parseForInEnumeration(parser, context, variable)
	}

	return NewParseError(fmt.Errorf("invalid 'for' quantifier syntax at %v", context.Position))
}

func (flqs *ForLoopQuantifierStrategy) parseAnyOfThem(parser *QuantifierParser, context ParseContext) ParseResult {
	parser.nextToken() // consume 'any'

	if !parser.currentTokenIs(token.OF) {
		return NewParseError(fmt.Errorf("expected 'of' after 'any' at %v", parser.current.Pos))
	}
	parser.nextToken() // consume 'of'

	// Parse the expression after "any of"
	expr, err := parser.exprParser.ParseExpression()
	if err != nil {
		return NewParseError(fmt.Errorf("error parsing expression after 'any of': %w", err))
	}

	return NewParseResult(&ast.OfExpression{
		Count:   &ast.Identifier{Name: QuantifierAny, Pos: context.Position},
		Strings: expr,
		Pos:     context.Position,
	}, 2) // consumed 'for', 'any', 'of'
}

func (flqs *ForLoopQuantifierStrategy) parseAllOfThem(parser *QuantifierParser, context ParseContext) ParseResult {
	parser.nextToken() // consume 'all'

	if !parser.currentTokenIs(token.OF) {
		return NewParseError(fmt.Errorf("expected 'of' after 'all' at %v", parser.current.Pos))
	}
	parser.nextToken() // consume 'of'

	// Parse the expression after "all of"
	expr, err := parser.exprParser.ParseExpression()
	if err != nil {
		return NewParseError(fmt.Errorf("error parsing expression after 'all of': %w", err))
	}

	return NewParseResult(&ast.OfExpression{
		Count:   &ast.Identifier{Name: QuantifierAll, Pos: context.Position},
		Strings: expr,
		Pos:     context.Position,
	}, 2) // consumed 'for', 'all', 'of'
}

func (flqs *ForLoopQuantifierStrategy) parseNoneOfThem(parser *QuantifierParser, context ParseContext) ParseResult {
	parser.nextToken() // consume 'none'

	if !parser.currentTokenIs(token.OF) {
		return NewParseError(fmt.Errorf("expected 'of' after 'none' at %v", parser.current.Pos))
	}
	parser.nextToken() // consume 'of'

	// Parse the expression after "none of"
	expr, err := parser.exprParser.ParseExpression()
	if err != nil {
		return NewParseError(fmt.Errorf("error parsing expression after 'none of': %w", err))
	}

	return NewParseResult(&ast.OfExpression{
		Count:   &ast.Identifier{Name: QuantifierNone, Pos: context.Position},
		Strings: expr,
		Pos:     context.Position,
	}, 2) // consumed 'for', 'none', 'of'
}

func (flqs *ForLoopQuantifierStrategy) parseForInRange(parser *QuantifierParser, context ParseContext) ParseResult {
	variable := parser.current.Literal
	parser.nextToken() // consume variable name
	parser.nextToken() // consume 'in'

	// Handle different range formats
	if parser.currentTokenIs(token.LPAREN) {
		return flqs.parseRange(parser, context, variable)
	}

	// Handle "for identifier in expression" format
	expr, err := parser.exprParser.ParseExpression()
	if err != nil {
		return NewParseError(fmt.Errorf("error parsing range expression: %w", err))
	}

	return NewParseResult(&ast.ForLoop{
		Pos:       context.Position,
		Variable:  variable,
		Condition: expr,
	}, 2) // consumed 'for', variable, 'in'
}

func (flqs *ForLoopQuantifierStrategy) parseForInEnumeration(parser *QuantifierParser, context ParseContext, variable string) ParseResult {
	parser.nextToken() // consume '('

	// Parse start range
	start, err := parser.exprParser.ParseExpression()
	if err != nil {
		return NewParseError(fmt.Errorf("error parsing range start: %w", err))
	}

	// Expect '..' (represented as two DOT tokens)
	if !parser.currentTokenIs(token.DOT) {
		return NewParseError(fmt.Errorf("expected '..' in range at %v", parser.current.Pos))
	}
	parser.nextToken() // consume first '.'

	if !parser.currentTokenIs(token.DOT) {
		return NewParseError(fmt.Errorf("expected '..' in range at %v", parser.current.Pos))
	}
	parser.nextToken() // consume second '.'

	// Parse end range
	end, err := parser.exprParser.ParseExpression()
	if err != nil {
		return NewParseError(fmt.Errorf("error parsing range end: %w", err))
	}

	// Expect ')'
	if !parser.currentTokenIs(token.RPAREN) {
		return NewParseError(fmt.Errorf("expected ')' in range at %v", parser.current.Pos))
	}
	parser.nextToken() // consume ')'

	return NewParseResult(&ast.ForLoop{
		Pos:      context.Position,
		Variable: variable,
		Range: &ast.BinaryOp{
			Op:    token.DOT,
			Left:  start,
			Right: end,
			Pos:   context.Position,
		},
	}, 5) // consumed '(', start, '.', '.', end, ')'
}

func (flqs *ForLoopQuantifierStrategy) parseRange(parser *QuantifierParser, context ParseContext, variable string) ParseResult {
	// This is a helper method that delegates to parseForInEnumeration
	return flqs.parseForInEnumeration(parser, context, variable)
}

func (flqs *ForLoopQuantifierStrategy) Name() string  { return "ForLoopQuantifierStrategy" }
func (flqs *ForLoopQuantifierStrategy) Priority() int { return 1 }

// StandardQuantifierStrategy handles standard quantifiers (any, all, none)
type StandardQuantifierStrategy struct {
	classifier TokenClassifier
}

// NewStandardQuantifierStrategy creates a new standard quantifier strategy
func NewStandardQuantifierStrategy() *StandardQuantifierStrategy {
	return &StandardQuantifierStrategy{
		classifier: DefaultTokenClassifier{},
	}
}

func (sqs *StandardQuantifierStrategy) CanHandle(currentToken, peekToken token.TokenType) bool {
	return sqs.classifier.IsQuantifierToken(currentToken)
}

func (sqs *StandardQuantifierStrategy) Parse(parser *QuantifierParser, context ParseContext) ParseResult {
	var quantifier string
	var consumed int

	switch context.CurrentToken.Type {
	case token.ANY:
		quantifier = QuantifierAny
		consumed = 1
	case token.ALL:
		quantifier = QuantifierAll
		consumed = 1
	case token.NONE:
		quantifier = QuantifierNone
		consumed = 1
	default:
		return NewParseError(fmt.Errorf("unexpected quantifier token: %s", context.CurrentToken.Type))
	}

	parser.nextToken() // consume quantifier

	// Check if there's an "of" keyword
	if parser.currentTokenIs(token.OF) {
		parser.nextToken() // consume 'of'
		consumed++
	}

	// Parse the expression after quantifier
	expr, err := parser.exprParser.ParseExpression()
	if err != nil {
		return NewParseError(fmt.Errorf("error parsing expression after quantifier: %w", err))
	}

	return NewParseResult(&ast.OfExpression{
		Count:   &ast.Identifier{Name: quantifier, Pos: context.Position},
		Strings: expr,
		Pos:     context.Position,
	}, consumed)
}

func (sqs *StandardQuantifierStrategy) Name() string  { return "StandardQuantifierStrategy" }
func (sqs *StandardQuantifierStrategy) Priority() int { return 2 }

// NumericQuantifierStrategy handles numeric quantifiers (specific counts)
type NumericQuantifierStrategy struct{}

// NewNumericQuantifierStrategy creates a new numeric quantifier strategy
func NewNumericQuantifierStrategy() *NumericQuantifierStrategy {
	return &NumericQuantifierStrategy{}
}

func (nqs *NumericQuantifierStrategy) CanHandle(currentToken, peekToken token.TokenType) bool {
	// Numeric quantifiers are typically integers followed by "of"
	return currentToken == token.INTEGER_LIT && peekToken == token.OF
}

func (nqs *NumericQuantifierStrategy) Parse(parser *QuantifierParser, context ParseContext) ParseResult {
	// Parse the numeric count
	countValue := parser.current.Literal
	parser.nextToken() // consume number

	// Expect "of"
	if !parser.currentTokenIs(token.OF) {
		return NewParseError(fmt.Errorf("expected 'of' after numeric count at %v", parser.current.Pos))
	}
	parser.nextToken() // consume 'of'

	// Parse the expression after count
	expr, err := parser.exprParser.ParseExpression()
	if err != nil {
		return NewParseError(fmt.Errorf("error parsing expression after numeric count: %w", err))
	}

	return NewParseResult(&ast.OfExpression{
		Count: &ast.Literal{
			Type:  token.INTEGER_LIT,
			Value: countValue,
			Pos:   context.Position,
		},
		Strings: expr,
		Pos:     context.Position,
	}, 2) // consumed number and 'of'
}

func (nqs *NumericQuantifierStrategy) Name() string  { return "NumericQuantifierStrategy" }
func (nqs *NumericQuantifierStrategy) Priority() int { return 3 }

// QuantifierStrategyRegistry manages quantifier strategies
type QuantifierStrategyRegistry struct {
	strategies []QuantifierStrategy
	classifier TokenClassifier
}

// NewQuantifierStrategyRegistry creates a new quantifier strategy registry
func NewQuantifierStrategyRegistry() *QuantifierStrategyRegistry {
	registry := &QuantifierStrategyRegistry{
		strategies: make([]QuantifierStrategy, 0),
		classifier: DefaultTokenClassifier{},
	}

	// Register default quantifier strategies
	registry.RegisterStrategy(NewForLoopQuantifierStrategy())
	registry.RegisterStrategy(NewStandardQuantifierStrategy())
	registry.RegisterStrategy(NewNumericQuantifierStrategy())

	return registry
}

// RegisterStrategy adds a quantifier strategy to the registry
func (qsr *QuantifierStrategyRegistry) RegisterStrategy(strategy QuantifierStrategy) {
	qsr.strategies = append(qsr.strategies, strategy)
}

// FindStrategy finds the best strategy for parsing a quantifier
func (qsr *QuantifierStrategyRegistry) FindStrategy(currentToken, peekToken token.TokenType) QuantifierStrategy {
	for _, strategy := range qsr.strategies {
		if strategy.CanHandle(currentToken, peekToken) {
			return strategy
		}
	}
	return nil
}

// GetClassifier returns the token classifier
func (qsr *QuantifierStrategyRegistry) GetClassifier() TokenClassifier {
	return qsr.classifier
}

// SetClassifier sets the token classifier
func (qsr *QuantifierStrategyRegistry) SetClassifier(classifier TokenClassifier) {
	qsr.classifier = classifier
}
