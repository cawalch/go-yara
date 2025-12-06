package parser

import (
	"fmt"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

// PrimaryExpressionStrategy defines the interface for parsing primary expressions
type PrimaryExpressionStrategy interface {
	// CanHandle determines if this strategy can handle the current token
	CanHandle(currentToken token.Type, peekToken token.Type) bool

	// Parse attempts to parse the expression using this strategy
	Parse(parser *ExpressionParser, context ParseContext) ParseResult

	// Name returns the name of this strategy for debugging
	Name() string

	// Priority returns the priority (lower number = higher priority) for strategy selection
	Priority() int
}

// BinaryExpressionStrategy defines the interface for parsing binary expressions
type BinaryExpressionStrategy interface {
	// CanHandle determines if this strategy can handle the given operator
	CanHandle(operator token.Type, leftExpr, rightExpr ast.Expression) bool

	// Parse attempts to parse the binary expression using this strategy
	Parse(parser *ExpressionParser, left ast.Expression, operator token.Type, right ast.Expression, context ParseContext) ParseResult

	// Name returns the name of this strategy for debugging
	Name() string

	// Associativity returns the associativity of this operator
	Associativity() Associativity

	// Precedence returns the precedence level of this operator
	Precedence() int
}

// UnaryExpressionStrategy defines the interface for parsing unary expressions
type UnaryExpressionStrategy interface {
	// CanHandle determines if this strategy can handle the given unary operator
	CanHandle(operator token.Type, operand ast.Expression) bool

	// Parse attempts to parse the unary expression using this strategy
	Parse(parser *ExpressionParser, operator token.Type, operand ast.Expression, context ParseContext) ParseResult

	// Name returns the name of this strategy for debugging
	Name() string
}

// Associativity represents operator associativity
type Associativity int

const (
	// LeftAssociative operators are evaluated left-to-right
	LeftAssociative Associativity = iota
	// RightAssociative operators are evaluated right-to-left
	RightAssociative
	// NonAssociative operators don't associate (require parentheses)
	NonAssociative
)

// StrategyRegistry manages collections of parsing strategies
type StrategyRegistry struct {
	primaryStrategies []PrimaryExpressionStrategy
	binaryStrategies  []BinaryExpressionStrategy
	unaryStrategies   []UnaryExpressionStrategy
	classifier        TokenClassifier
}

// NewStrategyRegistry creates a new strategy registry with default strategies
func NewStrategyRegistry() *StrategyRegistry {
	registry := &StrategyRegistry{
		primaryStrategies: make([]PrimaryExpressionStrategy, 0, 8), // Pre-allocate for common strategies
		binaryStrategies:  make([]BinaryExpressionStrategy, 0, 6),  // Pre-allocate for common strategies
		unaryStrategies:   make([]UnaryExpressionStrategy, 0, 4),   // Pre-allocate for common strategies
		classifier:        DefaultTokenClassifier{},
	}

	// Register default strategies
	registry.registerDefaultStrategies()
	return registry
}

// RegisterPrimaryStrategy adds a primary expression strategy to the registry
func (sr *StrategyRegistry) RegisterPrimaryStrategy(strategy PrimaryExpressionStrategy) {
	sr.primaryStrategies = append(sr.primaryStrategies, strategy)
}

// RegisterBinaryStrategy adds a binary expression strategy to the registry
func (sr *StrategyRegistry) RegisterBinaryStrategy(strategy BinaryExpressionStrategy) {
	sr.binaryStrategies = append(sr.binaryStrategies, strategy)
}

// RegisterUnaryStrategy adds a unary expression strategy to the registry
func (sr *StrategyRegistry) RegisterUnaryStrategy(strategy UnaryExpressionStrategy) {
	sr.unaryStrategies = append(sr.unaryStrategies, strategy)
}

// GetClassifier returns the token classifier
func (sr *StrategyRegistry) GetClassifier() TokenClassifier {
	return sr.classifier
}

// SetClassifier sets the token classifier
func (sr *StrategyRegistry) SetClassifier(classifier TokenClassifier) {
	sr.classifier = classifier
}

// FindPrimaryStrategy finds the best strategy for parsing a primary expression
func (sr *StrategyRegistry) FindPrimaryStrategy(currentToken, peekToken token.Type) PrimaryExpressionStrategy {
	for _, strategy := range sr.primaryStrategies {
		if strategy.CanHandle(currentToken, peekToken) {
			return strategy
		}
	}
	return nil
}

// FindBinaryStrategy finds the best strategy for parsing a binary expression
func (sr *StrategyRegistry) FindBinaryStrategy(operator token.Type, leftExpr, rightExpr ast.Expression) BinaryExpressionStrategy {
	for _, strategy := range sr.binaryStrategies {
		if strategy.CanHandle(operator, leftExpr, rightExpr) {
			return strategy
		}
	}
	return nil
}

// FindUnaryStrategy finds the best strategy for parsing a unary expression
func (sr *StrategyRegistry) FindUnaryStrategy(operator token.Type, operand ast.Expression) UnaryExpressionStrategy {
	for _, strategy := range sr.unaryStrategies {
		if strategy.CanHandle(operator, operand) {
			return strategy
		}
	}
	return nil
}

// GetPrimaryStrategies returns all registered primary strategies (sorted by priority)
func (sr *StrategyRegistry) GetPrimaryStrategies() []PrimaryExpressionStrategy {
	// Sort by priority (lower number = higher priority)
	strategies := make([]PrimaryExpressionStrategy, len(sr.primaryStrategies))
	copy(strategies, sr.primaryStrategies)

	// Simple bubble sort for small arrays
	for i := 0; i < len(strategies)-1; i++ {
		for j := 0; j < len(strategies)-i-1; j++ {
			if strategies[j].Priority() > strategies[j+1].Priority() {
				strategies[j], strategies[j+1] = strategies[j+1], strategies[j]
			}
		}
	}

	return strategies
}

// GetBinaryStrategies returns all registered binary strategies
func (sr *StrategyRegistry) GetBinaryStrategies() []BinaryExpressionStrategy {
	result := make([]BinaryExpressionStrategy, len(sr.binaryStrategies))
	copy(result, sr.binaryStrategies)
	return result
}

// GetUnaryStrategies returns all registered unary strategies
func (sr *StrategyRegistry) GetUnaryStrategies() []UnaryExpressionStrategy {
	result := make([]UnaryExpressionStrategy, len(sr.unaryStrategies))
	copy(result, sr.unaryStrategies)
	return result
}

// registerDefaultStrategies registers the default parsing strategies
func (sr *StrategyRegistry) registerDefaultStrategies() {
	// Register binary expression strategies
	sr.RegisterBinaryStrategy(NewArithmeticStrategy())
	sr.RegisterBinaryStrategy(NewLogicalStrategy())
	sr.RegisterBinaryStrategy(NewComparisonStrategy())
	sr.RegisterBinaryStrategy(NewBitwiseStrategy())
	sr.RegisterBinaryStrategy(NewOfStrategy())
}

// StrategyError represents an error that occurs during strategy execution
type StrategyError struct {
	StrategyName string
	Position     token.Position
	Message      string
}

// Error implements the error interface
func (se StrategyError) Error() string {
	return fmt.Sprintf("%s strategy error at %d:%d: %s", se.StrategyName, se.Position.Line, se.Position.Column, se.Message)
}

// NewStrategyError creates a new strategy error
func NewStrategyError(strategyName string, position token.Position, message string) StrategyError {
	return StrategyError{
		StrategyName: strategyName,
		Position:     position,
		Message:      message,
	}
}

// Binary expression strategies

// ArithmeticStrategy handles arithmetic operations (+, -, *, /, %)
type ArithmeticStrategy struct {
	classifier TokenClassifier
}

// NewArithmeticStrategy creates a new arithmetic strategy
func NewArithmeticStrategy() *ArithmeticStrategy {
	return &ArithmeticStrategy{
		classifier: DefaultTokenClassifier{},
	}
}

// CanHandle checks if the strategy can handle the given arithmetic operator
func (as *ArithmeticStrategy) CanHandle(operator token.Type, _ ast.Expression, _ ast.Expression) bool {
	return as.classifier.IsArithmeticOperator(operator)
}

// Parse parses an arithmetic expression using the given left and right operands
func (as *ArithmeticStrategy) Parse(_ *ExpressionParser, left ast.Expression, operator token.Type, right ast.Expression, context ParseContext) ParseResult {
	return NewParseResult(&ast.BinaryOp{
		Op:    operator,
		Left:  left,
		Right: right,
		Pos:   context.Position,
	}, 1)
}

// Name returns the name of the strategy
func (as *ArithmeticStrategy) Name() string { return "ArithmeticStrategy" }

// Associativity returns the associativity of arithmetic operations
func (as *ArithmeticStrategy) Associativity() Associativity { return LeftAssociative }

// Precedence returns the precedence level of arithmetic operations
func (as *ArithmeticStrategy) Precedence() int { return 5 }

// LogicalStrategy handles logical operations (and, or)
type LogicalStrategy struct {
	classifier TokenClassifier
}

// NewLogicalStrategy creates a new logical strategy
func NewLogicalStrategy() *LogicalStrategy {
	return &LogicalStrategy{
		classifier: DefaultTokenClassifier{},
	}
}

// CanHandle checks if the strategy can handle the given logical operator
func (ls *LogicalStrategy) CanHandle(operator token.Type, _ ast.Expression, _ ast.Expression) bool {
	return ls.classifier.IsLogicalOperator(operator)
}

// Parse parses a logical expression using the given left and right operands
func (ls *LogicalStrategy) Parse(_ *ExpressionParser, left ast.Expression, operator token.Type, right ast.Expression, context ParseContext) ParseResult {
	return NewParseResult(&ast.BinaryOp{
		Op:    operator,
		Left:  left,
		Right: right,
		Pos:   context.Position,
	}, 1)
}

// Name returns the name of the strategy
func (ls *LogicalStrategy) Name() string { return "LogicalStrategy" }

// Associativity returns the associativity of logical operations
func (ls *LogicalStrategy) Associativity() Associativity { return LeftAssociative }

// Precedence returns the precedence level of logical operations
func (ls *LogicalStrategy) Precedence() int { return 1 }

// ComparisonStrategy handles comparison operations (==, !=, <, <=, >, >=, contains, etc.)
type ComparisonStrategy struct {
	classifier TokenClassifier
}

// NewComparisonStrategy creates a new comparison strategy
func NewComparisonStrategy() *ComparisonStrategy {
	return &ComparisonStrategy{
		classifier: DefaultTokenClassifier{},
	}
}

// CanHandle checks if the strategy can handle the given comparison operator
func (cs *ComparisonStrategy) CanHandle(operator token.Type, _ ast.Expression, _ ast.Expression) bool {
	return cs.classifier.IsComparisonOp(operator)
}

// Parse parses a comparison expression using the given left and right operands
func (cs *ComparisonStrategy) Parse(_ *ExpressionParser, left ast.Expression, operator token.Type, right ast.Expression, context ParseContext) ParseResult {
	return NewParseResult(&ast.BinaryOp{
		Op:    operator,
		Left:  left,
		Right: right,
		Pos:   context.Position,
	}, 1)
}

// Name returns the name of the strategy
func (cs *ComparisonStrategy) Name() string { return "ComparisonStrategy" }

// Associativity returns the associativity of comparison operations
func (cs *ComparisonStrategy) Associativity() Associativity { return LeftAssociative }

// Precedence returns the precedence level of comparison operations
func (cs *ComparisonStrategy) Precedence() int { return 3 }

// BitwiseStrategy handles bitwise operations (&, |, ^, <<, >>)
type BitwiseStrategy struct {
	classifier TokenClassifier
}

// NewBitwiseStrategy creates a new bitwise strategy
func NewBitwiseStrategy() *BitwiseStrategy {
	return &BitwiseStrategy{
		classifier: DefaultTokenClassifier{},
	}
}

// CanHandle checks if the strategy can handle the given bitwise operator
func (bs *BitwiseStrategy) CanHandle(operator token.Type, _ ast.Expression, _ ast.Expression) bool {
	return bs.classifier.IsBitwiseOperator(operator)
}

// Parse parses a bitwise expression using the given left and right operands
func (bs *BitwiseStrategy) Parse(_ *ExpressionParser, left ast.Expression, operator token.Type, right ast.Expression, context ParseContext) ParseResult {
	return NewParseResult(&ast.BinaryOp{
		Op:    operator,
		Left:  left,
		Right: right,
		Pos:   context.Position,
	}, 1)
}

// Name returns the name of the strategy
func (bs *BitwiseStrategy) Name() string { return "BitwiseStrategy" }

// Associativity returns the associativity of bitwise operations
func (bs *BitwiseStrategy) Associativity() Associativity { return LeftAssociative }

// Precedence returns the precedence level of bitwise operations
func (bs *BitwiseStrategy) Precedence() int { return 4 }

// OfStrategy handles "of" operations for quantifiers
type OfStrategy struct{}

// NewOfStrategy creates a new of strategy
func NewOfStrategy() *OfStrategy {
	return &OfStrategy{}
}

// CanHandle checks if the strategy can handle the given "of" operator
func (os *OfStrategy) CanHandle(operator token.Type, _ ast.Expression, _ ast.Expression) bool {
	return operator == token.OF
}

// Parse parses an "of" expression into an AST node
func (os *OfStrategy) Parse(parser *ExpressionParser, left ast.Expression, _ token.Type, _ ast.Expression, context ParseContext) ParseResult {
	// Parse the quantifier target directly
	var target ast.Expression
	var err error

	// Handle different types of quantifier targets
	switch parser.current.Type {
	case token.THEM:
		target = &ast.Identifier{
			Name: "them",
			Pos:  parser.current.Pos,
		}
		parser.nextToken()
	case token.StringIdentifier:
		target = &ast.Identifier{
			Name: parser.current.Literal,
			Pos:  parser.current.Pos,
		}
		parser.nextToken()
	case token.LPAREN:
		target, err = os.parseParenthesizedTarget(parser, context.Position)
		if err != nil {
			return NewParseError(err)
		}
	default:
		return NewParseError(fmt.Errorf("expected 'them', string pattern, or '(' after 'of' at %v", parser.current.Pos))
	}

	return NewParseResult(&ast.OfExpression{
		Count:   left,
		Strings: target,
		Pos:     context.Position,
	}, 1)
}

// parseParenthesizedTarget parses parenthesized quantifier targets like ($test1, $test2, $test3)
func (os *OfStrategy) parseParenthesizedTarget(parser *ExpressionParser, pos token.Position) (ast.Expression, error) {
	parser.nextToken() // consume '('

	// Parse the first expression
	firstExpr, err := os.parseFirstParenthesizedExpression(parser, pos)
	if err != nil {
		return nil, err
	}

	// Parse additional comma-separated expressions if any
	expressions, err := os.parseCommaSeparatedExpressions(parser, pos, firstExpr)
	if err != nil {
		return nil, err
	}

	if !parser.currentTokenIs(token.RPAREN) {
		return nil, fmt.Errorf("expected ')' after expression at %v", parser.current.Pos)
	}
	parser.nextToken() // consume ')'

	return os.createCommaExpression(pos, expressions), nil
}

// parseFirstParenthesizedExpression parses the first expression in a parenthesized list
func (os *OfStrategy) parseFirstParenthesizedExpression(parser *ExpressionParser, _ token.Position) (ast.Expression, error) {
	switch parser.current.Type {
	case token.StringIdentifier:
		expr := &ast.Identifier{
			Name: parser.current.Literal,
			Pos:  parser.current.Pos,
		}
		parser.nextToken()
		return expr, nil
	default:
		return nil, fmt.Errorf("expected string identifier in parenthesized list at %v", parser.current.Pos)
	}
}

// parseCommaSeparatedExpressions parses comma-separated expressions
func (os *OfStrategy) parseCommaSeparatedExpressions(parser *ExpressionParser, pos token.Position, firstExpr ast.Expression) ([]ast.Expression, error) {
	expressions := []ast.Expression{firstExpr}

	for parser.currentTokenIs(token.COMMA) {
		parser.nextToken() // consume ','

		nextExpr, err := os.parseNextParenthesizedExpression(parser, pos)
		if err != nil {
			return nil, err
		}
		expressions = append(expressions, nextExpr)
	}

	return expressions, nil
}

// parseNextParenthesizedExpression parses the next expression in a comma-separated list
func (os *OfStrategy) parseNextParenthesizedExpression(parser *ExpressionParser, _ token.Position) (ast.Expression, error) {
	if parser.currentTokenIs(token.StringIdentifier) {
		expr := &ast.Identifier{
			Name: parser.current.Literal,
			Pos:  parser.current.Pos,
		}
		parser.nextToken()
		return expr, nil
	}
	return nil, fmt.Errorf("expected string identifier after comma at %v", parser.current.Pos)
}

// createCommaExpression creates a comma expression from multiple expressions
func (os *OfStrategy) createCommaExpression(pos token.Position, expressions []ast.Expression) ast.Expression {
	if len(expressions) == 1 {
		return expressions[0]
	}

	// Create a representation for comma-separated list
	// For now, create a simple representation - this could be enhanced later
	target := expressions[0]
	for i := 1; i < len(expressions); i++ {
		target = &ast.BinaryOp{
			Left:  target,
			Op:    token.COMMA,
			Right: expressions[i],
			Pos:   pos,
		}
	}
	return target
}

// Name returns the name of the strategy
func (os *OfStrategy) Name() string { return "OfStrategy" }

// Associativity returns the associativity of "of" operations
func (os *OfStrategy) Associativity() Associativity { return LeftAssociative }

// Precedence returns the precedence level of "of" operations
func (os *OfStrategy) Precedence() int { return 2 }
