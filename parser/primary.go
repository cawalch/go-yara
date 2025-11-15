package parser

import (
	"fmt"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

// LiteralStrategy handles literal values (numbers, strings, booleans, etc.)
type LiteralStrategy struct {
	classifier TokenClassifier
}

// NewLiteralStrategy creates a new literal strategy
func NewLiteralStrategy() *LiteralStrategy {
	return &LiteralStrategy{
		classifier: DefaultTokenClassifier{},
	}
}

// CanHandle checks if the strategy can handle the given literal token
func (ls *LiteralStrategy) CanHandle(currentToken, _ token.Type) bool {
	return ls.classifier.IsLiteral(currentToken)
}

// Parse parses a literal token into an AST node
func (ls *LiteralStrategy) Parse(parser *ExpressionParser, context ParseContext) ParseResult {
	switch context.CurrentToken.Type {
	case token.IntegerLit, token.HexIntegerLit, token.OctalIntegerLit:
		value := parser.current.Literal
		parser.nextToken()
		return NewParseResult(&ast.Literal{
			Type:  context.CurrentToken.Type,
			Value: value,
			Pos:   context.Position,
		}, 1)

	case token.FloatLit:
		value := parser.current.Literal
		parser.nextToken()
		return NewParseResult(&ast.Literal{
			Type:  context.CurrentToken.Type,
			Value: value,
			Pos:   context.Position,
		}, 1)

	case token.StringLit:
		value := parser.current.Literal
		parser.nextToken()
		return NewParseResult(&ast.Literal{
			Type:  context.CurrentToken.Type,
			Value: value,
			Pos:   context.Position,
		}, 1)

	case token.TRUE, token.FALSE:
		value := parser.current.Literal
		parser.nextToken()
		return NewParseResult(&ast.Literal{
			Type:  context.CurrentToken.Type,
			Value: value,
			Pos:   context.Position,
		}, 1)

	case token.RegexLit:
		value := parser.current.Literal
		parser.nextToken()
		return NewParseResult(&ast.Literal{
			Type:  context.CurrentToken.Type,
			Value: value,
			Pos:   context.Position,
		}, 1)

	case token.SizeLit:
		value := parser.current.Literal
		parser.nextToken()
		return NewParseResult(&ast.Literal{
			Type:  context.CurrentToken.Type,
			Value: value,
			Pos:   context.Position,
		}, 1)

	default:
		return NewParseError(fmt.Errorf("unsupported literal type: %s", context.CurrentToken.Type))
	}
}

// Name returns the name of the strategy
func (ls *LiteralStrategy) Name() string { return "LiteralStrategy" }

// Priority returns the priority of the strategy
func (ls *LiteralStrategy) Priority() int { return 1 }

// IdentifierStrategy handles identifiers (variables, strings, functions, etc.)
type IdentifierStrategy struct {
	classifier TokenClassifier
}

// NewIdentifierStrategy creates a new identifier strategy
func NewIdentifierStrategy() *IdentifierStrategy {
	return &IdentifierStrategy{
		classifier: DefaultTokenClassifier{},
	}
}

// CanHandle checks if the strategy can handle the given identifier token
func (is *IdentifierStrategy) CanHandle(currentToken, _ token.Type) bool {
	return is.classifier.IsIdentifier(currentToken)
}

// Parse parses an identifier token into an AST node
func (is *IdentifierStrategy) Parse(parser *ExpressionParser, context ParseContext) ParseResult {
	name := parser.current.Literal
	parser.nextToken()

	// Handle member access (dot notation) like pe.entry_point
	if parser.currentTokenIs(token.DOT) {
		return is.parseMemberAccess(parser, context, name)
	}

	return NewParseResult(&ast.Identifier{
		Name: name,
		Pos:  context.Position,
	}, 1)
}

// parseMemberAccess handles member access expressions like pe.entry_point
func (is *IdentifierStrategy) parseMemberAccess(parser *ExpressionParser, context ParseContext, baseName string) ParseResult {
	var left ast.Expression = &ast.Identifier{
		Name: baseName,
		Pos:  context.Position,
	}

	for parser.currentTokenIs(token.DOT) {
		parser.nextToken() // consume '.'

		if !parser.currentTokenIs(token.IDENTIFIER) {
			return NewParseError(fmt.Errorf("expected identifier after '.' at %v", parser.current.Pos))
		}

		memberName := parser.current.Literal
		memberPos := parser.current.Pos
		parser.nextToken()

		right := &ast.Identifier{
			Name: memberName,
			Pos:  memberPos,
		}

		// Create binary operation for dot notation
		left = &ast.BinaryOp{
			Left:  left,
			Op:    token.DOT,
			Right: right,
			Pos:   context.Position,
		}
	}

	return NewParseResult(left, 1)
}

// Name returns the name of the strategy
func (is *IdentifierStrategy) Name() string { return "IdentifierStrategy" }

// Priority returns the priority of the strategy
func (is *IdentifierStrategy) Priority() int { return 2 }

// ParenthesizedExpressionStrategy handles expressions in parentheses
type ParenthesizedExpressionStrategy struct{}

// NewParenthesizedExpressionStrategy creates a new parenthesized expression strategy
func NewParenthesizedExpressionStrategy() *ParenthesizedExpressionStrategy {
	return &ParenthesizedExpressionStrategy{}
}

// CanHandle checks if the strategy can handle the given parenthesized expression token
func (pes *ParenthesizedExpressionStrategy) CanHandle(currentToken, _ token.Type) bool {
	return currentToken == token.LPAREN
}

// Parse parses a parenthesized expression token into an AST node
func (pes *ParenthesizedExpressionStrategy) Parse(parser *ExpressionParser, _ ParseContext) ParseResult {
	parser.nextToken() // consume '('

	// Parse the expression inside parentheses
	expr, err := parser.ParseExpression()
	if err != nil {
		return NewParseError(fmt.Errorf("error in parenthesized expression: %w", err))
	}

	// Expect closing parenthesis
	if !parser.currentTokenIs(token.RPAREN) {
		return NewParseError(fmt.Errorf("expected ')' at %v", parser.current.Pos))
	}

	parser.nextToken()             // consume ')'
	return NewParseResult(expr, 2) // consumed '(' and ')'
}

// Name returns the name of the strategy
func (pes *ParenthesizedExpressionStrategy) Name() string { return "ParenthesizedExpressionStrategy" }

// Priority returns the priority of the strategy
func (pes *ParenthesizedExpressionStrategy) Priority() int { return 0 }

// UnaryOperatorStrategy handles unary operators (not, -, ~, etc.)
type UnaryOperatorStrategy struct {
	classifier TokenClassifier
}

// NewUnaryOperatorStrategy creates a new unary operator strategy
func NewUnaryOperatorStrategy() *UnaryOperatorStrategy {
	return &UnaryOperatorStrategy{
		classifier: DefaultTokenClassifier{},
	}
}

// CanHandle checks if the strategy can handle the given unary operator token
func (uos *UnaryOperatorStrategy) CanHandle(currentToken, _ token.Type) bool {
	return uos.classifier.IsUnaryOperator(currentToken)
}

// Parse parses a unary operator into an AST expression
func (uos *UnaryOperatorStrategy) Parse(parser *ExpressionParser, context ParseContext) ParseResult {
	operator := parser.current
	operatorType := operator.Type
	parser.nextToken()

	// Parse the operand
	operand, err := parser.parsePrimary()
	if err != nil {
		return NewParseError(fmt.Errorf("error parsing unary operand: %w", err))
	}

	return NewParseResult(&ast.UnaryOp{
		Op:    operatorType,
		Right: operand,
		Pos:   context.Position,
	}, 1)
}

// Name returns the name of the strategy
func (uos *UnaryOperatorStrategy) Name() string { return "UnaryOperatorStrategy" }

// Priority returns the priority of the strategy
func (uos *UnaryOperatorStrategy) Priority() int { return 3 }

// DataTypeFunctionStrategy handles data type conversion functions (uint8, int16, etc.)
type DataTypeFunctionStrategy struct{}

// NewDataTypeFunctionStrategy creates a new data type function strategy
func NewDataTypeFunctionStrategy() *DataTypeFunctionStrategy {
	return &DataTypeFunctionStrategy{}
}

// CanHandle checks if the strategy can handle the given data type function token
func (dtfs *DataTypeFunctionStrategy) CanHandle(currentToken, _ token.Type) bool {
	// Check if current token is a data type function name
	switch currentToken {
	case token.UINT8, token.UINT16, token.UINT32, token.INT8, token.INT16, token.INT32,
		token.UINT8BE, token.UINT16BE, token.UINT32BE, token.INT8BE, token.INT16BE, token.INT32BE:
		return true
	case token.IDENTIFIER:
		// For IDENTIFIER tokens, we would need to check the literal value
		// This is handled in the Parse method instead
		return true
	default:
		return false
	}
}

// Parse parses a data type function call into an AST node
func (dtfs *DataTypeFunctionStrategy) Parse(parser *ExpressionParser, context ParseContext) ParseResult {
	// Extract function name
	functionName := ""
	switch context.CurrentToken.Type {
	case token.IDENTIFIER:
		functionName = context.CurrentToken.Literal
		// Check if it's a known data type function
		switch functionName {
		case "uint8", "uint16", "uint32", "int8", "int16", "int32",
			"uint8be", "uint16be", "uint32be", "int8be", "int16be", "int32be",
			"concat":
			// Valid function name
		default:
			return NewParseError(fmt.Errorf("unsupported data type function: %s", functionName))
		}
	case token.UINT8, token.UINT16, token.UINT32, token.INT8, token.INT16, token.INT32,
		token.UINT8BE, token.UINT16BE, token.UINT32BE, token.INT8BE, token.INT16BE, token.INT32BE:
		functionName = context.CurrentToken.Type.String()
	default:
		return NewParseError(fmt.Errorf("invalid data type function: %s", context.CurrentToken.Type))
	}

	parser.nextToken() // consume function name

	// Check for opening parenthesis
	if !parser.currentTokenIs(token.LPAREN) {
		return NewParseError(fmt.Errorf("expected '(' after function %s", functionName))
	}
	parser.nextToken() // consume '('

	// Parse arguments
	var args []ast.Expression
	for !parser.currentTokenIs(token.RPAREN) {
		arg, err := parser.ParseExpression()
		if err != nil {
			return NewParseError(fmt.Errorf("error parsing function argument: %w", err))
		}
		args = append(args, arg)

		// Check for comma separator
		if parser.currentTokenIs(token.COMMA) {
			parser.nextToken()
		} else if !parser.currentTokenIs(token.RPAREN) {
			return NewParseError(fmt.Errorf("expected ',' or ')' in function arguments"))
		}
	}

	parser.nextToken() // consume ')'

	return NewParseResult(&ast.FunctionCall{
		Function: functionName,
		Args:     args,
		Pos:      context.Position,
	}, 2) // consumed function name and parentheses
}

// Name returns the name of the strategy
func (dtfs *DataTypeFunctionStrategy) Name() string { return "DataTypeFunctionStrategy" }

// Priority returns the priority of the strategy
func (dtfs *DataTypeFunctionStrategy) Priority() int { return 4 }

// YaraBuiltInStrategy handles YARA built-in functions and special literals
type YaraBuiltInStrategy struct{}

// NewYaraBuiltInStrategy creates a new YARA built-in strategy
func NewYaraBuiltInStrategy() *YaraBuiltInStrategy {
	return &YaraBuiltInStrategy{}
}

// CanHandle checks if the strategy can handle the given YARA built-in token
func (ybs *YaraBuiltInStrategy) CanHandle(currentToken, _ token.Type) bool {
	// Handle YARA-specific built-ins and special literals
	switch currentToken {
	case token.ENTRYPOINT, token.DEFINED, token.SizeLit, token.FILESIZE:
		return true
	case token.StringIdentifier:
		// Handle string references like $a
		return true
	default:
		return false
	}
}

// Parse parses a YARA built-in function or literal into an AST node
func (ybs *YaraBuiltInStrategy) Parse(parser *ExpressionParser, context ParseContext) ParseResult {
	switch context.CurrentToken.Type {
	case token.ENTRYPOINT:
		value := parser.current.Literal
		parser.nextToken()
		return NewParseResult(&ast.Literal{
			Type:  context.CurrentToken.Type,
			Value: value,
			Pos:   context.Position,
		}, 1)

	case token.DEFINED:
		value := parser.current.Literal
		parser.nextToken()
		return NewParseResult(&ast.Literal{
			Type:  context.CurrentToken.Type,
			Value: value,
			Pos:   context.Position,
		}, 1)

	case token.SizeLit:
		value := parser.current.Literal
		parser.nextToken()
		return NewParseResult(&ast.Literal{
			Type:  context.CurrentToken.Type,
			Value: value,
			Pos:   context.Position,
		}, 1)

	case token.FILESIZE:
		value := parser.current.Literal
		parser.nextToken()
		return NewParseResult(&ast.Literal{
			Type:  context.CurrentToken.Type,
			Value: value,
			Pos:   context.Position,
		}, 1)

	case token.StringIdentifier:
		value := parser.current.Literal
		parser.nextToken()
		return NewParseResult(&ast.Identifier{
			Name: value,
			Pos:  context.Position,
		}, 1)

	default:
		return NewParseError(fmt.Errorf("unsupported YARA built-in: %s", context.CurrentToken.Type))
	}
}

// Name returns the name of the strategy
func (ybs *YaraBuiltInStrategy) Name() string { return "YaraBuiltInStrategy" }

// Priority returns the priority of the strategy
func (ybs *YaraBuiltInStrategy) Priority() int { return 6 }

// ArrayIndexStrategy handles array indexing expressions (e.g., identifier[index])
type ArrayIndexStrategy struct{}

// NewArrayIndexStrategy creates a new array index strategy
func NewArrayIndexStrategy() *ArrayIndexStrategy {
	return &ArrayIndexStrategy{}
}

// CanHandle checks if the strategy can handle the given array indexing tokens
func (ais *ArrayIndexStrategy) CanHandle(_, _ token.Type) bool {
	// This strategy handles cases after we've parsed an identifier
	// and encounter a '[' - so it's handled at a different level
	return false // This is handled in ExpressionParser.parsePostfix()
}

// Parse parses an array indexing expression (not directly used)
func (ais *ArrayIndexStrategy) Parse(_ *ExpressionParser, _ ParseContext) ParseResult {
	return NewParseError(fmt.Errorf("ArrayIndexStrategy should be handled via parsePostfix"))
}

// Name returns the name of the strategy
func (ais *ArrayIndexStrategy) Name() string { return "ArrayIndexStrategy" }

// Priority returns the priority of the strategy
func (ais *ArrayIndexStrategy) Priority() int { return 5 }

// QuantifierTokenStrategy handles quantifier keywords (any, all, none, for)
type QuantifierTokenStrategy struct {
	classifier TokenClassifier
}

// NewQuantifierTokenStrategy creates a new quantifier token strategy
func NewQuantifierTokenStrategy() *QuantifierTokenStrategy {
	return &QuantifierTokenStrategy{
		classifier: DefaultTokenClassifier{},
	}
}

// CanHandle checks if the strategy can handle the given quantifier token
func (qs *QuantifierTokenStrategy) CanHandle(currentToken, _ token.Type) bool {
	return qs.classifier.IsQuantifierToken(currentToken) ||
		currentToken == token.FOR ||
		currentToken == token.THEM
}

// Parse parses a quantifier token into an AST node
func (qs *QuantifierTokenStrategy) Parse(parser *ExpressionParser, context ParseContext) ParseResult {
	switch context.CurrentToken.Type {
	case token.ANY, token.ALL, token.NONE:
		value := parser.current.Literal
		parser.nextToken()
		return NewParseResult(&ast.Identifier{
			Name: value,
			Pos:  context.Position,
		}, 1)

	case token.FOR:
		value := parser.current.Literal
		parser.nextToken()
		return NewParseResult(&ast.Identifier{
			Name: value,
			Pos:  context.Position,
		}, 1)

	case token.THEM:
		value := parser.current.Literal
		parser.nextToken()
		return NewParseResult(&ast.Identifier{
			Name: value,
			Pos:  context.Position,
		}, 1)

	default:
		return NewParseError(fmt.Errorf("unsupported quantifier: %s", context.CurrentToken.Type))
	}
}

// Name returns the name of the strategy
func (qs *QuantifierTokenStrategy) Name() string { return "QuantifierTokenStrategy" }

// Priority returns the priority of the strategy
func (qs *QuantifierTokenStrategy) Priority() int { return 7 }

// QuantifierExpressionStrategy handles full quantifier expressions like "2 of them", "any of ($test1, $test2)"
type QuantifierExpressionStrategy struct {
	classifier TokenClassifier
}

// NewQuantifierExpressionStrategy creates a new quantifier expression strategy
func NewQuantifierExpressionStrategy() *QuantifierExpressionStrategy {
	return &QuantifierExpressionStrategy{
		classifier: DefaultTokenClassifier{},
	}
}

// CanHandle checks if the strategy can handle the given quantifier expression token combination
func (qes *QuantifierExpressionStrategy) CanHandle(currentToken, peekToken token.Type) bool {
	// Handle numeric quantifiers: "2 of them" (current=INTEGER, peek=OF)
	if (currentToken == token.IntegerLit || currentToken == token.HexIntegerLit || currentToken == token.OctalIntegerLit) && peekToken == token.OF {
		return true
	}
	// Handle keyword quantifiers: "any of them", "all of them" (current=ANY/ALL/NONE, peek=OF)
	if (currentToken == token.ANY || currentToken == token.ALL || currentToken == token.NONE) && peekToken == token.OF {
		return true
	}
	// Handle "for" quantifiers
	if currentToken == token.FOR {
		return true
	}
	return false
}

// Parse parses a quantifier expression into an AST node
func (qes *QuantifierExpressionStrategy) Parse(parser *ExpressionParser, context ParseContext) ParseResult {
	// Use the quantifier parser if available
	if parser.quantifierParser != nil {
		// Update tokens for quantifier parser
		parser.quantifierParser.SetCurrentTokens(parser.current, parser.peek)

		// Parse the full quantifier expression
		expr, err := parser.quantifierParser.ParseQuantifier(context.Position)
		if err != nil {
			return NewParseError(err)
		}

		// Update current tokens after quantifier parsing
		parser.current = parser.quantifierParser.current
		parser.peek = parser.quantifierParser.peek

		return NewParseResult(expr, 1) // Token count will vary
	}

	// Fallback: create a simple identifier
	ident := &ast.Identifier{
		Name: context.CurrentToken.Literal,
		Pos:  context.Position,
	}
	parser.nextToken()
	return NewParseResult(ident, 1)
}

// Name returns the name of the strategy
func (qes *QuantifierExpressionStrategy) Name() string { return "QuantifierExpressionStrategy" }

// Priority returns the priority of the strategy
func (qes *QuantifierExpressionStrategy) Priority() int { return 10 } // Very high priority

// RegisterDefaultPrimaryStrategies registers the default primary expression strategies
func RegisterDefaultPrimaryStrategies(registry *StrategyRegistry) {
	registry.RegisterPrimaryStrategy(NewQuantifierExpressionStrategy()) // High priority for quantifiers
	registry.RegisterPrimaryStrategy(NewParenthesizedExpressionStrategy())
	registry.RegisterPrimaryStrategy(NewLiteralStrategy())
	registry.RegisterPrimaryStrategy(NewIdentifierStrategy())
	registry.RegisterPrimaryStrategy(NewUnaryOperatorStrategy())
	registry.RegisterPrimaryStrategy(NewDataTypeFunctionStrategy())
	registry.RegisterPrimaryStrategy(NewYaraBuiltInStrategy())
	registry.RegisterPrimaryStrategy(NewArrayIndexStrategy())
	registry.RegisterPrimaryStrategy(NewQuantifierTokenStrategy())
}
