package parser

import (
	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

// ParseContext provides rich context information for parsing strategies
type ParseContext struct {
	Position     token.Position
	CurrentToken token.Token
	PeekToken    token.Token
	Depth        int // For tracking nested expression depth
}

// ParseResult wraps parsing results with additional metadata
type ParseResult struct {
	Node      ast.Expression
	Consumed  int // Number of tokens consumed
	Remaining int // Tokens remaining for lookahead
	Error     error
}

// NewParseResult creates a successful parse result
func NewParseResult(node ast.Expression, consumed int) ParseResult {
	return ParseResult{
		Node:     node,
		Consumed: consumed,
	}
}

// NewParseResultWithRemaining creates a successful parse result with remaining tokens info
func NewParseResultWithRemaining(node ast.Expression, consumed, remaining int) ParseResult {
	return ParseResult{
		Node:      node,
		Consumed:  consumed,
		Remaining: remaining,
	}
}

// NewParseError creates a parse error result
func NewParseError(err error) ParseResult {
	return ParseResult{
		Error: err,
	}
}

// IsSuccess returns true if the parse was successful
func (pr ParseResult) IsSuccess() bool {
	return pr.Node != nil && pr.Error == nil
}

// IsError returns true if the parse resulted in an error
func (pr ParseResult) IsError() bool {
	return pr.Error != nil
}

// TokenClassifier provides methods to classify tokens consistently across strategies
type TokenClassifier interface {
	// Expression classification
	IsComparisonOp(token.TokenType) bool
	IsUnaryOperator(token.TokenType) bool
	IsLogicalOperator(token.TokenType) bool
	IsArithmeticOperator(token.TokenType) bool
	IsBitwiseOperator(token.TokenType) bool

	// Primary expression classification
	IsLiteral(token.TokenType) bool
	IsIdentifier(token.TokenType) bool
	IsDataTypeFunction(token.TokenType) bool
	IsStringModifier(token.TokenType) bool

	// Quantifier classification
	IsQuantifierKeyword(token.TokenType) bool
	IsQuantifierToken(token.TokenType) bool

	// Declaration classification
	IsPatternLiteral(token.TokenType) bool
	IsModifier(token.TokenType) bool
}

// DefaultTokenClassifier provides default implementations for token classification
type DefaultTokenClassifier struct{}

// IsComparisonOp returns true if the token is a comparison operator
func (tc DefaultTokenClassifier) IsComparisonOp(tok token.TokenType) bool {
	switch tok {
	case token.EQ, token.NEQ, token.LT, token.LE, token.GT, token.GE,
		token.CONTAINS, token.ICONTAINS, token.STARTSWITH, token.ISTARTSWITH,
		token.ENDSWITH, token.IENDSWITH, token.IEQUALS, token.MATCHES:
		return true
	default:
		return false
	}
}

// IsUnaryOperator returns true if the token is a unary operator
func (tc DefaultTokenClassifier) IsUnaryOperator(tok token.TokenType) bool {
	switch tok {
	case token.NOT, token.BITWISE_NOT, token.MINUS, token.DEFINED,
		token.HASH, token.AT:
		return true
	default:
		return false
	}
}

// IsLogicalOperator returns true if the token is a logical operator
func (tc DefaultTokenClassifier) IsLogicalOperator(tok token.TokenType) bool {
	return tok == token.AND || tok == token.OR
}

// IsArithmeticOperator returns true if the token is an arithmetic operator
func (tc DefaultTokenClassifier) IsArithmeticOperator(tok token.TokenType) bool {
	switch tok {
	case token.PLUS, token.MINUS, token.MULTIPLY, token.DIVIDE, token.MODULO:
		return true
	default:
		return false
	}
}

// IsBitwiseOperator returns true if the token is a bitwise operator
func (tc DefaultTokenClassifier) IsBitwiseOperator(tok token.TokenType) bool {
	switch tok {
	case token.BITWISE_AND, token.BITWISE_OR, token.BITWISE_XOR,
		token.LEFT_SHIFT, token.RIGHT_SHIFT:
		return true
	default:
		return false
	}
}

// IsLiteral returns true if the token represents a literal value
func (tc DefaultTokenClassifier) IsLiteral(tok token.TokenType) bool {
	switch tok {
	case token.INTEGER_LIT, token.HEX_INTEGER_LIT, token.OCTAL_INTEGER_LIT,
		token.FLOAT_LIT, token.STRING_LIT, token.TRUE, token.FALSE, token.SIZE_LIT,
		token.REGEX_LIT:
		return true
	default:
		return false
	}
}

// IsIdentifier returns true if the token is an identifier
func (tc DefaultTokenClassifier) IsIdentifier(tok token.TokenType) bool {
	return tok == token.IDENTIFIER
}

// IsDataTypeFunction returns true if the token represents a data type conversion function
func (tc DefaultTokenClassifier) IsDataTypeFunction(tok token.TokenType) bool {
	switch tok {
	case token.UINT8, token.UINT16, token.UINT32, token.INT8, token.INT16, token.INT32,
		token.UINT8BE, token.UINT16BE, token.UINT32BE, token.INT8BE, token.INT16BE, token.INT32BE:
		return true
	case token.IDENTIFIER:
		// Would need to check against known function names like "concat"
		return false // Let individual strategies handle this
	default:
		return false
	}
}

// IsStringModifier returns true if the token is a string modifier
func (tc DefaultTokenClassifier) IsStringModifier(tok token.TokenType) bool {
	switch tok {
	case token.NOCASE, token.WIDE, token.ASCII, token.FULLWORD, token.PRIVATE,
		token.XOR, token.BASE64, token.BASE64WIDE:
		return true
	default:
		return false
	}
}

// IsQuantifierKeyword returns true if the token is a quantifier keyword
func (tc DefaultTokenClassifier) IsQuantifierKeyword(tok token.TokenType) bool {
	return tok == token.FOR
}

// IsQuantifierToken returns true if the token can start a quantifier expression
func (tc DefaultTokenClassifier) IsQuantifierToken(tok token.TokenType) bool {
	switch tok {
	case token.ANY, token.ALL, token.NONE:
		return true
	default:
		return false
	}
}

// IsPatternLiteral returns true if the token is a pattern literal type
func (tc DefaultTokenClassifier) IsPatternLiteral(tok token.TokenType) bool {
	switch tok {
	case token.STRING_LIT, token.HEX_STRING_LIT, token.REGEX_LIT:
		return true
	default:
		return false
	}
}

// IsModifier returns true if the token is a modifier
func (tc DefaultTokenClassifier) IsModifier(tok token.TokenType) bool {
	return tc.IsStringModifier(tok)
}
