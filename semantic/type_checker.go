// Package semantic implements semantic analysis and validation for YARA rules.
package semantic

import (
	"fmt"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

// TypeChecker handles type checking for expressions and operations
type TypeChecker struct {
	symbolTable *SymbolTable
	errors      []error
}

// NewTypeChecker creates a new type checker
func NewTypeChecker(symbolTable *SymbolTable) *TypeChecker {
	return &TypeChecker{
		symbolTable: symbolTable,
		errors:      make([]error, 0),
	}
}

// CheckExpressionTypes performs type checking on an expression
func (tc *TypeChecker) CheckExpressionTypes(expr ast.Expression) (*TypeInfo, []error) {
	tc.errors = tc.errors[:0] // Clear previous errors
	typeInfo := tc.checkExpression(expr)
	return typeInfo, tc.errors
}

// checkExpression recursively checks expression types
func (tc *TypeChecker) checkExpression(expr ast.Expression) *TypeInfo {
	switch e := expr.(type) {
	case *ast.Literal:
		return tc.checkLiteral(e)

	case *ast.Identifier:
		return tc.checkIdentifier(e)

	case *ast.BinaryOp:
		return tc.checkBinaryOp(e)

	case *ast.UnaryOp:
		return tc.checkUnaryOp(e)

	default:
		// For unimplemented expression types, return unknown
		return &TypeInfo{DataType: TypeUnknown}
	}
}

// checkLiteral checks the type of a literal value
func (tc *TypeChecker) checkLiteral(literal *ast.Literal) *TypeInfo {
	return InferTypeFromLiteral(literal.Type, literal.Value)
}

// checkIdentifier checks the type of an identifier
func (tc *TypeChecker) checkIdentifier(identifier *ast.Identifier) *TypeInfo {
	// Look up the identifier in the symbol table
	if symbol, exists := tc.symbolTable.Lookup(identifier.Name); exists {
		symbol.Used = true
		return tc.getTypeFromSymbol(symbol)
	}

	// Check for special identifiers
	switch identifier.Name {
	case filesizeKeyword:
		return &TypeInfo{DataType: TypeInteger, IntegerType: Uint64Type}
	case entrypointKeyword:
		return &TypeInfo{DataType: TypeInteger, IntegerType: Uint64Type}
	case flagsKeyword:
		return &TypeInfo{DataType: TypeInteger, IntegerType: Uint64Type}
	case themKeyword:
		return &TypeInfo{DataType: TypeBoolean}
	case "$":
		// Special case for $ in quantifiers like "for any of them : ($)"
		return &TypeInfo{DataType: TypeBoolean}
	default:
		tc.addError(&SemanticError{
			Message:  fmt.Sprintf("undefined identifier: %s", identifier.Name),
			Position: identifier.Position(),
		})
		return &TypeInfo{DataType: TypeUnknown}
	}
}

// checkBinaryOp checks the types of a binary operation
func (tc *TypeChecker) checkBinaryOp(binaryOp *ast.BinaryOp) *TypeInfo {
	leftType := tc.checkExpression(binaryOp.Left)
	rightType := tc.checkExpression(binaryOp.Right)

	if leftType == nil || rightType == nil {
		return &TypeInfo{DataType: TypeUnknown}
	}

	// Check operation-specific type requirements
	switch binaryOp.Op {
	case token.PLUS, token.MINUS, token.MULTIPLY, token.DIVIDE, token.MODULO:
		return tc.checkArithmeticOp(binaryOp.Op, leftType, rightType, binaryOp.Position())

	case token.BITWISE_AND, token.BITWISE_OR, token.BITWISE_XOR,
		token.LEFT_SHIFT, token.RIGHT_SHIFT:
		return tc.checkBitwiseOp(binaryOp.Op, leftType, rightType, binaryOp.Position())

	case token.EQ, token.NEQ, token.LT, token.LE, token.GT, token.GE:
		return tc.checkComparisonOp(binaryOp.Op, leftType, rightType, binaryOp.Position())

	case token.AND, token.OR:
		return tc.checkLogicalOp(binaryOp.Op, leftType, rightType, binaryOp.Position())

	case token.CONTAINS, token.ICONTAINS, token.STARTSWITH, token.ENDSWITH,
		token.ISTARTSWITH, token.IENDSWITH, token.IEQUALS, token.MATCHES:
		return tc.checkStringOp(binaryOp.Op, leftType, rightType, binaryOp.Position())

	case token.OF:
		return tc.checkQuantifierOp(leftType, rightType, binaryOp.Position())

	case token.AT:
		// AT operator: $string at offset
		// Left should be string identifier, right should be integer
		if !tc.isStringIdentifier(leftType) {
			tc.addError(&SemanticError{
				Message:  "AT operator requires string identifier as left operand",
				Position: binaryOp.Position(),
			})
		}
		if rightType.DataType != TypeInteger {
			tc.addError(&SemanticError{
				Message:  "AT operator requires integer offset as right operand",
				Position: binaryOp.Position(),
			})
		}
		// The result should be boolean
		return &TypeInfo{DataType: TypeBoolean}

	case token.IN:
		// IN operator: $string in (start..end)
		// Left should be string identifier, right should be range
		if !tc.isStringIdentifier(leftType) {
			tc.addError(&SemanticError{
				Message:  "IN operator requires string identifier as left operand",
				Position: binaryOp.Position(),
			})
		}
		// Right operand should be a range (integer type)
		if rightType.DataType != TypeInteger {
			tc.addError(&SemanticError{
				Message:  "IN operator requires integer range as right operand",
				Position: binaryOp.Position(),
			})
		}
		// The result should be boolean
		return &TypeInfo{DataType: TypeBoolean}

	case token.DOT:
		// DOT operator (..) represents range expression: start..end
		// Both operands should be integers, result is integer (represents the range)
		if leftType.DataType != TypeInteger {
			tc.addError(&SemanticError{
				Message:  "range expression requires integer start value",
				Position: binaryOp.Position(),
			})
		}
		if rightType.DataType != TypeInteger {
			tc.addError(&SemanticError{
				Message:  "range expression requires integer end value",
				Position: binaryOp.Position(),
			})
		}
		// Range expressions evaluate to integer type
		return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}

	case token.COLON:
		// COLON is used in "for" quantifiers like "for any of them : ($)"
		// The left side is the quantifier expression, right side is the condition
		// The result should be boolean
		return &TypeInfo{DataType: TypeBoolean}

	default:
		tc.addError(&SemanticError{
			Message:  fmt.Sprintf("unknown binary operator: %s", binaryOp.Op),
			Position: binaryOp.Position(),
		})
		return &TypeInfo{DataType: TypeUnknown}
	}
}

// checkUnaryOp checks the types of a unary operation
func (tc *TypeChecker) checkUnaryOp(unaryOp *ast.UnaryOp) *TypeInfo {
	operandType := tc.checkExpression(unaryOp.Right)

	if operandType == nil {
		return &TypeInfo{DataType: TypeUnknown}
	}

	switch unaryOp.Op {
	case token.NOT:
		if operandType.DataType != TypeBoolean {
			tc.addError(&SemanticError{
				Message:  "logical NOT requires boolean operand",
				Position: unaryOp.Position(),
			})
			return &TypeInfo{DataType: TypeUnknown}
		}
		return &TypeInfo{DataType: TypeBoolean}

	case token.BITWISE_NOT:
		if !operandType.IsInteger() {
			tc.addError(&SemanticError{
				Message:  "bitwise NOT requires integer operand",
				Position: unaryOp.Position(),
			})
			return &TypeInfo{DataType: TypeUnknown}
		}
		return &TypeInfo{DataType: TypeInteger, IntegerType: operandType.IntegerType}

	case token.MINUS:
		if !operandType.IsNumeric() {
			tc.addError(&SemanticError{
				Message:  "unary minus requires numeric operand",
				Position: unaryOp.Position(),
			})
			return &TypeInfo{DataType: TypeUnknown}
		}
		return operandType

	case token.DEFINED:
		// DEFINED can work on any type
		return &TypeInfo{DataType: TypeBoolean}

	case token.HASH:
		// '#' count returns integer; operand should be a string identifier but we allow validation to proceed
		return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}

	case token.AT:
		// '@' position returns integer offset
		return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}

	default:
		tc.addError(&SemanticError{
			Message:  fmt.Sprintf("unknown unary operator: %s", unaryOp.Op),
			Position: unaryOp.Position(),
		})
		return &TypeInfo{DataType: TypeUnknown}
	}
}

// checkArithmeticOp checks arithmetic operation types
func (tc *TypeChecker) checkArithmeticOp(op token.TokenType, left, right *TypeInfo, pos token.Position) *TypeInfo {
	if !left.CanPerformArithmetic(right) {
		tc.addError(&SemanticError{
			Message:  fmt.Sprintf("cannot perform %s between %s and %s", op, left.String(), right.String()),
			Position: pos,
		})
		return &TypeInfo{DataType: TypeUnknown}
	}

	// Result is float if either operand is float, otherwise integer
	if left.DataType == TypeFloat || right.DataType == TypeFloat {
		return &TypeInfo{DataType: TypeFloat}
	}
	return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}
}

// checkBitwiseOp checks bitwise operation types
func (tc *TypeChecker) checkBitwiseOp(op token.TokenType, left, right *TypeInfo, pos token.Position) *TypeInfo {
	if !left.CanPerformBitwise(right) {
		tc.addError(&SemanticError{
			Message:  fmt.Sprintf("cannot perform %s between %s and %s", op, left.String(), right.String()),
			Position: pos,
		})
		return &TypeInfo{DataType: TypeUnknown}
	}

	// For shift operations, right operand should be integer
	if op == token.LEFT_SHIFT || op == token.RIGHT_SHIFT {
		if !right.IsInteger() {
			tc.addError(&SemanticError{
				Message:  fmt.Sprintf("shift amount must be integer, got %s", right.String()),
				Position: pos,
			})
			return &TypeInfo{DataType: TypeUnknown}
		}
	}

	return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}
}

// checkComparisonOp checks comparison operation types
func (tc *TypeChecker) checkComparisonOp(_ token.TokenType, left, right *TypeInfo, pos token.Position) *TypeInfo {
	if !left.CanCompare(right) {
		tc.addError(&SemanticError{
			Message:  fmt.Sprintf("cannot compare %s and %s", left.String(), right.String()),
			Position: pos,
		})
		return &TypeInfo{DataType: TypeUnknown}
	}

	return &TypeInfo{DataType: TypeBoolean}
}

// checkLogicalOp checks logical operation types
func (tc *TypeChecker) checkLogicalOp(op token.TokenType, left, right *TypeInfo, pos token.Position) *TypeInfo {
	if left.DataType != TypeBoolean || right.DataType != TypeBoolean {
		tc.addError(&SemanticError{
			Message:  fmt.Sprintf("logical %s requires boolean operands", op),
			Position: pos,
		})
		return &TypeInfo{DataType: TypeUnknown}
	}

	return &TypeInfo{DataType: TypeBoolean}
}

// checkStringOp checks string operation types
func (tc *TypeChecker) checkStringOp(op token.TokenType, left, right *TypeInfo, pos token.Position) *TypeInfo {
	// In YARA, string operations like "contains" and "matches" work with:
	// - Left: string identifier (boolean type when used in conditions)
	// - Right: string literal or regex pattern
	// So we need to be more flexible about the left operand type

	if !left.IsString() && left.DataType != TypeBoolean {
		tc.addError(&SemanticError{
			Message:  fmt.Sprintf("string operation %s requires string or string identifier as left operand", op),
			Position: pos,
		})
		return &TypeInfo{DataType: TypeUnknown}
	}

	if !right.IsString() {
		tc.addError(&SemanticError{
			Message:  fmt.Sprintf("string operation %s requires string as right operand", op),
			Position: pos,
		})
		return &TypeInfo{DataType: TypeUnknown}
	}

	return &TypeInfo{DataType: TypeBoolean}
}

// checkQuantifierOp checks quantifier operation types
func (tc *TypeChecker) checkQuantifierOp(_ *TypeInfo, _ *TypeInfo, _ token.Position) *TypeInfo {
	// Left side should be a quantifier (all, any, none) or number
	// Right side should be a string set or "them"

	// For now, assume quantifier operations return boolean
	// This would be more sophisticated in a full implementation
	return &TypeInfo{DataType: TypeBoolean}
}

// getTypeFromSymbol returns type information for a symbol
func (tc *TypeChecker) getTypeFromSymbol(symbol *Symbol) *TypeInfo {
	switch symbol.Type {
	case SymbolRule:
		return &TypeInfo{DataType: TypeBoolean}
	case SymbolString:
		return &TypeInfo{DataType: TypeBoolean}
	case SymbolVariable:
		// For now, assume variables are integers
		// This will be refined as we add more type information
		return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}
	case SymbolExternal:
		// External variables could be string, integer, or boolean
		// For now, assume integer type (will be refined with type hints)
		return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}
	default:
		return &TypeInfo{DataType: TypeUnknown}
	}
}

// addError adds a type checking error
func (tc *TypeChecker) addError(err error) {
	tc.errors = append(tc.errors, err)
}

// GetErrors returns all type checking errors
func (tc *TypeChecker) GetErrors() []error {
	return tc.errors
}

// HasErrors returns true if there are type checking errors
func (tc *TypeChecker) HasErrors() bool {
	return len(tc.errors) > 0
}

// isStringIdentifier checks if a type represents a string identifier (like $a, $b, etc.)
func (tc *TypeChecker) isStringIdentifier(typeInfo *TypeInfo) bool {
	// String identifiers have boolean type in YARA (they represent whether the pattern matches)
	// For now, we assume any boolean type from a string identifier is valid
	// In a more complete implementation, we'd track the symbol type more precisely
	return typeInfo.DataType == TypeBoolean
}
