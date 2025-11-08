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
		tc.addError(&Error{
			Message:  "undefined identifier: " + identifier.Name,
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

	handler := tc.getBinaryOpHandler(binaryOp.Op)
	if handler == nil {
		tc.addError(&Error{
			Message:  fmt.Sprintf("unknown binary operator: %s", binaryOp.Op),
			Position: binaryOp.Position(),
		})
		return &TypeInfo{DataType: TypeUnknown}
	}

	return handler.Handle(binaryOp, leftType, rightType)
}

// getBinaryOpHandler returns the appropriate handler for a binary operator
func (tc *TypeChecker) getBinaryOpHandler(op token.TokenType) BinaryOpHandler {
	switch op {
	case token.PLUS, token.MINUS, token.MULTIPLY, token.DIVIDE, token.MODULO, token.INT_DIVIDE:
		return &ArithmeticOpHandler{BaseOpHandler: BaseOpHandler{tc: tc}}
	case token.BITWISE_AND, token.BITWISE_OR, token.BITWISE_XOR, token.LEFT_SHIFT, token.RIGHT_SHIFT:
		return &BitwiseOpHandler{BaseOpHandler: BaseOpHandler{tc: tc}}
	case token.EQ, token.NEQ, token.LT, token.LE, token.GT, token.GE:
		return &ComparisonOpHandler{BaseOpHandler: BaseOpHandler{tc: tc}}
	case token.AND, token.OR:
		return &LogicalOpHandler{BaseOpHandler: BaseOpHandler{tc: tc}}
	case token.CONTAINS, token.ICONTAINS, token.STARTSWITH, token.ENDSWITH,
		token.ISTARTSWITH, token.IENDSWITH, token.IEQUALS, token.MATCHES:
		return &StringOpHandler{BaseOpHandler: BaseOpHandler{tc: tc}}
	case token.OF:
		return &QuantifierOpHandler{BaseOpHandler: BaseOpHandler{tc: tc}}
	case token.AT:
		return &AtOpHandler{BaseOpHandler: BaseOpHandler{tc: tc}}
	case token.IN:
		return &InOpHandler{BaseOpHandler: BaseOpHandler{tc: tc}}
	case token.DOT:
		return &DotOpHandler{BaseOpHandler: BaseOpHandler{tc: tc}}
	case token.COLON:
		return &ColonOpHandler{BaseOpHandler: BaseOpHandler{tc: tc}}
	default:
		return nil
	}
}

// BinaryOpHandler defines the interface for handling binary operations
type BinaryOpHandler interface {
	Handle(binaryOp *ast.BinaryOp, leftType, rightType *TypeInfo) *TypeInfo
}

// BaseOpHandler provides common functionality for operation handlers
type BaseOpHandler struct {
	tc *TypeChecker
}

// ArithmeticOpHandler handles arithmetic operations
type ArithmeticOpHandler struct {
	BaseOpHandler
}

func (h *ArithmeticOpHandler) Handle(binaryOp *ast.BinaryOp, leftType, rightType *TypeInfo) *TypeInfo {
	return h.tc.checkArithmeticOp(binaryOp, leftType, rightType)
}

// BitwiseOpHandler handles bitwise operations
type BitwiseOpHandler struct {
	BaseOpHandler
}

func (h *BitwiseOpHandler) Handle(binaryOp *ast.BinaryOp, leftType, rightType *TypeInfo) *TypeInfo {
	return h.tc.checkBitwiseOp(binaryOp, leftType, rightType)
}

// ComparisonOpHandler handles comparison operations
type ComparisonOpHandler struct {
	BaseOpHandler
}

func (h *ComparisonOpHandler) Handle(binaryOp *ast.BinaryOp, leftType, rightType *TypeInfo) *TypeInfo {
	return h.tc.checkComparisonOp(binaryOp, leftType, rightType)
}

// LogicalOpHandler handles logical operations
type LogicalOpHandler struct {
	BaseOpHandler
}

func (h *LogicalOpHandler) Handle(binaryOp *ast.BinaryOp, leftType, rightType *TypeInfo) *TypeInfo {
	return h.tc.checkLogicalOp(binaryOp, leftType, rightType)
}

// StringOpHandler handles string operations
type StringOpHandler struct {
	BaseOpHandler
}

func (h *StringOpHandler) Handle(binaryOp *ast.BinaryOp, leftType, rightType *TypeInfo) *TypeInfo {
	return h.tc.checkStringOp(binaryOp, leftType, rightType)
}

// QuantifierOpHandler handles quantifier operations
type QuantifierOpHandler struct {
	BaseOpHandler
}

func (h *QuantifierOpHandler) Handle(binaryOp *ast.BinaryOp, leftType, rightType *TypeInfo) *TypeInfo {
	return h.tc.checkQuantifierOp(leftType, rightType, binaryOp.Position())
}

// AtOpHandler handles the 'at' operator
type AtOpHandler struct {
	BaseOpHandler
}

func (h *AtOpHandler) Handle(binaryOp *ast.BinaryOp, leftType, rightType *TypeInfo) *TypeInfo {
	return h.tc.checkAtOperator(leftType, rightType, binaryOp.Position())
}

// InOpHandler handles the 'in' operator
type InOpHandler struct {
	BaseOpHandler
}

func (h *InOpHandler) Handle(binaryOp *ast.BinaryOp, leftType, rightType *TypeInfo) *TypeInfo {
	return h.tc.checkInOperator(leftType, rightType, binaryOp.Position())
}

// DotOpHandler handles the '.' operator
type DotOpHandler struct {
	BaseOpHandler
}

func (h *DotOpHandler) Handle(binaryOp *ast.BinaryOp, leftType, rightType *TypeInfo) *TypeInfo {
	return h.tc.checkDotOperator(leftType, rightType, binaryOp.Position())
}

// ColonOpHandler handles the ':' operator
type ColonOpHandler struct {
	BaseOpHandler
}

func (h *ColonOpHandler) Handle(binaryOp *ast.BinaryOp, leftType, rightType *TypeInfo) *TypeInfo {
	return h.tc.checkColonOperator()
}

// checkArithmeticOp handles arithmetic operations (+, -, *, /, %, //)
func (tc *TypeChecker) checkArithmeticOp(binaryOp *ast.BinaryOp, leftType, rightType *TypeInfo) *TypeInfo {
	if !leftType.CanPerformArithmetic(rightType) {
		tc.addError(&Error{
			Message:  fmt.Sprintf("cannot perform %s between %s and %s", binaryOp.Op, leftType.String(), rightType.String()),
			Position: binaryOp.Position(),
		})
		return &TypeInfo{DataType: TypeUnknown}
	}

	// Result is float if either operand is float, otherwise integer
	if leftType.DataType == TypeFloat || rightType.DataType == TypeFloat {
		return &TypeInfo{DataType: TypeFloat}
	}
	return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}
}

// checkBitwiseOp handles bitwise operations (&, |, ^, <<, >>)
func (tc *TypeChecker) checkBitwiseOp(binaryOp *ast.BinaryOp, leftType, rightType *TypeInfo) *TypeInfo {
	if !leftType.CanPerformBitwise(rightType) {
		tc.addError(&Error{
			Message:  fmt.Sprintf("cannot perform %s between %s and %s", binaryOp.Op, leftType.String(), rightType.String()),
			Position: binaryOp.Position(),
		})
		return &TypeInfo{DataType: TypeUnknown}
	}

	// For shift operations, right operand should be integer
	if binaryOp.Op == token.LEFT_SHIFT || binaryOp.Op == token.RIGHT_SHIFT {
		if !rightType.IsInteger() {
			tc.addError(&Error{
				Message:  "shift amount must be integer, got " + rightType.String(),
				Position: binaryOp.Position(),
			})
			return &TypeInfo{DataType: TypeUnknown}
		}
	}
	return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}
}

// checkComparisonOp handles comparison operations (==, !=, <, <=, >, >=)
func (tc *TypeChecker) checkComparisonOp(binaryOp *ast.BinaryOp, leftType, rightType *TypeInfo) *TypeInfo {
	if !leftType.CanCompare(rightType) {
		tc.addError(&Error{
			Message:  fmt.Sprintf("cannot compare %s and %s", leftType.String(), rightType.String()),
			Position: binaryOp.Position(),
		})
		return &TypeInfo{DataType: TypeUnknown}
	}
	return &TypeInfo{DataType: TypeBoolean}
}

// checkLogicalOp handles logical operations (&&, ||)
func (tc *TypeChecker) checkLogicalOp(binaryOp *ast.BinaryOp, leftType, rightType *TypeInfo) *TypeInfo {
	if leftType.DataType != TypeBoolean || rightType.DataType != TypeBoolean {
		tc.addError(&Error{
			Message:  fmt.Sprintf("logical %s requires boolean operands", binaryOp.Op),
			Position: binaryOp.Position(),
		})
		return &TypeInfo{DataType: TypeUnknown}
	}
	return &TypeInfo{DataType: TypeBoolean}
}

// checkStringOp handles string operations (contains, matches, etc.)
func (tc *TypeChecker) checkStringOp(binaryOp *ast.BinaryOp, leftType, rightType *TypeInfo) *TypeInfo {
	// In YARA, string operations like "contains" and "matches" work with:
	// - Left: string identifier (boolean type when used in conditions)
	// - Right: string literal or regex pattern
	// So we need to be more flexible about the left operand type
	if !leftType.IsString() && leftType.DataType != TypeBoolean {
		tc.addError(&Error{
			Message:  fmt.Sprintf("string operation %s requires string or string identifier as left operand", binaryOp.Op),
			Position: binaryOp.Position(),
		})
		return &TypeInfo{DataType: TypeUnknown}
	}

	if !rightType.IsString() {
		tc.addError(&Error{
			Message:  fmt.Sprintf("string operation %s requires string as right operand", binaryOp.Op),
			Position: binaryOp.Position(),
		})
		return &TypeInfo{DataType: TypeUnknown}
	}
	return &TypeInfo{DataType: TypeBoolean}
}

// checkAtOperator handles AT operator type checking
func (tc *TypeChecker) checkAtOperator(leftType, rightType *TypeInfo, pos token.Position) *TypeInfo {
	// AT operator: $string at offset
	// Left should be string identifier, right should be integer
	if !tc.isStringIdentifier(leftType) {
		tc.addError(&Error{
			Message:  "AT operator requires string identifier as left operand",
			Position: pos,
		})
	}
	if rightType.DataType != TypeInteger {
		tc.addError(&Error{
			Message:  "AT operator requires integer offset as right operand",
			Position: pos,
		})
	}
	// The result should be boolean
	return &TypeInfo{DataType: TypeBoolean}
}

// checkInOperator handles IN operator type checking
func (tc *TypeChecker) checkInOperator(leftType, rightType *TypeInfo, pos token.Position) *TypeInfo {
	// IN operator: $string in (start..end)
	// Left should be string identifier, right should be range
	if !tc.isStringIdentifier(leftType) {
		tc.addError(&Error{
			Message:  "IN operator requires string identifier as left operand",
			Position: pos,
		})
	}
	// Right operand should be a range (integer type)
	if rightType.DataType != TypeInteger {
		tc.addError(&Error{
			Message:  "IN operator requires integer range as right operand",
			Position: pos,
		})
	}
	// The result should be boolean
	return &TypeInfo{DataType: TypeBoolean}
}

// checkDotOperator handles DOT operator type checking
func (tc *TypeChecker) checkDotOperator(leftType, rightType *TypeInfo, pos token.Position) *TypeInfo {
	// DOT operator (..) represents range expression: start..end
	// Both operands should be integers, result is integer (represents the range)
	if leftType.DataType != TypeInteger {
		tc.addError(&Error{
			Message:  "range expression requires integer start value",
			Position: pos,
		})
	}
	if rightType.DataType != TypeInteger {
		tc.addError(&Error{
			Message:  "range expression requires integer end value",
			Position: pos,
		})
	}
	// Range expressions evaluate to integer type
	return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}
}

// checkColonOperator handles COLON operator type checking
func (tc *TypeChecker) checkColonOperator() *TypeInfo {
	// COLON is used in "for" quantifiers like "for any of them : ($)"
	// The left side is the quantifier expression, right side is the condition
	// The result should be boolean
	return &TypeInfo{DataType: TypeBoolean}
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
			tc.addError(&Error{
				Message:  "logical NOT requires boolean operand",
				Position: unaryOp.Position(),
			})
			return &TypeInfo{DataType: TypeUnknown}
		}
		return &TypeInfo{DataType: TypeBoolean}

	case token.BITWISE_NOT:
		if !operandType.IsInteger() {
			tc.addError(&Error{
				Message:  "bitwise NOT requires integer operand",
				Position: unaryOp.Position(),
			})
			return &TypeInfo{DataType: TypeUnknown}
		}
		return &TypeInfo{DataType: TypeInteger, IntegerType: operandType.IntegerType}

	case token.MINUS:
		if !operandType.IsNumeric() {
			tc.addError(&Error{
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
		tc.addError(&Error{
			Message:  fmt.Sprintf("unknown unary operator: %s", unaryOp.Op),
			Position: unaryOp.Position(),
		})
		return &TypeInfo{DataType: TypeUnknown}
	}
}

// checkQuantifierOp checks quantifier operation types
func (tc *TypeChecker) checkQuantifierOp(_, _ *TypeInfo, _ token.Position) *TypeInfo {
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
