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

	case *ast.FunctionCall:
		return tc.checkFunctionCall(e)
	case *ast.StringLength:
		return tc.checkStringLength(e)
	case *ast.ArrayIndex:
		return tc.checkArrayIndex(e)

	case *ast.OfExpression:
		return tc.checkOfExpression(e)

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

	return handler(binaryOp, leftType, rightType)
}

// getBinaryOpHandler returns the appropriate handler for a binary operator
func (tc *TypeChecker) getBinaryOpHandler(op token.Type) BinaryOpHandler {
	if handler := tc.getArithmeticHandler(op); handler != nil {
		return handler
	}

	if handler := tc.getComparisonHandler(op); handler != nil {
		return handler
	}

	if handler := tc.getStringHandler(op); handler != nil {
		return handler
	}

	if handler := tc.getSpecialHandler(op); handler != nil {
		return handler
	}

	return nil
}

// getArithmeticHandler returns handler for arithmetic and bitwise operations
func (tc *TypeChecker) getArithmeticHandler(op token.Type) BinaryOpHandler {
	switch op {
	case token.PLUS, token.MINUS, token.MULTIPLY, token.DIVIDE, token.MODULO, token.IntDivide:
		return tc.createArithmeticHandler()
	case token.BitwiseAnd, token.BitwiseOr, token.BitwiseXor, token.LeftShift, token.RightShift:
		return tc.createBitwiseHandler()
	case token.AND, token.OR:
		return tc.createLogicalHandler()
	default:
		return nil
	}
}

// getComparisonHandler returns handler for comparison operations
func (tc *TypeChecker) getComparisonHandler(op token.Type) BinaryOpHandler {
	switch op {
	case token.EQ, token.NEQ, token.LT, token.LE, token.GT, token.GE:
		return tc.createComparisonHandler()
	default:
		return nil
	}
}

// getStringHandler returns handler for string operations
func (tc *TypeChecker) getStringHandler(op token.Type) BinaryOpHandler {
	stringOps := map[token.Type]bool{
		token.CONTAINS:    true,
		token.ICONTAINS:   true,
		token.STARTSWITH:  true,
		token.ENDSWITH:    true,
		token.ISTARTSWITH: true,
		token.IENDSWITH:   true,
		token.IEQUALS:     true,
		token.MATCHES:     true,
	}

	if stringOps[op] {
		return tc.createStringHandler()
	}
	return nil
}

// getSpecialHandler returns handler for special operations
func (tc *TypeChecker) getSpecialHandler(op token.Type) BinaryOpHandler {
	switch op {
	case token.OF:
		return tc.createQuantifierHandler()
	case token.AT:
		return tc.createAtHandler()
	case token.IN:
		return tc.createInHandler()
	case token.DOT:
		return tc.createDotHandler()
	case token.COLON:
		return tc.createColonHandler()
	default:
		return nil
	}
}

// BinaryOpHandler defines a function type for handling binary operations
// This replaces the interface with a function type, eliminating the anti-pattern
type BinaryOpHandler func(binaryOp *ast.BinaryOp, leftType, rightType *TypeInfo) *TypeInfo

// createArithmeticHandler creates a function handler for arithmetic operations
func (tc *TypeChecker) createArithmeticHandler() BinaryOpHandler {
	return func(binaryOp *ast.BinaryOp, leftType, rightType *TypeInfo) *TypeInfo {
		return tc.checkArithmeticOp(binaryOp, leftType, rightType)
	}
}

// createBitwiseHandler creates a function handler for bitwise operations
func (tc *TypeChecker) createBitwiseHandler() BinaryOpHandler {
	return func(binaryOp *ast.BinaryOp, leftType, rightType *TypeInfo) *TypeInfo {
		return tc.checkBitwiseOp(binaryOp, leftType, rightType)
	}
}

// createComparisonHandler creates a function handler for comparison operations
func (tc *TypeChecker) createComparisonHandler() BinaryOpHandler {
	return func(binaryOp *ast.BinaryOp, leftType, rightType *TypeInfo) *TypeInfo {
		return tc.checkComparisonOp(binaryOp, leftType, rightType)
	}
}

// createLogicalHandler creates a function handler for logical operations
func (tc *TypeChecker) createLogicalHandler() BinaryOpHandler {
	return func(binaryOp *ast.BinaryOp, leftType, rightType *TypeInfo) *TypeInfo {
		return tc.checkLogicalOp(binaryOp, leftType, rightType)
	}
}

// createStringHandler creates a function handler for string operations
func (tc *TypeChecker) createStringHandler() BinaryOpHandler {
	return func(binaryOp *ast.BinaryOp, leftType, rightType *TypeInfo) *TypeInfo {
		return tc.checkStringOp(binaryOp, leftType, rightType)
	}
}

// createQuantifierHandler creates a function handler for quantifier operations
func (tc *TypeChecker) createQuantifierHandler() BinaryOpHandler {
	return func(binaryOp *ast.BinaryOp, leftType, rightType *TypeInfo) *TypeInfo {
		return tc.checkQuantifierOp(leftType, rightType, binaryOp.Position())
	}
}

// createAtHandler creates a function handler for 'at' operations
func (tc *TypeChecker) createAtHandler() BinaryOpHandler {
	return func(binaryOp *ast.BinaryOp, leftType, rightType *TypeInfo) *TypeInfo {
		return tc.checkAtOperator(leftType, rightType, binaryOp.Position())
	}
}

// createInHandler creates a function handler for 'in' operations
func (tc *TypeChecker) createInHandler() BinaryOpHandler {
	return func(binaryOp *ast.BinaryOp, leftType, rightType *TypeInfo) *TypeInfo {
		return tc.checkInOperator(leftType, rightType, binaryOp.Position())
	}
}

// createDotHandler creates a function handler for '.' operations
func (tc *TypeChecker) createDotHandler() BinaryOpHandler {
	return func(binaryOp *ast.BinaryOp, leftType, rightType *TypeInfo) *TypeInfo {
		return tc.checkDotOperator(leftType, rightType, binaryOp.Position())
	}
}

// createColonHandler creates a function handler for ':' operations
func (tc *TypeChecker) createColonHandler() BinaryOpHandler {
	return func(_ *ast.BinaryOp, _, _ *TypeInfo) *TypeInfo {
		return tc.checkColonOperator()
	}
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
	if binaryOp.Op == token.LeftShift || binaryOp.Op == token.RightShift {
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
	// The result should be integer (the offset)
	return &TypeInfo{DataType: TypeInteger}
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
		return tc.checkLogicalNotOp(unaryOp, operandType)
	case token.BitwiseNot:
		return tc.checkBitwiseNotOp(unaryOp, operandType)
	case token.MINUS:
		return tc.checkUnaryMinusOp(unaryOp, operandType)
	case token.DEFINED:
		return tc.checkDefinedOp()
	case token.HASH:
		return tc.checkHashOp()
	case token.AT:
		return tc.checkAtOp()
	default:
		return tc.checkUnknownUnaryOp(unaryOp)
	}
}

// checkLogicalNotOp handles logical NOT operator
func (tc *TypeChecker) checkLogicalNotOp(unaryOp *ast.UnaryOp, operandType *TypeInfo) *TypeInfo {
	if operandType.DataType != TypeBoolean {
		tc.addError(&Error{
			Message:  "logical NOT requires boolean operand",
			Position: unaryOp.Position(),
		})
		return &TypeInfo{DataType: TypeUnknown}
	}
	return &TypeInfo{DataType: TypeBoolean}
}

// checkBitwiseNotOp handles bitwise NOT operator
func (tc *TypeChecker) checkBitwiseNotOp(unaryOp *ast.UnaryOp, operandType *TypeInfo) *TypeInfo {
	if !operandType.IsInteger() {
		tc.addError(&Error{
			Message:  "bitwise NOT requires integer operand",
			Position: unaryOp.Position(),
		})
		return &TypeInfo{DataType: TypeUnknown}
	}
	return &TypeInfo{DataType: TypeInteger, IntegerType: operandType.IntegerType}
}

// checkUnaryMinusOp handles unary minus operator
func (tc *TypeChecker) checkUnaryMinusOp(unaryOp *ast.UnaryOp, operandType *TypeInfo) *TypeInfo {
	if !operandType.IsNumeric() {
		tc.addError(&Error{
			Message:  "unary minus requires numeric operand",
			Position: unaryOp.Position(),
		})
		return &TypeInfo{DataType: TypeUnknown}
	}
	return operandType
}

// checkDefinedOp handles DEFINED operator
func (tc *TypeChecker) checkDefinedOp() *TypeInfo {
	// DEFINED can work on any type
	return &TypeInfo{DataType: TypeBoolean}
}

// checkHashOp handles HASH (#) operator
func (tc *TypeChecker) checkHashOp() *TypeInfo {
	// '#' count returns integer; operand should be a string identifier but we allow validation to proceed
	return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}
}

// checkAtOp handles AT (@) operator
func (tc *TypeChecker) checkAtOp() *TypeInfo {
	// '@' position returns integer offset
	return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}
}

// checkUnknownUnaryOp handles unknown unary operators
func (tc *TypeChecker) checkUnknownUnaryOp(unaryOp *ast.UnaryOp) *TypeInfo {
	tc.addError(&Error{
		Message:  fmt.Sprintf("unknown unary operator: %s", unaryOp.Op),
		Position: unaryOp.Position(),
	})
	return &TypeInfo{DataType: TypeUnknown}
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

// checkFunctionCall checks the type of function call expressions
func (tc *TypeChecker) checkFunctionCall(funcCall *ast.FunctionCall) *TypeInfo {
	// Check argument types
	for _, arg := range funcCall.Args {
		tc.checkExpression(arg)
	}

	// YARA has several built-in functions with known return types
	switch funcCall.Function {
	case "filesize":
		return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}
	case "entrypoint", "offset", "read":
		return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}
	case "string":
		return &TypeInfo{DataType: TypeString}
	// Data type conversion functions - use the type system to get proper return types
	case "uint8", "uint16", "uint32", "uint64",
		"int8", "int16", "int32", "int64",
		"uint8be", "uint16be", "uint32be", "uint64be",
		"int8be", "int16be", "int32be", "int64be":
		returnType, err := GetIntegerTypeFromFunction(funcCall.Function)
		if err != nil {
			// This should not happen if the function name is valid
			return &TypeInfo{DataType: TypeUnknown}
		}
		return &TypeInfo{DataType: TypeInteger, IntegerType: returnType}
	default:
		// Unknown function - return unknown type
		return &TypeInfo{DataType: TypeUnknown}
	}
}

// checkStringLength checks the type of string length expressions
func (tc *TypeChecker) checkStringLength(strLen *ast.StringLength) *TypeInfo {
	// Check the string expression type
	stringType := tc.checkExpression(strLen.String)

	// String length should be applicable to string expressions
	if stringType.DataType == TypeUnknown {
		return &TypeInfo{DataType: TypeUnknown}
	}

	// String length always returns an integer
	return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}
}

// checkOfExpression checks the type of "of" expressions
func (tc *TypeChecker) checkOfExpression(ofExpr *ast.OfExpression) *TypeInfo {
	// Check the count expression
	countType := tc.checkExpression(ofExpr.Count)
	if countType.DataType != TypeInteger && countType.DataType != TypeUnknown {
		tc.addError(fmt.Errorf("count in 'of' expression must be an integer"))
	}

	// Check the strings expression
	_ = tc.checkExpression(ofExpr.Strings) // Check strings expression but ignore type for now

	// "of" expressions always return boolean (true/false)
	return &TypeInfo{DataType: TypeBoolean}
}

// checkArrayIndex checks the type of array indexing expressions
func (tc *TypeChecker) checkArrayIndex(arrayIndex *ast.ArrayIndex) *TypeInfo {
	// The array should be a unary operation (@, !, or #)
	unaryOp, ok := arrayIndex.Array.(*ast.UnaryOp)
	if !ok {
		tc.addError(&Error{
			Message:  "array indexing requires @, !, or # operator",
			Position: arrayIndex.Position(),
		})
		return &TypeInfo{DataType: TypeUnknown}
	}

	// Check that we have a supported operator
	if unaryOp.Op != token.AT && unaryOp.Op != token.StringLength && unaryOp.Op != token.HASH {
		tc.addError(&Error{
			Message:  fmt.Sprintf("unsupported operator for array indexing: %s", unaryOp.Op),
			Position: arrayIndex.Position(),
		})
		return &TypeInfo{DataType: TypeUnknown}
	}

	// Check the array operand (string identifier)
	arrayType := tc.checkExpression(unaryOp.Right)

	// Special handling for string operators: @a[i], !a[i], #a[i]
	// For string operators, we accept identifiers even if they don't exist in symbol table
	// This mirrors the behavior of non-indexed string operators which are lenient
	if ident, ok := unaryOp.Right.(*ast.Identifier); ok && (unaryOp.Op == token.AT || unaryOp.Op == token.StringLength || unaryOp.Op == token.HASH) {
		// Check if this identifier could be a string reference
		if symbol, exists := tc.symbolTable.Lookup("$" + ident.Name); exists {
			symbol.Used = true
			arrayType = &TypeInfo{DataType: TypeBoolean}
		} else {
			// For string operators, assume valid syntax and continue
			// This matches the lenient behavior of non-indexed string operators
			arrayType = &TypeInfo{DataType: TypeBoolean}
		}
	}

	// For non-string operators, still validate strictly
	if arrayType.DataType != TypeBoolean && (unaryOp.Op != token.AT && unaryOp.Op != token.StringLength && unaryOp.Op != token.HASH) {
		tc.addError(&Error{
			Message: fmt.Sprintf("%s operator requires string identifier", map[token.Type]string{
				token.AT:           "@",
				token.StringLength: "!",
				token.HASH:         "#",
			}[unaryOp.Op]),
			Position: unaryOp.Position(),
		})
		return &TypeInfo{DataType: TypeUnknown}
	}

	// Check the index expression
	indexType := tc.checkExpression(arrayIndex.Index)
	if indexType.DataType != TypeInteger {
		tc.addError(&Error{
			Message:  "array index must be integer",
			Position: arrayIndex.Index.Position(),
		})
		return &TypeInfo{DataType: TypeUnknown}
	}

	// All array indexing operations return integer
	return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}
}
