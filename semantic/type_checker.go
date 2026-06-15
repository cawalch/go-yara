package semantic

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

// Special identifier keywords
const (
	filesizeKeyword   = "filesize"
	entrypointKeyword = "entrypoint"
	flagsKeyword      = "flags"
	themKeyword       = "them"
)

// TypeChecker handles type checking for expressions and operations
type TypeChecker struct {
	symbolTable   *SymbolTable
	errors        []error
	loopVariables map[string]string // loop variable name -> type
}

// NewTypeChecker creates a new type checker
func NewTypeChecker(symbolTable *SymbolTable) *TypeChecker {
	return &TypeChecker{
		symbolTable:   symbolTable,
		errors:        make([]error, 0),
		loopVariables: make(map[string]string),
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

	case *ast.OfExpression:
		return tc.checkOfExpression(e)

	case *ast.StringOffset:
		return tc.checkStringOffset(e)

	case *ast.StringCount:
		return tc.checkStringCount(e)

	case *ast.LengthOf:
		return tc.checkLengthOf(e)

	case *ast.ForLoop:
		return tc.checkForLoop(e)

	default:
		// For unimplemented expression types, return unknown
		return &TypeInfo{DataType: TypeUnknown}
	}
}

// checkLiteral checks the type of a literal value
func (tc *TypeChecker) checkLiteral(literal *ast.Literal) *TypeInfo {
	return InferTypeFromLiteral(literal.Type, literal.Value)
}

// checkIdentifier validates an identifier against the symbol table and returns its type
func (tc *TypeChecker) checkIdentifier(identifier *ast.Identifier) *TypeInfo {
	// Check if it's a loop variable
	if loopType, ok := tc.loopVariables[identifier.Name]; ok {
		switch loopType {
		case "string":
			return &TypeInfo{DataType: TypeString}
		case "integer":
			return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}
		default:
			return &TypeInfo{DataType: TypeUnknown}
		}
	}

	// Check if it's a symbol in the symbol table
	if symbol, exists := tc.symbolTable.Lookup(identifier.Name); exists {
		symbol.Used = true
		info := tc.getTypeFromSymbol(symbol)
		// If symbol is a loop variable, use the loopVariables map for type info
		if info.DataType == TypeUnknown {
			if typ, ok := tc.loopVariables[identifier.Name]; ok {
				switch typ {
				case "string":
					return &TypeInfo{DataType: TypeString}
				case "integer":
					return &TypeInfo{DataType: TypeInteger, IntegerType: Uint64Type}
				}
			}
		}
		return info
	}

	// Check for wildcard string set identifiers (e.g., $a*, $str*)
	// These are valid in quantifier expressions like "any of ($a*)" or "#a in (1..3) of ($a*)"
	// The compiler handles expansion at compile time; we just need to allow the identifier.
	if strings.HasPrefix(identifier.Name, "$") && strings.HasSuffix(identifier.Name, "*") {
		return &TypeInfo{DataType: TypeBoolean}
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

// checkBinaryOp checks the types of a binary operation.
func (tc *TypeChecker) checkBinaryOp(binaryOp *ast.BinaryOp) *TypeInfo {
	leftType := tc.checkExpression(binaryOp.Left)
	rightType := tc.checkExpression(binaryOp.Right)

	if leftType == nil || rightType == nil {
		return &TypeInfo{DataType: TypeUnknown}
	}

	switch binaryOp.Op {
	case token.PLUS, token.MINUS, token.MULTIPLY, token.DIVIDE, token.MODULO, token.IntDivide:
		return tc.checkArithmeticOp(binaryOp, leftType, rightType)
	case token.BitwiseAnd, token.BitwiseOr, token.BitwiseXor, token.LeftShift, token.RightShift:
		return tc.checkBitwiseOp(binaryOp, leftType, rightType)
	case token.AND, token.OR:
		return tc.checkLogicalOp(binaryOp, leftType, rightType)
	case token.EQ, token.NEQ, token.LT, token.LE, token.GT, token.GE:
		return tc.checkComparisonOp(binaryOp, leftType, rightType)
	case token.CONTAINS, token.ICONTAINS, token.STARTSWITH, token.ENDSWITH,
		token.ISTARTSWITH, token.IENDSWITH, token.IEQUALS, token.MATCHES:
		return tc.checkStringOp(binaryOp, leftType, rightType)
	case token.OF:
		return tc.checkQuantifierOp(leftType, rightType, binaryOp.Position())
	case token.AT:
		return tc.checkAtOperator(leftType, rightType, binaryOp.Position())
	case token.IN:
		return tc.checkInOperator(leftType, rightType, binaryOp.Position())
	case token.DOT:
		return tc.checkDotOperator(leftType, rightType, binaryOp.Position())
	case token.COLON:
		return tc.checkColonOperator()
	case token.COMMA:
		// Comma is only used to build string sets (e.g., ($a, $b)).
		// Its value is not directly used in conditions, so treat as unknown.
		return &TypeInfo{DataType: TypeUnknown}
	default:
		tc.addError(&Error{
			Message:  fmt.Sprintf("unknown binary operator: %s", binaryOp.Op),
			Position: binaryOp.Position(),
		})
		return &TypeInfo{DataType: TypeUnknown}
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
	// IN operator has two forms:
	// 1. $string in (start..end) — left is string identifier, right is integer range
	// 2. #string in (min..max) — left is integer (count), right is integer range
	if !tc.isStringIdentifier(leftType) && leftType.DataType != TypeInteger {
		tc.addError(&Error{
			Message:  "IN operator requires string identifier or count as left operand",
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
		// Runtime external variables are dynamically typed by the caller.
		return &TypeInfo{DataType: TypeUnknown}
	case SymbolGlobal:
		if symbol.TypeInfo != nil {
			return symbol.TypeInfo
		}
		return &TypeInfo{DataType: TypeUnknown}
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
	case "concat", "tostring", "md5", "sha1", "sha256":
		return &TypeInfo{DataType: TypeString}
	case "int":
		return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}
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
		tc.addError(errors.New("count in 'of' expression must be an integer"))
	}

	// Check the strings expression
	_ = tc.checkExpression(ofExpr.Strings) // Check strings expression but ignore type for now

	// "of" expressions always return boolean (true/false)
	return &TypeInfo{DataType: TypeBoolean}
}

// checkStringOffset checks the type of string offset expressions (@ operator)
func (tc *TypeChecker) checkStringOffset(strOffset *ast.StringOffset) *TypeInfo {
	// Check the string expression type
	stringType := tc.checkExpression(strOffset.String)

	// String offset should be applicable to string expressions
	if stringType.DataType == TypeUnknown {
		return &TypeInfo{DataType: TypeUnknown}
	}

	// If there's an index expression, check it
	if strOffset.Index != nil {
		indexType := tc.checkExpression(strOffset.Index)
		if indexType.DataType != TypeInteger && indexType.DataType != TypeUnknown {
			tc.addError(errors.New("string offset index must be an integer"))
		}
	}

	// String offset always returns an integer (offset position)
	return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}
}

// checkStringCount checks the type of string count expressions (# operator)
func (tc *TypeChecker) checkStringCount(strCount *ast.StringCount) *TypeInfo {
	// Check the string expression type
	stringType := tc.checkExpression(strCount.String)

	// String count should be applicable to string expressions
	if stringType.DataType == TypeUnknown {
		return &TypeInfo{DataType: TypeUnknown}
	}

	// If there's an index expression, check it
	if strCount.Index != nil {
		indexType := tc.checkExpression(strCount.Index)
		if indexType.DataType != TypeInteger && indexType.DataType != TypeUnknown {
			tc.addError(errors.New("string count index must be an integer"))
		}
	}

	// String count always returns an integer (number of matches)
	return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}
}

// checkLengthOf checks the type of length of expressions
func (tc *TypeChecker) checkLengthOf(lengthOf *ast.LengthOf) *TypeInfo {
	// Check the target expression type
	tc.checkExpression(lengthOf.Target)

	// Length of always returns an integer (total length of matches)
	return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}
}

// checkForLoop checks the type of for loop expressions
func (tc *TypeChecker) checkForLoop(forLoop *ast.ForLoop) *TypeInfo {
	// Determine loop variable type from range expression
	loopVarType := TypeUnknown
	switch forLoop.Range.(type) {
	case *ast.StringTuple:
		loopVarType = TypeString
	case *ast.BinaryOp:
		// Integer range (min..max)
		loopVarType = TypeInteger
	}

	// Create a scope for the loop variables so it is visible in the condition.
	tc.symbolTable.EnterScope("for_loop")
	for _, variable := range forLoop.Variables {
		if variable != "" {
			if err := tc.symbolTable.DefineVariable(variable, forLoop.Pos, SymbolVariable); err != nil {
				tc.addError(err)
			}
			// Register in loopVariables map so getExpressionType can resolve the type
			switch loopVarType {
			case TypeString:
				tc.loopVariables[variable] = "string"
			case TypeInteger:
				tc.loopVariables[variable] = "integer"
			}
		}
	}

	// Check the range expression type
	rangeType := tc.checkExpression(forLoop.Range)
	if len(forLoop.Variables) > 0 {
		if rangeType.DataType != TypeInteger && rangeType.DataType != TypeUnknown && rangeType.DataType != TypeString {
			tc.addError(errors.New("for loop range must be an integer or string tuple"))
		}
	}

	// Check the condition expression type
	conditionType := tc.checkExpression(forLoop.Condition)
	if conditionType.DataType != TypeBoolean && conditionType.DataType != TypeUnknown {
		tc.addError(errors.New("for loop condition must be boolean"))
	}

	// Clean up loop variables
	for _, variable := range forLoop.Variables {
		delete(tc.loopVariables, variable)
	}

	tc.symbolTable.ExitScope()

	// For loop expressions always return boolean (true/false)
	return &TypeInfo{DataType: TypeBoolean}
}
