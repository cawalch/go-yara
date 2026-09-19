package semantic

import (
	"errors"
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
	case *ast.PercentExpression:
		if tc.checkExpression(e.Value).DataType != TypeInteger {
			tc.addError(errors.New("percentage must be an integer"))
		}
		return &TypeInfo{DataType: TypeInteger}

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

func (tc *TypeChecker) checkBinaryOp(expr *ast.BinaryOp) *TypeInfo {
	left := tc.checkExpression(expr.Left)
	right := tc.checkExpression(expr.Right)
	result, err := InferTypeFromBinaryOp(left, expr.Op, right)
	return tc.operatorResult(result, err, expr.Position())
}

func (tc *TypeChecker) checkUnaryOp(expr *ast.UnaryOp) *TypeInfo {
	operand := tc.checkExpression(expr.Right)
	result, err := InferTypeFromUnaryOp(expr.Op, operand)
	return tc.operatorResult(result, err, expr.Position())
}

func (tc *TypeChecker) operatorResult(result *TypeInfo, err error, pos token.Position) *TypeInfo {
	if err != nil {
		tc.addError(&Error{Message: err.Error(), Position: pos})
		return &TypeInfo{DataType: TypeUnknown}
	}
	return result
}

// getTypeFromSymbol returns type information for a symbol
func (tc *TypeChecker) getTypeFromSymbol(symbol *Symbol) *TypeInfo {
	switch symbol.Type {
	case SymbolRule:
		return &TypeInfo{DataType: TypeBoolean}
	case SymbolString:
		return &TypeInfo{DataType: TypeBoolean}
	case SymbolVariable:
		// Variables without explicit type metadata default to int64.
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

// checkFunctionCall checks the type of function call expressions
func (tc *TypeChecker) checkFunctionCall(funcCall *ast.FunctionCall) *TypeInfo {
	// Check argument types
	for _, arg := range funcCall.Args {
		tc.checkExpression(arg)
	}

	// YARA has several built-in functions with known return types
	function := strings.ToLower(funcCall.Function)
	switch function {
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
		returnType, err := GetIntegerTypeFromFunction(function)
		if err != nil {
			// This should not happen if the function name is valid
			return &TypeInfo{DataType: TypeUnknown}
		}
		return &TypeInfo{DataType: TypeInteger, IntegerType: returnType}
	default:
		// Module signatures are owned by Validator; this checker has no registry.
		if _, moduleCall := moduleNameFromDottedName(funcCall.Function); !moduleCall {
			tc.addError(&Error{Message: "unknown function: " + funcCall.Function, Position: funcCall.Pos})
		}
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
	_ = tc.checkExpression(ofExpr.Strings) // Validate the string-set expression; its type is not used.

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
