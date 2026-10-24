// Package semantic implements semantic analysis and validation for YARA rules.
package semantic

import (
	"errors"
	"fmt"

	"github.com/cawalch/go-yara/token"
)

// DataType represents the data type of an expression or variable
type DataType int

const (
	// TypeUnknown represents an unknown data type
	TypeUnknown DataType = iota
	// TypeInteger represents an integer type
	TypeInteger
	// TypeFloat represents a floating-point type
	TypeFloat
	// TypeString represents a string type
	TypeString
	// TypeBoolean represents a boolean type
	TypeBoolean
	// TypeRegexp represents a regular expression type
	TypeRegexp
	// TypeStruct, TypeArray and TypeDictionary represent schema-backed module values.
	TypeStruct
	TypeArray
	TypeDictionary
)

// IntegerType represents different integer types and their properties
type IntegerType struct {
	Size      int  // Size in bytes (1, 2, 4, 8)
	Signed    bool // true for signed, false for unsigned
	BigEndian bool // true for big-endian, false for little-endian
}

// TypeInfo contains complete type information for expressions
type TypeInfo struct {
	Fields      map[string]*TypeInfo
	Element     *TypeInfo
	DataType    DataType
	IntegerType *IntegerType // Only valid when DataType is TypeInteger
	StringType  *StringType  // Only valid when DataType is TypeString
}

// StringType represents string type information
type StringType struct {
	IsWide  bool // UTF-16 string
	IsASCII bool // ASCII string
	IsHex   bool // Hexadecimal string
	IsRegex bool // Regular expression
}

// Common integer types based on YARA data type functions
var (
	// Uint8Type represents unsigned 8-bit integer type
	Uint8Type  = &IntegerType{Size: 1, Signed: false, BigEndian: false}
	Uint16Type = &IntegerType{Size: 2, Signed: false, BigEndian: false}
	Uint32Type = &IntegerType{Size: 4, Signed: false, BigEndian: false}
	Uint64Type = &IntegerType{Size: 8, Signed: false, BigEndian: false}

	// Int8Type represents signed 8-bit integer type
	Int8Type  = &IntegerType{Size: 1, Signed: true, BigEndian: false}
	Int16Type = &IntegerType{Size: 2, Signed: true, BigEndian: false}
	Int32Type = &IntegerType{Size: 4, Signed: true, BigEndian: false}
	Int64Type = &IntegerType{Size: 8, Signed: true, BigEndian: false}

	// Uint8BEType represents unsigned 8-bit big-endian integer type
	Uint8BEType  = &IntegerType{Size: 1, Signed: false, BigEndian: true}
	Uint16BEType = &IntegerType{Size: 2, Signed: false, BigEndian: true}
	Uint32BEType = &IntegerType{Size: 4, Signed: false, BigEndian: true}
	Uint64BEType = &IntegerType{Size: 8, Signed: false, BigEndian: true}

	Int8BEType  = &IntegerType{Size: 1, Signed: true, BigEndian: true}
	Int16BEType = &IntegerType{Size: 2, Signed: true, BigEndian: true}
	Int32BEType = &IntegerType{Size: 4, Signed: true, BigEndian: true}
	Int64BEType = &IntegerType{Size: 8, Signed: true, BigEndian: true}
)

// String returns a string representation of the type
func (it *IntegerType) String() string {
	var prefix string
	var endian string

	if it.Signed {
		prefix = "int"
	} else {
		prefix = "uint"
	}

	if it.BigEndian {
		endian = "be"
	} else {
		endian = ""
	}

	return fmt.Sprintf("%s%d%s", prefix, it.Size*8, endian)
}

// String returns a string representation of the type info
func (ti *TypeInfo) String() string {
	switch ti.DataType {
	case TypeStruct:
		return "structure"
	case TypeArray:
		return "array"
	case TypeDictionary:
		return "dictionary"
	case TypeInteger:
		return ti.formatIntegerType()
	case TypeFloat:
		return "float"
	case TypeString:
		return ti.formatStringType()
	case TypeBoolean:
		return "boolean"
	case TypeRegexp:
		return "regexp"
	default:
		return "unknown"
	}
}

// formatIntegerType formats integer type with its specific representation
func (ti *TypeInfo) formatIntegerType() string {
	if ti.IntegerType != nil {
		return ti.IntegerType.String()
	}
	return "integer"
}

// formatStringType formats string type with its modifiers
func (ti *TypeInfo) formatStringType() string {
	if ti.StringType == nil {
		return "string"
	}

	switch {
	case ti.StringType.IsRegex:
		return "regexp"
	case ti.StringType.IsWide:
		return "wide_string"
	case ti.StringType.IsHex:
		return "hex_string"
	default:
		return "string"
	}
}

// IsNumeric returns true if the type is numeric (integer or float)
func (ti *TypeInfo) IsNumeric() bool {
	return ti.DataType == TypeInteger || ti.DataType == TypeFloat
}

// IsInteger returns true if the type is an integer type
func (ti *TypeInfo) IsInteger() bool {
	return ti.DataType == TypeInteger
}

// IsString returns true if the type is a string type
func (ti *TypeInfo) IsString() bool {
	return ti.DataType == TypeString || ti.DataType == TypeRegexp
}

// IsBoolean returns true if the type is boolean
func (ti *TypeInfo) IsBoolean() bool {
	return ti.DataType == TypeBoolean
}

// CanCompare returns true if two types can be compared
func (ti *TypeInfo) CanCompare(other *TypeInfo) bool {
	if ti.DataType == TypeUnknown || other.DataType == TypeUnknown {
		return true
	}

	if ti.isStructured() || other.isStructured() {
		return false
	}
	// Same scalar types can always be compared
	if ti.DataType == other.DataType {
		return true
	}

	// Numeric types can be compared with each other
	if ti.IsNumeric() && other.IsNumeric() {
		return true
	}

	// Strings and regex can be compared
	if ti.IsString() && other.IsString() {
		return true
	}

	return false
}

// CanPerformArithmetic returns true if arithmetic operations can be performed
func (ti *TypeInfo) CanPerformArithmetic(other *TypeInfo) bool {
	// Both must be numeric
	return ti.IsNumeric() && other.IsNumeric()
}

// CanPerformBitwise returns true if bitwise operations can be performed
func (ti *TypeInfo) CanPerformBitwise(other *TypeInfo) bool {
	// Both must be integers
	return ti.IsInteger() && other.IsInteger()
}

// InferTypeFromLiteral infers type information from a literal token
func InferTypeFromLiteral(tokenType token.Type, _ any) *TypeInfo {
	switch {
	case isBooleanLiteral(tokenType):
		return &TypeInfo{DataType: TypeBoolean}
	case isIntegerLiteral(tokenType):
		return inferIntegerType(tokenType)
	case isStringLiteral(tokenType):
		return inferStringType(tokenType)
	case tokenType == token.FloatLit:
		return &TypeInfo{DataType: TypeFloat}
	case tokenType == token.FILESIZE, tokenType == token.ENTRYPOINT:
		return &TypeInfo{DataType: TypeInteger, IntegerType: Uint64Type}
	case tokenType == token.DEFINED:
		return &TypeInfo{DataType: TypeBoolean}
	default:
		return &TypeInfo{DataType: TypeUnknown}
	}
}

// isBooleanLiteral checks if token is a boolean literal
func isBooleanLiteral(tokenType token.Type) bool {
	return tokenType == token.TRUE || tokenType == token.FALSE
}

// isIntegerLiteral checks if token is an integer literal
func isIntegerLiteral(tokenType token.Type) bool {
	return tokenType == token.IntegerLit ||
		tokenType == token.HexIntegerLit ||
		tokenType == token.OctalIntegerLit ||
		tokenType == token.SizeLit
}

// isStringLiteral checks if token is a string literal
func isStringLiteral(tokenType token.Type) bool {
	return tokenType == token.StringLit ||
		tokenType == token.HexStringLit ||
		tokenType == token.RegexLit
}

// inferIntegerType infers type for integer literals
func inferIntegerType(tokenType token.Type) *TypeInfo {
	switch tokenType {
	case token.IntegerLit, token.OctalIntegerLit:
		return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}
	case token.HexIntegerLit, token.SizeLit:
		return &TypeInfo{DataType: TypeInteger, IntegerType: Uint64Type}
	default:
		return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}
	}
}

// inferStringType infers type for string literals
func inferStringType(tokenType token.Type) *TypeInfo {
	stringType := &StringType{
		IsWide:  false,
		IsASCII: false,
		IsHex:   false,
		IsRegex: false,
	}

	switch tokenType {
	case token.StringLit:
		stringType.IsASCII = true
	case token.HexStringLit:
		stringType.IsHex = true
	case token.RegexLit:
		stringType.IsRegex = true
	}

	dataType := TypeString
	if tokenType == token.RegexLit {
		dataType = TypeRegexp
	}

	return &TypeInfo{
		DataType:   dataType,
		StringType: stringType,
	}
}

// InferTypeFromBinaryOp infers the result type of a binary operation
func InferTypeFromBinaryOp(left *TypeInfo, op token.Type, right *TypeInfo) (*TypeInfo, error) {
	if handler, exists := binaryOpHandlers[op]; exists {
		return handler(left, right)
	}
	return nil, fmt.Errorf("unknown binary operator: %s", op)
}

// binaryOpHandlers maps binary operators to their type inference handlers
var binaryOpHandlers = map[token.Type]func(*TypeInfo, *TypeInfo) (*TypeInfo, error){
	token.PLUS:        func(l, r *TypeInfo) (*TypeInfo, error) { return inferArithmeticType(l, token.PLUS, r) },
	token.MINUS:       func(l, r *TypeInfo) (*TypeInfo, error) { return inferArithmeticType(l, token.MINUS, r) },
	token.MULTIPLY:    func(l, r *TypeInfo) (*TypeInfo, error) { return inferArithmeticType(l, token.MULTIPLY, r) },
	token.DIVIDE:      func(l, r *TypeInfo) (*TypeInfo, error) { return inferArithmeticType(l, token.DIVIDE, r) },
	token.MODULO:      func(l, r *TypeInfo) (*TypeInfo, error) { return inferArithmeticType(l, token.MODULO, r) },
	token.IntDivide:   func(l, r *TypeInfo) (*TypeInfo, error) { return inferArithmeticType(l, token.IntDivide, r) },
	token.BitwiseAnd:  func(l, r *TypeInfo) (*TypeInfo, error) { return inferBitwiseType(l, token.BitwiseAnd, r) },
	token.BitwiseOr:   func(l, r *TypeInfo) (*TypeInfo, error) { return inferBitwiseType(l, token.BitwiseOr, r) },
	token.BitwiseXor:  func(l, r *TypeInfo) (*TypeInfo, error) { return inferBitwiseType(l, token.BitwiseXor, r) },
	token.LeftShift:   func(l, r *TypeInfo) (*TypeInfo, error) { return inferBitwiseType(l, token.LeftShift, r) },
	token.RightShift:  func(l, r *TypeInfo) (*TypeInfo, error) { return inferBitwiseType(l, token.RightShift, r) },
	token.EQ:          inferComparisonType,
	token.NEQ:         inferComparisonType,
	token.LT:          inferComparisonType,
	token.LE:          inferComparisonType,
	token.GT:          inferComparisonType,
	token.GE:          inferComparisonType,
	token.AND:         inferLogicalType,
	token.OR:          inferLogicalType,
	token.CONTAINS:    inferStringOperationType,
	token.ICONTAINS:   inferStringOperationType,
	token.STARTSWITH:  inferStringOperationType,
	token.ENDSWITH:    inferStringOperationType,
	token.ISTARTSWITH: inferStringOperationType,
	token.IENDSWITH:   inferStringOperationType,
	token.IEQUALS:     inferStringOperationType,
	token.MATCHES:     inferStringOperationType,
	token.AT:          inferAtOperatorType,
	token.IN:          inferInOperatorType,
	token.DOT:         inferDotOperatorType,
	token.OF:          func(_, _ *TypeInfo) (*TypeInfo, error) { return &TypeInfo{DataType: TypeBoolean}, nil },
	token.COLON:       func(_, _ *TypeInfo) (*TypeInfo, error) { return &TypeInfo{DataType: TypeBoolean}, nil },
	token.LPAREN: func(_, _ *TypeInfo) (*TypeInfo, error) {
		return &TypeInfo{DataType: TypeInteger, IntegerType: Uint64Type}, nil
	},
	// COMMA is used for comma-separated lists in quantifier expressions
	// The result type is the same as the left operand type
	token.COMMA: func(l, _ *TypeInfo) (*TypeInfo, error) { return l, nil },
}

// inferArithmeticType infers the result type of arithmetic operations
func inferArithmeticType(left *TypeInfo, op token.Type, right *TypeInfo) (*TypeInfo, error) {
	if left.DataType == TypeUnknown || right.DataType == TypeUnknown {
		return &TypeInfo{DataType: TypeUnknown}, nil
	}
	if !left.CanPerformArithmetic(right) {
		return nil, fmt.Errorf("cannot perform arithmetic operation %s between %s and %s",
			op, left.String(), right.String())
	}
	// Result is float if either operand is float, otherwise integer
	if left.DataType == TypeFloat || right.DataType == TypeFloat {
		return &TypeInfo{DataType: TypeFloat}, nil
	}
	return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}, nil
}

// inferBitwiseType infers the result type of bitwise operations
func inferBitwiseType(left *TypeInfo, op token.Type, right *TypeInfo) (*TypeInfo, error) {
	if left.DataType == TypeUnknown || right.DataType == TypeUnknown {
		return &TypeInfo{DataType: TypeUnknown}, nil
	}
	if !left.CanPerformBitwise(right) {
		return nil, fmt.Errorf("cannot perform bitwise operation %s between %s and %s",
			op, left.String(), right.String())
	}
	return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}, nil
}

// inferComparisonType infers the result type of comparison operations
func inferComparisonType(left, right *TypeInfo) (*TypeInfo, error) {
	if !left.CanCompare(right) {
		return nil, fmt.Errorf("cannot compare %s and %s", left.String(), right.String())
	}
	return &TypeInfo{DataType: TypeBoolean}, nil
}

// inferLogicalType infers the result type of logical operations
func inferLogicalType(left, right *TypeInfo) (*TypeInfo, error) {
	if left.isStructured() || right.isStructured() {
		return nil, errors.New("logical operators require scalar operands")
	}
	// In YARA, logical operators can work with any type (integers, strings, etc.)
	// They are treated as truthy/falsy values
	// Both operands must be comparable types, but don't have to be boolean
	if left.DataType == TypeUnknown || right.DataType == TypeUnknown {
		return &TypeInfo{DataType: TypeBoolean}, nil
	}
	return &TypeInfo{DataType: TypeBoolean}, nil
}

// inferStringOperationType infers the result type of string operations
func inferStringOperationType(left, right *TypeInfo) (*TypeInfo, error) {
	// In YARA, string operations work with:
	// - Left: string identifier (boolean type when used in conditions)
	// - Right: string literal or regex pattern
	if left.DataType == TypeUnknown || right.DataType == TypeUnknown {
		return &TypeInfo{DataType: TypeBoolean}, nil
	}
	if (!left.IsString() && left.DataType != TypeBoolean) || !right.IsString() {
		return nil, errors.New("string operations require string operands")
	}
	return &TypeInfo{DataType: TypeBoolean}, nil
}

// inferAtOperatorType infers the result type of AT operator
func inferAtOperatorType(left, right *TypeInfo) (*TypeInfo, error) {
	// AT operator: $string at offset
	// Left should be string identifier (boolean), right should be integer offset
	if left.DataType != TypeBoolean {
		return nil, errors.New("AT operator requires string identifier as left operand")
	}
	if right.DataType != TypeInteger {
		return nil, errors.New("AT operator requires integer offset as right operand")
	}
	// The result is integer (the offset where the string appears)
	return &TypeInfo{DataType: TypeInteger}, nil
}

// inferInOperatorType infers the result type of IN operator
func inferInOperatorType(left, right *TypeInfo) (*TypeInfo, error) {
	// IN operator has two forms:
	// 1. $string in (start..end) — left is string identifier (boolean), right is integer range
	// 2. #string in (min..max) — left is integer (count), right is integer range
	if left.DataType != TypeBoolean && left.DataType != TypeInteger {
		return nil, errors.New("IN operator requires string identifier or count as left operand")
	}
	if right.DataType != TypeInteger {
		return nil, errors.New("IN operator requires integer range as right operand")
	}
	return &TypeInfo{DataType: TypeBoolean}, nil
}

// inferDotOperatorType infers the result type of DOT operator
func inferDotOperatorType(left, right *TypeInfo) (*TypeInfo, error) {
	// DOT operator (..) represents range expression: start..end
	// Both operands should be integers, result is integer (represents the range)
	if left.DataType != TypeInteger {
		return nil, errors.New("range expression requires integer start value")
	}
	if right.DataType != TypeInteger {
		return nil, errors.New("range expression requires integer end value")
	}
	return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}, nil
}

// InferTypeFromUnaryOp infers the result type of a unary operation
func InferTypeFromUnaryOp(op token.Type, operand *TypeInfo) (*TypeInfo, error) {
	if handler, exists := unaryOpHandlers[op]; exists {
		return handler(operand)
	}
	return nil, fmt.Errorf("unknown unary operator: %s", op)
}

// unaryOpHandlers maps unary operators to their type inference handlers
var unaryOpHandlers = map[token.Type]func(*TypeInfo) (*TypeInfo, error){
	token.NOT:        handleLogicalNotOp,
	token.BitwiseNot: handleBitwiseNotOp,
	token.MINUS:      handleUnaryMinusOp,
	token.DEFINED:    func(*TypeInfo) (*TypeInfo, error) { return &TypeInfo{DataType: TypeBoolean}, nil },
	token.HASH: func(*TypeInfo) (*TypeInfo, error) {
		return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}, nil
	},
	token.AT: func(*TypeInfo) (*TypeInfo, error) {
		return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}, nil
	},
	token.StringLength: func(*TypeInfo) (*TypeInfo, error) {
		return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}, nil
	},
}

// handleLogicalNotOp handles logical NOT operator
func handleLogicalNotOp(operand *TypeInfo) (*TypeInfo, error) {
	if operand.DataType == TypeUnknown {
		return &TypeInfo{DataType: TypeBoolean}, nil
	}
	if operand.DataType != TypeBoolean && operand.DataType != TypeInteger {
		return nil, errors.New("logical not requires boolean or integer operand")
	}
	return &TypeInfo{DataType: TypeBoolean}, nil
}

// handleBitwiseNotOp handles bitwise NOT operator
func handleBitwiseNotOp(operand *TypeInfo) (*TypeInfo, error) {
	if operand.DataType == TypeUnknown {
		return &TypeInfo{DataType: TypeUnknown}, nil
	}
	if !operand.IsInteger() {
		return nil, errors.New("bitwise not requires integer operand")
	}
	return &TypeInfo{DataType: TypeInteger, IntegerType: operand.IntegerType}, nil
}

// handleUnaryMinusOp handles unary minus operator
func handleUnaryMinusOp(operand *TypeInfo) (*TypeInfo, error) {
	if operand.DataType == TypeUnknown {
		return &TypeInfo{DataType: TypeUnknown}, nil
	}
	if !operand.IsNumeric() {
		return nil, errors.New("unary minus requires numeric operand")
	}
	return operand, nil
}

func (ti *TypeInfo) isStructured() bool {
	return ti.DataType == TypeStruct || ti.DataType == TypeArray || ti.DataType == TypeDictionary
}
