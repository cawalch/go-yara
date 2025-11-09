// Package semantic implements semantic analysis and validation for YARA rules.
package semantic

import (
	"errors"
	"fmt"
	"math"

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
)

// IntegerType represents different integer types and their properties
type IntegerType struct {
	Size      int  // Size in bytes (1, 2, 4, 8)
	Signed    bool // true for signed, false for unsigned
	BigEndian bool // true for big-endian, false for little-endian
}

// TypeInfo contains complete type information for expressions
type TypeInfo struct {
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

// integerTypeMap maps function names to their corresponding integer types
var integerTypeMap = map[string]*IntegerType{
	"uint8": Uint8Type, "u8": Uint8Type,
	"uint16": Uint16Type, "u16": Uint16Type,
	"uint32": Uint32Type, "u32": Uint32Type,
	"uint64": Uint64Type, "u64": Uint64Type,
	"int8": Int8Type, "i8": Int8Type,
	"int16": Int16Type, "i16": Int16Type,
	"int32": Int32Type, "i32": Int32Type,
	"int64": Int64Type, "i64": Int64Type,
	"uint8be": Uint8BEType, "u8be": Uint8BEType,
	"uint16be": Uint16BEType, "u16be": Uint16BEType,
	"uint32be": Uint32BEType, "u32be": Uint32BEType,
	"uint64be": Uint64BEType, "u64be": Uint64BEType,
	"int8be": Int8BEType, "i8be": Int8BEType,
	"int16be": Int16BEType, "i16be": Int16BEType,
	"int32be": Int32BEType, "i32be": Int32BEType,
	"int64be": Int64BEType, "i64be": Int64BEType,
}

// GetIntegerTypeFromFunction returns the appropriate integer type for a data type function
func GetIntegerTypeFromFunction(funcName string) (*IntegerType, error) {
	if intType, exists := integerTypeMap[funcName]; exists {
		return intType, nil
	}
	return nil, fmt.Errorf("unknown integer type function: %s", funcName)
}

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
	// Same types can always be compared
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

// CanCastTo returns true if this type can be cast to the target type
func (ti *TypeInfo) CanCastTo(target *TypeInfo) bool {
	// Can always cast to same type
	if ti.DataType == target.DataType {
		return true
	}

	// Can cast between numeric types
	if ti.IsNumeric() && target.IsNumeric() {
		return true
	}

	// Can cast integers to boolean
	if ti.IsInteger() && target.IsBoolean() {
		return true
	}

	// Can cast strings to boolean
	if ti.IsString() && target.IsBoolean() {
		return true
	}

	return false
}

// GetIntegerRange returns the valid range for an integer type
func (it *IntegerType) GetIntegerRange() (minVal, maxVal int64) {
	if it.Signed {
		switch it.Size {
		case 1:
			return math.MinInt8, math.MaxInt8
		case 2:
			return math.MinInt16, math.MaxInt16
		case 4:
			return math.MinInt32, math.MaxInt32
		case 8:
			return math.MinInt64, math.MaxInt64
		}
	} else {
		switch it.Size {
		case 1:
			return 0, int64(math.MaxUint8)
		case 2:
			return 0, int64(math.MaxUint16)
		case 4:
			return 0, int64(math.MaxUint32)
		case 8:
			// MaxUint64 doesn't fit in int64, so we return MaxInt64 as a practical limit
			return 0, math.MaxInt64
		}
	}
	return 0, 0
}

// InferTypeFromLiteral infers type information from a literal token
func InferTypeFromLiteral(tokenType token.TokenType, _ any) *TypeInfo {
	switch {
	case isBooleanLiteral(tokenType):
		return &TypeInfo{DataType: TypeBoolean}
	case isIntegerLiteral(tokenType):
		return inferIntegerType(tokenType)
	case isStringLiteral(tokenType):
		return inferStringType(tokenType)
	case tokenType == token.FLOAT_LIT:
		return &TypeInfo{DataType: TypeFloat}
	default:
		return &TypeInfo{DataType: TypeUnknown}
	}
}

// isBooleanLiteral checks if token is a boolean literal
func isBooleanLiteral(tokenType token.TokenType) bool {
	return tokenType == token.TRUE || tokenType == token.FALSE
}

// isIntegerLiteral checks if token is an integer literal
func isIntegerLiteral(tokenType token.TokenType) bool {
	return tokenType == token.INTEGER_LIT ||
		tokenType == token.HEX_INTEGER_LIT ||
		tokenType == token.OCTAL_INTEGER_LIT ||
		tokenType == token.SIZE_LIT
}

// isStringLiteral checks if token is a string literal
func isStringLiteral(tokenType token.TokenType) bool {
	return tokenType == token.STRING_LIT ||
		tokenType == token.HEX_STRING_LIT ||
		tokenType == token.REGEX_LIT
}

// inferIntegerType infers type for integer literals
func inferIntegerType(tokenType token.TokenType) *TypeInfo {
	switch tokenType {
	case token.INTEGER_LIT, token.OCTAL_INTEGER_LIT:
		return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}
	case token.HEX_INTEGER_LIT, token.SIZE_LIT:
		return &TypeInfo{DataType: TypeInteger, IntegerType: Uint64Type}
	default:
		return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}
	}
}

// inferStringType infers type for string literals
func inferStringType(tokenType token.TokenType) *TypeInfo {
	stringType := &StringType{
		IsWide:  false,
		IsASCII: false,
		IsHex:   false,
		IsRegex: false,
	}

	switch tokenType {
	case token.STRING_LIT:
		stringType.IsASCII = true
	case token.HEX_STRING_LIT:
		stringType.IsHex = true
	case token.REGEX_LIT:
		stringType.IsRegex = true
	}

	dataType := TypeString
	if tokenType == token.REGEX_LIT {
		dataType = TypeRegexp
	}

	return &TypeInfo{
		DataType:   dataType,
		StringType: stringType,
	}
}

// InferTypeFromBinaryOp infers the result type of a binary operation
func InferTypeFromBinaryOp(left *TypeInfo, op token.TokenType, right *TypeInfo) (*TypeInfo, error) {
	if handler, exists := binaryOpHandlers[op]; exists {
		return handler(left, right)
	}
	return nil, fmt.Errorf("unknown binary operator: %s", op)
}

// binaryOpHandlers maps binary operators to their type inference handlers
var binaryOpHandlers = map[token.TokenType]func(*TypeInfo, *TypeInfo) (*TypeInfo, error){
	token.PLUS:        func(l, r *TypeInfo) (*TypeInfo, error) { return inferArithmeticType(l, token.PLUS, r) },
	token.MINUS:       func(l, r *TypeInfo) (*TypeInfo, error) { return inferArithmeticType(l, token.MINUS, r) },
	token.MULTIPLY:    func(l, r *TypeInfo) (*TypeInfo, error) { return inferArithmeticType(l, token.MULTIPLY, r) },
	token.DIVIDE:      func(l, r *TypeInfo) (*TypeInfo, error) { return inferArithmeticType(l, token.DIVIDE, r) },
	token.MODULO:      func(l, r *TypeInfo) (*TypeInfo, error) { return inferArithmeticType(l, token.MODULO, r) },
	token.INT_DIVIDE:  func(l, r *TypeInfo) (*TypeInfo, error) { return inferArithmeticType(l, token.INT_DIVIDE, r) },
	token.BITWISE_AND: func(l, r *TypeInfo) (*TypeInfo, error) { return inferBitwiseType(l, token.BITWISE_AND, r) },
	token.BITWISE_OR:  func(l, r *TypeInfo) (*TypeInfo, error) { return inferBitwiseType(l, token.BITWISE_OR, r) },
	token.BITWISE_XOR: func(l, r *TypeInfo) (*TypeInfo, error) { return inferBitwiseType(l, token.BITWISE_XOR, r) },
	token.LEFT_SHIFT:  func(l, r *TypeInfo) (*TypeInfo, error) { return inferBitwiseType(l, token.LEFT_SHIFT, r) },
	token.RIGHT_SHIFT: func(l, r *TypeInfo) (*TypeInfo, error) { return inferBitwiseType(l, token.RIGHT_SHIFT, r) },
	token.EQ:          func(l, r *TypeInfo) (*TypeInfo, error) { return inferComparisonType(l, r) },
	token.NEQ:         func(l, r *TypeInfo) (*TypeInfo, error) { return inferComparisonType(l, r) },
	token.LT:          func(l, r *TypeInfo) (*TypeInfo, error) { return inferComparisonType(l, r) },
	token.LE:          func(l, r *TypeInfo) (*TypeInfo, error) { return inferComparisonType(l, r) },
	token.GT:          func(l, r *TypeInfo) (*TypeInfo, error) { return inferComparisonType(l, r) },
	token.GE:          func(l, r *TypeInfo) (*TypeInfo, error) { return inferComparisonType(l, r) },
	token.AND:         func(l, r *TypeInfo) (*TypeInfo, error) { return inferLogicalType(l, r) },
	token.OR:          func(l, r *TypeInfo) (*TypeInfo, error) { return inferLogicalType(l, r) },
	token.CONTAINS:    func(l, r *TypeInfo) (*TypeInfo, error) { return inferStringOperationType(l, r) },
	token.ICONTAINS:   func(l, r *TypeInfo) (*TypeInfo, error) { return inferStringOperationType(l, r) },
	token.STARTSWITH:  func(l, r *TypeInfo) (*TypeInfo, error) { return inferStringOperationType(l, r) },
	token.ENDSWITH:    func(l, r *TypeInfo) (*TypeInfo, error) { return inferStringOperationType(l, r) },
	token.ISTARTSWITH: func(l, r *TypeInfo) (*TypeInfo, error) { return inferStringOperationType(l, r) },
	token.IENDSWITH:   func(l, r *TypeInfo) (*TypeInfo, error) { return inferStringOperationType(l, r) },
	token.IEQUALS:     func(l, r *TypeInfo) (*TypeInfo, error) { return inferStringOperationType(l, r) },
	token.MATCHES:     func(l, r *TypeInfo) (*TypeInfo, error) { return inferStringOperationType(l, r) },
	token.AT:          inferAtOperatorType,
	token.IN:          inferInOperatorType,
	token.DOT:         inferDotOperatorType,
	token.OF:          func(_, _ *TypeInfo) (*TypeInfo, error) { return &TypeInfo{DataType: TypeBoolean}, nil },
	token.COLON:       func(_, _ *TypeInfo) (*TypeInfo, error) { return &TypeInfo{DataType: TypeBoolean}, nil },
	token.LPAREN: func(_, _ *TypeInfo) (*TypeInfo, error) {
		return &TypeInfo{DataType: TypeInteger, IntegerType: Uint64Type}, nil
	},
}

// inferArithmeticType infers the result type of arithmetic operations
func inferArithmeticType(left *TypeInfo, op token.TokenType, right *TypeInfo) (*TypeInfo, error) {
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
func inferBitwiseType(left *TypeInfo, op token.TokenType, right *TypeInfo) (*TypeInfo, error) {
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
	// In YARA, logical operators can work with any type (integers, strings, etc.)
	// They are treated as truthy/falsy values
	// Both operands must be comparable types, but don't have to be boolean
	if left.DataType == TypeUnknown || right.DataType == TypeUnknown {
		return nil, errors.New("logical operators require known operand types")
	}
	return &TypeInfo{DataType: TypeBoolean}, nil
}

// inferStringOperationType infers the result type of string operations
func inferStringOperationType(left, right *TypeInfo) (*TypeInfo, error) {
	// In YARA, string operations work with:
	// - Left: string identifier (boolean type when used in conditions)
	// - Right: string literal or regex pattern
	if (!left.IsString() && left.DataType != TypeBoolean) || !right.IsString() {
		return nil, errors.New("string operations require string operands")
	}
	return &TypeInfo{DataType: TypeBoolean}, nil
}

// inferAtOperatorType infers the result type of AT operator
func inferAtOperatorType(left, right *TypeInfo) (*TypeInfo, error) {
	// AT operator: $string at offset
	// Left should be string identifier, right should be integer offset
	if left.DataType != TypeBoolean {
		return nil, errors.New("AT operator requires string identifier as left operand")
	}
	if right.DataType != TypeInteger {
		return nil, errors.New("AT operator requires integer offset as right operand")
	}
	return &TypeInfo{DataType: TypeBoolean}, nil
}

// inferInOperatorType infers the result type of IN operator
func inferInOperatorType(left, right *TypeInfo) (*TypeInfo, error) {
	// IN operator: $string in (start..end)
	// Left should be string identifier, right should be range
	if left.DataType != TypeBoolean {
		return nil, errors.New("IN operator requires string identifier as left operand")
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
func InferTypeFromUnaryOp(op token.TokenType, operand *TypeInfo) (*TypeInfo, error) {
	if handler, exists := unaryOpHandlers[op]; exists {
		return handler(operand)
	}
	return nil, fmt.Errorf("unknown unary operator: %s", op)
}

// unaryOpHandlers maps unary operators to their type inference handlers
var unaryOpHandlers = map[token.TokenType]func(*TypeInfo) (*TypeInfo, error){
	token.NOT:         handleLogicalNotOp,
	token.BITWISE_NOT: handleBitwiseNotOp,
	token.MINUS:       handleUnaryMinusOp,
	token.DEFINED:     func(*TypeInfo) (*TypeInfo, error) { return &TypeInfo{DataType: TypeBoolean}, nil },
	token.HASH: func(*TypeInfo) (*TypeInfo, error) {
		return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}, nil
	},
	token.AT: func(*TypeInfo) (*TypeInfo, error) {
		return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}, nil
	},
}

// handleLogicalNotOp handles logical NOT operator
func handleLogicalNotOp(operand *TypeInfo) (*TypeInfo, error) {
	if operand.DataType != TypeBoolean {
		return nil, errors.New("logical not requires boolean operand")
	}
	return &TypeInfo{DataType: TypeBoolean}, nil
}

// handleBitwiseNotOp handles bitwise NOT operator
func handleBitwiseNotOp(operand *TypeInfo) (*TypeInfo, error) {
	if !operand.IsInteger() {
		return nil, errors.New("bitwise not requires integer operand")
	}
	return &TypeInfo{DataType: TypeInteger, IntegerType: operand.IntegerType}, nil
}

// handleUnaryMinusOp handles unary minus operator
func handleUnaryMinusOp(operand *TypeInfo) (*TypeInfo, error) {
	if !operand.IsNumeric() {
		return nil, errors.New("unary minus requires numeric operand")
	}
	return operand, nil
}
