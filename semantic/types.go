// Package semantic implements semantic analysis and validation for YARA rules.
package semantic

import (
	"fmt"
	"math"

	"github.com/cawalch/go-yara/token"
)

// DataType represents the data type of an expression or variable
type DataType int

const (
	TypeUnknown DataType = iota
	TypeInteger
	TypeFloat
	TypeString
	TypeBoolean
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
	IsWide  bool   // UTF-16 string
	IsASCII bool   // ASCII string
	IsHex   bool   // Hexadecimal string
	IsRegex bool   // Regular expression
}

// Common integer types based on YARA data type functions
var (
	// Unsigned integer types
	Uint8Type = &IntegerType{Size: 1, Signed: false, BigEndian: false}
	Uint16Type = &IntegerType{Size: 2, Signed: false, BigEndian: false}
	Uint32Type = &IntegerType{Size: 4, Signed: false, BigEndian: false}
	Uint64Type = &IntegerType{Size: 8, Signed: false, BigEndian: false}

	// Signed integer types
	Int8Type = &IntegerType{Size: 1, Signed: true, BigEndian: false}
	Int16Type = &IntegerType{Size: 2, Signed: true, BigEndian: false}
	Int32Type = &IntegerType{Size: 4, Signed: true, BigEndian: false}
	Int64Type = &IntegerType{Size: 8, Signed: true, BigEndian: false}

	// Big-endian variants
	Uint8BEType = &IntegerType{Size: 1, Signed: false, BigEndian: true}
	Uint16BEType = &IntegerType{Size: 2, Signed: false, BigEndian: true}
	Uint32BEType = &IntegerType{Size: 4, Signed: false, BigEndian: true}
	Uint64BEType = &IntegerType{Size: 8, Signed: false, BigEndian: true}

	Int8BEType = &IntegerType{Size: 1, Signed: true, BigEndian: true}
	Int16BEType = &IntegerType{Size: 2, Signed: true, BigEndian: true}
	Int32BEType = &IntegerType{Size: 4, Signed: true, BigEndian: true}
	Int64BEType = &IntegerType{Size: 8, Signed: true, BigEndian: true}
)

// GetIntegerTypeFromFunction returns the appropriate integer type for a data type function
func GetIntegerTypeFromFunction(funcName string) (*IntegerType, error) {
	switch funcName {
	case "uint8", "u8":
		return Uint8Type, nil
	case "uint16", "u16":
		return Uint16Type, nil
	case "uint32", "u32":
		return Uint32Type, nil
	case "uint64", "u64":
		return Uint64Type, nil
	case "int8", "i8":
		return Int8Type, nil
	case "int16", "i16":
		return Int16Type, nil
	case "int32", "i32":
		return Int32Type, nil
	case "int64", "i64":
		return Int64Type, nil
	case "uint8be", "u8be":
		return Uint8BEType, nil
	case "uint16be", "u16be":
		return Uint16BEType, nil
	case "uint32be", "u32be":
		return Uint32BEType, nil
	case "uint64be", "u64be":
		return Uint64BEType, nil
	case "int8be", "i8be":
		return Int8BEType, nil
	case "int16be", "i16be":
		return Int16BEType, nil
	case "int32be", "i32be":
		return Int32BEType, nil
	case "int64be", "i64be":
		return Int64BEType, nil
	default:
		return nil, fmt.Errorf("unknown integer type function: %s", funcName)
	}
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
		if ti.IntegerType != nil {
			return ti.IntegerType.String()
		}
		return "integer"
	case TypeFloat:
		return "float"
	case TypeString:
		if ti.StringType != nil {
			if ti.StringType.IsRegex {
				return "regexp"
			}
			if ti.StringType.IsWide {
				return "wide_string"
			}
			if ti.StringType.IsHex {
				return "hex_string"
			}
			return "string"
		}
		return "string"
	case TypeBoolean:
		return "boolean"
	case TypeRegexp:
		return "regexp"
	default:
		return "unknown"
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
func (it *IntegerType) GetIntegerRange() (int64, int64) {
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
func InferTypeFromLiteral(tokenType token.TokenType, value interface{}) *TypeInfo {
	switch tokenType {
	case token.TRUE, token.FALSE:
		return &TypeInfo{DataType: TypeBoolean}
	case token.INTEGER_LIT:
		return &TypeInfo{
			DataType:    TypeInteger,
			IntegerType: Int64Type, // Default to int64 for literals
		}
	case token.HEX_INTEGER_LIT:
		return &TypeInfo{
			DataType:    TypeInteger,
			IntegerType: Uint64Type, // Default to uint64 for hex literals
		}
	case token.SIZE_LIT:
		return &TypeInfo{
			DataType:    TypeInteger,
			IntegerType: Uint64Type, // Size literals are unsigned
		}
	case token.STRING_LIT:
		return &TypeInfo{
			DataType: TypeString,
			StringType: &StringType{
				IsWide:  false,
				IsASCII: true,
				IsHex:   false,
				IsRegex: false,
			},
		}
	case token.HEX_STRING_LIT:
		return &TypeInfo{
			DataType: TypeString,
			StringType: &StringType{
				IsWide:  false,
				IsASCII: false,
				IsHex:   true,
				IsRegex: false,
			},
		}
	case token.REGEX_LIT:
		return &TypeInfo{
			DataType: TypeRegexp,
			StringType: &StringType{
				IsWide:  false,
				IsASCII: false,
				IsHex:   false,
				IsRegex: true,
			},
		}
	default:
		return &TypeInfo{DataType: TypeUnknown}
	}
}

// InferTypeFromBinaryOp infers the result type of a binary operation
func InferTypeFromBinaryOp(left *TypeInfo, op token.TokenType, right *TypeInfo) (*TypeInfo, error) {
	switch op {
	case token.PLUS, token.MINUS, token.MULTIPLY, token.DIVIDE, token.MODULO:
		if !left.CanPerformArithmetic(right) {
			return nil, fmt.Errorf("cannot perform arithmetic operation %s between %s and %s",
				op, left.String(), right.String())
		}
		// Result is float if either operand is float, otherwise integer
		if left.DataType == TypeFloat || right.DataType == TypeFloat {
			return &TypeInfo{DataType: TypeFloat}, nil
		}
		return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}, nil

	case token.BITWISE_AND, token.BITWISE_OR, token.BITWISE_XOR,
		 token.LEFT_SHIFT, token.RIGHT_SHIFT, token.BITWISE_NOT:
		if !left.CanPerformBitwise(right) {
			return nil, fmt.Errorf("cannot perform bitwise operation %s between %s and %s",
				op, left.String(), right.String())
		}
		return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}, nil

	case token.EQ, token.NEQ, token.LT, token.LE, token.GT, token.GE:
		if !left.CanCompare(right) {
			return nil, fmt.Errorf("cannot compare %s and %s", left.String(), right.String())
		}
		return &TypeInfo{DataType: TypeBoolean}, nil

	case token.AND, token.OR:
		if left.DataType != TypeBoolean || right.DataType != TypeBoolean {
			return nil, fmt.Errorf("logical operators require boolean operands")
		}
		return &TypeInfo{DataType: TypeBoolean}, nil

	case token.CONTAINS, token.ICONTAINS, token.STARTSWITH, token.ENDSWITH,
		 token.ISTARTSWITH, token.IENDSWITH, token.IEQUALS, token.MATCHES:
		if !left.IsString() || !right.IsString() {
			return nil, fmt.Errorf("string operations require string operands")
		}
		return &TypeInfo{DataType: TypeBoolean}, nil

	case token.OF:
		// Quantifier expressions (all/any/none of them) return boolean
		// Left operand is the quantifier (all/any/none), right is the target (them or pattern)
		return &TypeInfo{DataType: TypeBoolean}, nil

	default:
		return nil, fmt.Errorf("unknown binary operator: %s", op)
	}
}

// InferTypeFromUnaryOp infers the result type of a unary operation
func InferTypeFromUnaryOp(op token.TokenType, operand *TypeInfo) (*TypeInfo, error) {
	switch op {
	case token.NOT:
		if operand.DataType != TypeBoolean {
			return nil, fmt.Errorf("logical not requires boolean operand")
		}
		return &TypeInfo{DataType: TypeBoolean}, nil

	case token.BITWISE_NOT:
		if !operand.IsInteger() {
			return nil, fmt.Errorf("bitwise not requires integer operand")
		}
		return &TypeInfo{DataType: TypeInteger, IntegerType: operand.IntegerType}, nil

	case token.MINUS:
		if !operand.IsNumeric() {
			return nil, fmt.Errorf("unary minus requires numeric operand")
		}
		return operand, nil

	case token.DEFINED:
		return &TypeInfo{DataType: TypeBoolean}, nil

	default:
		return nil, fmt.Errorf("unknown unary operator: %s", op)
	}
}