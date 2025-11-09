package semantic

import (
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

func TestCheckBinaryOp(t *testing.T) {
	st := NewSymbolTable()
	st.EnterScope("test")
	checker := NewTypeChecker(st)

	pos := token.Position{Line: 1, Column: 1}

	tests := []struct {
		name    string
		left    ast.Expression
		op      token.TokenType
		right   ast.Expression
		wantErr bool
	}{
		{
			name:    "integer addition",
			left:    &ast.Literal{Type: token.INTEGER_LIT, Value: 1, Pos: pos},
			op:      token.PLUS,
			right:   &ast.Literal{Type: token.INTEGER_LIT, Value: 2, Pos: pos},
			wantErr: false,
		},
		{
			name:    "boolean and",
			left:    &ast.Literal{Type: token.TRUE, Value: true, Pos: pos},
			op:      token.AND,
			right:   &ast.Literal{Type: token.FALSE, Value: false, Pos: pos},
			wantErr: false,
		},
		{
			name:    "integer comparison",
			left:    &ast.Literal{Type: token.INTEGER_LIT, Value: 5, Pos: pos},
			op:      token.GT,
			right:   &ast.Literal{Type: token.INTEGER_LIT, Value: 3, Pos: pos},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binOp := &ast.BinaryOp{
				Pos:   pos,
				Left:  tt.left,
				Op:    tt.op,
				Right: tt.right,
			}

			_, errs := checker.CheckExpressionTypes(binOp)
			hasErr := len(errs) > 0

			if hasErr != tt.wantErr {
				t.Errorf("CheckExpressionTypes() error = %v, wantErr %v, errors: %v", hasErr, tt.wantErr, errs)
			}
		})
	}
}

func TestCheckUnaryOp(t *testing.T) {
	st := NewSymbolTable()
	st.EnterScope("test")
	checker := NewTypeChecker(st)

	pos := token.Position{Line: 1, Column: 1}

	tests := []struct {
		name    string
		op      token.TokenType
		operand ast.Expression
		wantErr bool
	}{
		{
			name:    "logical not",
			op:      token.NOT,
			operand: &ast.Literal{Type: token.TRUE, Value: true, Pos: pos},
			wantErr: false,
		},
		{
			name:    "bitwise not",
			op:      token.BITWISE_NOT,
			operand: &ast.Literal{Type: token.INTEGER_LIT, Value: 42, Pos: pos},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unaryOp := &ast.UnaryOp{
				Pos:   pos,
				Op:    tt.op,
				Right: tt.operand,
			}

			_, errs := checker.CheckExpressionTypes(unaryOp)
			hasErr := len(errs) > 0

			if hasErr != tt.wantErr {
				t.Errorf("CheckExpressionTypes() error = %v, wantErr %v, errors: %v", hasErr, tt.wantErr, errs)
			}
		})
	}
}

func TestCheckIdentifier(t *testing.T) {
	st := NewSymbolTable()
	st.EnterScope("test")

	pos := token.Position{Line: 1, Column: 1}

	// Define a string for testing
	str := &ast.String{Identifier: "$s1", Pos: pos}
	_ = st.DefineString("$s1", pos, str)

	checker := NewTypeChecker(st)

	tests := []struct {
		name     string
		ident    *ast.Identifier
		wantType DataType
		wantErr  bool
	}{
		{
			name:     "string_identifier",
			ident:    &ast.Identifier{Name: "$s1", Pos: pos},
			wantType: TypeBoolean,
			wantErr:  false,
		},
		{
			name:     "filesize_keyword",
			ident:    &ast.Identifier{Name: "filesize", Pos: pos},
			wantType: TypeInteger,
			wantErr:  false,
		},
		{
			name:     "entrypoint_keyword",
			ident:    &ast.Identifier{Name: "entrypoint", Pos: pos},
			wantType: TypeInteger,
			wantErr:  false,
		},
		{
			name:     "undefined_identifier",
			ident:    &ast.Identifier{Name: "$undefined", Pos: pos},
			wantType: TypeUnknown,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			typeInfo, errs := checker.CheckExpressionTypes(tt.ident)

			hasErrors := len(errs) > 0
			if hasErrors != tt.wantErr {
				t.Errorf("CheckExpressionTypes() error status = %v, wantErr %v\nerrors: %v",
					hasErrors, tt.wantErr, errs)
			}

			if !tt.wantErr && typeInfo.DataType != tt.wantType {
				t.Errorf("CheckExpressionTypes() got type %v, want %v",
					typeInfo.DataType, tt.wantType)
			}
		})
	}
}

func TestGetTypeFromSymbol(t *testing.T) {
	st := NewSymbolTable()
	st.EnterScope("test")

	pos := token.Position{Line: 1, Column: 1}

	// Define different symbol types
	str := &ast.String{Identifier: "$s1", Pos: pos}
	_ = st.DefineString("$s1", pos, str)

	rule := &ast.Rule{Name: "test_rule", Pos: pos}
	_ = st.DefineRule("test_rule", pos, rule)

	checker := NewTypeChecker(st)

	tests := []struct {
		name         string
		symbolName   string
		expectedType DataType
	}{
		{
			name:         "string symbol",
			symbolName:   "$s1",
			expectedType: TypeBoolean,
		},
		{
			name:         "rule symbol",
			symbolName:   "test_rule",
			expectedType: TypeBoolean,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			symbol, exists := st.Lookup(tt.symbolName)
			if !exists {
				t.Fatalf("Symbol %s not found", tt.symbolName)
			}

			typeInfo := checker.getTypeFromSymbol(symbol)
			if typeInfo.DataType != tt.expectedType {
				t.Errorf("getTypeFromSymbol() got %v, want %v", typeInfo.DataType, tt.expectedType)
			}
		})
	}
}

func TestTypeInfoMethods(t *testing.T) {
	t.Run("TypeIdentification", testTypeIdentificationMethods)
	t.Run("TypeCapabilities", testTypeCapabilityMethods)
	t.Run("TypeCasting", testTypeCastingMethods)
	t.Run("IntegerTypeMethods", testIntegerTypeMethods)
}

func testTypeIdentificationMethods(t *testing.T) {
	intType := &TypeInfo{DataType: TypeInteger, IntegerType: Int32Type}
	boolType := &TypeInfo{DataType: TypeBoolean}
	strType := &TypeInfo{DataType: TypeString}

	identificationTests := []struct {
		name     string
		testFunc func(*TypeInfo) bool
		typeInfo *TypeInfo
		expected bool
	}{
		{"IsNumeric_integer", (*TypeInfo).IsNumeric, intType, true},
		{"IsNumeric_boolean", (*TypeInfo).IsNumeric, boolType, false},
		{"IsString_string", (*TypeInfo).IsString, strType, true},
		{"IsString_integer", (*TypeInfo).IsString, intType, false},
		{"IsInteger_integer", (*TypeInfo).IsInteger, intType, true},
		{"IsBoolean_boolean", (*TypeInfo).IsBoolean, boolType, true},
	}

	for _, test := range identificationTests {
		t.Run(test.name, func(t *testing.T) {
			if result := test.testFunc(test.typeInfo); result != test.expected {
				t.Errorf("Expected %v, got %v", test.expected, result)
			}
		})
	}
}

func testTypeCapabilityMethods(t *testing.T) {
	intType := &TypeInfo{DataType: TypeInteger, IntegerType: Int32Type}

	capabilityTests := []struct {
		name     string
		testFunc func(*TypeInfo, *TypeInfo) bool
		expected bool
	}{
		{"CanPerformArithmetic", (*TypeInfo).CanPerformArithmetic, true},
		{"CanPerformBitwise", (*TypeInfo).CanPerformBitwise, true},
	}

	for _, test := range capabilityTests {
		t.Run(test.name, func(t *testing.T) {
			if result := test.testFunc(intType, intType); result != test.expected {
				t.Errorf("Expected %v, got %v", test.expected, result)
			}
		})
	}
}

func testTypeCastingMethods(t *testing.T) {
	intType := &TypeInfo{DataType: TypeInteger, IntegerType: Int32Type}
	uint32Type := &TypeInfo{DataType: TypeInteger, IntegerType: Uint32Type}

	if !intType.CanCastTo(uint32Type) {
		t.Error("CanCastTo() should allow integer to integer cast")
	}
}

func testIntegerTypeMethods(t *testing.T) {
	minVal, maxVal := Int32Type.GetIntegerRange()
	if minVal == 0 && maxVal == 0 {
		t.Error("GetIntegerRange() should return non-zero range for Int32Type")
	}
}

func TestInferTypeFromLiteral(t *testing.T) {
	tests := []struct {
		name         string
		tokenType    token.TokenType
		value        any
		expectedType DataType
	}{
		{
			name:         "boolean true",
			tokenType:    token.TRUE,
			value:        true,
			expectedType: TypeBoolean,
		},
		{
			name:         "boolean false",
			tokenType:    token.FALSE,
			value:        false,
			expectedType: TypeBoolean,
		},
		{
			name:         "integer",
			tokenType:    token.INTEGER_LIT,
			value:        42,
			expectedType: TypeInteger,
		},
		{
			name:         "hex integer",
			tokenType:    token.HEX_INTEGER_LIT,
			value:        0xFF,
			expectedType: TypeInteger,
		},
		{
			name:         "string",
			tokenType:    token.STRING_LIT,
			value:        "test",
			expectedType: TypeString,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			typeInfo := InferTypeFromLiteral(tt.tokenType, tt.value)
			if typeInfo.DataType != tt.expectedType {
				t.Errorf("InferTypeFromLiteral() got %v, want %v", typeInfo.DataType, tt.expectedType)
			}
		})
	}
}

func TestInferTypeFromBinaryOp(t *testing.T) {
	t.Run("ArithmeticOperations", testBinaryOpArithmeticOperations)
	t.Run("ComparisonOperations", testBinaryOpComparisonOperations)
	t.Run("LogicalOperations", testBinaryOpLogicalOperations)
	t.Run("StringOperations", testBinaryOpStringOperations)
	t.Run("BitwiseOperations", testBinaryOpBitwiseOperations)
}

// testBinaryOpArithmeticOperations tests arithmetic binary operations
func testBinaryOpArithmeticOperations(t *testing.T) {
	intType := &TypeInfo{DataType: TypeInteger, IntegerType: Int32Type}

	tests := []struct {
		name         string
		op           token.TokenType
		expectedType DataType
	}{
		{"addition", token.PLUS, TypeInteger},
		{"subtraction", token.MINUS, TypeInteger},
		{"multiplication", token.MULTIPLY, TypeInteger},
		{"division", token.DIVIDE, TypeInteger},
		{"modulo", token.MODULO, TypeInteger},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			typeInfo, err := InferTypeFromBinaryOp(intType, tt.op, intType)
			if err != nil {
				t.Errorf("InferTypeFromBinaryOp() error = %v, wantErr false", err)
				return
			}
			if typeInfo.DataType != tt.expectedType {
				t.Errorf("InferTypeFromBinaryOp() got %v, want %v", typeInfo.DataType, tt.expectedType)
			}
		})
	}
}

// testBinaryOpComparisonOperations tests comparison binary operations
func testBinaryOpComparisonOperations(t *testing.T) {
	intType := &TypeInfo{DataType: TypeInteger, IntegerType: Int32Type}

	tests := []struct {
		name         string
		op           token.TokenType
		expectedType DataType
	}{
		{"equal", token.EQ, TypeBoolean},
		{"not_equal", token.NEQ, TypeBoolean},
		{"less_than", token.LT, TypeBoolean},
		{"less_equal", token.LE, TypeBoolean},
		{"greater_than", token.GT, TypeBoolean},
		{"greater_equal", token.GE, TypeBoolean},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			typeInfo, err := InferTypeFromBinaryOp(intType, tt.op, intType)
			if err != nil {
				t.Errorf("InferTypeFromBinaryOp() error = %v, wantErr false", err)
				return
			}
			if typeInfo.DataType != tt.expectedType {
				t.Errorf("InferTypeFromBinaryOp() got %v, want %v", typeInfo.DataType, tt.expectedType)
			}
		})
	}
}

// testBinaryOpLogicalOperations tests logical binary operations
func testBinaryOpLogicalOperations(t *testing.T) {
	boolType := &TypeInfo{DataType: TypeBoolean}

	tests := []struct {
		name         string
		op           token.TokenType
		expectedType DataType
	}{
		{"logical_and", token.AND, TypeBoolean},
		{"logical_or", token.OR, TypeBoolean},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			typeInfo, err := InferTypeFromBinaryOp(boolType, tt.op, boolType)
			if err != nil {
				t.Errorf("InferTypeFromBinaryOp() error = %v, wantErr false", err)
				return
			}
			if typeInfo.DataType != tt.expectedType {
				t.Errorf("InferTypeFromBinaryOp() got %v, want %v", typeInfo.DataType, tt.expectedType)
			}
		})
	}
}

// testBinaryOpStringOperations tests string binary operations
func testBinaryOpStringOperations(t *testing.T) {
	strType := &TypeInfo{DataType: TypeString}

	tests := []struct {
		name         string
		op           token.TokenType
		expectedType DataType
	}{
		{"string_contains", token.CONTAINS, TypeBoolean},
		{"string_matches", token.MATCHES, TypeBoolean},
		{"string_startswith", token.STARTSWITH, TypeBoolean},
		{"string_endswith", token.ENDSWITH, TypeBoolean},
		{"string_icontains", token.ICONTAINS, TypeBoolean},
		{"string_istartswith", token.ISTARTSWITH, TypeBoolean},
		{"string_iendswith", token.IENDSWITH, TypeBoolean},
		{"string_iequals", token.IEQUALS, TypeBoolean},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			typeInfo, err := InferTypeFromBinaryOp(strType, tt.op, strType)
			if err != nil {
				t.Errorf("InferTypeFromBinaryOp() error = %v, wantErr false", err)
				return
			}
			if typeInfo.DataType != tt.expectedType {
				t.Errorf("InferTypeFromBinaryOp() got %v, want %v", typeInfo.DataType, tt.expectedType)
			}
		})
	}
}

// testBinaryOpBitwiseOperations tests bitwise binary operations
func testBinaryOpBitwiseOperations(t *testing.T) {
	intType := &TypeInfo{DataType: TypeInteger, IntegerType: Int32Type}

	tests := []struct {
		name         string
		op           token.TokenType
		expectedType DataType
	}{
		{"bitwise_and", token.BITWISE_AND, TypeInteger},
		{"bitwise_or", token.BITWISE_OR, TypeInteger},
		{"bitwise_xor", token.BITWISE_XOR, TypeInteger},
		{"left_shift", token.LEFT_SHIFT, TypeInteger},
		{"right_shift", token.RIGHT_SHIFT, TypeInteger},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			typeInfo, err := InferTypeFromBinaryOp(intType, tt.op, intType)
			if err != nil {
				t.Errorf("InferTypeFromBinaryOp() error = %v, wantErr false", err)
				return
			}
			if typeInfo.DataType != tt.expectedType {
				t.Errorf("InferTypeFromBinaryOp() got %v, want %v", typeInfo.DataType, tt.expectedType)
			}
		})
	}
}

func TestInferTypeFromUnaryOp(t *testing.T) {
	intType := &TypeInfo{DataType: TypeInteger, IntegerType: Int32Type}
	boolType := &TypeInfo{DataType: TypeBoolean}

	tests := []struct {
		name         string
		op           token.TokenType
		operand      *TypeInfo
		expectedType DataType
		wantErr      bool
	}{
		{
			name:         "logical not",
			op:           token.NOT,
			operand:      boolType,
			expectedType: TypeBoolean,
			wantErr:      false,
		},
		{
			name:         "bitwise not",
			op:           token.BITWISE_NOT,
			operand:      intType,
			expectedType: TypeInteger,
			wantErr:      false,
		},
		{
			name:         "unary minus",
			op:           token.MINUS,
			operand:      intType,
			expectedType: TypeInteger,
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			typeInfo, err := InferTypeFromUnaryOp(tt.op, tt.operand)
			if (err != nil) != tt.wantErr {
				t.Errorf("InferTypeFromUnaryOp() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && typeInfo.DataType != tt.expectedType {
				t.Errorf("InferTypeFromUnaryOp() got %v, want %v", typeInfo.DataType, tt.expectedType)
			}
		})
	}
}

func TestIntegerTypeString(t *testing.T) {
	tests := []struct {
		intType *IntegerType
		want    string
	}{
		{Int8Type, "int8"},
		{Int16Type, "int16"},
		{Int32Type, "int32"},
		{Int64Type, "int64"},
		{Uint8Type, "uint8"},
		{Uint16Type, "uint16"},
		{Uint32Type, "uint32"},
		{Uint64Type, "uint64"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.intType.String()
			if got != tt.want {
				t.Errorf("IntegerType.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTypeInfoString(t *testing.T) {
	tests := []struct {
		typeInfo *TypeInfo
		want     string
	}{
		{&TypeInfo{DataType: TypeUnknown}, "unknown"},
		{&TypeInfo{DataType: TypeInteger, IntegerType: Int32Type}, "int32"},
		{&TypeInfo{DataType: TypeFloat}, "float"},
		{&TypeInfo{DataType: TypeString}, "string"},
		{&TypeInfo{DataType: TypeBoolean}, "boolean"},
		{&TypeInfo{DataType: TypeRegexp}, "regexp"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.typeInfo.String()
			if got != tt.want {
				t.Errorf("TypeInfo.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetIntegerTypeFromFunction(t *testing.T) {
	tests := []struct {
		name     string
		funcName string
		want     *IntegerType
		wantErr  bool
	}{
		{"int8", "int8", Int8Type, false},
		{"int16", "int16", Int16Type, false},
		{"int32", "int32", Int32Type, false},
		{"int64", "int64", Int64Type, false},
		{"uint8", "uint8", Uint8Type, false},
		{"uint16", "uint16", Uint16Type, false},
		{"uint32", "uint32", Uint32Type, false},
		{"uint64", "uint64", Uint64Type, false},
		{"unknown", "unknown", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetIntegerTypeFromFunction(tt.funcName)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetIntegerTypeFromFunction() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("GetIntegerTypeFromFunction() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckStringOp(t *testing.T) {
	st := NewSymbolTable()
	st.EnterScope("test")
	checker := NewTypeChecker(st)

	pos := token.Position{Line: 1, Column: 1}

	// Define strings
	str1 := &ast.String{Identifier: "$s1", Pos: pos}
	str2 := &ast.String{Identifier: "$s2", Pos: pos}
	_ = st.DefineString("$s1", pos, str1)
	_ = st.DefineString("$s2", pos, str2)

	// Test contains
	containsOp := &ast.BinaryOp{
		Op:    token.CONTAINS,
		Left:  &ast.Literal{Type: token.STRING_LIT, Value: "malware", Pos: pos},
		Right: &ast.Literal{Type: token.STRING_LIT, Value: "mal", Pos: pos},
	}

	typeInfo, errs := checker.CheckExpressionTypes(containsOp)
	if len(errs) > 0 {
		t.Errorf("CheckExpressionTypes() unexpected errors: %v", errs)
	}
	if typeInfo.DataType != TypeBoolean {
		t.Errorf("CheckExpressionTypes() wrong type for contains")
	}

	// Test matches
	matchesOp := &ast.BinaryOp{
		Op:    token.MATCHES,
		Left:  &ast.Literal{Type: token.STRING_LIT, Value: "malware", Pos: pos},
		Right: &ast.Literal{Type: token.STRING_LIT, Value: "mal", Pos: pos},
	}

	typeInfo, errs = checker.CheckExpressionTypes(matchesOp)
	if len(errs) > 0 {
		t.Errorf("CheckExpressionTypes() unexpected errors: %v", errs)
	}
	if typeInfo.DataType != TypeBoolean {
		t.Errorf("CheckExpressionTypes() wrong type for matches")
	}
}

func TestTypeCheckerErrors(t *testing.T) {
	st := NewSymbolTable()
	st.EnterScope("test")
	checker := NewTypeChecker(st)

	pos := token.Position{Line: 1, Column: 1}

	// Test with invalid expression
	invalidExpr := &ast.BinaryOp{
		Op:    token.PLUS,
		Left:  &ast.Literal{Type: token.STRING_LIT, Value: "str", Pos: pos},
		Right: &ast.Literal{Type: token.INTEGER_LIT, Value: int64(1), Pos: pos},
	}

	_, errs := checker.CheckExpressionTypes(invalidExpr)
	if len(errs) == 0 {
		t.Error("Expected errors for invalid expression")
	}

	// Test GetErrors and HasErrors
	if !checker.HasErrors() {
		t.Error("HasErrors() should return true")
	}

	errors := checker.GetErrors()
	if len(errors) == 0 {
		t.Error("GetErrors() should return errors")
	}
}
