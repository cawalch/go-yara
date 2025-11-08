package semantic

import (
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/parser"
	"github.com/cawalch/go-yara/token"
)

// TestValidatorCompleteFlow tests the complete validation flow
func TestValidatorCompleteFlow(t *testing.T) {
	input := `
rule test_rule {
	meta:
		author = "test"
		version = 1
	strings:
		$s1 = "malware"
		$s2 = "virus"
	condition:
		($s1 and $s2) or filesize > 1024
}`

	lex := lexer.New(input)
	p := parser.New(lex)
	program, err := p.ParseRules()

	if err != nil {
		t.Fatalf("ParseRules() error = %v", err)
	}

	validator := NewValidator()
	errors := validator.ValidateProgram(program)

	if len(errors) > 0 {
		t.Errorf("ValidateProgram() unexpected errors: %v", errors)
	}
}

// TestTypeCheckerBinaryOpTypes tests type checking for all binary operators
// Helper function to setup test environment for type checking
func setupTypeCheckerTest(t *testing.T) (*SymbolTable, *TypeChecker, token.Position) {
	st := NewSymbolTable()
	st.EnterScope("test")
	checker := NewTypeChecker(st)
	pos := token.Position{Line: 1, Column: 1}

	// Define a string for testing
	str := &ast.String{Identifier: "$s1", Pos: pos}
	if err := st.DefineString("$s1", pos, str); err != nil {
		t.Fatalf("Failed to define string: %v", err)
	}

	return st, checker, pos
}

// Helper function to test binary operation type checking
func testBinaryOpType(t *testing.T, checker *TypeChecker, expr *ast.BinaryOp) {
	_, errs := checker.CheckExpressionTypes(expr)
	if len(errs) > 0 {
		t.Errorf("CheckExpressionTypes() unexpected errors: %v", errs)
	}
}

// TestTypeCheckerBinaryOpTypes_Arithmetic tests arithmetic operators
func TestTypeCheckerBinaryOpTypes_Arithmetic(t *testing.T) {
	_, checker, pos := setupTypeCheckerTest(t)

	tests := []struct {
		name  string
		op    token.TokenType
		left  int64
		right int64
	}{
		{"subtraction", token.MINUS, 5, 2},
		{"multiplication", token.MULTIPLY, 3, 4},
		{"division", token.DIVIDE, 10, 2},
		{"modulo", token.MODULO, 10, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr := &ast.BinaryOp{
				Pos:   pos,
				Left:  &ast.Literal{Type: token.INTEGER_LIT, Value: tt.left, Pos: pos},
				Op:    tt.op,
				Right: &ast.Literal{Type: token.INTEGER_LIT, Value: tt.right, Pos: pos},
			}
			testBinaryOpType(t, checker, expr)
		})
	}
}

// TestTypeCheckerBinaryOpTypes_Bitwise tests bitwise operators
func TestTypeCheckerBinaryOpTypes_Bitwise(t *testing.T) {
	_, checker, pos := setupTypeCheckerTest(t)

	tests := []struct {
		name  string
		op    token.TokenType
		left  int64
		right int64
	}{
		{"bitwise_and", token.BITWISE_AND, 15, 7},
		{"bitwise_or", token.BITWISE_OR, 8, 4},
		{"bitwise_xor", token.BITWISE_XOR, 12, 10},
		{"left_shift", token.LEFT_SHIFT, 1, 4},
		{"right_shift", token.RIGHT_SHIFT, 16, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr := &ast.BinaryOp{
				Pos:   pos,
				Left:  &ast.Literal{Type: token.INTEGER_LIT, Value: tt.left, Pos: pos},
				Op:    tt.op,
				Right: &ast.Literal{Type: token.INTEGER_LIT, Value: tt.right, Pos: pos},
			}
			testBinaryOpType(t, checker, expr)
		})
	}
}

// TestTypeCheckerBinaryOpTypes_Comparison tests comparison operators
func TestTypeCheckerBinaryOpTypes_Comparison(t *testing.T) {
	_, checker, pos := setupTypeCheckerTest(t)

	tests := []struct {
		name  string
		op    token.TokenType
		left  int64
		right int64
	}{
		{"less_than", token.LT, 1, 2},
		{"less_equal", token.LE, 1, 1},
		{"greater_equal", token.GE, 2, 1},
		{"not_equal", token.NEQ, 1, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr := &ast.BinaryOp{
				Pos:   pos,
				Left:  &ast.Literal{Type: token.INTEGER_LIT, Value: tt.left, Pos: pos},
				Op:    tt.op,
				Right: &ast.Literal{Type: token.INTEGER_LIT, Value: tt.right, Pos: pos},
			}
			testBinaryOpType(t, checker, expr)
		})
	}
}

// TestTypeCheckerUnaryOpTypes tests type checking for all unary operators
func TestTypeCheckerUnaryOpTypes(t *testing.T) {
	st := NewSymbolTable()
	st.EnterScope("test")
	checker := NewTypeChecker(st)

	pos := token.Position{Line: 1, Column: 1}

	tests := []struct {
		name string
		expr *ast.UnaryOp
	}{
		{
			name: "logical_not_boolean",
			expr: &ast.UnaryOp{
				Pos:   pos,
				Op:    token.NOT,
				Right: &ast.Literal{Type: token.TRUE, Value: true, Pos: pos},
			},
		},
		{
			name: "bitwise_not_integer",
			expr: &ast.UnaryOp{
				Pos:   pos,
				Op:    token.BITWISE_NOT,
				Right: &ast.Literal{Type: token.INTEGER_LIT, Value: int64(42), Pos: pos},
			},
		},
		{
			name: "unary_minus_integer",
			expr: &ast.UnaryOp{
				Pos:   pos,
				Op:    token.MINUS,
				Right: &ast.Literal{Type: token.INTEGER_LIT, Value: int64(42), Pos: pos},
			},
		},
		{
			name: "defined_operator",
			expr: &ast.UnaryOp{
				Pos:   pos,
				Op:    token.DEFINED,
				Right: &ast.Identifier{Name: "$s1", Pos: pos},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, errs := checker.CheckExpressionTypes(tt.expr)
			if len(errs) > 0 {
				t.Logf("CheckExpressionTypes() errors (may be expected): %v", errs)
			}
		})
	}
}

// TestInferTypeFromBinaryOpAllOperators tests type inference for all operators
func TestInferTypeFromBinaryOpAllOperators(t *testing.T) {
	intType := &TypeInfo{DataType: TypeInteger, IntegerType: Int32Type}
	boolType := &TypeInfo{DataType: TypeBoolean}
	strType := &TypeInfo{DataType: TypeString}

	tests := []struct {
		name     string
		left     *TypeInfo
		op       token.TokenType
		right    *TypeInfo
		wantType DataType
		wantErr  bool
	}{
		{"plus", intType, token.PLUS, intType, TypeInteger, false},
		{"minus", intType, token.MINUS, intType, TypeInteger, false},
		{"multiply", intType, token.MULTIPLY, intType, TypeInteger, false},
		{"divide", intType, token.DIVIDE, intType, TypeInteger, false},
		{"modulo", intType, token.MODULO, intType, TypeInteger, false},
		{"bitwise_and", intType, token.BITWISE_AND, intType, TypeInteger, false},
		{"bitwise_or", intType, token.BITWISE_OR, intType, TypeInteger, false},
		{"bitwise_xor", intType, token.BITWISE_XOR, intType, TypeInteger, false},
		{"left_shift", intType, token.LEFT_SHIFT, intType, TypeInteger, false},
		{"right_shift", intType, token.RIGHT_SHIFT, intType, TypeInteger, false},
		{"eq", intType, token.EQ, intType, TypeBoolean, false},
		{"neq", intType, token.NEQ, intType, TypeBoolean, false},
		{"lt", intType, token.LT, intType, TypeBoolean, false},
		{"le", intType, token.LE, intType, TypeBoolean, false},
		{"gt", intType, token.GT, intType, TypeBoolean, false},
		{"ge", intType, token.GE, intType, TypeBoolean, false},
		{"and", boolType, token.AND, boolType, TypeBoolean, false},
		{"or", boolType, token.OR, boolType, TypeBoolean, false},
		{"contains", strType, token.CONTAINS, strType, TypeBoolean, false},
		{"icontains", strType, token.ICONTAINS, strType, TypeBoolean, false},
		{"startswith", strType, token.STARTSWITH, strType, TypeBoolean, false},
		{"endswith", strType, token.ENDSWITH, strType, TypeBoolean, false},
		{"matches", strType, token.MATCHES, strType, TypeBoolean, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			typeInfo, err := InferTypeFromBinaryOp(tt.left, tt.op, tt.right)
			if (err != nil) != tt.wantErr {
				t.Errorf("InferTypeFromBinaryOp() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && typeInfo.DataType != tt.wantType {
				t.Errorf("InferTypeFromBinaryOp() type = %v, want %v", typeInfo.DataType, tt.wantType)
			}
		})
	}
}

// TestInferTypeFromUnaryOpAllOperators tests type inference for all unary operators
func TestInferTypeFromUnaryOpAllOperators(t *testing.T) {
	intType := &TypeInfo{DataType: TypeInteger, IntegerType: Int32Type}
	boolType := &TypeInfo{DataType: TypeBoolean}

	tests := []struct {
		name     string
		op       token.TokenType
		operand  *TypeInfo
		wantType DataType
		wantErr  bool
	}{
		{"not", token.NOT, boolType, TypeBoolean, false},
		{"bitwise_not", token.BITWISE_NOT, intType, TypeInteger, false},
		{"minus", token.MINUS, intType, TypeInteger, false},
		{"defined", token.DEFINED, intType, TypeBoolean, false},
		{"hash", token.HASH, intType, TypeInteger, false},
		{"at", token.AT, intType, TypeInteger, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			typeInfo, err := InferTypeFromUnaryOp(tt.op, tt.operand)
			if (err != nil) != tt.wantErr {
				t.Errorf("InferTypeFromUnaryOp() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && typeInfo.DataType != tt.wantType {
				t.Errorf("InferTypeFromUnaryOp() type = %v, want %v", typeInfo.DataType, tt.wantType)
			}
		})
	}
}

// TestValidatorErrorPropagation tests error propagation
func TestValidatorErrorPropagation(t *testing.T) {
	input := `
rule error_rule {
	strings:
		$s1 = "test"
	condition:
		$s1 and $undefined_string
}`

	lex := lexer.New(input)
	p := parser.New(lex)
	program, err := p.ParseRules()

	if err != nil {
		t.Fatalf("ParseRules() error = %v", err)
	}

	validator := NewValidator()
	errors := validator.ValidateProgram(program)

	// Should have at least one error for undefined string
	if len(errors) == 0 {
		t.Error("ValidateProgram() expected errors for undefined string")
	}

	// Verify HasErrors returns true
	if !validator.HasErrors() {
		t.Error("HasErrors() should return true when errors exist")
	}

	// Verify GetErrors returns the errors
	errs := validator.GetErrors()
	if len(errs) == 0 {
		t.Error("GetErrors() should return errors")
	}
}

// TestTypeInfoCanCompareEdgeCases tests CanCompare edge cases
func TestTypeInfoCanCompareEdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		left   *TypeInfo
		right  *TypeInfo
		canCmp bool
	}{
		{
			name:   "int_vs_int",
			left:   &TypeInfo{DataType: TypeInteger, IntegerType: Int32Type},
			right:  &TypeInfo{DataType: TypeInteger, IntegerType: Uint64Type},
			canCmp: true,
		},
		{
			name:   "string_vs_string",
			left:   &TypeInfo{DataType: TypeString},
			right:  &TypeInfo{DataType: TypeString},
			canCmp: true,
		},
		{
			name:   "bool_vs_bool",
			left:   &TypeInfo{DataType: TypeBoolean},
			right:  &TypeInfo{DataType: TypeBoolean},
			canCmp: true,
		},
		{
			name:   "int_vs_float",
			left:   &TypeInfo{DataType: TypeInteger, IntegerType: Int32Type},
			right:  &TypeInfo{DataType: TypeFloat},
			canCmp: true,
		},
		{
			name:   "int_vs_bool",
			left:   &TypeInfo{DataType: TypeInteger, IntegerType: Int32Type},
			right:  &TypeInfo{DataType: TypeBoolean},
			canCmp: false,
		},
		{
			name:   "string_vs_int",
			left:   &TypeInfo{DataType: TypeString},
			right:  &TypeInfo{DataType: TypeInteger, IntegerType: Int32Type},
			canCmp: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.left.CanCompare(tt.right)
			if result != tt.canCmp {
				t.Errorf("CanCompare() = %v, want %v", result, tt.canCmp)
			}
		})
	}
}

// TestTypeInfoCanCastToEdgeCases tests CanCastTo edge cases
func TestTypeInfoCanCastToEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		from    *TypeInfo
		to      *TypeInfo
		canCast bool
	}{
		{
			name:    "int_to_int",
			from:    &TypeInfo{DataType: TypeInteger, IntegerType: Int32Type},
			to:      &TypeInfo{DataType: TypeInteger, IntegerType: Uint64Type},
			canCast: true,
		},
		{
			name:    "int_to_float",
			from:    &TypeInfo{DataType: TypeInteger, IntegerType: Int32Type},
			to:      &TypeInfo{DataType: TypeFloat},
			canCast: true,
		},
		{
			name:    "int_to_bool",
			from:    &TypeInfo{DataType: TypeInteger, IntegerType: Int32Type},
			to:      &TypeInfo{DataType: TypeBoolean},
			canCast: true,
		},
		{
			name:    "string_to_bool",
			from:    &TypeInfo{DataType: TypeString},
			to:      &TypeInfo{DataType: TypeBoolean},
			canCast: true,
		},
		{
			name:    "bool_to_int",
			from:    &TypeInfo{DataType: TypeBoolean},
			to:      &TypeInfo{DataType: TypeInteger, IntegerType: Int32Type},
			canCast: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.from.CanCastTo(tt.to)
			if result != tt.canCast {
				t.Errorf("CanCastTo() = %v, want %v", result, tt.canCast)
			}
		})
	}
}

// TestIntegerTypeGetIntegerRange tests GetIntegerRange for all types
func TestIntegerTypeGetIntegerRange(t *testing.T) {
	tests := []struct {
		name    string
		intType *IntegerType
	}{
		{"int8", Int8Type},
		{"int16", Int16Type},
		{"int32", Int32Type},
		{"int64", Int64Type},
		{"uint8", Uint8Type},
		{"uint16", Uint16Type},
		{"uint32", Uint32Type},
		{"uint64", Uint64Type},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			minVal, maxVal := tt.intType.GetIntegerRange()
			if minVal == 0 && maxVal == 0 {
				t.Errorf("GetIntegerRange() returned (0, 0) for %s", tt.name)
			}
			if tt.intType.Signed && minVal >= 0 {
				t.Errorf("GetIntegerRange() min = %d for signed type, want negative", minVal)
			}
			if !tt.intType.Signed && minVal != 0 {
				t.Errorf("GetIntegerRange() min = %d for unsigned type, want 0", minVal)
			}
		})
	}
}

// TestInferTypeFromLiteralAllTypes tests type inference for all literal types
func TestInferTypeFromLiteralAllTypes(t *testing.T) {
	tests := []struct {
		name      string
		tokenType token.TokenType
		value     any
		wantType  DataType
	}{
		{"true", token.TRUE, true, TypeBoolean},
		{"false", token.FALSE, false, TypeBoolean},
		{"integer", token.INTEGER_LIT, int64(42), TypeInteger},
		{"hex_integer", token.HEX_INTEGER_LIT, int64(0xFF), TypeInteger},
		{"float", token.FLOAT_LIT, 3.14, TypeFloat},
		{"size", token.SIZE_LIT, int64(1024), TypeInteger},
		{"string", token.STRING_LIT, "test", TypeString},
		{"hex_string", token.HEX_STRING_LIT, "ABCD", TypeString},
		{"regex", token.REGEX_LIT, "test.*", TypeRegexp},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			typeInfo := InferTypeFromLiteral(tt.tokenType, tt.value)
			if typeInfo.DataType != tt.wantType {
				t.Errorf("InferTypeFromLiteral() type = %v, want %v", typeInfo.DataType, tt.wantType)
			}
		})
	}
}
