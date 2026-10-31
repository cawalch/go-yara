package semantic

import (
	"context"
	"testing"

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
	program, err := p.ParseRulesWithContext(context.Background())

	if err != nil {
		t.Fatalf("ParseRules() error = %v", err)
	}

	validator := NewValidator()
	errors := validator.ValidateProgram(program)

	if len(errors) > 0 {
		t.Errorf("ValidateProgram() unexpected errors: %v", errors)
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
		op       token.Type
		right    *TypeInfo
		wantType DataType
		wantErr  bool
	}{
		{"plus", intType, token.PLUS, intType, TypeInteger, false},
		{"minus", intType, token.MINUS, intType, TypeInteger, false},
		{"multiply", intType, token.MULTIPLY, intType, TypeInteger, false},
		{"divide", intType, token.DIVIDE, intType, TypeInteger, false},
		{"modulo", intType, token.MODULO, intType, TypeInteger, false},
		{"bitwise_and", intType, token.BitwiseAnd, intType, TypeInteger, false},
		{"bitwise_or", intType, token.BitwiseOr, intType, TypeInteger, false},
		{"bitwise_xor", intType, token.BitwiseXor, intType, TypeInteger, false},
		{"left_shift", intType, token.LeftShift, intType, TypeInteger, false},
		{"right_shift", intType, token.RightShift, intType, TypeInteger, false},
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
		op       token.Type
		operand  *TypeInfo
		wantType DataType
		wantErr  bool
	}{
		{"not", token.NOT, boolType, TypeBoolean, false},
		{"not_integer", token.NOT, intType, TypeBoolean, false},
		{"not_float", token.NOT, &TypeInfo{DataType: TypeFloat}, TypeBoolean, false},
		{"not_string", token.NOT, &TypeInfo{DataType: TypeString}, TypeBoolean, false},
		{"not_unknown", token.NOT, &TypeInfo{DataType: TypeUnknown}, TypeBoolean, false},
		{"not_regexp", token.NOT, &TypeInfo{DataType: TypeRegexp}, TypeUnknown, true},
		{"not_struct", token.NOT, &TypeInfo{DataType: TypeStruct}, TypeUnknown, true},
		{"not_array", token.NOT, &TypeInfo{DataType: TypeArray}, TypeUnknown, true},
		{"not_dictionary", token.NOT, &TypeInfo{DataType: TypeDictionary}, TypeUnknown, true},
		{"bitwise_not", token.BitwiseNot, intType, TypeInteger, false},
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
	program, err := p.ParseRulesWithContext(context.Background())

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

// TestInferTypeFromLiteralAllTypes tests type inference for all literal types
func TestInferTypeFromLiteralAllTypes(t *testing.T) {
	tests := []struct {
		name      string
		tokenType token.Type
		value     any
		wantType  DataType
	}{
		{"true", token.TRUE, true, TypeBoolean},
		{"false", token.FALSE, false, TypeBoolean},
		{"integer", token.IntegerLit, int64(42), TypeInteger},
		{"hex_integer", token.HexIntegerLit, int64(0xFF), TypeInteger},
		{"float", token.FloatLit, 3.14, TypeFloat},
		{"size", token.SizeLit, int64(1024), TypeInteger},
		{"string", token.StringLit, "test", TypeString},
		{"hex_string", token.HexStringLit, "ABCD", TypeString},
		{"regex", token.RegexLit, "test.*", TypeRegexp},
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
