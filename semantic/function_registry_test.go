package semantic

import (
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

func TestBuiltinFunctionRegistryIsolation(t *testing.T) {
	integer := &ast.Literal{Type: token.IntegerLit, Value: int64(0)}
	text := &ast.Literal{Type: token.StringLit, Value: "text"}
	for _, tc := range []struct {
		name     string
		args     []ast.Expression
		dataType DataType
		intType  *IntegerType
		code     ErrorCode
	}{
		{"uint32", []ast.Expression{integer}, TypeInteger, Uint32Type, ""},
		{"int16be", []ast.Expression{integer}, TypeInteger, Int16BEType, ""},
		{"concat", []ast.Expression{text, text}, TypeString, nil, ""},
		{"sha256", []ast.Expression{text}, TypeString, nil, ""},
		{"uint8", nil, TypeInteger, Uint8Type, ErrCodeInvalidArgumentCount},
		{"uint16", []ast.Expression{text}, TypeInteger, Uint16Type, ErrCodeInvalidArgumentType},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v := NewValidator()
			call := &ast.FunctionCall{Function: tc.name, Args: tc.args}
			for range 20 {
				result, errs := v.validateFunctionCallExpression(call)
				if result.DataType != tc.dataType || result.IntegerType != tc.intType {
					t.Fatalf("return type = %+v", result)
				}
				if tc.code == "" && len(errs) != 0 || tc.code != "" && findSemanticErrorByCode(errs, tc.code) == nil {
					t.Fatalf("errors = %v, want code %q", errs, tc.code)
				}
				// A caller owns the TypeInfo wrapper returned for this call.
				result.DataType, result.IntegerType = TypeUnknown, nil
			}
		})
	}
}
