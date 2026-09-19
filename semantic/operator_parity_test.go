package semantic

import (
	"context"
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/parser"
	"github.com/cawalch/go-yara/token"
)

func TestOperatorValidationParity(t *testing.T) {
	for _, test := range []struct {
		expression string
		wantType   DataType
		wantError  bool
	}{
		{`1 and true`, TypeBoolean, false},
		{`"text" or false`, TypeBoolean, false},
		{`value + 1`, TypeUnknown, false},
		{`value matches /a/`, TypeBoolean, false},
		{`~value`, TypeUnknown, false},
		{`not value`, TypeBoolean, false},
		{`"text" + 1`, TypeUnknown, true},
		{`1 matches /a/`, TypeUnknown, true},
		{`missing() + 1`, TypeUnknown, true},
	} {
		t.Run(test.expression, func(t *testing.T) {
			program, err := parser.New(lexer.New(`external value rule r { condition: ` + test.expression + ` }`)).ParseRulesWithContext(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			validator := NewValidator()
			validationErrors := validator.ValidateProgram(program)
			checker := NewTypeChecker(validator.GetSymbolTable())
			info, checkErrors := checker.CheckExpressionTypes(program.Rules[0].Condition)
			if (len(validationErrors) > 0) != test.wantError || (len(checkErrors) > 0) != test.wantError || info.DataType != test.wantType {
				t.Fatalf("validation=%v, checking=%v, type=%v; want error=%v, type=%v", validationErrors, checkErrors, info.DataType, test.wantError, test.wantType)
			}
		})
	}
}

func TestDirectTypeCheckingParity(t *testing.T) {
	integer := &ast.Literal{Type: token.IntegerLit, Value: int64(50)}
	text := &ast.Literal{Type: token.StringLit, Value: "abc"}
	percent := &ast.PercentExpression{Value: integer}
	for _, test := range []struct {
		name      string
		expr      ast.Expression
		wantType  DataType
		wantError bool
	}{
		{"module", &ast.BinaryOp{Left: &ast.FunctionCall{Function: "hash.md5", Args: []ast.Expression{text}}, Op: token.EQ, Right: text}, TypeBoolean, false},
		{"uppercase builtin", &ast.FunctionCall{Function: "UINT8", Args: []ast.Expression{integer}}, TypeInteger, false},
		{"percent", &ast.BinaryOp{Left: percent, Op: token.PLUS, Right: integer}, TypeInteger, false},
		{"percent plus string", &ast.BinaryOp{Left: percent, Op: token.PLUS, Right: text}, TypeUnknown, true},
		{"invalid percent", &ast.PercentExpression{Value: text}, TypeInteger, true},
		{"undefined percent", &ast.PercentExpression{Value: &ast.Identifier{Name: "missing"}}, TypeInteger, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			validator := NewValidatorWithModules(ModuleFunctions{
				"hash.md5": {Signatures: [][]DataType{{TypeString}}, ReturnType: TypeString},
			})
			validationErrors := validator.ValidateProgram(&ast.Program{
				Imports: []*ast.Import{{Module: "hash"}},
				Rules:   []*ast.Rule{{Name: "r", Condition: test.expr}},
			})
			info, checkErrors := NewTypeChecker(validator.GetSymbolTable()).CheckExpressionTypes(test.expr)
			if (len(validationErrors) > 0) != test.wantError || (len(checkErrors) > 0) != test.wantError || info.DataType != test.wantType {
				t.Fatalf("validation=%v, checking=%v, type=%v; want error=%v, type=%v", validationErrors, checkErrors, info.DataType, test.wantError, test.wantType)
			}
		})
	}
}
