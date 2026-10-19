package semantic

import (
	"context"
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/parser"
	"github.com/cawalch/go-yara/token"
)

func TestOperatorValidation(t *testing.T) {
	for _, test := range []struct {
		expression string
		wantError  bool
	}{
		{`1 and true`, false},
		{`"text" or false`, false},
		{`value + 1`, false},
		{`value matches /a/`, false},
		{`~value`, false},
		{`not value`, false},
		{`"text" + 1`, true},
		{`1 matches /a/`, true},
		{`missing() + 1`, true},
	} {
		t.Run(test.expression, func(t *testing.T) {
			program, err := parser.New(lexer.New(`external value rule r { condition: ` + test.expression + ` }`)).ParseRulesWithContext(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			validator := NewValidator()
			validationErrors := validator.ValidateProgram(program)
			if (len(validationErrors) > 0) != test.wantError {
				t.Fatalf("validation=%v; want error=%v", validationErrors, test.wantError)
			}
		})
	}
}

func TestDirectExpressionValidation(t *testing.T) {
	integer := &ast.Literal{Type: token.IntegerLit, Value: int64(50)}
	text := &ast.Literal{Type: token.StringLit, Value: "abc"}
	percent := &ast.PercentExpression{Value: integer}
	for _, test := range []struct {
		name      string
		expr      ast.Expression
		wantError bool
	}{
		{"module", &ast.BinaryOp{Left: &ast.FunctionCall{Function: "hash.md5", Args: []ast.Expression{text}}, Op: token.EQ, Right: text}, false},
		{"uppercase builtin", &ast.FunctionCall{Function: "UINT8", Args: []ast.Expression{integer}}, false},
		{"percent", &ast.BinaryOp{Left: percent, Op: token.PLUS, Right: integer}, false},
		{"percent plus string", &ast.BinaryOp{Left: percent, Op: token.PLUS, Right: text}, true},
		{"invalid percent", &ast.PercentExpression{Value: text}, true},
		{"undefined percent", &ast.PercentExpression{Value: &ast.Identifier{Name: "missing"}}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			validator := NewValidatorWithModules(ModuleFunctions{
				"hash.md5": {Signatures: [][]DataType{{TypeString}}, ReturnType: TypeString},
			})
			validationErrors := validator.ValidateProgram(&ast.Program{
				Imports: []*ast.Import{{Module: "hash"}},
				Rules:   []*ast.Rule{{Name: "r", Condition: test.expr}},
			})
			if (len(validationErrors) > 0) != test.wantError {
				t.Fatalf("validation=%v; want error=%v", validationErrors, test.wantError)
			}
		})
	}
}
