package semantic

import (
	"context"
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/parser"
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
