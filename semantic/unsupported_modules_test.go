package semantic

import (
	"strings"
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

func TestValidatorUnsupportedModules(t *testing.T) {
	tests := []struct {
		name      string
		source    string
		wantError string
	}{
		{
			name: "import_pe",
			source: `import "pe"

rule test {
	condition:
		true
}`,
			wantError: "unsupported module: pe",
		},
		{
			name: "pe_member_access",
			source: `rule test {
	condition:
		pe.is_pe
}`,
			wantError: "unsupported module: pe",
		},
		{
			name: "pe_function_call",
			source: `rule test {
	condition:
		pe.imphash() == ""
}`,
			wantError: "unsupported module: pe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs, err := parseAndValidateProgram(t, tt.source)
			if err != nil {
				t.Fatalf("parseAndValidateProgram() error = %v", err)
			}
			if !errorsContain(errs, tt.wantError) {
				t.Fatalf("ValidateProgram() errors = %v, want containing %q", errs, tt.wantError)
			}
		})
	}
}

func TestValidatorUnsupportedHashModuleFunction(t *testing.T) {
	pos := token.Position{Line: 1, Column: 1}
	program := &ast.Program{
		Rules: []*ast.Rule{
			{
				Pos:  pos,
				Name: "test",
				Condition: &ast.BinaryOp{
					Pos: pos,
					Left: &ast.FunctionCall{
						Pos:      pos,
						Function: "hash.md5",
						Args: []ast.Expression{
							&ast.Literal{Pos: pos, Type: token.IntegerLit, Value: int64(0)},
							&ast.Literal{Pos: pos, Type: token.IntegerLit, Value: int64(4)},
						},
					},
					Op:    token.EQ,
					Right: &ast.Literal{Pos: pos, Type: token.StringLit, Value: ""},
				},
			},
		},
	}

	errs := NewValidator().ValidateProgram(program)
	if !errorsContain(errs, "unsupported module: hash") {
		t.Fatalf("ValidateProgram() errors = %v, want unsupported module: hash", errs)
	}
}

func TestValidatorBareHashBuiltinsRemainSupported(t *testing.T) {
	source := `rule test {
	condition:
		md5(0, 4) == "" and sha1("abc") == "" and sha256(0, 4) == ""
}`

	errs, err := parseAndValidateProgram(t, source)
	if err != nil {
		t.Fatalf("parseAndValidateProgram() error = %v", err)
	}
	if len(errs) > 0 {
		t.Fatalf("ValidateProgram() unexpected errors: %v", errs)
	}
}

func errorsContain(errs []error, want string) bool {
	for _, err := range errs {
		if strings.Contains(err.Error(), want) {
			return true
		}
	}
	return false
}
