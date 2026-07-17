package compiler

import (
	"crypto/md5" // #nosec G501 -- compatibility test.
	"fmt"
	"strings"
	"testing"
)

func TestHashModule(t *testing.T) {
	data := []byte("module data")
	wantMD5 := fmt.Sprintf("%x", md5.Sum(data)) // #nosec G401 -- compatibility test.
	c := NewCompiler()
	program, err := c.CompileSource(fmt.Sprintf(`
import "hash"
rule hash_module {
    condition:
        hash.md5(0, filesize) == "%s" and
        hash.sha256("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
}
`, wantMD5))
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}
	result, err := program.Scan(data)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if !result.RuleResults["hash_module"] {
		t.Fatal("hash_module did not match")
	}
}

func TestMathModule(t *testing.T) {
	c := NewCompiler()
	program, err := c.CompileSource(`
import "math"
rule math_module {
    condition:
        math.entropy(0, filesize) == 0.0 and
        math.mean(0, filesize) == 65.0 and
        math.deviation(0, filesize) == 0.0
}
rule mixed_boolean {
    condition:
        filesize == 4 and math.mean(0, filesize) == 65.0
}
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}
	result, err := program.Scan([]byte("AAAA"))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if !result.RuleResults["math_module"] {
		t.Fatal("math_module did not match")
	}
	if !result.RuleResults["mixed_boolean"] {
		t.Fatal("mixed_boolean did not match")
	}
}

func TestCustomModule(t *testing.T) {
	demo := Module{
		Name: "demo",
		Functions: map[string]ModuleFunction{
			"is_even": {
				Signatures: []ModuleSignature{{Arguments: []ModuleValueType{ModuleInteger}}},
				ReturnType: ModuleBoolean,
				Evaluate: func(ctx ModuleContext, args []ModuleValue) (ModuleValue, error) {
					if ctx.RuleName != "custom_module" {
						return ModuleValue{}, fmt.Errorf("unexpected rule context %q", ctx.RuleName)
					}
					return BooleanValue(args[0].Integer%2 == 0), nil
				},
			},
		},
	}

	c := NewCompiler(WithModule(demo))
	program, err := c.CompileSource(`
import "demo"
rule custom_module {
    condition:
        demo.is_even(uint8(0))
}
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}
	result, err := program.Scan([]byte{2})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if !result.RuleResults["custom_module"] {
		t.Fatal("custom_module did not match")
	}
}

func TestModuleValidation(t *testing.T) {
	tests := []struct {
		name    string
		source  string
		message string
	}{
		{
			name:    "missing import",
			source:  `rule test { condition: math.mean(0, filesize) > 0 }`,
			message: `module "math" must be imported`,
		},
		{
			name: "bad argument type",
			source: `import "math"
rule test { condition: math.mean("bad", 1) > 0 }`,
			message: "does not accept the supplied argument types",
		},
		{
			name: "unknown function",
			source: `import "math"
rule test { condition: math.unknown(0, 1) > 0 }`,
			message: "unsupported module: math",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewCompiler().CompileSource(tt.source)
			if err == nil || !strings.Contains(err.Error(), tt.message) {
				t.Fatalf("CompileSource() error = %v, want containing %q", err, tt.message)
			}
		})
	}
}
