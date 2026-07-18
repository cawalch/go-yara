package tests

import (
	"context"
	"fmt"
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/compiler"
	"github.com/cawalch/go-yara/token"
)

type testCompilerOptions struct {
	enableWarnings bool
}

func createTestCompiler(opts ...func(*testCompilerOptions)) *compiler.Compiler {
	options := testCompilerOptions{enableWarnings: true}
	for _, opt := range opts {
		opt(&options)
	}
	return compiler.NewCompiler(compiler.WithWarnings(options.enableWarnings))
}

func withWarnings(enabled bool) func(*testCompilerOptions) {
	return func(opts *testCompilerOptions) {
		opts.enableWarnings = enabled
	}
}

func compileTestRule(t *testing.T, source string) *compiler.CompiledProgram {
	t.Helper()

	c := createTestCompiler()
	program, err := c.CompileSourceWithContext(context.Background(), source)
	if err != nil {
		t.Logf("Compilation errors: %v", c.GetErrors())
		t.Fatalf("Failed to compile test rule: %v", err)
	}
	return program
}

func compileTestRuleWithError(t *testing.T, source string) (*compiler.CompiledProgram, []error) {
	t.Helper()

	c := createTestCompiler()
	program, err := c.CompileSourceWithContext(context.Background(), source)
	compErrors := c.GetErrors()
	errors := make([]error, 0, 1+len(compErrors))
	if err != nil {
		errors = append(errors, err)
	}
	for _, compErr := range compErrors {
		errors = append(errors, fmt.Errorf("%s: %s", compErr.Phase, compErr.Message))
	}
	return program, errors
}

func assertProgramValid(t *testing.T, program *compiler.CompiledProgram) {
	t.Helper()
	if program == nil {
		t.Fatal("Compiled program is nil")
	}
	if err := program.Validate(); err != nil {
		t.Errorf("Program validation failed: %v", err)
	}
}

func assertRuleCount(t *testing.T, program *compiler.CompiledProgram, expected int) {
	t.Helper()
	if program == nil {
		t.Fatal("Cannot check rule count on nil program")
	}
	if actual := program.GetRuleCount(); actual != expected {
		t.Errorf("Expected %d rules, got %d", expected, actual)
	}
}

func createTestAST() *ast.Program {
	return &ast.Program{
		Rules: []*ast.Rule{
			{
				Name: "test_rule",
				Meta: []*ast.Meta{
					{Key: "author", Value: ast.MetaString("test")},
					{Key: "date", Value: ast.MetaString("2024")},
				},
				Strings: []*ast.String{
					{
						Identifier: "$test",
						Pattern:    &ast.TextString{Value: "test pattern"},
						Modifiers:  []ast.StringModifier{{Type: ast.StringModifierNocase}},
					},
				},
				Condition: &ast.Literal{Type: token.TRUE, Value: true},
			},
		},
	}
}
