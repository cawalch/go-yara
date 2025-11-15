// Package testutils provides shared utilities and helpers for compiler testing.
package testutils

import (
	"fmt"
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/compiler"
	"github.com/cawalch/go-yara/token"
)

// TestCompilerOptions provides configuration for test compilers
type TestCompilerOptions struct {
	EnableOptimizations bool
	EnableWarnings      bool
	EnableDebugInfo     bool
	StrictMode          bool
	MaxErrors           int
	TargetVersion       string
}

// DefaultTestCompilerOptions returns sensible defaults for testing
func DefaultTestCompilerOptions() TestCompilerOptions {
	return TestCompilerOptions{
		EnableOptimizations: true,
		EnableWarnings:      true,
		EnableDebugInfo:     false,
		StrictMode:          false,
		MaxErrors:           10,
		TargetVersion:       "1.0",
	}
}

// CreateTestCompiler creates a compiler instance with test-friendly defaults
func CreateTestCompiler(opts ...func(*TestCompilerOptions)) *compiler.Compiler {
	options := DefaultTestCompilerOptions()
	for _, opt := range opts {
		opt(&options)
	}

	// Convert test options to compiler options
	compilerOpts := compiler.CompilationOptions{
		EnableOptimizations: options.EnableOptimizations,
		EnableDebugInfo:     options.EnableDebugInfo,
		EnableWarnings:      options.EnableWarnings,
		TargetVersion:       options.TargetVersion,
	}

	c := compiler.NewCompilerWithOptions(compilerOpts)
	return c
}

// WithOptimizations sets optimization level for test compiler
func WithOptimizations(enabled bool) func(*TestCompilerOptions) {
	return func(opts *TestCompilerOptions) {
		opts.EnableOptimizations = enabled
	}
}

// WithWarnings enables or disables warnings for test compiler
func WithWarnings(enabled bool) func(*TestCompilerOptions) {
	return func(opts *TestCompilerOptions) {
		opts.EnableWarnings = enabled
	}
}

// WithDebugInfo enables or disables debug info for test compiler
func WithDebugInfo(enabled bool) func(*TestCompilerOptions) {
	return func(opts *TestCompilerOptions) {
		opts.EnableDebugInfo = enabled
	}
}

// WithTargetVersion sets target version for test compiler
func WithTargetVersion(version string) func(*TestCompilerOptions) {
	return func(opts *TestCompilerOptions) {
		opts.TargetVersion = version
	}
}

// WithStrictMode enables strict parsing for tests
func WithStrictMode(enabled bool) func(*TestCompilerOptions) {
	return func(opts *TestCompilerOptions) {
		opts.StrictMode = enabled
	}
}

// CompileTestRule compiles a simple test rule and returns the program
func CompileTestRule(t *testing.T, source string) *compiler.CompiledProgram {
	t.Helper()

	c := CreateTestCompiler()
	program, err := c.CompileSource(source)
	if err != nil {
		t.Logf("Compilation errors: %v", c.GetErrors())
		t.Fatalf("Failed to compile test rule: %v", err)
	}

	return program
}

// CompileTestRuleWithError compiles a rule and returns both program and errors
func CompileTestRuleWithError(t *testing.T, source string) (*compiler.CompiledProgram, []error) {
	t.Helper()

	c := CreateTestCompiler()
	program, err := c.CompileSource(source)
	compErrors := c.GetErrors()

	// Convert compilation errors to standard errors
	errors := make([]error, 0, 1+len(compErrors))
	if err != nil {
		errors = append(errors, err)
	}
	for _, compErr := range compErrors {
		errors = append(errors, fmt.Errorf("%s: %s", compErr.Phase, compErr.Message))
	}

	return program, errors
}

// AssertProgramValid checks if a compiled program is valid
func AssertProgramValid(t *testing.T, program *compiler.CompiledProgram) {
	t.Helper()

	if program == nil {
		t.Fatal("Compiled program is nil")
	}

	if err := program.Validate(); err != nil {
		t.Errorf("Program validation failed: %v", err)
	}
}

// AssertRuleCount checks the number of rules in a compiled program
func AssertRuleCount(t *testing.T, program *compiler.CompiledProgram, expected int) {
	t.Helper()

	if program == nil {
		t.Fatal("Cannot check rule count on nil program")
	}

	actual := program.GetRuleCount()
	if actual != expected {
		t.Errorf("Expected %d rules, got %d", expected, actual)
	}
}

// CreateTestAST creates a simple AST node for testing
func CreateTestAST() *ast.Program {
	return &ast.Program{
		Rules: []*ast.Rule{
			{
				Name: "test_rule",
				Meta: []*ast.Meta{
					{
						Key:   "author",
						Value: ast.MetaString("test"),
					},
					{
						Key:   "date",
						Value: ast.MetaString("2024"),
					},
				},
				Strings: []*ast.String{
					{
						Identifier: "$test",
						Pattern: &ast.TextString{
							Value: "test pattern",
						},
						Modifiers: []ast.StringModifier{
							{Type: ast.StringModifierNocase},
						},
					},
				},
				Condition: &ast.Literal{Type: token.TRUE, Value: true},
			},
		},
	}
}

// CreateTestToken creates a token for testing
func CreateTestToken(tokenType token.Type, literal string, pos token.Position) token.Token {
	return token.Token{
		Type:    tokenType,
		Literal: literal,
		Pos:     pos,
	}
}

// AssertNoCompilationErrors checks that compilation succeeded without errors
func AssertNoCompilationErrors(t *testing.T, comp *compiler.Compiler) {
	t.Helper()

	errors := comp.GetErrors()
	if len(errors) > 0 {
		t.Errorf("Expected no compilation errors, got %d: %v", len(errors), errors)
	}
}

// AssertCompilationErrorCount checks that compilation produced expected number of errors
func AssertCompilationErrorCount(t *testing.T, comp *compiler.Compiler, expected int) {
	t.Helper()

	errors := comp.GetErrors()
	actual := len(errors)
	if actual != expected {
		t.Errorf("Expected %d compilation errors, got %d", expected, actual)
	}
}
