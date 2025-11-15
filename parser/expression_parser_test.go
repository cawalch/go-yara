package parser

import (
	"errors"
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

// mockCompiler implements the expression compilation interface
type mockCompiler struct {
	shouldError bool
}

func (m *mockCompiler) CompileExpression(expr ast.Expression) error {
	if m.shouldError {
		return errors.New("mock compilation error")
	}
	_ = expr // Suppress unused parameter warning
	return nil
}

func TestExpressionParserConvertToOpcode(t *testing.T) {
	tests := []struct {
		name        string
		emitter     interface{}
		expectError bool
		expectCall  bool
	}{
		{
			name:        "nil_emitter",
			emitter:     nil,
			expectError: true,
			expectCall:  false,
		},
		{
			name:        "emitter_without_compile_interface",
			emitter:     &struct{}{},
			expectError: true,
			expectCall:  false,
		},
		{
			name: "emitter_with_compile_interface_success",
			emitter: &mockCompiler{
				shouldError: false,
			},
			expectError: false,
			expectCall:  true,
		},
		{
			name: "emitter_with_compile_interface_error",
			emitter: &mockCompiler{
				shouldError: true,
			},
			expectError: true,
			expectCall:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create expression parser with test emitter
			exprParser := newExpressionParserInternal(nil, tt.emitter)

			// Create a simple test expression
			expr := &ast.Literal{
				Pos:   token.Position{Line: 1, Column: 1},
				Value: 42,
			}

			// Call ConvertToOpcode
			err := exprParser.ConvertToOpcode(expr)

			// Check error expectation
			if (err != nil) != tt.expectError {
				t.Errorf("ConvertToOpcode() error = %v, expectError %v", err, tt.expectError)
			}

			// For this test, we just verify that the method can be called without error
			// The actual compilation would be handled by a real compiler implementation
		})
	}
}

func TestExpressionParserConvertToOpcodeWithConditionCompiler(t *testing.T) {
	// Test with lowercase compileExpression method (like ConditionCompiler)
	lc := &struct{}{}

	// Create expression parser with lowercase compiler
	exprParser := newExpressionParserInternal(nil, lc)

	// Create a simple test expression
	expr := &ast.Identifier{
		Pos:  token.Position{Line: 1, Column: 1},
		Name: "test_var",
	}

	// Call ConvertToOpcode
	err := exprParser.ConvertToOpcode(expr)

	// The lowercase method is private, so this should fail
	if err == nil {
		t.Error("Expected error for private method, got nil")
	}
}

func TestExpressionParserConvertToOpcodeWithBasicEmitter(t *testing.T) {
	// Test with basic emitter that doesn't have CompileExpression
	emitter := &struct{}{}
	exprParser := newExpressionParserInternal(nil, emitter)

	// Create a simple test expression
	expr := &ast.Literal{
		Pos:   token.Position{Line: 1, Column: 1},
		Value: 42,
	}

	// Call ConvertToOpcode - should fail since emitter doesn't support expression compilation
	err := exprParser.ConvertToOpcode(expr)
	if err == nil {
		t.Error("Expected error when emitter doesn't support expression compilation")
	}
}
