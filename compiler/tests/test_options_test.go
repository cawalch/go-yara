package tests

import (
	"context"
	"testing"
)

func TestCompilerWarningsOption(t *testing.T) {
	// Test that warnings are properly configured
	source := `
		rule Test {
			strings:
				$unused = "test"
			condition:
				true
		}
	`

	// Test with warnings enabled (should produce warnings)
	compilerWithWarnings := createTestCompiler(withWarnings(true))
	program, err := compilerWithWarnings.CompileSourceWithContext(context.Background(), source)
	if err != nil {
		t.Fatalf("Compilation failed: %v", err)
	}

	warnings := compilerWithWarnings.GetWarnings()
	if len(warnings) == 0 {
		t.Error("Expected warnings when warnings are enabled, but got none")
	}

	// Test with warnings disabled (should produce no warnings)
	compilerWithoutWarnings := createTestCompiler(withWarnings(false))
	program2, err := compilerWithoutWarnings.CompileSourceWithContext(context.Background(), source)
	if err != nil {
		t.Fatalf("Compilation failed: %v", err)
	}

	warnings2 := compilerWithoutWarnings.GetWarnings()
	if len(warnings2) != 0 {
		t.Errorf("Expected no warnings when warnings are disabled, but got %d", len(warnings2))
	}

	// Both programs should be valid
	if program == nil {
		t.Error("Program with warnings should not be nil")
	}
	if program2 == nil {
		t.Error("Program without warnings should not be nil")
	}
}
