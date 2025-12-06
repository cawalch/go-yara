package tests

import (
	"context"
	"testing"

	"github.com/cawalch/go-yara/compiler/tests/testutils"
)

func TestCreateTestCompilerWithOptions(t *testing.T) {
	// Test with default options
	defaultCompiler := testutils.CreateTestCompiler()
	if defaultCompiler == nil {
		t.Fatal("Default compiler should not be nil")
	}

	// Test with optimizations disabled
	noOptCompiler := testutils.CreateTestCompiler(testutils.WithOptimizations(false))
	if noOptCompiler == nil {
		t.Fatal("Compiler should not be nil")
	}

	// Test with warnings disabled
	noWarnCompiler := testutils.CreateTestCompiler(testutils.WithWarnings(false))
	if noWarnCompiler == nil {
		t.Fatal("Compiler should not be nil")
	}

	// Test with debug info enabled
	debugCompiler := testutils.CreateTestCompiler(testutils.WithDebugInfo(true))
	if debugCompiler == nil {
		t.Fatal("Compiler should not be nil")
	}

	// Test with multiple options
	multiOptionCompiler := testutils.CreateTestCompiler(
		testutils.WithOptimizations(false),
		testutils.WithWarnings(false),
		testutils.WithDebugInfo(true),
		testutils.WithTargetVersion("1.1"),
	)
	if multiOptionCompiler == nil {
		t.Fatal("Compiler with multiple options should not be nil")
	}
}

func TestTestCompilerOptionsWithWarnings(t *testing.T) {
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
	compilerWithWarnings := testutils.CreateTestCompiler(testutils.WithWarnings(true))
	program, err := compilerWithWarnings.CompileSourceWithContext(context.Background(), source)
	if err != nil {
		t.Fatalf("Compilation failed: %v", err)
	}

	warnings := compilerWithWarnings.GetWarnings()
	if len(warnings) == 0 {
		t.Error("Expected warnings when warnings are enabled, but got none")
	}

	// Test with warnings disabled (should produce no warnings)
	compilerWithoutWarnings := testutils.CreateTestCompiler(testutils.WithWarnings(false))
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

func TestTestCompilerOptionsWithOptimizations(t *testing.T) {
	// Test that optimization setting is applied
	source := `
		rule Test {
			strings:
				$a = "hello"
			condition:
				$a
		}
	`

	// Test with optimizations enabled
	optimizedCompiler := testutils.CreateTestCompiler(testutils.WithOptimizations(true))
	program1, err := optimizedCompiler.CompileSourceWithContext(context.Background(), source)
	if err != nil {
		t.Fatalf("Compilation failed with optimizations: %v", err)
	}

	// Test with optimizations disabled
	unoptimizedCompiler := testutils.CreateTestCompiler(testutils.WithOptimizations(false))
	program2, err := unoptimizedCompiler.CompileSourceWithContext(context.Background(), source)
	if err != nil {
		t.Fatalf("Compilation failed without optimizations: %v", err)
	}

	// Both should compile successfully
	if program1 == nil {
		t.Error("Optimized program should not be nil")
	}
	if program2 == nil {
		t.Error("Unoptimized program should not be nil")
	}

	// String count should be the same
	if program1.GetStringCount() != program2.GetStringCount() {
		t.Errorf("String count mismatch: optimized=%d, unoptimized=%d",
			program1.GetStringCount(), program2.GetStringCount())
	}
}
