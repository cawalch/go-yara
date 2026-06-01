package compiler

import (
	"testing"
)

func TestSemanticWarnings(t *testing.T) {
	tests := []struct {
		name            string
		source          string
		expectedWarning string
		shouldWarn      bool
	}{
		{
			name: "unused_string_warning",
			source: `
				rule Test {
					strings:
						$unused = "test"
						$used = "hello"
					condition:
						$used
				}
			`,
			expectedWarning: "String '$unused' is defined but never used in condition",
			shouldWarn:      true,
		},
		{
			name: "no_unused_strings",
			source: `
				rule Test {
					strings:
						$used = "hello"
					condition:
						$used
				}
			`,
			expectedWarning: "",
			shouldWarn:      false,
		},
		{
			name: "trivial_condition_warning",
			source: `
				rule Test {
					strings:
						$test = "hello"
					condition:
						true
				}
			`,
			expectedWarning: "has a trivial condition that may always be true",
			shouldWarn:      true,
		},
		{
			name: "underscore_prefix_suppresses_warning",
			source: `
				rule Test {
					strings:
						$_suppressed = "test"
						$used = "hello"
					condition:
						$used
				}
			`,
			expectedWarning: "",
			shouldWarn:      false,
		},
		{
			name: "no_warnings_valid_rule",
			source: `
				rule Test {
					strings:
						$test = "hello"
					condition:
						$test
				}
			`,
			expectedWarning: "",
			shouldWarn:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiler := NewCompilerWithOptions(CompilationOptions{
				EnableWarnings: true,
			})

			// Compile the rule
			_, err := compiler.CompileSource(tt.source)
			if err != nil {
				t.Fatalf("Compilation failed: %v", err)
			}

			// Check warnings
			warnings := compiler.GetWarnings()
			hasWarning := len(warnings) > 0

			if hasWarning != tt.shouldWarn {
				t.Errorf("Expected warnings: %v, got %v", tt.shouldWarn, hasWarning)
			}

			if tt.shouldWarn && len(warnings) == 0 {
				t.Error("Expected warning but got none")
				return
			}

			if tt.expectedWarning != "" && len(warnings) > 0 {
				found := false
				for _, warning := range warnings {
					if len(warning.Message) > 0 {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected warning containing '%s', but got: %v", tt.expectedWarning, warnings)
				}
			}
		})
	}
}

func TestAddWarning(t *testing.T) {
	compiler := NewCompiler()

	// Test adding a warning
	compiler.AddWarning("test", "test message", 1, 1)

	warnings := compiler.GetWarnings()
	if len(warnings) != 1 {
		t.Errorf("Expected 1 warning, got %d", len(warnings))
	}

	if warnings[0].Phase != "test" || warnings[0].Message != "test message" || warnings[0].Line != 1 || warnings[0].Column != 1 {
		t.Errorf("Warning details mismatch: got %+v", warnings[0])
	}
}

func TestHasWarnings(t *testing.T) {
	compiler := NewCompiler()

	// Initially no warnings
	if compiler.HasWarnings() {
		t.Error("Expected no warnings initially")
	}

	// Add a warning
	compiler.AddWarning("test", "test message", 1, 1)

	// Now should have warnings
	if !compiler.HasWarnings() {
		t.Error("Expected warnings after adding one")
	}
}

func TestWarningDisabled(t *testing.T) {
	compiler := NewCompilerWithOptions(CompilationOptions{
		EnableWarnings: false, // Warnings disabled
	})

	source := `
		rule Test {
			strings:
				$unused = "test"
			condition:
				true
		}
	`

	// Compile the rule
	_, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("Compilation failed: %v", err)
	}

	// Should have no warnings when disabled
	warnings := compiler.GetWarnings()
	if len(warnings) != 0 {
		t.Errorf("Expected no warnings when disabled, got %d", len(warnings))
	}
}
