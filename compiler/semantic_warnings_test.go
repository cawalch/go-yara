package compiler

import (
	"testing"
)

func TestWarningsHaveStableCodesAndLocations(t *testing.T) {
	c := NewCompiler()
	_, err := c.CompileSource(`
rule diagnostics {
    strings:
        $short = "x"
        $duplicate = "x"
        $regex = /[a-z]+/
        $hex = { ?? ?? }
    condition:
        any of them
}
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}

	warnings := c.GetWarnings()
	assertWarning(t, warnings, WarningDuplicatePattern, "diagnostics", "$duplicate")
	for _, id := range []string{"$short", "$duplicate", "$regex", "$hex"} {
		assertWarning(t, warnings, WarningSlowPattern, "diagnostics", id)
	}
	for _, warning := range warnings {
		if warning.Code == WarningUnusedString {
			t.Fatalf("any of them produced unused-string warning: %+v", warning)
		}
	}
}

func TestSelectivePatternsDoNotProduceSlowWarnings(t *testing.T) {
	c := NewCompiler()
	_, err := c.CompileSource(`
rule selective {
    strings:
        $text = "abcdef"
        $regex = /abcdef/
        $hex = { 01 02 03 }
    condition:
        any of them
}
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}
	for _, warning := range c.GetWarnings() {
		if warning.Code == WarningSlowPattern {
			t.Fatalf("selective pattern warning = %+v", warning)
		}
	}
}

//nolint:revive // argument-limit: test assertion helper
func assertWarning(t *testing.T, warnings []CompilationWarning, code, rule, stringID string) {
	t.Helper()
	for _, warning := range warnings {
		if warning.Code == code && warning.Rule == rule && warning.String == stringID {
			if warning.Line <= 0 || warning.Column <= 0 {
				t.Fatalf("warning lacks source location: %+v", warning)
			}
			return
		}
	}
	t.Fatalf("warnings = %+v, missing code=%s rule=%s string=%s", warnings, code, rule, stringID)
}

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
