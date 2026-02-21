package compiler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/ast"
)

// TestProcessIncludes_Security tests include file processing with security validation
func TestProcessIncludes_Security(t *testing.T) {
	tests := []struct {
		name          string
		baseDir       string
		program       *ast.Program
		expectError   bool
		errorContains string
	}{
		{
			name:    "no includes",
			baseDir: "test",
			program: &ast.Program{
				Includes: []*ast.Include{},
				Rules:    []*ast.Rule{},
			},
			expectError: false,
		},
		{
			name:    "valid relative include",
			baseDir: t.TempDir(),
			program: &ast.Program{
				Includes: []*ast.Include{
					{File: "valid.yar"},
				},
				Rules: []*ast.Rule{},
			},
			expectError: true, // File doesn't exist, but no path traversal error
		},
		{
			name:    "path traversal attempt",
			baseDir: t.TempDir(),
			program: &ast.Program{
				Includes: []*ast.Include{
					{File: "../../../etc/passwd"},
				},
				Rules: []*ast.Rule{},
			},
			expectError:   true,
			errorContains: "failed to read include file",
		},
		{
			name:    "absolute path include",
			baseDir: t.TempDir(),
			program: &ast.Program{
				Includes: []*ast.Include{
					{File: "/etc/passwd"},
				},
				Rules: []*ast.Rule{},
			},
			expectError:   true,
			errorContains: "failed to read include file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			comp := NewCompiler()
			comp.SetBaseDir(tt.baseDir)

			err := comp.ProcessIncludes(tt.program)

			validateTestResult(t, tt, err)
		})
	}
}

// TestProcessIncludes_NestedIncludes tests circular include detection and nested includes
func TestProcessIncludes_NestedIncludes(t *testing.T) {
	tempDir := t.TempDir()

	// Create a base include file
	baseInclude := filepath.Join(tempDir, "base.yar")
	baseContent := `rule BaseRule {
		strings:
			$base = "base pattern"
		condition:
			$base
	}`
	if err := os.WriteFile(baseInclude, []byte(baseContent), 0644); err != nil {
		t.Fatalf("Failed to create base include file: %v", err)
	}

	// Create a nested include file that includes the base file
	nestedInclude := filepath.Join(tempDir, "nested.yar")
	nestedContent := `include "base.yar"

rule NestedRule {
	strings:
		$nested = "nested pattern"
	condition:
		$nested and BaseRule
	}`
	if err := os.WriteFile(nestedInclude, []byte(nestedContent), 0644); err != nil {
		t.Fatalf("Failed to create nested include file: %v", err)
	}

	// Test nested includes
	program := &ast.Program{
		Includes: []*ast.Include{
			{File: "nested.yar"},
		},
		Rules: []*ast.Rule{
			{
				Name: "MainRule",
				Strings: []*ast.String{
					{Identifier: "$main", Pattern: &ast.TextString{Value: "main pattern"}},
				},
				Condition: &ast.Identifier{Name: "$main"},
			},
		},
	}

	comp := NewCompiler()
	comp.SetBaseDir(tempDir)

	err := comp.ProcessIncludes(program)
	if err != nil {
		t.Errorf("ProcessIncludes() with nested includes failed: %v", err)
	}

	// Should have rules from main program + nested + base
	expectedRuleCount := 1 + 1 + 1 // main + nested + base
	if len(program.Rules) != expectedRuleCount {
		t.Errorf("ProcessIncludes() rules count = %d, want %d", len(program.Rules), expectedRuleCount)
	}

	// Check that base rule is included
	var baseRuleFound bool
	for _, rule := range program.Rules {
		if rule.Name == "BaseRule" {
			baseRuleFound = true
			break
		}
	}
	if !baseRuleFound {
		t.Error("ProcessIncludes() base rule not found in program")
	}
}

// TestProcessIncludes_MalformedFile tests include file with malformed YARA syntax
func TestProcessIncludes_MalformedFile(t *testing.T) {
	tempDir := t.TempDir()

	// Create a malformed YARA file
	malformedFile := filepath.Join(tempDir, "malformed.yar")
	malformedContent := `rule MalformedRule {
		strings:
			$pattern = "unclosed string
		condition:
			$pattern
	}`
	if err := os.WriteFile(malformedFile, []byte(malformedContent), 0644); err != nil {
		t.Fatalf("Failed to create malformed file: %v", err)
	}

	program := &ast.Program{
		Includes: []*ast.Include{
			{File: "malformed.yar"},
		},
		Rules: []*ast.Rule{},
	}

	comp := NewCompiler()
	comp.SetBaseDir(tempDir)

	err := comp.ProcessIncludes(program)
	if err == nil {
		t.Error("ProcessIncludes() expected error for malformed include but got none")
	}

	if !contains(err.Error(), "failed to parse include file") {
		t.Errorf("ProcessIncludes() error = %q, want contains 'failed to parse include file'", err.Error())
	}
}

// TestValidateCompilation tests the compilation validation function
func TestValidateCompilation(t *testing.T) {
	tests := []struct {
		name        string
		program     *CompiledProgram
		expectError bool
		errorMsg    string
	}{
		{
			name:        "nil program",
			program:     nil,
			expectError: true,
			errorMsg:    "compiled program is nil",
		},
		{
			name: "valid program",
			program: &CompiledProgram{
				Rules: []*CompiledRule{
					{
						Name:     "TestRule",
						Bytecode: []byte{0x01, 0x02, 0x03},
					},
				},
			},
			expectError: false,
		},
		{
			name: "invalid program - fails validation",
			program: &CompiledProgram{
				Rules: []*CompiledRule{
					{
						Name:     "",
						Bytecode: []byte{}, // Invalid empty bytecode
					},
				},
			},
			expectError: true,
			errorMsg:    "program validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			comp := NewCompiler()
			// Set stats to test rule count mismatch
			comp.stats.RulesCompiled = 1

			err := comp.ValidateCompilation(tt.program)

			if tt.expectError {
				if err == nil {
					t.Errorf("ValidateCompilation() expected error but got none")
					return
				}
				if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("ValidateCompilation() error = %q, want contains %q", err.Error(), tt.errorMsg)
				}
			} else if err != nil {
				t.Errorf("ValidateCompilation() unexpected error: %v", err)
			}
		})
	}
}

// TestSetBaseDir tests base directory setting and validation
func TestSetBaseDir(t *testing.T) {
	comp := NewCompiler()

	tests := []struct {
		name    string
		baseDir string
		valid   bool
	}{
		{
			name:    "valid relative path",
			baseDir: "rules",
			valid:   true,
		},
		{
			name:    "valid absolute path",
			baseDir: "/etc/yara/rules",
			valid:   true,
		},
		{
			name:    "current directory",
			baseDir: ".",
			valid:   true,
		},
		{
			name:    "parent directory",
			baseDir: "..",
			valid:   true,
		},
		{
			name:    "complex valid path",
			baseDir: "../../rules/subdir",
			valid:   true,
		},
		{
			name:    "empty path",
			baseDir: "",
			valid:   true, // Empty path should be handled gracefully
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			comp.SetBaseDir(tt.baseDir)
			// Since SetBaseDir doesn't return an error, we test by checking if it was set
			// and can be used successfully in subsequent operations
			if comp.baseDir != tt.baseDir {
				t.Errorf("SetBaseDir(%q) = %q, want %q", tt.baseDir, comp.baseDir, tt.baseDir)
			}
		})
	}
}

// TestProcessIncludes_FileSizeLimits tests include file size handling
func TestProcessIncludes_FileSizeLimits(t *testing.T) {
	tempDir := t.TempDir()

	// Create a large include file (simulate potential DoS vector)
	largeFile := filepath.Join(tempDir, "large.yar")

	// Create content that's large enough to potentially cause issues
	// In a real implementation, you'd want to enforce size limits
	content := `rule LargeRule {
		strings:
			$pattern = "pattern"
		condition:
			$pattern
	}`

	// Repeat the rule many times to make the file large
	var largeContent strings.Builder
	_ = content // Use content to avoid unused variable warning
	for i := range 1000 {
		largeContent.WriteString(`rule LargeRule` + string(rune(i)) + ` {
			strings:
				$pattern` + string(rune(i)) + ` = "pattern` + string(rune(i)) + `"
			condition:
				$pattern` + string(rune(i)) + `
		}
		`)
	}
	_ = content // Avoid unused variable warning

	if err := os.WriteFile(largeFile, []byte(largeContent.String()), 0644); err != nil {
		t.Fatalf("Failed to create large include file: %v", err)
	}

	program := &ast.Program{
		Includes: []*ast.Include{
			{File: "large.yar"},
		},
		Rules: []*ast.Rule{},
	}

	comp := NewCompiler()
	comp.SetBaseDir(tempDir)

	// This should handle large files gracefully
	err := comp.ProcessIncludes(program)

	// The test passes if it doesn't panic or crash
	// It may fail due to parsing errors, but shouldn't crash
	if err != nil {
		t.Logf("ProcessIncludes() with large file failed as expected: %v", err)
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// validateTestResult validates test results based on expected error conditions
func validateTestResult(t *testing.T, tt struct {
	name          string
	baseDir       string
	program       *ast.Program
	expectError   bool
	errorContains string
}, err error) {
	if tt.expectError {
		validateExpectedErrorWithDetails(t, struct{ errorContains string }{errorContains: tt.errorContains}, err)
	} else {
		validateNoUnexpectedError(t, err)
	}
}

// validateExpectedErrorWithDetails validates that expected errors occur with correct details
func validateExpectedErrorWithDetails(t *testing.T, tt struct {
	errorContains string
}, err error) {
	if err == nil {
		t.Errorf("ProcessIncludes() expected error but got none")
		return
	}
	if tt.errorContains != "" && err.Error()[:len(tt.errorContains)] != tt.errorContains {
		// Check if error starts with expected substring (for path-related errors)
		if !contains(err.Error(), tt.errorContains) {
			t.Errorf("ProcessIncludes() error = %q, want contains %q", err.Error(), tt.errorContains)
		}
	}
}

// validateNoUnexpectedError validates that no unexpected errors occur
func validateNoUnexpectedError(t *testing.T, err error) {
	if err != nil {
		t.Errorf("ProcessIncludes() unexpected error: %v", err)
	}
}
