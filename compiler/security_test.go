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

			if tt.expectError {
				if err == nil {
					t.Fatal("ProcessIncludes() expected error, got nil")
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Fatalf("ProcessIncludes() error = %q, want substring %q", err, tt.errorContains)
				}
			} else if err != nil {
				t.Fatalf("ProcessIncludes() unexpected error: %v", err)
			}
		})
	}
}

func TestProcessIncludesRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	baseDir := filepath.Join(root, "base")
	outsideDir := filepath.Join(root, "outside")
	if err := os.MkdirAll(baseDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(base) error = %v", err)
	}
	if err := os.MkdirAll(outsideDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(outside) error = %v", err)
	}

	outsideRule := filepath.Join(outsideDir, "outside.yar")
	if err := os.WriteFile(outsideRule, []byte(`rule escaped { condition: true }`), 0o600); err != nil {
		t.Fatalf("WriteFile(outside) error = %v", err)
	}
	link := filepath.Join(baseDir, "link.yar")
	if err := os.Symlink(outsideRule, link); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}

	program := &ast.Program{Includes: []*ast.Include{{File: "link.yar"}}}
	comp := NewCompiler()
	comp.SetBaseDir(baseDir)
	err := comp.ProcessIncludes(program)
	if err == nil || !strings.Contains(err.Error(), "path traversal detected") {
		t.Fatalf("ProcessIncludes() error = %v, want symlink traversal rejection", err)
	}
}

func TestProcessIncludesAllowsSymlinkWithinBase(t *testing.T) {
	baseDir := t.TempDir()
	targetDir := filepath.Join(baseDir, "rules")
	if err := os.MkdirAll(targetDir, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	target := filepath.Join(targetDir, "target.yar")
	if err := os.WriteFile(target, []byte(`rule linked { condition: true }`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Symlink(target, filepath.Join(baseDir, "link.yar")); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}

	program := &ast.Program{Includes: []*ast.Include{{File: "link.yar"}}}
	comp := NewCompiler()
	comp.SetBaseDir(baseDir)
	if err := comp.ProcessIncludes(program); err != nil {
		t.Fatalf("ProcessIncludes() error = %v", err)
	}
	if len(program.Rules) != 1 || program.Rules[0].Name != "linked" {
		t.Fatalf("included rules = %+v, want linked", program.Rules)
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

	if !strings.Contains(err.Error(), "failed to parse include file") {
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
				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
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
	largeFile := filepath.Join(tempDir, "large.yar")
	content := []byte(`rule LargeRule {
		strings:
			$pattern = "pattern"
		condition:
			$pattern
	}`)
	if err := os.WriteFile(largeFile, content, 0644); err != nil {
		t.Fatalf("Failed to create large include file: %v", err)
	}

	program := &ast.Program{
		Includes: []*ast.Include{
			{File: "large.yar"},
		},
		Rules: []*ast.Rule{},
	}

	comp := NewCompiler(WithMaxIncludeSize(int64(len(content) - 1)))
	comp.SetBaseDir(tempDir)

	err := comp.ProcessIncludes(program)
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum allowed") {
		t.Fatalf("ProcessIncludes() error = %v, want include size limit error", err)
	}
}

func TestCompileFileEnforcesInputSizeBeforeCompilation(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "large.yar")
	content := []byte(`rule large { condition: true }`)
	if err := os.WriteFile(filename, content, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := NewCompiler(WithMaxInputSize(int64(len(content) - 1))).CompileFile(filename)
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum allowed") {
		t.Fatalf("CompileFile() error = %v, want input size limit error", err)
	}
}

func TestCompileFileResolvesIncludesFromConfiguredBaseDirectory(t *testing.T) {
	baseDir := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(baseDir, "included.yar"),
		[]byte(`rule included { condition: true }`),
		0o600,
	); err != nil {
		t.Fatalf("WriteFile(include) error = %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(baseDir, "main.yar"),
		[]byte("include \"included.yar\"\nrule main { condition: included }"),
		0o600,
	); err != nil {
		t.Fatalf("WriteFile(main) error = %v", err)
	}

	comp := NewCompiler()
	comp.SetBaseDir(baseDir)
	program, err := comp.CompileFile("main.yar")
	if err != nil {
		t.Fatalf("CompileFile() error = %v", err)
	}
	if len(program.Rules) != 2 {
		t.Fatalf("CompileFile() compiled %d rules, want 2", len(program.Rules))
	}
}

func TestProcessIncludesRejectsCircularInclude(t *testing.T) {
	tempDir := t.TempDir()
	files := map[string]string{
		"a.yar": "include \"b.yar\"\nrule A { condition: true }",
		"b.yar": "include \"a.yar\"\nrule B { condition: true }",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(tempDir, name), []byte(content), 0644); err != nil {
			t.Fatalf("WriteFile(%q) error = %v", name, err)
		}
	}

	program := &ast.Program{
		Includes: []*ast.Include{{File: "a.yar"}},
	}
	comp := NewCompiler()
	comp.SetBaseDir(tempDir)
	err := comp.ProcessIncludes(program)
	if err == nil || !strings.Contains(err.Error(), "circular include detected") {
		t.Fatalf("ProcessIncludes() error = %v, want circular include error", err)
	}
}
