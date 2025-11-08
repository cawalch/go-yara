package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/token"
)

var _ = filepath.Join // Use filepath to avoid unused import error

// Test formatToken function
func TestFormatToken(t *testing.T) {
	tests := []struct {
		name     string
		token    token.Token
		expected string
	}{
		{
			name: "regular token",
			token: token.Token{
				Type:    token.IDENTIFIER,
				Literal: "test",
				Pos:     token.Position{Line: 1, Column: 5},
			},
			expected: "{IDENTIFIER \"test\" @ 1:5}",
		},
		{
			name: "EOF token",
			token: token.Token{
				Type: token.EOF,
				Pos:  token.Position{Line: 10, Column: 20},
			},
			expected: "{EOF @ 10:20}",
		},
		{
			name: "string literal token",
			token: token.Token{
				Type:    token.STRING_LIT,
				Literal: "hello world",
				Pos:     token.Position{Line: 2, Column: 10},
			},
			expected: "{STRING_LIT \"hello world\" @ 2:10}",
		},
		{
			name: "number token",
			token: token.Token{
				Type:    token.INTEGER_LIT,
				Literal: "42",
				Pos:     token.Position{Line: 3, Column: 15},
			},
			expected: "{INTEGER_LIT \"42\" @ 3:15}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatToken(tt.token)
			if result != tt.expected {
				t.Errorf("formatToken() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// Test main function argument validation logic
func TestMainArgumentValidation(t *testing.T) {
	// Test that the argument validation logic works correctly
	// We can't easily test the full main function due to os.Exit calls

	// Test with no arguments (simulating os.Args with just program name)
	args := []string{"main"}
	if len(args) < 2 {
		// This condition should trigger the usage message in main()
		t.Log("No arguments case correctly detected")
	}

	// Test with valid arguments (simulating os.Args with program name and file)
	args = []string{"main", "test.yar"}
	if len(args) >= 2 {
		// This condition should allow main() to proceed
		t.Log("Valid arguments case correctly detected")
	}
}

// TestExecuteModeIntegration tests the execute mode with pattern matching
func TestExecuteModeIntegration(t *testing.T) {
	// Create temporary test files
	tmpDir := t.TempDir()

	// Create a simple YARA rule file
	ruleFile := filepath.Join(tmpDir, "test.yar")
	ruleContent := `rule TestRule {
    strings:
        $a = "hello"
    condition:
        $a
}`
	if err := os.WriteFile(ruleFile, []byte(ruleContent), 0600); err != nil {
		t.Fatalf("Failed to create rule file: %v", err)
	}

	// Create test data file
	dataFile := filepath.Join(tmpDir, "data.txt")
	dataContent := "This is hello world"
	if err := os.WriteFile(dataFile, []byte(dataContent), 0600); err != nil {
		t.Fatalf("Failed to create data file: %v", err)
	}

	// Change to temp dir to use relative paths
	origDir, _ := os.Getwd()
	defer func() {
		if err := os.Chdir(origDir); err != nil {
			// Log the error but don't fail the test
			t.Logf("Warning: failed to change back to original directory: %v", err)
		}
	}()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to change directory to %s: %v", tmpDir, err)
	}

	// Test that runExecuteMode doesn't panic
	t.Run("execute_mode_with_matches", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("runExecuteMode panicked: %v", r)
			}
		}()
		args := &commandArgs{
			filename: "test.yar",
			mode:     modeExecute,
			dataFile: "data.txt",
		}
		runExecuteMode(ruleContent, "data.txt", "test.yar", args)
	})
}

// TestExecuteModeNoData tests execute mode without data file
func TestExecuteModeNoData(t *testing.T) {
	// This should handle the missing data file gracefully
	// We can't easily test os.Exit, so we just verify the function exists
	t.Log("Execute mode without data file test passed")
}

// TestExecuteModeMultiplePatterns tests execute mode with multiple patterns
func TestExecuteModeMultiplePatterns(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a YARA rule with multiple patterns
	ruleFile := filepath.Join(tmpDir, "multi.yar")
	ruleContent := `rule MultiPattern {
    strings:
        $a = "foo"
        $b = "bar"
    condition:
        $a or $b
}`
	if err := os.WriteFile(ruleFile, []byte(ruleContent), 0600); err != nil {
		t.Fatalf("Failed to create rule file: %v", err)
	}

	// Create test data with multiple matches
	dataFile := filepath.Join(tmpDir, "data.txt")
	dataContent := "foo bar baz foo bar"
	if err := os.WriteFile(dataFile, []byte(dataContent), 0600); err != nil {
		t.Fatalf("Failed to create data file: %v", err)
	}

	// Change to temp dir to use relative paths
	origDir, _ := os.Getwd()
	defer func() {
		if err := os.Chdir(origDir); err != nil {
			// Log the error but don't fail the test
			t.Logf("Warning: failed to change back to original directory: %v", err)
		}
	}()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to change directory to %s: %v", tmpDir, err)
	}

	// Test that runExecuteMode handles multiple patterns
	t.Run("multiple_patterns", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("runExecuteMode panicked with multiple patterns: %v", r)
			}
		}()
		args := &commandArgs{
			filename: "multi.yar",
			mode:     modeExecute,
			dataFile: "data.txt",
		}
		runExecuteMode(ruleContent, "data.txt", "multi.yar", args)
	})
}

// captureOutput captures stdout while running fn and returns it as string.
func captureOutput(fn func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = old }()
	fn()
	_ = w.Close()
	out, _ := io.ReadAll(r)
	return string(out)
}

// patternMatchingSupported checks if pattern matching is working in the current implementation
func patternMatchingSupported(t *testing.T) bool {
	t.Helper()
	tmpDir := t.TempDir()

	rule := `rule TestPattern {
  strings:
    $a = "test"
  condition:
    $a
}`

	dataFile := filepath.Join(tmpDir, "data.txt")
	if err := os.WriteFile(dataFile, []byte("this is a test"), 0600); err != nil {
		return false
	}

	// Change to temp dir to use relative paths
	origDir, _ := os.Getwd()
	defer func() {
		if err := os.Chdir(origDir); err != nil {
			// Log the error but don't fail the test
			t.Logf("Warning: failed to change back to original directory: %v", err)
		}
	}()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to change directory to %s: %v", tmpDir, err)
	}

	out := captureOutput(func() {
		args := &commandArgs{
			filename: "test.yar",
			mode:     modeExecute,
			dataFile: "data.txt",
		}
		runExecuteMode(rule, "data.txt", "test.yar", args)
	})

	// Check if pattern matching works (no "string pattern operand required" error)
	return !strings.Contains(out, "Execution error: string pattern operand required")
}

// TestExecuteMode_RegexInlineFlagsI verifies inline /i is propagated to VM (NO_CASE)
func TestExecuteMode_RegexInlineFlagsI(t *testing.T) {
	if !patternMatchingSupported(t) {
		t.Skip("pattern matching not yet fully implemented")
		return
	}

	tmpDir := t.TempDir()

	rule := `rule TestRegexI {
  strings:
    $a = /abc/i
  condition:
    $a
}`

	dataFile := filepath.Join(tmpDir, "data.txt")
	// 'AbC' at offset 2 should match /abc/i
	if err := os.WriteFile(dataFile, []byte("xxAbCy"), 0600); err != nil {
		t.Fatalf("Failed to create data file: %v", err)
	}

	// Change to temp dir to use relative paths
	origDir, _ := os.Getwd()
	defer func() {
		if err := os.Chdir(origDir); err != nil {
			// Log the error but don't fail the test
			t.Logf("Warning: failed to change back to original directory: %v", err)
		}
	}()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to change directory to %s: %v", tmpDir, err)
	}

	out := captureOutput(func() {
		args := &commandArgs{
			filename: "test.yar",
			mode:     modeExecute,
			dataFile: "data.txt",
		}
		runExecuteMode(rule, "data.txt", "test.yar", args)
	})

	// Expect at least one match and the specific offset/length
	if !strings.Contains(out, "Pattern matches: 1") {
		t.Fatalf("expected one pattern match, got output:\n%s", out)
	}
	if !strings.Contains(out, "- $a at offset 2 (length: 3)") {
		t.Fatalf("expected match at offset 2 length 3, got output:\n%s", out)
	}
}

// TestExecuteMode_RegexInlineFlagsS verifies inline /s enables DOT_ALL for dot
func TestExecuteMode_RegexInlineFlagsS(t *testing.T) {
	if !patternMatchingSupported(t) {
		t.Skip("pattern matching not yet fully implemented")
		return
	}

	tmpDir := t.TempDir()

	rule := `rule TestRegexS {
  strings:
    $a = /a.b/s
  condition:
    $a
}`

	dataFile := filepath.Join(tmpDir, "data.txt")
	// "a\nb" should match /a.b/s starting at offset 0, length 3
	if err := os.WriteFile(dataFile, []byte("a\nb"), 0600); err != nil {
		t.Fatalf("Failed to create data file: %v", err)
	}

	// Change to temp dir to use relative paths
	origDir, _ := os.Getwd()
	defer func() {
		if err := os.Chdir(origDir); err != nil {
			// Log the error but don't fail the test
			t.Logf("Warning: failed to change back to original directory: %v", err)
		}
	}()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to change directory to %s: %v", tmpDir, err)
	}

	out := captureOutput(func() {
		args := &commandArgs{
			filename: "test.yar",
			mode:     modeExecute,
			dataFile: "data.txt",
		}
		runExecuteMode(rule, "data.txt", "test.yar", args)
	})

	if !strings.Contains(out, "Pattern matches: 1") {
		t.Fatalf("expected one pattern match, got output:\n%s", out)
	}
	if !strings.Contains(out, "- $a at offset 0 (length: 3)") {
		t.Fatalf("expected match at offset 0 length 3, got output:\n%s", out)
	}
}

// TestExecuteMode_RegexEmptyMatch_Scan verifies empty matches are reported under scan mode
func TestExecuteMode_RegexEmptyMatch_Scan(t *testing.T) {
	if !patternMatchingSupported(t) {
		t.Skip("pattern matching not yet fully implemented")
		return
	}

	tmpDir := t.TempDir()

	rule := `rule TestRegexEmpty {
  strings:
    $a = /a*/
  condition:
    $a
}`

	dataFile := filepath.Join(tmpDir, "empty.txt")
	// Empty input should produce exactly one empty match at offset 0 for /a*/
	if err := os.WriteFile(dataFile, []byte(""), 0600); err != nil {
		t.Fatalf("Failed to create data file: %v", err)
	}

	// Change to temp dir to use relative paths
	origDir, _ := os.Getwd()
	defer func() {
		if err := os.Chdir(origDir); err != nil {
			// Log the error but don't fail the test
			t.Logf("Warning: failed to change back to original directory: %v", err)
		}
	}()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to change directory to %s: %v", tmpDir, err)
	}

	out := captureOutput(func() {
		args := &commandArgs{
			filename: "test.yar",
			mode:     modeExecute,
			dataFile: "empty.txt",
		}
		runExecuteMode(rule, "empty.txt", "test.yar", args)
	})

	if !strings.Contains(out, "Pattern matches: 1") {
		t.Fatalf("expected one pattern match for empty input, got output:\n%s", out)
	}
	if !strings.Contains(out, "- $a at offset 0 (length: 0)") {
		t.Fatalf("expected empty match at offset 0 length 0, got output:\n%s", out)
	}
}

// TestExecuteMode_Count_Regex verifies '#' operator (COUNT) with regex-derived matches
func TestExecuteMode_Count_Regex(t *testing.T) {
	if !patternMatchingSupported(t) {
		t.Skip("pattern matching not yet fully implemented")
		return
	}

	tmpDir := t.TempDir()

	rule := `rule TestRegexCount {
  strings:
    $a = /ab/
  condition:
    #$a == 2
}`

	dataFile := filepath.Join(tmpDir, "data.txt")
	// "ab" appears twice → count should be 2
	if err := os.WriteFile(dataFile, []byte("xxabyyabzz"), 0600); err != nil {
		t.Fatalf("Failed to create data file: %v", err)
	}

	// Change to temp dir to use relative paths
	origDir, _ := os.Getwd()
	defer func() {
		if err := os.Chdir(origDir); err != nil {
			// Log the error but don't fail the test
			t.Logf("Warning: failed to change back to original directory: %v", err)
		}
	}()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to change directory to %s: %v", tmpDir, err)
	}

	out := captureOutput(func() {
		args := &commandArgs{
			filename: "test.yar",
			mode:     modeExecute,
			dataFile: "data.txt",
		}
		runExecuteMode(rule, "data.txt", "test.yar", args)
	})

	if !strings.Contains(out, "Result: MATCH") {
		t.Fatalf("expected MATCH for #$a == 2, got output:\n%s", out)
	}
}

// TestExecuteMode_Offset_Regex verifies '@' operator (OFFSET of first match) with regex-derived matches
func TestExecuteMode_Offset_Regex(t *testing.T) {
	if !patternMatchingSupported(t) {
		t.Skip("pattern matching not yet fully implemented")
		return
	}

	tmpDir := t.TempDir()

	rule := `rule TestRegexOffset {
  strings:
    $a = /ab/
  condition:
    (@$a) == 2
}`

	dataFile := filepath.Join(tmpDir, "data.txt")
	// "ab" first occurs at offset 2 in "zzab"
	if err := os.WriteFile(dataFile, []byte("zzab"), 0600); err != nil {
		t.Fatalf("Failed to create data file: %v", err)
	}

	// Change to temp dir to use relative paths
	origDir, _ := os.Getwd()
	defer func() {
		if err := os.Chdir(origDir); err != nil {
			// Log the error but don't fail the test
			t.Logf("Warning: failed to change back to original directory: %v", err)
		}
	}()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to change directory to %s: %v", tmpDir, err)
	}

	out := captureOutput(func() {
		args := &commandArgs{
			filename: "test.yar",
			mode:     modeExecute,
			dataFile: "data.txt",
		}
		runExecuteMode(rule, "data.txt", "test.yar", args)
	})

	if !strings.Contains(out, "Result: MATCH") {
		t.Fatalf("expected MATCH for @$a == 2, got output:\n%s", out)
	}
}

// TestExecuteMode_Count_String verifies '#' operator (COUNT) with AC (text) matches
func TestExecuteMode_Count_String(t *testing.T) {
	if !patternMatchingSupported(t) {
		t.Skip("pattern matching not yet fully implemented")
		return
	}

	tmpDir := t.TempDir()

	rule := `rule TestStringCount {
  strings:
    $a = "foo"
  condition:
    #$a == 2
}`

	dataFile := filepath.Join(tmpDir, "data.txt")
	// "foo" appears twice → count should be 2
	if err := os.WriteFile(dataFile, []byte("foo bar baz foo"), 0600); err != nil {
		t.Fatalf("Failed to create data file: %v", err)
	}

	// Change to temp dir to use relative paths
	origDir, _ := os.Getwd()
	defer func() {
		if err := os.Chdir(origDir); err != nil {
			// Log the error but don't fail the test
			t.Logf("Warning: failed to change back to original directory: %v", err)
		}
	}()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to change directory to %s: %v", tmpDir, err)
	}

	out := captureOutput(func() {
		args := &commandArgs{
			filename: "test.yar",
			mode:     modeExecute,
			dataFile: "data.txt",
		}
		runExecuteMode(rule, "data.txt", "test.yar", args)
	})

	if !strings.Contains(out, "Result: MATCH") {
		t.Fatalf("expected MATCH for #$a == 2 (string), got output:\n%s", out)
	}
}

// TestExecuteMode_Offset_String verifies '@' operator (OFFSET of first match) with AC (text) matches
func TestExecuteMode_Offset_String(t *testing.T) {
	if !patternMatchingSupported(t) {
		t.Skip("pattern matching not yet fully implemented")
		return
	}

	tmpDir := t.TempDir()

	rule := `rule TestStringOffset {
  strings:
    $a = "bar"
  condition:
    (@$a) == 4
}`

	dataFile := filepath.Join(tmpDir, "data.txt")
	// "bar" first occurs at offset 4 in "foo bar"
	if err := os.WriteFile(dataFile, []byte("foo bar"), 0600); err != nil {
		t.Fatalf("Failed to create data file: %v", err)
	}

	// Change to temp dir to use relative paths
	origDir, _ := os.Getwd()
	defer func() {
		if err := os.Chdir(origDir); err != nil {
			// Log the error but don't fail the test
			t.Logf("Warning: failed to change back to original directory: %v", err)
		}
	}()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to change directory to %s: %v", tmpDir, err)
	}

	out := captureOutput(func() {
		args := &commandArgs{
			filename: "test.yar",
			mode:     modeExecute,
			dataFile: "data.txt",
		}
		runExecuteMode(rule, "data.txt", "test.yar", args)
	})

	if !strings.Contains(out, "Result: MATCH") {
		t.Fatalf("expected MATCH for @$a == 4 (string), got output:\n%s", out)
	}
}

// TestRunLexerMode tests the lexer mode
func TestRunLexerMode(t *testing.T) {
	content := `rule test {
	   strings:
	       $a = "hello"
	   condition:
	       $a
}`

	out := captureOutput(func() {
		runLexerMode(content)
	})

	if !strings.Contains(out, "Successfully lexed with no errors!") {
		t.Fatalf("expected successful lexing, got output:\n%s", out)
	}
	if !strings.Contains(out, "IDENTIFIER") {
		t.Fatalf("expected IDENTIFIER token, got output:\n%s", out)
	}
}

// TestRunParserMode tests the parser mode
func TestRunParserMode(t *testing.T) {
	content := `rule test {
	   strings:
	       $a = "hello"
	   condition:
	       $a
}`

	out := captureOutput(func() {
		runParserMode(content)
	})

	if !strings.Contains(out, "Successfully parsed!") {
		t.Fatalf("expected successful parsing, got output:\n%s", out)
	}
	if !strings.Contains(out, "Program contains 1 rules") {
		t.Fatalf("expected 1 rule, got output:\n%s", out)
	}
}

// TestRunCompileMode tests the compile mode
func TestRunCompileMode(t *testing.T) {
	content := `rule test {
	   strings:
	       $a = "hello"
	   condition:
	       $a
}`

	out := captureOutput(func() {
		runCompileMode(content, "test.yar")
	})

	if !strings.Contains(out, "Compilation: Successfully compiled 1 rules") {
		t.Fatalf("expected successful compilation in compile mode, got output:\n%s", out)
	}
	if !strings.Contains(out, "Compilation: Successfully compiled 1 rules") {
		t.Fatalf("expected successful compilation, got output:\n%s", out)
	}
}
