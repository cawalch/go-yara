package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/compiler"
	"github.com/cawalch/go-yara/token"
)

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
				Type:    token.StringLit,
				Literal: "hello world",
				Pos:     token.Position{Line: 2, Column: 10},
			},
			expected: "{StringLit \"hello world\" @ 2:10}",
		},
		{
			name: "number token",
			token: token.Token{
				Type:    token.IntegerLit,
				Literal: "42",
				Pos:     token.Position{Line: 3, Column: 15},
			},
			expected: "{IntegerLit \"42\" @ 3:15}",
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

func TestParseArgsValidation(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "negative-match-data",
			args: []string{"rules.yar", "--mode=execute", "--data", "sample.bin", "--match-data=-1"},
			want: "--match-data must be non-negative",
		},
		{
			name: "negative-match-context",
			args: []string{"rules.yar", "--mode=execute", "--data", "sample.bin", "--match-context=-1"},
			want: "--match-context must be non-negative",
		},
		{name: "missing-file", want: "missing YARA file"},
		{name: "empty-file", args: []string{""}, want: "missing YARA file"},
		{name: "file-not-first", args: []string{"--mode=lex", "rules.yar"}, want: "YARA file must be the first argument"},
		{name: "unknown-mode", args: []string{"rules.yar", "--mode=unknown"}, want: "unknown mode"},
		{name: "execute-without-data", args: []string{"rules.yar", "--mode=execute"}, want: "requires --data"},
		{name: "zero-chunk-size", args: []string{"rules.yar", "--chunk-size=0"}, want: "--chunk-size must be positive"},
		{name: "zero-concurrency", args: []string{"rules.yar", "--max-concurrency=0"}, want: "--max-concurrency must be positive"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseArgs(tt.args)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("parseArgs() error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

// TestExecuteModeIntegration tests the execute mode with pattern matching
func TestExecuteModeIntegration(t *testing.T) {
	ruleContent := `rule TestRule {
    strings:
        $a = "hello"
    condition:
        $a
}`
	out := executeModeOutput(t, ruleContent, []byte("This is hello world"))
	for _, want := range []string{"Pattern matches: 1", "Result: MATCH", "- $a at offset 8 (length: 5)"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

// TestExecuteModeMultiplePatterns tests execute mode with multiple patterns
func TestExecuteModeMultiplePatterns(t *testing.T) {
	ruleContent := `rule MultiPattern {
    strings:
        $a = "foo"
        $b = "bar"
    condition:
        $a or $b
}`
	out := executeModeOutput(t, ruleContent, []byte("foo bar baz foo bar"))
	for _, want := range []string{"Pattern matches: 4", "Result: MATCH", "$a", "$b"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, out)
		}
	}
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
	_ = r.Close()
	return string(out)
}

func executeModeOutput(t *testing.T, rule string, data []byte) string {
	t.Helper()
	tmpDir := t.TempDir()
	ruleFile := filepath.Join(tmpDir, "rules.yar")
	dataFile := filepath.Join(tmpDir, "data.bin")
	if err := os.WriteFile(dataFile, data, 0600); err != nil {
		t.Fatalf("write data file: %v", err)
	}

	return captureOutput(func() {
		args := &commandArgs{
			filename: ruleFile,
			mode:     modeExecute,
			dataFile: dataFile,
		}
		runExecuteMode(rule, dataFile, ruleFile, args)
	})
}

func TestExecuteRulesStreamingReportsPatternOnlySemantics(t *testing.T) {
	source := `rule FalseCondition {
  strings:
    $a = "foo"
  condition:
    false
}`

	c := compiler.NewCompiler()
	program, err := c.CompileSourceWithContext(context.Background(), source)
	if err != nil {
		t.Fatalf("CompileSourceWithContext() error = %v", err)
	}

	out := captureOutput(func() {
		args := &commandArgs{
			enableStreaming: false,
			chunkSize:       4,
			maxConcurrency:  1,
		}
		executeRulesStreaming(program, []byte("foo"), args)
	})

	expected := []string{
		"Streaming pattern scan enabled",
		"reports string pattern matches only; rule conditions are not evaluated",
		"Streaming Pattern Results",
		"Total pattern matches: 1",
		"Rule: FalseCondition, Pattern: $a",
	}
	for _, text := range expected {
		if !strings.Contains(out, text) {
			t.Fatalf("expected streaming output to contain %q, got:\n%s", text, out)
		}
	}

	if strings.Contains(out, "Result: MATCH") || strings.Contains(out, "Execution: Success") {
		t.Fatalf("streaming output implied full rule execution, got:\n%s", out)
	}
}

// TestExecuteMode_RegexInlineFlagsI verifies inline /i is propagated to VM (NO_CASE)
func TestExecuteMode_RegexInlineFlagsI(t *testing.T) {
	rule := `rule TestRegexI {
  strings:
    $a = /abc/i
  condition:
    $a
}`
	out := executeModeOutput(t, rule, []byte("xxAbCy"))

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
	rule := `rule TestRegexS {
  strings:
    $a = /a.b/s
  condition:
    $a
}`
	out := executeModeOutput(t, rule, []byte("a\nb"))

	if !strings.Contains(out, "Pattern matches: 1") {
		t.Fatalf("expected one pattern match, got output:\n%s", out)
	}
	if !strings.Contains(out, "- $a at offset 0 (length: 3)") {
		t.Fatalf("expected match at offset 0 length 3, got output:\n%s", out)
	}
}

// TestExecuteMode_RegexEmptyMatch_Scan verifies empty matches are reported under scan mode
func TestExecuteMode_RegexEmptyMatch_Scan(t *testing.T) {
	rule := `rule TestRegexEmpty {
  strings:
    $a = /a*/
  condition:
    $a
}`
	out := executeModeOutput(t, rule, nil)

	if !strings.Contains(out, "Pattern matches: 1") {
		t.Fatalf("expected one pattern match for empty input, got output:\n%s", out)
	}
	if !strings.Contains(out, "- $a at offset 0 (length: 0)") {
		t.Fatalf("expected empty match at offset 0 length 0, got output:\n%s", out)
	}
}

// TestExecuteMode_Count_Regex verifies '#' operator (COUNT) with regex-derived matches
func TestExecuteMode_Count_Regex(t *testing.T) {
	rule := `rule TestRegexCount {
  strings:
    $a = /ab/
  condition:
    #$a == 2
}`
	out := executeModeOutput(t, rule, []byte("xxabyyabzz"))

	if !strings.Contains(out, "Result: MATCH") {
		t.Fatalf("expected MATCH for #$a == 2, got output:\n%s", out)
	}
}

// TestExecuteMode_Offset_Regex verifies '@' operator (OFFSET of first match) with regex-derived matches
func TestExecuteMode_Offset_Regex(t *testing.T) {
	rule := `rule TestRegexOffset {
  strings:
    $a = /ab/
  condition:
    (@$a) == 2
}`
	out := executeModeOutput(t, rule, []byte("zzab"))

	if !strings.Contains(out, "Result: MATCH") {
		t.Fatalf("expected MATCH for @$a == 2, got output:\n%s", out)
	}
}

// TestExecuteMode_Count_String verifies '#' operator (COUNT) with AC (text) matches
func TestExecuteMode_Count_String(t *testing.T) {
	rule := `rule TestStringCount {
  strings:
    $a = "foo"
  condition:
    #$a == 2
}`
	out := executeModeOutput(t, rule, []byte("foo bar baz foo"))

	if !strings.Contains(out, "Result: MATCH") {
		t.Fatalf("expected MATCH for #$a == 2 (string), got output:\n%s", out)
	}
}

// TestExecuteMode_Offset_String verifies '@' operator (OFFSET of first match) with AC (text) matches
func TestExecuteMode_Offset_String(t *testing.T) {
	rule := `rule TestStringOffset {
  strings:
    $a = "bar"
  condition:
    (@$a) == 4
}`
	out := executeModeOutput(t, rule, []byte("foo bar"))

	if !strings.Contains(out, "Result: MATCH") {
		t.Fatalf("expected MATCH for @$a == 4 (string), got output:\n%s", out)
	}
}

func TestExecuteModeMatchEvidenceOutput(t *testing.T) {
	source := `rule Evidence {
  strings:
    $a = "bar"
  condition:
    $a
}`

	c := compiler.NewCompiler()
	program, err := c.CompileSourceWithContext(context.Background(), source)
	if err != nil {
		t.Fatalf("CompileSourceWithContext() error = %v", err)
	}

	out := captureOutput(func() {
		args := &commandArgs{
			matchDataBytes:    2,
			matchContextBytes: 4,
		}
		executeRules(program, []byte("foo bar baz"), args)
	})

	expected := []string{
		"- $a at offset 4 (length: 3)",
		`matched-data: "ba" (truncated)`,
		`context-before: "foo "`,
		`context-after: " baz"`,
	}
	for _, text := range expected {
		if !strings.Contains(out, text) {
			t.Fatalf("expected execute output to contain %q, got:\n%s", text, out)
		}
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
}
