package main

import (
	"context"
	"io"
	"os"
	"os/exec"
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

func TestParseArgsSuccess(t *testing.T) {
	args, err := parseArgs([]string{
		"rules.yar",
		"--mode=execute",
		"--data=sample.bin",
		"--streaming",
		"--chunk-size=4096",
		"--early-termination",
		"--match-data=8",
		"--match-context=4",
	})
	if err != nil {
		t.Fatalf("parseArgs() error = %v", err)
	}
	if args.filename != "rules.yar" || args.mode != modeExecute || args.dataFile != "sample.bin" {
		t.Fatalf("parseArgs() paths = %+v", args)
	}
	if !args.enableStreaming || !args.earlyTermination || args.chunkSize != 4096 {
		t.Fatalf("parseArgs() streaming options = %+v", args)
	}
	if args.matchDataBytes != 8 || args.matchContextBytes != 4 {
		t.Fatalf("parseArgs() match options = %+v", args)
	}
}

func TestRunModes(t *testing.T) {
	tmpDir := t.TempDir()
	ruleFile := filepath.Join(tmpDir, "rules.yar")
	dataFile := filepath.Join(tmpDir, "data.bin")
	rule := []byte(`rule test : sample { strings: $a = "hello" condition: $a }`)
	if err := os.WriteFile(ruleFile, rule, 0600); err != nil {
		t.Fatalf("write rule file: %v", err)
	}
	if err := os.WriteFile(dataFile, []byte("hello"), 0600); err != nil {
		t.Fatalf("write data file: %v", err)
	}

	tests := []struct {
		mode string
		args []string
		want string
	}{
		{mode: modeLex, args: []string{ruleFile, "--mode=lex"}, want: "Successfully lexed"},
		{mode: modeParse, args: []string{ruleFile, "--mode=parse"}, want: "Tags: [sample]"},
		{mode: modeCompile, args: []string{ruleFile}, want: "Successfully compiled 1 rules"},
		{mode: modeExecute, args: []string{ruleFile, "--mode=execute", "--data=" + dataFile}, want: "Result: MATCH"},
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			out, err := captureOutputWithError(func() error { return run(tt.args) })
			if err != nil {
				t.Fatalf("run() error = %v", err)
			}
			if !strings.Contains(out, tt.want) {
				t.Fatalf("run() output missing %q:\n%s", tt.want, out)
			}
		})
	}
}

func TestRunErrorPaths(t *testing.T) {
	tmpDir := t.TempDir()
	dataFile := filepath.Join(tmpDir, "data.bin")
	if err := os.WriteFile(dataFile, []byte("sample"), 0600); err != nil {
		t.Fatalf("write data file: %v", err)
	}

	writeRule := func(t *testing.T, name, source string) string {
		t.Helper()
		filename := filepath.Join(tmpDir, name)
		if err := os.WriteFile(filename, []byte(source), 0600); err != nil {
			t.Fatalf("write rule file: %v", err)
		}
		return filename
	}

	validRule := writeRule(t, "valid.yar", `rule valid { condition: true }`)
	lexerError := writeRule(t, "lexer-error.yar", `rule broken { strings: $a = "unterminated condition: $a }`)
	parserError := writeRule(t, "parser-error.yar", `rule broken { condition: ) }`)
	compileError := writeRule(t, "compile-error.yar", `rule broken { condition: missing_identifier }`)
	missingInclude := writeRule(t, "include-error.yar", `include "missing.yar" rule main { condition: true }`)

	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "missing-arguments", want: "missing YARA file"},
		{name: "missing-rule-file", args: []string{filepath.Join(tmpDir, "missing.yar")}, want: "reading YARA file"},
		{name: "lexer-error", args: []string{lexerError, "--mode=lex"}, want: "lexer errors detected"},
		{name: "parser-error", args: []string{parserError, "--mode=parse"}, want: "parsing failed"},
		{name: "compile-error", args: []string{compileError}, want: "compilation failed"},
		{name: "include-error", args: []string{missingInclude, "--mode=parse"}, want: "processing includes"},
		{name: "missing-data-file", args: []string{validRule, "--mode=execute", "--data=" + filepath.Join(tmpDir, "missing.bin")}, want: "reading data file"},
		{name: "execute-compile-error", args: []string{compileError, "--mode=execute", "--data=" + dataFile}, want: "compiling rules"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := captureOutputWithError(func() error { return run(tt.args) })
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("run() error = %v, want containing %q", err, tt.want)
			}
		})
	}

	if err := runMode("invalid", nil, &commandArgs{filename: validRule}); err == nil {
		t.Fatal("runMode() accepted an unknown mode")
	}
}

func TestCLIHelperProcess(t *testing.T) {
	if os.Getenv("GO_YARA_CLI_HELPER") != "1" {
		return
	}
	separator := 0
	for i, arg := range os.Args {
		if arg == "--" {
			separator = i
			break
		}
	}
	os.Args = append([]string{"go-yara"}, os.Args[separator+1:]...)
	main()
}

func TestCLIExecutionErrorsExitNonZero(t *testing.T) {
	tmpDir := t.TempDir()
	validRule := filepath.Join(tmpDir, "valid.yar")
	invalidRule := filepath.Join(tmpDir, "invalid.yar")
	dataFile := filepath.Join(tmpDir, "data.bin")
	for filename, content := range map[string]string{
		validRule:   `rule valid { condition: true }`,
		invalidRule: `rule invalid { condition: missing_identifier }`,
		dataFile:    "sample",
	} {
		if err := os.WriteFile(filename, []byte(content), 0600); err != nil {
			t.Fatalf("write %s: %v", filename, err)
		}
	}

	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "missing-data",
			args: []string{validRule, "--mode=execute", "--data=" + filepath.Join(tmpDir, "missing.bin")},
			want: "reading data file",
		},
		{
			name: "invalid-rule",
			args: []string{invalidRule, "--mode=execute", "--data=" + dataFile},
			want: "compiling rules",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmdArgs := append([]string{"-test.run=TestCLIHelperProcess", "--"}, tt.args...)
			cmd := exec.Command(os.Args[0], cmdArgs...)
			cmd.Env = append(os.Environ(), "GO_YARA_CLI_HELPER=1")
			output, err := cmd.CombinedOutput()
			exitErr, ok := err.(*exec.ExitError)
			if !ok || exitErr.ExitCode() != 1 {
				t.Fatalf("CLI error = %v, output:\n%s", err, output)
			}
			if !strings.Contains(string(output), tt.want) {
				t.Fatalf("CLI output missing %q:\n%s", tt.want, output)
			}
		})
	}
}

func TestCLIHelpExitsZero(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestCLIHelperProcess", "--", "--help")
	cmd.Env = append(os.Environ(), "GO_YARA_CLI_HELPER=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI help error = %v, output:\n%s", err, output)
	}
	if !strings.Contains(string(output), "Usage: go-yara") {
		t.Fatalf("CLI help output missing usage:\n%s", output)
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

func captureOutputWithError(fn func() error) (string, error) {
	var err error
	out := captureOutput(func() {
		err = fn()
	})
	return out, err
}

func executeModeOutput(t *testing.T, rule string, data []byte) string {
	t.Helper()
	tmpDir := t.TempDir()
	ruleFile := filepath.Join(tmpDir, "rules.yar")
	dataFile := filepath.Join(tmpDir, "data.bin")
	if err := os.WriteFile(dataFile, data, 0600); err != nil {
		t.Fatalf("write data file: %v", err)
	}

	out, err := captureOutputWithError(func() error {
		args := &commandArgs{
			filename: ruleFile,
			mode:     modeExecute,
			dataFile: dataFile,
		}
		return runExecuteMode(rule, dataFile, ruleFile, args)
	})
	if err != nil {
		t.Fatalf("runExecuteMode() error = %v", err)
	}
	return out
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

	out, err := captureOutputWithError(func() error {
		args := &commandArgs{
			enableStreaming: false,
			chunkSize:       4,
		}
		return executeRulesStreaming(program, []byte("foo"), args)
	})
	if err != nil {
		t.Fatalf("executeRulesStreaming() error = %v", err)
	}

	expected := []string{
		"Streaming pattern scan enabled",
		"reports literal text-pattern matches only; regex, hex, and rule conditions are not evaluated",
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

	out, err := captureOutputWithError(func() error {
		args := &commandArgs{
			matchDataBytes:    2,
			matchContextBytes: 4,
		}
		return executeRules(program, []byte("foo bar baz"), args)
	})
	if err != nil {
		t.Fatalf("executeRules() error = %v", err)
	}

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

	out, err := captureOutputWithError(func() error {
		return runLexerMode(content)
	})
	if err != nil {
		t.Fatalf("runLexerMode() error = %v", err)
	}

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

	out, err := captureOutputWithError(func() error {
		return runParserMode(content, "test.yar")
	})
	if err != nil {
		t.Fatalf("runParserMode() error = %v", err)
	}

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

	out, err := captureOutputWithError(func() error {
		return runCompileMode(content, "test.yar")
	})
	if err != nil {
		t.Fatalf("runCompileMode() error = %v", err)
	}

	if !strings.Contains(out, "Compilation: Successfully compiled 1 rules") {
		t.Fatalf("expected successful compilation in compile mode, got output:\n%s", out)
	}
}
