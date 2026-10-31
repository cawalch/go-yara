package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
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
		{
			name: "negative-max-match-span",
			args: []string{"rules.yar", "--mode=execute", "--data", "sample.bin", "--max-match-span=-1"},
			want: "--max-match-span must be non-negative",
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
		"--max-match-span=1024",
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
	if args.matchDataBytes != 8 || args.matchContextBytes != 4 || args.maxMatchSpan != 1024 {
		t.Fatalf("parseArgs() match options = %+v", args)
	}
}

func TestParseArgsVersion(t *testing.T) {
	for _, flagArg := range []string{"-v", "--version", "-version"} {
		t.Run(flagArg, func(t *testing.T) {
			args, err := parseArgs([]string{flagArg})
			if args != nil {
				t.Fatalf("parseArgs(%q) returned non-nil args: %+v", flagArg, args)
			}
			if !errors.Is(err, flag.ErrHelp) {
				t.Fatalf("parseArgs(%q) error = %v, want flag.ErrHelp", flagArg, err)
			}
		})
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
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
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
	dataFile := filepath.Join(t.TempDir(), "data.bin")
	if err := os.WriteFile(dataFile, []byte("foo"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	out, err := captureOutputWithError(func() error {
		args := &commandArgs{
			enableStreaming: false,
			chunkSize:       4,
		}
		return executeRulesStreaming(program, dataFile, args)
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

func TestRunExecuteModeStreamsFromFile(t *testing.T) {
	rule := `rule streamed {
  strings:
    $a = "foo"
  condition:
    $a
}`
	tmpDir := t.TempDir()
	ruleFile := filepath.Join(tmpDir, "rules.yar")
	dataFile := filepath.Join(tmpDir, "data.bin")
	if err := os.WriteFile(dataFile, []byte("foo---foo"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	out, err := captureOutputWithError(func() error {
		args := &commandArgs{
			enableStreaming: true,
			chunkSize:       4,
		}
		return runExecuteMode(rule, dataFile, ruleFile, args)
	})
	if err != nil {
		t.Fatalf("runExecuteMode() error = %v", err)
	}
	for _, want := range []string{
		"Data content (first 256 bytes):",
		"Streaming pattern scan enabled",
		"Total pattern matches: 2",
		"Progress: 9/9 bytes (100.0%)",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("streaming execute output missing %q:\n%s", want, out)
		}
	}
}

func TestPrintStreamingDataSummaryBoundsPreview(t *testing.T) {
	dataFile := filepath.Join(t.TempDir(), "data.bin")
	if err := os.WriteFile(dataFile, []byte(strings.Repeat("z", 300)), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	out, err := captureOutputWithError(func() error {
		return printStreamingDataSummary(dataFile)
	})
	if err != nil {
		t.Fatalf("printStreamingDataSummary() error = %v", err)
	}
	if !strings.Contains(out, strings.Repeat("z", 256)+"...") {
		t.Fatalf("streaming preview was not truncated at 256 bytes:\n%s", out)
	}
	if strings.Contains(out, strings.Repeat("z", 257)) {
		t.Fatalf("streaming preview included more than 256 data bytes:\n%s", out)
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

// TestExecuteMode_RegexEmptyMatch_Scan requires a candidate byte, as libyara does.
func TestExecuteMode_RegexEmptyMatch_Scan(t *testing.T) {
	rule := `rule TestRegexEmpty {
  strings:
    $a = /a*/
  condition:
    $a
}`
	out := executeModeOutput(t, rule, nil)
	if !strings.Contains(out, "Total matches found: 0") || strings.Contains(out, "- $a at offset") {
		t.Fatalf("expected no occurrence on empty input, got output:\n%s", out)
	}
	out = executeModeOutput(t, rule, []byte("!"))
	if !strings.Contains(out, "Pattern matches: 1") {
		t.Fatalf("expected one zero-length match before the punctuation, got output:\n%s", out)
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

func TestStandardScanPositional(t *testing.T) {
	tmpDir := t.TempDir()
	ruleFile := filepath.Join(tmpDir, "rules.yar")
	dataFile := filepath.Join(tmpDir, "sample.bin")

	rule := `rule Alpha { strings: $a = "alpha" condition: $a }`
	if err := os.WriteFile(ruleFile, []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataFile, []byte("hello alpha world"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := captureOutputWithError(func() error {
		return run([]string{ruleFile, dataFile})
	})
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	want := "Alpha " + dataFile
	if !strings.Contains(out, want) {
		t.Fatalf("expected output to contain %q, got:\n%s", want, out)
	}
}

func TestStandardScanPrintStrings(t *testing.T) {
	tmpDir := t.TempDir()
	ruleFile := filepath.Join(tmpDir, "rules.yar")
	dataFile := filepath.Join(tmpDir, "sample.bin")

	rule := `rule Alpha { strings: $a = "alpha" condition: $a }`
	if err := os.WriteFile(ruleFile, []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataFile, []byte("hello alpha world"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := captureOutputWithError(func() error {
		return run([]string{ruleFile, "-s", dataFile})
	})
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	for _, want := range []string{"Alpha", "0x6:$a: alpha"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestStandardScanPrintMetaAndTags(t *testing.T) {
	tmpDir := t.TempDir()
	ruleFile := filepath.Join(tmpDir, "rules.yar")
	dataFile := filepath.Join(tmpDir, "sample.bin")

	rule := `rule FullMeta : sample tag2 {
		meta:
			author = "test"
			version = 2
		strings:
			$a = "hello"
		condition:
			$a
	}`
	if err := os.WriteFile(ruleFile, []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataFile, []byte("hello world"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := captureOutputWithError(func() error {
		return run([]string{ruleFile, "-m", "-g", dataFile})
	})
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	for _, want := range []string{"FullMeta", "[sample,tag2]", `[author="test",version=2]`} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestStandardScanCount(t *testing.T) {
	tmpDir := t.TempDir()
	ruleFile := filepath.Join(tmpDir, "rules.yar")
	dataFile := filepath.Join(tmpDir, "sample.bin")

	rule := `
		rule R1 { strings: $a = "a" condition: $a }
		rule R2 { strings: $b = "b" condition: $b }
		rule R3 { strings: $c = "c" condition: $c }
	`
	if err := os.WriteFile(ruleFile, []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataFile, []byte("a and b here"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := captureOutputWithError(func() error {
		return run([]string{ruleFile, "-c", dataFile})
	})
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if strings.TrimSpace(out) != "2" {
		t.Fatalf("expected count 2, got:\n%s", out)
	}
}

func TestStandardScanFilters(t *testing.T) {
	tmpDir := t.TempDir()
	ruleFile := filepath.Join(tmpDir, "rules.yar")
	dataFile := filepath.Join(tmpDir, "sample.bin")

	rule := `
		rule R1 : alpha { strings: $a = "match" condition: $a }
		rule R2 : beta  { strings: $a = "match" condition: $a }
	`
	if err := os.WriteFile(ruleFile, []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataFile, []byte("match"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Filter by tag
	outTag, err := captureOutputWithError(func() error {
		return run([]string{ruleFile, "-t", "alpha", dataFile})
	})
	if err != nil {
		t.Fatalf("run with -t failed: %v", err)
	}
	if !strings.Contains(outTag, "R1") || strings.Contains(outTag, "R2") {
		t.Fatalf("expected only R1, got:\n%s", outTag)
	}

	// Filter by identifier
	outIdent, err := captureOutputWithError(func() error {
		return run([]string{ruleFile, "-i", "R2", dataFile})
	})
	if err != nil {
		t.Fatalf("run with -i failed: %v", err)
	}
	if !strings.Contains(outIdent, "R2") || strings.Contains(outIdent, "R1") {
		t.Fatalf("expected only R2, got:\n%s", outIdent)
	}
}

func TestStandardScanNegate(t *testing.T) {
	tmpDir := t.TempDir()
	ruleFile := filepath.Join(tmpDir, "rules.yar")
	dataFile := filepath.Join(tmpDir, "sample.bin")

	rule := `
		rule Matched { strings: $a = "hit" condition: $a }
		rule Unmatched { strings: $a = "miss" condition: $a }
	`
	if err := os.WriteFile(ruleFile, []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataFile, []byte("hit"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := captureOutputWithError(func() error {
		return run([]string{ruleFile, "-n", dataFile})
	})
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if !strings.Contains(out, "Unmatched") || strings.Contains(out, "Matched") {
		t.Fatalf("expected only Unmatched with -n, got:\n%s", out)
	}
}

func TestStandardScanDirectoryRecursiveAndParallel(t *testing.T) {
	tmpDir := t.TempDir()
	ruleFile := filepath.Join(tmpDir, "rules.yar")
	subDir := filepath.Join(tmpDir, "subdir")
	if err := os.Mkdir(subDir, 0o750); err != nil {
		t.Fatal(err)
	}

	file1 := filepath.Join(tmpDir, "f1.bin")
	file2 := filepath.Join(subDir, "f2.bin")
	file3 := filepath.Join(subDir, "f3.bin")

	if err := os.WriteFile(file1, []byte("target_pattern"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file2, []byte("no_match"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file3, []byte("target_pattern in sub"), 0o600); err != nil {
		t.Fatal(err)
	}

	rule := `rule TargetRule { strings: $a = "target_pattern" condition: $a }`
	if err := os.WriteFile(ruleFile, []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := captureOutputWithError(func() error {
		return run([]string{ruleFile, "-r", "-p", "4", tmpDir})
	})
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	if !strings.Contains(out, file1) || !strings.Contains(out, file3) {
		t.Fatalf("expected matches on f1 and f3, got:\n%s", out)
	}
	if strings.Contains(out, file2) {
		t.Fatalf("unexpected match on f2 in output:\n%s", out)
	}
}

func TestStandardScanDirectoryWithoutRecursiveFails(t *testing.T) {
	tmpDir := t.TempDir()
	ruleFile := filepath.Join(tmpDir, "rules.yar")
	rule := `rule R { condition: true }`
	if err := os.WriteFile(ruleFile, []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}

	err := run([]string{ruleFile, tmpDir})
	if err == nil || !strings.Contains(err.Error(), "use -r / --recursive") {
		t.Fatalf("expected error containing 'use -r / --recursive', got: %v", err)
	}
}

func TestStandardScanFastScan(t *testing.T) {
	tmpDir := t.TempDir()
	ruleFile := filepath.Join(tmpDir, "rules.yar")
	dataFile := filepath.Join(tmpDir, "sample.bin")

	rule := `rule Fast { strings: $a = "test" condition: $a }`
	if err := os.WriteFile(ruleFile, []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataFile, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := captureOutputWithError(func() error {
		return run([]string{ruleFile, "--fast-scan", dataFile})
	})
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if !strings.Contains(out, "Fast") {
		t.Fatalf("expected match with --fast-scan, got:\n%s", out)
	}
}

func TestStandardScanJSONOutput(t *testing.T) {
	tmpDir := t.TempDir()
	ruleFile := filepath.Join(tmpDir, "rules.yar")
	dataFile := filepath.Join(tmpDir, "sample.bin")

	rule := `rule JSONRule : json_tag {
		meta:
			author = "developer"
		strings:
			$a = "json_target"
		condition:
			$a
	}`
	if err := os.WriteFile(ruleFile, []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataFile, []byte("start json_target end"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := captureOutputWithError(func() error {
		return run([]string{ruleFile, "--json", dataFile})
	})
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	var rep jsonMatchReport
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &rep); err != nil {
		t.Fatalf("failed to unmarshal JSON output %q: %v", out, err)
	}

	if rep.Rule != "JSONRule" || rep.Target != dataFile {
		t.Fatalf("unexpected JSON fields: %+v", rep)
	}
	if len(rep.Tags) != 1 || rep.Tags[0] != "json_tag" {
		t.Fatalf("unexpected JSON tags: %v", rep.Tags)
	}
	if rep.Meta["author"] != "developer" {
		t.Fatalf("unexpected JSON meta: %v", rep.Meta)
	}
	if len(rep.Matches) != 1 || rep.Matches[0].Identifier != "$a" || rep.Matches[0].Offset != 6 || rep.Matches[0].Data != "json_target" {
		t.Fatalf("unexpected JSON matches: %+v", rep.Matches)
	}
}

func TestParseArgsStandardOptions(t *testing.T) {
	args, err := parseArgs([]string{
		"rules.yar",
		"-r",
		"-p", "8",
		"-s",
		"-m",
		"-g",
		"-c",
		"-t", "threat",
		"-i", "RuleA",
		"-n",
		"--fast-scan",
		"--json",
		"target_dir",
	})
	if err != nil {
		t.Fatalf("parseArgs failed: %v", err)
	}
	if !args.recursive || args.threads != 8 || !args.printStrings || !args.printMeta ||
		!args.printTags || !args.countOnly || args.tagFilter != "threat" ||
		args.identFilter != "RuleA" || !args.negate || !args.fastScan || !args.jsonOutput ||
		args.target != "target_dir" {
		t.Fatalf("unexpected parsed options: %+v", args)
	}
}
