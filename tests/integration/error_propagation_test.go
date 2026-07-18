package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/compiler"
)

type compileExpectation struct {
	expectError bool
	description string
}

type compileResult struct {
	program *compiler.CompiledProgram
	err     error
}

func (result compileResult) handleExpectedError(t *testing.T, expectation compileExpectation, noErrorDetail string) bool {
	t.Helper()
	if !expectation.expectError {
		return false
	}
	if result.err == nil {
		t.Fatalf("expected error not produced: %s (%s)", expectation.description, noErrorDetail)
	}
	return true
}

func assertSimpleCompileExpectation(t *testing.T, result compileResult, expectation compileExpectation) {
	t.Helper()
	if result.handleExpectedError(t, expectation, "no error produced") {
		return
	}
	switch {
	case result.err != nil:
		t.Fatalf("unexpected compilation error: %v", result.err)
	case result.program == nil:
		t.Fatal("compilation succeeded without a program")
	}
}

func simpleCompileExpectation(expectError bool, description string) compileExpectation {
	return compileExpectation{
		expectError: expectError,
		description: description,
	}
}

// assertCompileResult verifies whether compilation succeeds or fails as expected.
func assertCompileResult(t *testing.T, result compileResult, tt struct {
	name        string
	rule        string
	expectError bool
	description string
}) {
	t.Helper()
	expectation := compileExpectation{
		expectError: tt.expectError,
		description: tt.description,
	}
	if result.handleExpectedError(t, expectation, "no error produced") {
		return
	}
	switch {
	case result.err != nil:
		t.Fatalf("unexpected compilation error: %v", result.err)
	case result.program == nil:
		t.Fatal("compilation succeeded without a program")
	}
}

// TestLexerErrorPropagation documents how lexer errors propagate through pipeline
func TestLexerErrorPropagation(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "unterminated-string",
			rule:        `rule test { strings: $a = "unclosed condition: $a }`,
			expectError: true,
			description: "Documents lexer error for unterminated string",
		},
		{
			name:        "unterminated-hex",
			rule:        `rule test { strings: $a = { DE AD condition: $a }`,
			expectError: true,
			description: "Documents lexer error for unterminated hex string",
		},
		{
			name:        "unterminated-regex",
			rule:        `rule test { strings: $a = /test[ condition: $a }`,
			expectError: true,
			description: "Documents lexer error for unterminated regex",
		},
		{
			name:        "invalid-escape-string",
			rule:        `rule test { strings: $a = "test\p" condition: $a }`,
			expectError: true,
			description: "Rejects invalid escape sequence in strings",
		},
		{
			name:        "invalid-escape-regex",
			rule:        `rule test { strings: $a = /test\p/ condition: $a }`,
			expectError: true,
			description: "Rejects invalid escape sequence in regex",
		},
		{
			name:        "invalid-hex-digit",
			rule:        `rule test { strings: $a = { TG } condition: $a }`,
			expectError: true,
			description: "Documents lexer error for invalid hex digit",
		},
		{
			name:        "illegal-character",
			rule:        `rule test { condition: @ }`,
			expectError: true,
			description: "Documents lexer error for illegal character",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiler := compiler.NewCompiler()
			program, err := compiler.CompileSourceWithContext(context.Background(), tt.rule)
			assertCompileResult(t, compileResult{program: program, err: err}, tt)

		})
	}
}

// TestParserErrorPropagation documents how parser errors propagate through pipeline
func TestParserErrorPropagation(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "missing-rule-keyword",
			rule:        `test { condition: true }`,
			expectError: true,
			description: "Documents parser error for missing 'rule' keyword",
		},
		{
			name:        "missing-identifier",
			rule:        `rule { condition: true }`,
			expectError: true,
			description: "Documents parser error for missing rule identifier",
		},
		{
			name:        "unbalanced-braces-rule",
			rule:        `rule test { condition: true `,
			expectError: true,
			description: "Documents parser error for unbalanced rule braces",
		},
		{
			name:        "unbalanced-parentheses",
			rule:        `rule test { condition: (true }`,
			expectError: true,
			description: "Documents parser error for unbalanced parentheses",
		},
		{
			name:        "invalid-section-name",
			rule:        `rule test { invalid: $a = "test" condition: true }`,
			expectError: true,
			description: "Documents parser error for invalid section name",
		},
		{
			name:        "duplicate-section",
			rule:        `rule test { strings: $a = "test" strings: $b = "test2" condition: true }`,
			expectError: true,
			description: "Documents parser error for duplicate sections",
		},
		{
			name:        "missing-colon-identifier",
			rule:        `rule test condition true }`,
			expectError: true,
			description: "Documents parser error for missing colon after identifier",
		},
		{
			name:        "invalid-operator",
			rule:        `rule test { condition: true && false }`,
			expectError: true,
			description: "Documents parser error for invalid operator (&& instead of and)",
		},
		{
			name:        "empty-hex-alternative",
			rule:        `rule test { strings: $a = { DE AD () BE EF } condition: $a }`,
			expectError: true,
			description: "Rejects an empty hex alternative during compilation",
		},
		{
			name:        "invalid-hex-jump",
			rule:        `rule test { strings: $a = { DE [-100] AD } condition: $a }`,
			expectError: true,
			description: "Documents parser error for invalid hex jump (negative)",
		},
		{
			name:        "invalid-regex-quantifier",
			rule:        `rule test { strings: $a = /test{a}/ condition: $a }`,
			expectError: true,
			description: "Documents parser error for invalid regex quantifier",
		},
		{
			name:        "invalid-modifier",
			rule:        `rule test { strings: $a = "test" invalidmod condition: $a }`,
			expectError: true,
			description: "Documents parser error for invalid string modifier",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiler := compiler.NewCompiler()
			program, err := compiler.CompileSourceWithContext(context.Background(), tt.rule)
			assertCompileResult(t, compileResult{program: program, err: err}, tt)

		})
	}
}

// TestSemanticErrorPropagation documents how semantic validation errors propagate
func TestSemanticErrorPropagation(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "undefined-string-reference",
			rule:        `rule test { condition: $undefined }`,
			expectError: true,
			description: "Documents semantic error for undefined string reference",
		},
		{
			name:        "undefined-external-reference",
			rule:        `rule test { condition: ext_var }`,
			expectError: true,
			description: "Documents semantic error for undefined external variable",
		},
		{
			name:        "type-mismatch-string-int",
			rule:        `rule test { strings: $a = "test" condition: $a == 10 }`,
			expectError: true,
			description: "Documents semantic error for type mismatch (string vs int)",
		},
		{
			name:        "type-mismatch-bool-string",
			rule:        `rule test { condition: true == "test" }`,
			expectError: true,
			description: "Documents semantic error for type mismatch (bool vs string)",
		},
		{
			name:        "invalid-function-argument",
			rule:        `rule test { condition: int8("string") }`,
			expectError: true,
			description: "Rejects int8() with a non-integer argument",
		},
		{
			name:        "undefined-function",
			rule:        `rule test { condition: undefined_func(0) }`,
			expectError: true,
			description: "Documents semantic error for undefined function",
		},
		{
			name:        "wrong-argument-count",
			rule:        `rule test { condition: int8() }`,
			expectError: true,
			description: "Documents semantic error for wrong argument count",
		},
		{
			name:        "circular-dependency",
			rule:        `rule a { condition: b } rule b { condition: a }`,
			expectError: true,
			description: "Rejects circular rule dependencies",
		},
		{
			name:        "invalid-of-expression",
			rule:        `rule test { condition: any of 123 }`,
			expectError: true,
			description: "Documents semantic error for invalid of-expression",
		},
		{
			name:        "invalid-for-loop-variable",
			rule:        `rule test { strings: $a = "test" condition: for any i in ($a) : ( i == 1 ) }`,
			expectError: true,
			description: "Documents semantic error for invalid for-loop variable usage",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiler := compiler.NewCompiler()
			program, err := compiler.CompileSourceWithContext(context.Background(), tt.rule)
			assertCompileResult(t, compileResult{program: program, err: err}, tt)

		})
	}
}

// TestCompilerErrorPropagation documents how compiler errors propagate
func TestCompilerErrorPropagation(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name: "too-many-strings",
			rule: strings.Join([]string{
				`rule test {`,
				`strings:`,
				`$a1 = "test1" $a2 = "test2" $a3 = "test3" $a4 = "test4" $a5 = "test5"`,
				`$a6 = "test6" $a7 = "test7" $a8 = "test8" $a9 = "test9" $a10 = "test10"`,
				`condition:`,
				`any of them`,
				`}`,
			}, " "),
			expectError: false,
			description: "Documents compiler handles many strings without error",
		},
		{
			name:        "complex-regex-nesting",
			rule:        `rule test { strings: $a = /(((a*b)+c)?d)/ condition: $a }`,
			expectError: false,
			description: "Documents compiler handles complex regex nesting",
		},
		{
			name: "very-long-condition",
			rule: strings.Join([]string{
				`rule test {`,
				`strings:`,
				`$a = "a" $b = "b" $c = "c" $d = "d" $e = "e"`,
				`condition:`,
				`$a and $b and $c and $d and $e or`,
				`$a and $b and $c and $d and $e or`,
				`$a and $b and $c and $d and $e`,
				`}`,
			}, " "),
			expectError: false,
			description: "Documents compiler handles very long conditions",
		},
		{
			name:        "deep-arithmetic-nesting",
			rule:        `rule test { condition: 1 + 2 * (3 + (4 * (5 + (6 * 7)))) }`,
			expectError: false,
			description: "Documents compiler handles deep arithmetic nesting",
		},
		{
			name:        "multiple-private-strings",
			rule:        `rule test { strings: $a = "test" private $b = "test2" private condition: $a or $b }`,
			expectError: false,
			description: "Documents compiler handles multiple private strings",
		},
		{
			name:        "xor-with-key",
			rule:        `rule test { strings: $a = "test" xor condition: $a }`,
			expectError: false,
			description: "Documents compiler handles xor modifier",
		},
		{
			name:        "base64-with-alphabet",
			rule:        `rule test { strings: $a = "test" base64 condition: $a }`,
			expectError: false,
			description: "Documents compiler handles base64 modifier",
		},
		{
			name:        "hex-with-large-jumps",
			rule:        `rule test { strings: $a = { DE [100] AD [200] BE } condition: $a }`,
			expectError: false,
			description: "Documents compiler handles large hex jumps",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiler := compiler.NewCompiler()
			program, err := compiler.CompileSourceWithContext(context.Background(), tt.rule)

			expectation := compileExpectation{
				expectError: tt.expectError,
				description: tt.description,
			}
			result := compileResult{program: program, err: err}
			if result.handleExpectedError(t, expectation, "no error produced") {
				return
			}
			switch {
			case result.err != nil:
				t.Fatalf("unexpected compilation error: %v", result.err)
			case result.program == nil:
				t.Fatal("compilation succeeded without a program")
			}
		})
	}
}

// TestErrorRecovery documents how errors are recovered from
func TestErrorRecovery(t *testing.T) {
	tests := []struct {
		name        string
		rules       string
		expectError bool
		description string
	}{
		{
			name:        "one-invalid-one-valid",
			rules:       `rule test1 { condition: ) } rule test2 { condition: true }`,
			expectError: true,
			description: "Documents that one invalid rule prevents entire compilation",
		},
		{
			name:        "valid-rules-after-invalid",
			rules:       `rule test1 { condition: true } rule test2 { invalid syntax } rule test3 { condition: true }`,
			expectError: true,
			description: "Documents that valid rules after invalid are not compiled",
		},
		{
			name:        "multiple-invalid-rules",
			rules:       `rule test1 { condition: ) } rule test2 { strings: $a = "test condition: $a }`,
			expectError: true,
			description: "Documents multiple invalid rules both cause errors",
		},
		{
			name:        "partial-error-in-string",
			rules:       `rule test1 { strings: $a = "test" $b = "unclosed condition: $a }`,
			expectError: true,
			description: "Documents error in string section prevents compilation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiler := compiler.NewCompiler()
			program, err := compiler.CompileSourceWithContext(context.Background(), tt.rules)

			assertSimpleCompileExpectation(t, compileResult{program: program, err: err}, compileExpectation{
				expectError: tt.expectError,
				description: tt.description,
			})
		})
	}
}

// TestWarningConditions documents conditions that might generate warnings
func TestWarningConditions(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "empty-strings-section",
			rule:        `rule test { strings: condition: true }`,
			expectError: false,
			description: "Documents empty strings section (may generate warning)",
		},
		{
			name:        "empty-meta-section",
			rule:        `rule test { meta: condition: true }`,
			expectError: false,
			description: "Documents empty meta section (may generate warning)",
		},
		{
			name:        "always-true-rule",
			rule:        `rule test { condition: true }`,
			expectError: false,
			description: "Documents always-true rule (may generate warning)",
		},
		{
			name:        "always-false-rule",
			rule:        `rule test { condition: false }`,
			expectError: false,
			description: "Documents always-false rule (may generate warning)",
		},
		{
			name:        "unused-string",
			rule:        `rule test { strings: $a = "test" $b = "unused" condition: $a }`,
			expectError: false,
			description: "Documents unused string (may generate warning)",
		},
		{
			name:        "unreachable-condition",
			rule:        `rule test { condition: false and true }`,
			expectError: false,
			description: "Documents unreachable condition due to short-circuit (may generate warning)",
		},
		{
			name:        "redundant-condition",
			rule:        `rule test { strings: $a = "test" condition: $a or $a }`,
			expectError: false,
			description: "Documents redundant condition (may generate warning)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiler := compiler.NewCompiler()
			program, err := compiler.CompileSourceWithContext(context.Background(), tt.rule)

			expectation := compileExpectation{
				expectError: tt.expectError,
				description: tt.description,
			}
			result := compileResult{program: program, err: err}
			if result.handleExpectedError(t, expectation, "no error produced") {
				return
			}
			switch {
			case result.err != nil:
				t.Fatalf("unexpected compilation error: %v", result.err)
			case result.program == nil:
				t.Fatal("compilation succeeded without a program")
			}
		})
	}
}

// TestEdgeCaseErrorConditions documents edge cases in error handling
func TestEdgeCaseErrorConditions(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "max-string-identifier-length",
			rule:        `rule test { strings: $` + strings.Repeat("a", 10000) + ` = "test" condition: true }`,
			expectError: false,
			description: "Documents handling of very long string identifiers",
		},
		{
			name:        "max-rule-name-length",
			rule:        `rule ` + strings.Repeat("a", 10000) + ` { condition: true }`,
			expectError: false,
			description: "Documents handling of very long rule names",
		},
		{
			name:        "maximum-integer-literal",
			rule:        `rule test { condition: 9223372036854775807 == 9223372036854775807 }`,
			expectError: false,
			description: "Documents handling of max int64 literal",
		},
		{
			name:        "minimum-integer-literal",
			rule:        `rule test { condition: -9223372036854775808 == -9223372036854775808 }`,
			expectError: false,
			description: "Documents handling of min int64 literal",
		},
		{
			name:        "zero-length-hex",
			rule:        `rule test { strings: $a = {} condition: true }`,
			expectError: true,
			description: "Rejects zero-length hex pattern",
		},
		{
			name:        "single-byte-hex",
			rule:        `rule test { strings: $a = { DE } condition: $a }`,
			expectError: false,
			description: "Documents handling of single-byte hex pattern",
		},
		{
			name:        "zero-length-string",
			rule:        `rule test { strings: $a = "" condition: true }`,
			expectError: true,
			description: "Rejects zero-length text strings",
		},
		{
			name:        "very-long-string-literal",
			rule:        `rule test { strings: $a = "` + strings.Repeat("a", 10000) + `" condition: $a }`,
			expectError: false,
			description: "Documents handling of very long string literals",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiler := compiler.NewCompiler()
			program, err := compiler.CompileSourceWithContext(context.Background(), tt.rule)

			assertSimpleCompileExpectation(t, compileResult{program: program, err: err}, compileExpectation{
				expectError: tt.expectError,
				description: tt.description,
			})
		})
	}
}
