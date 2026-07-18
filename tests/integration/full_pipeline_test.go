package integration

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cawalch/go-yara/compiler"
	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/parser"
	"github.com/cawalch/go-yara/token"
)

type pipelineExpectation struct {
	expectError bool
	description string
}

type pipelineResult struct {
	program *compiler.CompiledProgram
	err     error
}

func (result pipelineResult) handleExpectedError(t *testing.T, expectation pipelineExpectation, noErrorDetail string) bool {
	t.Helper()
	if !expectation.expectError {
		return false
	}
	if result.err == nil {
		t.Fatalf("expected error not produced: %s (%s)", expectation.description, noErrorDetail)
	}
	return true
}

// assertPipelineResult is a test helper that flattens nested if/else for pipeline results.
func assertPipelineResult(t *testing.T, result pipelineResult, expectation pipelineExpectation) {
	t.Helper()
	if result.handleExpectedError(t, expectation, "no pipeline error produced") {
		return
	}
	switch {
	case result.err != nil:
		t.Fatalf("unexpected pipeline error: %v", result.err)
	case result.program == nil:
		t.Fatal("pipeline succeeded without a program")
	}
}

// TestFullPipelineSimpleRule documents end-to-end pipeline for simple rules
func TestFullPipelineSimpleRule(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "minimal-rule",
			rule:        `rule test { condition: true }`,
			expectError: false,
			description: "Documents pipeline for minimal true rule",
		},
		{
			name:        "minimal-false-rule",
			rule:        `rule test { condition: false }`,
			expectError: false,
			description: "Documents pipeline for minimal false rule",
		},
		{
			name:        "rule-with-single-string",
			rule:        `rule test { strings: $a = "test" condition: $a }`,
			expectError: false,
			description: "Documents pipeline for rule with single string",
		},
		{
			name:        "rule-with-hex-string",
			rule:        `rule test { strings: $a = { DE AD BE EF } condition: $a }`,
			expectError: false,
			description: "Documents pipeline for rule with hex string",
		},
		{
			name:        "rule-with-regex",
			rule:        `rule test { strings: $a = /test/ condition: $a }`,
			expectError: false,
			description: "Documents pipeline for rule with regex",
		},
		{
			name:        "rule-with-meta",
			rule:        `rule test { meta: author = "test" condition: true }`,
			expectError: false,
			description: "Documents pipeline for rule with meta section",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Phase 1: Lexical Analysis
			l := lexer.New(tt.rule)
			tokens := collectTokens(l)
			t.Logf("Phase 1 (Lexer): Produced %d tokens", len(tokens))

			// Phase 2: Parsing
			l2 := lexer.New(tt.rule)
			p := parser.New(l2)
			program, err := p.ParseRulesWithContext(context.Background())

			expectation := pipelineExpectation{
				expectError: tt.expectError,
				description: tt.description,
			}
			if (pipelineResult{err: err}).handleExpectedError(t, expectation, "no pipeline error produced") {
				return
			}

			require.NoError(t, err, "Parser should not error for valid rule")
			require.NotNil(t, program, "Program should not be nil")

			// Phase 3: Semantic Validation
			t.Logf("Phase 2 (Parser): Parsed %d rules", len(program.Rules))

			// Phase 4: Compilation
			compiler := compiler.NewCompiler()
			compiledProgram, err := compiler.CompileSourceWithContext(context.Background(), tt.rule)

			if (pipelineResult{program: compiledProgram, err: err}).handleExpectedError(t, expectation, "no compilation error produced") {
				return
			}

			require.NoError(t, err, "Compiler should not error for valid rule")
			require.NotNil(t, compiledProgram, "Compiled program should not be nil")

			// Phase 5: Validation
			t.Logf("Phase 3 (Compiler): Compiled %d rules", compiledProgram.GetRuleCount())

			err = compiledProgram.Validate()
			require.NoError(t, err, "Program validation should succeed")

			// Document bytecode characteristics
			stats := compiler.GetStats()
			t.Logf("Phase 4 (Validation): %d rules compiled, %d total bytecode bytes",
				stats.RulesCompiled, compiledProgram.GetTotalBytecodeSize())
		})
	}
}

// TestFullPipelineComplexRule documents end-to-end pipeline for complex rules
func TestFullPipelineComplexRule(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name: "many-strings",
			rule: `rule test {
	strings:
			$a1 = "alpha"
		$a2 = "beta"
		$a3 = "gamma"
		$a4 = "delta"
		$a5 = "epsilon"
		$b1 = "one"
		$b2 = "two"
		$b3 = "three"
		condition:
		3 of ($a*, $b*)
}`,
			expectError: false,
			description: "Documents pipeline for rule with many strings",
		},
		{
			name: "complex-condition",
			rule: `rule test {
	strings:
		$malware = "malware"
		$version = "1.0"
		condition:
		$malware and filesize > 1000 and #malware == 1
		or
		$version and @version > 100
}`,
			expectError: false,
			description: "Documents pipeline with complex condition",
		},
		{
			name: "nested-expressions",
			rule: `rule test {
	strings:
		$a = "a"
		$b = "b"
		$c = "c"
	condition:
		(($a and $b) or $c) and filesize > 0
}`,
			expectError: false,
			description: "Documents pipeline with nested expressions",
		},
		{
			name: "for-loop-in-condition",
			rule: `rule test {
	strings:
		$a = "a"
		$b = "b"
		$c = "c"
		condition:
		for any i in (1..10) : ( i > 5 )
}`,
			expectError: false,
			description: "Documents pipeline with for-in loop",
		},
		{
			name: "of-expressions",
			rule: `rule test {
	strings:
		$a1 = "test1"
		$a2 = "test2"
		$b1 = "other1"
		$b2 = "other2"
	condition:
		2 of ($a*, $b*)
}`,
			expectError: false,
			description: "Documents pipeline with of-expressions",
		},
		{
			name: "built-in-functions",
			rule: `rule test {
	strings:
		$a = "test"
	condition:
		int8(@a[1]) == 0x74
	}`,
			expectError: false,
			description: "Documents pipeline with built-in functions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Full pipeline: lexer → parser → semantic → compiler → validator
			compiler := compiler.NewCompiler()
			program, err := compiler.CompileSourceWithContext(context.Background(), tt.rule)

			assertPipelineResult(t, pipelineResult{program: program, err: err}, pipelineExpectation{
				expectError: tt.expectError,
				description: tt.description,
			})
		})
	}
}

// TestFullPipelineMultipleRules documents end-to-end pipeline for multiple rules
func TestFullPipelineMultipleRules(t *testing.T) {
	tests := []struct {
		name        string
		rules       string
		expectError bool
		description string
	}{
		{
			name:        "two-independent-rules",
			rules:       `rule test1 { condition: true } rule test2 { condition: false }`,
			expectError: false,
			description: "Documents pipeline with multiple independent rules",
		},
		{
			name:        "dependent-rules",
			rules:       `rule base { strings: $a = "a" condition: $a } rule derived { condition: base }`,
			expectError: false,
			description: "Documents pipeline with rule dependencies",
		},
		{
			name:        "global-rule",
			rules:       `global rule always_true { condition: true } rule test { condition: always_true }`,
			expectError: false,
			description: "Documents pipeline with global rule",
		},
		{
			name:        "private-rules",
			rules:       `private rule hidden { strings: $a = "secret" condition: $a } rule test { condition: true }`,
			expectError: false,
			description: "Documents pipeline with private rules",
		},
		{
			name:        "tagged-rules",
			rules:       `rule first : malware { condition: true } rule second : benign { condition: false }`,
			expectError: false,
			description: "Documents pipeline with tagged rules",
		},
		{
			name: "many-rules",
			rules: strings.Join([]string{
				`rule test1 { condition: true }`,
				`rule test2 { condition: false }`,
				`rule test3 { strings: $a = "test" condition: $a }`,
				`rule test4 { condition: filesize > 0 }`,
				`rule test5 { condition: entrypoint > 0 }`,
			}, " "),
			expectError: false,
			description: "Documents pipeline with many rules",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiler := compiler.NewCompiler()
			program, err := compiler.CompileSourceWithContext(context.Background(), tt.rules)

			assertPipelineResult(t, pipelineResult{program: program, err: err}, pipelineExpectation{
				expectError: tt.expectError,
				description: tt.description,
			})
		})
	}
}

// TestFullPipelineWithIncludes verifies include resolution through compilation and scanning.
func TestFullPipelineWithIncludes(t *testing.T) {
	t.Run("simple include", func(t *testing.T) {
		dir := t.TempDir()
		includedPath := filepath.Join(dir, "included.yar")
		mainPath := filepath.Join(dir, "main.yar")
		require.NoError(t, os.WriteFile(includedPath, []byte(`
rule included {
    strings: $a = "test"
    condition: $a
}`), 0600))
		require.NoError(t, os.WriteFile(mainPath, []byte(`
include "included.yar"
rule main { condition: true }
`), 0600))

		program, err := compiler.NewCompiler().CompileFileWithContext(context.Background(), mainPath)
		require.NoError(t, err)
		require.Len(t, program.Rules, 2)

		result, err := program.Scan([]byte("contains test data"))
		require.NoError(t, err)
		require.True(t, result.RuleResults["included"])
		require.True(t, result.RuleResults["main"])
	})

	t.Run("missing include", func(t *testing.T) {
		dir := t.TempDir()
		mainPath := filepath.Join(dir, "main.yar")
		require.NoError(t, os.WriteFile(mainPath, []byte(`
include "missing.yar"
rule main { condition: true }
`), 0600))

		_, err := compiler.NewCompiler().CompileFileWithContext(context.Background(), mainPath)
		require.ErrorContains(t, err, "failed to read include file missing.yar")
	})

	t.Run("missing nested include", func(t *testing.T) {
		dir := t.TempDir()
		nestedPath := filepath.Join(dir, "nested.yar")
		mainPath := filepath.Join(dir, "main.yar")
		require.NoError(t, os.WriteFile(nestedPath, []byte(`
include "inner.yar"
rule nested { condition: true }
`), 0600))
		require.NoError(t, os.WriteFile(mainPath, []byte(`
include "nested.yar"
rule main { condition: nested }
`), 0600))

		_, err := compiler.NewCompiler().CompileFileWithContext(context.Background(), mainPath)
		require.ErrorContains(t, err, "failed to process includes in nested.yar")
		require.ErrorContains(t, err, "failed to read include file inner.yar")
	})
}

// TestFullPipelineWithErrorRecovery documents error handling across pipeline stages
func TestFullPipelineWithErrorRecovery(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "lexer-error",
			rule:        `rule test { strings: $a = "unclosed string condition: $a }`,
			expectError: true,
			description: "Documents error handling for lexer errors",
		},
		{
			name:        "parser-error",
			rule:        `rule test { condition: ) }`,
			expectError: true,
			description: "Documents error handling for parser errors",
		},
		{
			name:        "semantic-error",
			rule:        `rule test { strings: $a = "test" condition: $undefined }`,
			expectError: true,
			description: "Documents error handling for undefined references",
		},
		{
			name:        "compiler-error",
			rule:        `rule test { strings: $a = "test" invalid_syntax }`,
			expectError: true,
			description: "Documents error handling for invalid syntax",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiler := compiler.NewCompiler()
			program, err := compiler.CompileSourceWithContext(context.Background(), tt.rule)

			assertPipelineResult(t, pipelineResult{program: program, err: err}, pipelineExpectation{
				expectError: tt.expectError,
				description: tt.description,
			})
		})
	}
}

// Helper function to collect all tokens from lexer
func collectTokens(l *lexer.Lexer) []string {
	var tokens []string
	for {
		tok := l.NextToken()
		tokens = append(tokens, tok.String())
		if tok.Type == token.EOF || tok.Type == token.ILLEGAL {
			break
		}
	}
	return tokens
}
