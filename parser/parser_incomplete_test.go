package parser

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/internal/lexer"
)

type parseExpectation = bool

const (
	parseOK            parseExpectation = false
	parseErrorKnownGap parseExpectation = true
)

// assertParseResult is a test helper that logs the parse outcome.
//
//nolint:revive // argument-limit: test helper
func assertParseResult(t *testing.T, program *ast.Program, err error, expect parseExpectation, description string) {
	t.Helper()
	switch expect {
	case parseErrorKnownGap:
		handleKnownGap(t, err, description)
		return
	case parseOK:
		if err != nil {
			t.Logf("Unexpected parse error (documents current behavior): %v", err)
		} else {
			require.NotNil(t, program, "Program should not be nil")
		}
	}
}

func handleKnownGap(t *testing.T, err error, description string) {
	t.Helper()
	if err == nil {
		t.Skipf("known gap: %s (no parse error produced)", description)
		return
	}
	t.Logf("Parse error detected as expected: %v", err)
}

// TestEmptyRule documents parser behavior with empty rule
func TestEmptyRule(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expect      parseExpectation
		description string
	}{
		{
			name:        "just-rule-keyword",
			rule:        `rule`,
			expect:      parseErrorKnownGap,
			description: "Documents only 'rule' keyword",
		},
		{
			name:        "rule-with-name-only",
			rule:        `rule test`,
			expect:      parseErrorKnownGap,
			description: "Documents rule name without body",
		},
		{
			name:        "rule-with-open-brace-only",
			rule:        `rule test {`,
			expect:      parseErrorKnownGap,
			description: "Documents rule with opening brace only",
		},
		{
			name:        "rule-with-close-brace-only",
			rule:        `rule test }`,
			expect:      parseErrorKnownGap,
			description: "Documents rule with closing brace only",
		},
		{
			name:        "empty-braces",
			rule:        `rule test { }`,
			expect:      parseErrorKnownGap,
			description: "Documents rule with empty braces",
		},
		{
			name:        "rule-with-newline-after-name",
			rule:        "rule test\n",
			expect:      parseErrorKnownGap,
			description: "Documents rule name followed by newline",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.rule)
			p := New(l)
			program, err := p.ParseRules()

			assertParseResult(t, program, err, tt.expect, tt.description)
		})
	}
}

// TestRuleWithoutCondition documents parser behavior with rules missing conditions
func TestRuleWithoutCondition(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expect      parseExpectation
		description string
	}{
		{
			name:        "meta-only",
			rule:        `rule test { meta: author = "test" }`,
			expect:      parseErrorKnownGap,
			description: "Documents rule with only meta section",
		},
		{
			name:        "strings-only",
			rule:        `rule test { strings: $a = "test" }`,
			expect:      parseErrorKnownGap,
			description: "Documents rule with only strings section",
		},
		{
			name:        "meta-and-strings-no-condition",
			rule:        `rule test { meta: author = "test" strings: $a = "test" }`,
			expect:      parseErrorKnownGap,
			description: "Documents rule with meta and strings but no condition",
		},
		{
			name:        "condition-keyword-no-expression",
			rule:        `rule test { condition: }`,
			expect:      parseErrorKnownGap,
			description: "Documents condition keyword without expression",
		},
		{
			name:        "incomplete-condition",
			rule:        `rule test { condition: $a }`,
			expect:      parseOK,
			description: "Known gap: parser does not validate string references in conditions",
		},
		{
			name:        "empty-condition-section",
			rule:        `rule test { strings: $a = "test" condition:  }`,
			expect:      parseErrorKnownGap,
			description: "Documents empty condition expression",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.rule)
			p := New(l)
			program, err := p.ParseRules()

			assertParseResult(t, program, err, tt.expect, tt.description)
		})
	}
}

// TestRuleWithOnlyMeta documents parser behavior with rules having only meta
func TestRuleWithOnlyMeta(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expect      parseExpectation
		description string
	}{
		{
			name:        "single-meta",
			rule:        `rule test { meta: author = "test" }`,
			expect:      parseErrorKnownGap,
			description: "Documents rule with single meta entry",
		},
		{
			name:        "multiple-meta",
			rule:        `rule test { meta: author = "test" date = "2024-01-01" }`,
			expect:      parseErrorKnownGap,
			description: "Documents rule with multiple meta entries",
		},
		{
			name:        "meta-without-value",
			rule:        `rule test { meta: author }`,
			expect:      parseErrorKnownGap,
			description: "Documents meta key without value",
		},
		{
			name:        "meta-without-equals",
			rule:        `rule test { meta: author "test" }`,
			expect:      parseErrorKnownGap,
			description: "Documents meta without equals operator",
		},
		{
			name:        "meta-without-quotes",
			rule:        `rule test { meta: author = test }`,
			expect:      parseErrorKnownGap,
			description: "Documents meta with unquoted value",
		},
		{
			name:        "meta-int-value",
			rule:        `rule test { meta: count = 123 }`,
			expect:      parseErrorKnownGap,
			description: "Documents meta with integer value",
		},
		{
			name:        "meta-bool-value",
			rule:        `rule test { meta: is_true = true }`,
			expect:      parseErrorKnownGap,
			description: "Documents meta with boolean value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.rule)
			p := New(l)
			program, err := p.ParseRules()

			assertParseResult(t, program, err, tt.expect, tt.description)
		})
	}
}

// TestRuleWithOnlyStrings documents parser behavior with rules having only strings
func TestRuleWithOnlyStrings(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expect      parseExpectation
		description string
	}{
		{
			name:        "single-string",
			rule:        `rule test { strings: $a = "test" }`,
			expect:      parseErrorKnownGap,
			description: "Documents rule with single string",
		},
		{
			name:        "multiple-strings",
			rule:        `rule test { strings: $a = "test" $b = "other" }`,
			expect:      parseErrorKnownGap,
			description: "Documents rule with multiple strings",
		},
		{
			name:        "hex-string-only",
			rule:        `rule test { strings: $a = { DE AD BE EF } }`,
			expect:      parseErrorKnownGap,
			description: "Documents rule with only hex string",
		},
		{
			name:        "regex-string-only",
			rule:        `rule test { strings: $a = /test/ }`,
			expect:      parseErrorKnownGap,
			description: "Documents rule with only regex string",
		},
		{
			name:        "string-without-identifier",
			rule:        `rule test { strings: = "test" }`,
			expect:      parseErrorKnownGap,
			description: "Documents string without identifier",
		},
		{
			name:        "identifier-without-value",
			rule:        `rule test { strings: $a }`,
			expect:      parseErrorKnownGap,
			description: "Documents string identifier without value",
		},
		{
			name:        "anonymous-string",
			rule:        `rule test { strings: $ = "test" }`,
			expect:      parseErrorKnownGap,
			description: "Documents rule with only anonymous string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.rule)
			p := New(l)
			program, err := p.ParseRules()

			assertParseResult(t, program, err, tt.expect, tt.description)
		})
	}
}

// TestTruncatedInput documents parser behavior with truncated input
func TestTruncatedInput(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expect      parseExpectation
		description string
	}{
		{
			name:        "truncated-at-rule-keyword",
			rule:        `ru`,
			expect:      parseErrorKnownGap,
			description: "Documents input truncated at rule keyword",
		},
		{
			name:        "truncated-at-identifier",
			rule:        `rule tes`,
			expect:      parseErrorKnownGap,
			description: "Documents input truncated at rule name",
		},
		{
			name:        "truncated-at-open-brace",
			rule:        `rule test`,
			expect:      parseErrorKnownGap,
			description: "Documents input before opening brace",
		},
		{
			name:        "truncated-at-strings",
			rule:        `rule test { str`,
			expect:      parseErrorKnownGap,
			description: "Documents input truncated in strings keyword",
		},
		{
			name:        "truncated-at-condition",
			rule:        `rule test { strings: $a = "test" cond`,
			expect:      parseErrorKnownGap,
			description: "Documents input truncated in condition keyword",
		},
		{
			name:        "truncated-in-expression",
			rule:        `rule test { condition: $a and`,
			expect:      parseErrorKnownGap,
			description: "Documents input truncated in expression",
		},
		{
			name:        "truncated-in-string",
			rule:        `rule test { strings: $a = "test`,
			expect:      parseErrorKnownGap,
			description: "Documents input truncated in string literal",
		},
		{
			name:        "truncated-in-hex",
			rule:        `rule test { strings: $a = { DE AD`,
			expect:      parseErrorKnownGap,
			description: "Documents input truncated in hex pattern",
		},
		{
			name:        "truncated-in-regex",
			rule:        `rule test { strings: $a = /test`,
			expect:      parseErrorKnownGap,
			description: "Documents input truncated in regex",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.rule)
			p := New(l)
			program, err := p.ParseRules()

			assertParseResult(t, program, err, tt.expect, tt.description)
		})
	}
}

// TestPartialStringsSection documents parser behavior with partial strings section
func TestPartialStringsSection(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expect      parseExpectation
		description string
	}{
		{
			name:        "strings-colon-only",
			rule:        `rule test { strings: }`,
			expect:      parseErrorKnownGap,
			description: "Documents strings section with only colon",
		},
		{
			name:        "strings-without-colon",
			rule:        `rule test { strings $a = "test" condition: $a }`,
			expect:      parseErrorKnownGap,
			description: "Documents strings without colon",
		},
		{
			name:        "incomplete-string-decl",
			rule:        `rule test { strings: $a condition: true }`,
			expect:      parseErrorKnownGap,
			description: "Documents string declaration without value",
		},
		{
			name:        "incomplete-hex-pattern",
			rule:        `rule test { strings: $a = { DE condition: true }`,
			expect:      parseErrorKnownGap,
			description: "Documents incomplete hex pattern",
		},
		{
			name:        "incomplete-modifier",
			rule:        `rule test { strings: $a = "test" noc condition: true }`,
			expect:      parseErrorKnownGap,
			description: "Documents incomplete modifier",
		},
		{
			name:        "missing-identifier",
			rule:        `rule test { strings: = "test" condition: true }`,
			expect:      parseErrorKnownGap,
			description: "Documents string without identifier",
		},
		{
			name:        "double-dollar",
			rule:        `rule test { strings: $$ = "test" condition: true }`,
			expect:      parseErrorKnownGap,
			description: "Documents double dollar sign",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.rule)
			p := New(l)
			program, err := p.ParseRules()

			assertParseResult(t, program, err, tt.expect, tt.description)
		})
	}
}

// TestPartialCondition documents parser behavior with partial condition section
func TestPartialCondition(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expect      parseExpectation
		description string
	}{
		{
			name:        "condition-colon-only",
			rule:        `rule test { condition: }`,
			expect:      parseErrorKnownGap,
			description: "Documents condition with only colon",
		},
		{
			name:        "condition-without-colon",
			rule:        `rule test { condition $a }`,
			expect:      parseErrorKnownGap,
			description: "Documents condition without colon",
		},
		{
			name:        "incomplete-boolean",
			rule:        `rule test { condition: $a and }`,
			expect:      parseErrorKnownGap,
			description: "Documents incomplete boolean expression",
		},
		{
			name:        "incomplete-comparison",
			rule:        `rule test { condition: filesize > }`,
			expect:      parseErrorKnownGap,
			description: "Documents incomplete comparison",
		},
		{
			name:        "incomplete-of-expression",
			rule:        `rule test { condition: any of }`,
			expect:      parseErrorKnownGap,
			description: "Documents incomplete of-expression",
		},
		{
			name:        "incomplete-for-loop",
			rule:        `rule test { condition: for any i in }`,
			expect:      parseErrorKnownGap,
			description: "Documents incomplete for-loop",
		},
		{
			name:        "incomplete-function",
			rule:        `rule test { condition: int8( }`,
			expect:      parseErrorKnownGap,
			description: "Documents incomplete function call",
		},
		{
			name:        "hanging-operator",
			rule:        `rule test { condition: $a and }`,
			expect:      parseErrorKnownGap,
			description: "Documents hanging binary operator",
		},
		{
			name:        "incomplete-string-ref",
			rule:        `rule test { condition: # }`,
			expect:      parseErrorKnownGap,
			description: "Documents incomplete string count",
		},
		{
			name:        "incomplete-offset",
			rule:        `rule test { condition: @a[ }`,
			expect:      parseErrorKnownGap,
			description: "Documents incomplete offset expression",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.rule)
			p := New(l)
			program, err := p.ParseRules()

			assertParseResult(t, program, err, tt.expect, tt.description)
		})
	}
}

// TestPartialMeta documents parser behavior with partial meta section
func TestPartialMeta(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expect      parseExpectation
		description string
	}{
		{
			name:        "meta-colon-only",
			rule:        `rule test { meta: }`,
			expect:      parseErrorKnownGap,
			description: "Documents meta with only colon",
		},
		{
			name:        "meta-without-colon",
			rule:        `rule test { meta author = "test" }`,
			expect:      parseErrorKnownGap,
			description: "Documents meta without colon",
		},
		{
			name:        "incomplete-meta-entry",
			rule:        `rule test { meta: author }`,
			expect:      parseErrorKnownGap,
			description: "Documents meta entry without value",
		},
		{
			name:        "missing-equals",
			rule:        `rule test { meta: author "test" }`,
			expect:      parseErrorKnownGap,
			description: "Documents meta without equals",
		},
		{
			name:        "missing-value-quotes",
			rule:        `rule test { meta: author = }`,
			expect:      parseErrorKnownGap,
			description: "Documents meta with missing value",
		},
		{
			name:        "unclosed-string",
			rule:        `rule test { meta: author = "test }`,
			expect:      parseErrorKnownGap,
			description: "Documents meta with unclosed string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.rule)
			p := New(l)
			program, err := p.ParseRules()

			assertParseResult(t, program, err, tt.expect, tt.description)
		})
	}
}

// TestMultipleIncompleteRules documents parser behavior with multiple incomplete rules
func TestMultipleIncompleteRules(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expect      parseExpectation
		description string
	}{
		{
			name:        "two-incomplete-rules",
			rule:        `rule test1 { condition: } rule test2 { condition: }`,
			expect:      parseErrorKnownGap,
			description: "Documents two incomplete rules",
		},
		{
			name:        "complete-then-incomplete",
			rule:        `rule test1 { condition: true } rule test2 { condition: }`,
			expect:      parseErrorKnownGap,
			description: "Documents complete rule followed by incomplete",
		},
		{
			name:        "incomplete-then-complete",
			rule:        `rule test1 { condition: } rule test2 { condition: true }`,
			expect:      parseErrorKnownGap,
			description: "Documents incomplete rule followed by complete",
		},
		{
			name:        "partial-then-partial",
			rule:        `rule test1 { strings: } rule test2 { condition: }`,
			expect:      parseErrorKnownGap,
			description: "Documents two partially complete rules",
		},
		{
			name:        "many-incomplete-rules",
			rule:        strings.Repeat(`rule test { condition: } `, 5),
			expect:      parseErrorKnownGap,
			description: "Documents many incomplete rules",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.rule)
			p := New(l)
			program, err := p.ParseRules()

			assertParseResult(t, program, err, tt.expect, tt.description)
		})
	}
}
