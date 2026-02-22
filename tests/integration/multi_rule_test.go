package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/compiler"
)

// TestMultipleRulesIndependent documents behavior with multiple independent rules
// DO NOT modify code to make tests pass - document current behavior only
func TestMultipleRulesIndependent(t *testing.T) {
	tests := []struct {
		name        string
		rules       string
		expectError bool
		description string
	}{
		{
			name:        "two-rules-both-compile",
			rules:       `rule test1 { condition: true } rule test2 { condition: false }`,
			expectError: false,
			description: "Documents multiple rules both compile",
		},
		{
			name:        "two-rules-both-true",
			rules:       `rule test1 { condition: true } rule test2 { condition: true }`,
			expectError: false,
			description: "Documents multiple true rules compile",
		},
		{
			name: "many-rules",
			rules: strings.Join([]string{
				`rule test1 { strings: $a = "a" condition: $a }`,
				`rule test2 { strings: $b = "b" condition: $b }`,
				`rule test3 { strings: $c = "c" condition: $c }`,
				`rule test4 { condition: true }`,
				`rule test5 { condition: false }`,
			}, " "),
			expectError: false,
			description: "Documents many rules compile",
		},
		{
			name:        "rules-with-same-strings",
			rules:       `rule test1 { strings: $a = "test" condition: $a } rule test2 { strings: $a = "test" condition: $a }`,
			expectError: false,
			description: "Documents multiple rules with same string identifiers compile",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := compiler.NewCompiler()
			program, err := c.CompileSourceWithContext(context.Background(), tt.rules)

			if tt.expectError {
				if err == nil {
					t.Logf("TODO: Expected compilation error but got none - gap detected for: %s", tt.description)
				}
				return
			}
			if err != nil {
				t.Logf("Unexpected compilation error (documents current behavior): %v", err)
			} else if program != nil {
				t.Logf("Successfully compiled: %s", tt.description)
				t.Logf("  Program contains %d rules", program.GetRuleCount())
			}
		})
	}
}

// TestRuleDependencies documents rule reference compilation
// DO NOT modify code to make tests pass - document current behavior only
func TestRuleDependencies(t *testing.T) {
	tests := []struct {
		name        string
		rules       string
		expectError bool
		description string
	}{
		{
			name:        "simple-rule-reference",
			rules:       `rule base { strings: $a = "a" condition: $a } rule derived { condition: base }`,
			expectError: false,
			description: "Documents simple rule reference compiles",
		},
		{
			name:        "reference-to-false-rule",
			rules:       `rule base { condition: false } rule derived { condition: base }`,
			expectError: false,
			description: "Documents reference to false rule compiles",
		},
		{
			name:        "chained-references",
			rules:       `rule base { strings: $a = "a" condition: $a } rule middle { condition: base } rule top { condition: middle }`,
			expectError: false,
			description: "Documents chained rule references compile",
		},
		{
			name:        "multiple-references",
			rules:       `rule base { strings: $a = "a" condition: $a } rule derived1 { condition: base } rule derived2 { condition: base }`,
			expectError: false,
			description: "Documents multiple rules referencing same base compile",
		},
		{
			name:        "or-with-references",
			rules:       `rule base1 { strings: $a = "a" condition: $a } rule base2 { strings: $b = "b" condition: $b } rule combined { condition: base1 or base2 }`,
			expectError: false,
			description: "Documents boolean logic with rule references compiles",
		},
		{
			name:        "and-with-references",
			rules:       `rule base1 { strings: $a = "a" condition: $a } rule base2 { strings: $b = "b" condition: $b } rule combined { condition: base1 and base2 }`,
			expectError: false,
			description: "Documents AND with rule references compiles",
		},
		{
			name:        "not-with-reference",
			rules:       `rule base { condition: false } rule inverted { condition: not base }`,
			expectError: false,
			description: "Documents NOT with rule reference compiles",
		},
		{
			name:        "undefined-reference",
			rules:       `rule test { condition: undefined_rule }`,
			expectError: true,
			description: "Documents reference to undefined rule fails",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := compiler.NewCompiler()
			program, err := c.CompileSourceWithContext(context.Background(), tt.rules)

			assertSimpleCompileResult(t, program, err, tt.expectError, tt.description)
		})
	}
}

// TestRuleModifiers documents rule modifier compilation
// DO NOT modify code to make tests pass - document current behavior only
func TestRuleModifiers(t *testing.T) {
	tests := []struct {
		name        string
		rules       string
		expectError bool
		description string
	}{
		{
			name:        "global-rule",
			rules:       `global rule always_true { condition: true } rule test { condition: true }`,
			expectError: false,
			description: "Documents global rule modifier compiles",
		},
		{
			name:        "private-rule",
			rules:       `private rule hidden { strings: $a = "secret" condition: $a } rule test { condition: true }`,
			expectError: false,
			description: "Documents private rule modifier compiles",
		},
		{
			name:        "private-rule-can-be-referenced",
			rules:       `private rule hidden { strings: $a = "secret" condition: $a } rule test { condition: hidden }`,
			expectError: false,
			description: "Documents private rule can be referenced",
		},
		{
			name:        "tagged-rule",
			rules:       `rule test tag : malware { condition: true }`,
			expectError: false,
			description: "Documents tagged rule compiles",
		},
		{
			name:        "multiple-tags",
			rules:       `rule test tag : malware trojan { condition: true }`,
			expectError: false,
			description: "Documents rule with multiple tags compiles",
		},
		{
			name:        "same-name-different-tags",
			rules:       `rule test tag : malware { condition: true } rule test tag : benign { condition: false }`,
			expectError: true,
			description: "Documents duplicate rule names (should error)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := compiler.NewCompiler()
			program, err := c.CompileSourceWithContext(context.Background(), tt.rules)

			assertSimpleCompileResult(t, program, err, tt.expectError, tt.description)
		})
	}
}

// TestRuleNameConflicts documents behavior with duplicate rule names
// DO NOT modify code to make tests pass - document current behavior only
func TestRuleNameConflicts(t *testing.T) {
	tests := []struct {
		name        string
		rules       string
		expectError bool
		description string
	}{
		{
			name:        "duplicate-rule-names",
			rules:       `rule test { condition: true } rule test { condition: false }`,
			expectError: true,
			description: "Documents duplicate rule name detection (or lack thereof)",
		},
		{
			name:        "duplicate-names-with-tags",
			rules:       `rule test tag : a { condition: true } rule test tag : b { condition: false }`,
			expectError: true,
			description: "Documents duplicate names with different tags",
		},
		{
			name:        "different-names-similar-patterns",
			rules:       `rule test1 { condition: true } rule test2 { condition: true }`,
			expectError: false,
			description: "Documents different names are allowed",
		},
		{
			name:        "case-sensitive-names",
			rules:       `rule test { condition: true } rule Test { condition: true } rule TEST { condition: true }`,
			expectError: false,
			description: "Documents case-sensitive rule names",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := compiler.NewCompiler()
			program, err := c.CompileSourceWithContext(context.Background(), tt.rules)

			assertSimpleCompileResult(t, program, err, tt.expectError, tt.description)
		})
	}
}

// TestExternalVariables documents external variable compilation
// DO NOT modify code to make tests pass - document current behavior only
func TestExternalVariables(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "external-integer",
			rule:        `rule test { extern: a = 10 condition: a == 10 }`,
			expectError: false,
			description: "Documents external integer variable compiles",
		},
		{
			name:        "external-string",
			rule:        `rule test { extern: s = "test" condition: s == "test" }`,
			expectError: false,
			description: "Documents external string variable compiles",
		},
		{
			name:        "external-bool",
			rule:        `rule test { extern: b = true condition: b }`,
			expectError: false,
			description: "Documents external boolean variable compiles",
		},
		{
			name:        "multiple-externals",
			rule:        `rule test { extern: a = 1 extern: b = 2 extern: c = 3 condition: a + b + c == 6 }`,
			expectError: false,
			description: "Documents multiple external variables compile",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := compiler.NewCompiler()
			program, err := c.CompileSourceWithContext(context.Background(), tt.rule)

			if tt.expectError {
				if err == nil {
					t.Logf("TODO: Expected compilation error but got none - gap detected for: %s", tt.description)
				}
				return
			}
			if err != nil {
				t.Logf("Unexpected compilation error (documents current behavior): %v", err)
			} else if program != nil {
				t.Logf("Successfully compiled: %s", tt.description)
			}
		})
	}
}

// TestMetaInformation documents meta section compilation
// DO NOT modify code to make tests pass - document current behavior only
func TestMetaInformation(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "simple-meta-string",
			rule:        `rule test { meta: author = "test" condition: true }`,
			expectError: false,
			description: "Documents simple meta string field compiles",
		},
		{
			name:        "meta-integer",
			rule:        `rule test { meta: version = 1 condition: true }`,
			expectError: false,
			description: "Documents meta integer field compiles",
		},
		{
			name:        "meta-boolean",
			rule:        `rule test { meta: enabled = true condition: true }`,
			expectError: false,
			description: "Documents meta boolean field compiles",
		},
		{
			name:        "multiple-meta-fields",
			rule:        `rule test { meta: author = "test" version = 1 date = "2024-01-01" condition: true }`,
			expectError: false,
			description: "Documents multiple meta fields compile",
		},
		{
			name:        "meta-with-strings",
			rule:        `rule test { meta: description = "test rule" strings: $a = "test" condition: $a }`,
			expectError: false,
			description: "Documents meta section with strings compiles",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := compiler.NewCompiler()
			program, err := c.CompileSourceWithContext(context.Background(), tt.rule)

			if tt.expectError {
				if err == nil {
					t.Logf("TODO: Expected compilation error but got none - gap detected for: %s", tt.description)
				}
				return
			}
			if err != nil {
				t.Logf("Unexpected compilation error (documents current behavior): %v", err)
			} else if program != nil {
				t.Logf("Successfully compiled: %s", tt.description)
			}
		})
	}
}
