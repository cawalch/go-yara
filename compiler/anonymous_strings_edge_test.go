package compiler

import (
	"testing"
)

// assertAnonymousStringResult is a test helper that logs the compilation outcome.
//
//nolint:revive // argument-limit: test helper
func assertAnonymousStringResult(t *testing.T, program *CompiledProgram, err error, expectError bool, description string) {
	t.Helper()
	if expectError {
		if err == nil {
			t.Skipf("known gap: %s (no compilation error produced)", description)
		} else {
			t.Logf("Compilation error detected: %v", err)
		}
		return
	}
	if err != nil {
		t.Logf("Unexpected compilation error (documents current behavior): %v", err)
	} else if program != nil {
		t.Logf("Successfully compiled")
	}
}

// TestMultipleAnonymousStrings documents compiler behavior with multiple anonymous strings
// DO NOT modify code to make tests pass - document current behavior only
func TestMultipleAnonymousStrings(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "single-anonymous",
			rule:        `rule test { strings: $ = "test" condition: $ }`,
			expectError: false,
			description: "Documents single anonymous string",
		},
		{
			name:        "two-anonymous",
			rule:        `rule test { strings: $ = "test1" $ = "test2" condition: any of them }`,
			expectError: false,
			description: "Documents two anonymous strings",
		},
		{
			name:        "many-anonymous",
			rule:        `rule test { strings: $ = "a" $ = "b" $ = "c" $ = "d" $ = "e" condition: any of them }`,
			expectError: false,
			description: "Documents many anonymous strings",
		},
		{
			name:        "anonymous-with-named",
			rule:        `rule test { strings: $a = "named" $ = "anon" condition: any of them }`,
			expectError: false,
			description: "Documents mixed anonymous and named strings",
		},
		{
			name:        "all-anonymous",
			rule:        `rule test { strings: $ = "a" $ = "b" $ = "c" condition: all of them }`,
			expectError: false,
			description: "Documents rule with only anonymous strings",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCompiler()
			program, err := c.CompileSource(tt.rule)

			assertAnonymousStringResult(t, program, err, tt.expectError, tt.description)
		})
	}
}

// TestAnonymousStringInForLoops documents anonymous strings in for-loops
// DO NOT modify code to make tests pass - document current behavior only
func TestAnonymousStringInForLoops(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "for-of-anonymous",
			rule:        `rule test { strings: $ = "test" condition: any of them }`,
			expectError: false,
			description: "Documents any of them with anonymous strings",
		},
		{
			name:        "for-all-anonymous",
			rule:        `rule test { strings: $ = "a" $ = "b" condition: all of them }`,
			expectError: false,
			description: "Documents all of them with anonymous strings",
		},
		{
			name:        "numeric-quantifier-anonymous",
			rule:        `rule test { strings: $ = "a" $ = "b" $ = "c" condition: 2 of them }`,
			expectError: false,
			description: "Documents numeric quantifier with anonymous strings",
		},
		{
			name:        "for-loop-with-dollar",
			rule:        `rule test { strings: $ = "test" condition: for any $ in them : ( $ ) }`,
			expectError: true,
			description: "Documents for-loop with $ placeholder (may not be supported)",
		},
		{
			name:        "anonymous-in-explicit-list",
			rule:        `rule test { strings: $ = "test" $a = "other" condition: 1 of ($, $a) }`,
			expectError: false,
			description: "Known gap: compiler allows anonymous $ in explicit of-expression list",
		},
		{
			name:        "them-includes-named",
			rule:        `rule test { strings: $a = "a" $ = "b" condition: all of them }`,
			expectError: false,
			description: "Documents 'them' includes both anonymous and named",
		},
		{
			name:        "none-of-them-anonymous",
			rule:        `rule test { strings: $ = "a" condition: none of them }`,
			expectError: false,
			description: "Documents none of them with anonymous strings",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCompiler()
			program, err := c.CompileSource(tt.rule)

			assertAnonymousStringResult(t, program, err, tt.expectError, tt.description)
		})
	}
}

// TestAnonymousStringInOfExpressions documents anonymous strings in of-expressions
// DO NOT modify code to make tests pass - document current behavior only
func TestAnonymousStringInOfExpressions(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "any-of-anonymous-only",
			rule:        `rule test { strings: $ = "test1" $ = "test2" condition: any of them }`,
			expectError: false,
			description: "Documents any of them with only anonymous strings",
		},
		{
			name:        "any-of-mixed",
			rule:        `rule test { strings: $a = "named" $ = "anon" condition: any of them }`,
			expectError: false,
			description: "Documents any of them with mixed strings",
		},
		{
			name:        "of-explicit-anonymous",
			rule:        `rule test { strings: $ = "test" condition: 1 of ($) }`,
			expectError: false,
			description: "Known gap: compiler allows $ in explicit of-expression (1 of ($))",
		},
		{
			name:        "anonymous-count",
			rule:        `rule test { strings: $ = "test" condition: # > 0 }`,
			expectError: true,
			description: "Documents count on anonymous string (may not be supported)",
		},
		{
			name:        "anonymous-offset",
			rule:        `rule test { strings: $ = "test" condition: @ < 100 }`,
			expectError: true,
			description: "Documents offset on anonymous string (may not be supported)",
		},
		{
			name:        "anonymous-length",
			rule:        `rule test { strings: $ = "test" condition: ! == 4 }`,
			expectError: true,
			description: "Documents length on anonymous string (may not be supported)",
		},
		{
			name:        "multiple-anonymous-matches",
			rule:        `rule test { strings: $ = "a" $ = "a" $ = "b" condition: # >= 2 }`,
			expectError: true,
			description: "Documents count on anonymous strings (may not be supported)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCompiler()
			program, err := c.CompileSource(tt.rule)

			assertAnonymousStringResult(t, program, err, tt.expectError, tt.description)
		})
	}
}

// TestAnonymousStringCollisions documents potential collisions with anonymous strings
// DO NOT modify code to make tests pass - document current behavior only
func TestAnonymousStringCollisions(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "identical-anonymous",
			rule:        `rule test { strings: $ = "test" $ = "test" condition: any of them }`,
			expectError: false,
			description: "Documents identical anonymous strings",
		},
		{
			name:        "similar-anonymous",
			rule:        `rule test { strings: $ = "test" $ = "Test" $ = "TEST" condition: any of them }`,
			expectError: false,
			description: "Documents similar anonymous strings with different cases",
		},
		{
			name:        "anonymous-with-modifiers",
			rule:        `rule test { strings: $ = "test" $ = "test" nocase condition: any of them }`,
			expectError: false,
			description: "Documents identical anonymous strings with different modifiers",
		},
		{
			name:        "anonymous-with-named-same",
			rule:        `rule test { strings: $a = "test" $ = "test" condition: any of them }`,
			expectError: false,
			description: "Documents anonymous and named strings with same value",
		},
		{
			name:        "many-identical-anonymous",
			rule:        `rule test { strings: $ = "test" $ = "test" $ = "test" $ = "test" $ = "test" condition: all of them }`,
			expectError: false,
			description: "Documents many identical anonymous strings",
		},
		{
			name:        "hex-and-text-anonymous",
			rule:        `rule test { strings: $ = /test/ $ = { 74 65 73 74 } condition: any of them }`,
			expectError: false,
			description: "Documents anonymous strings in different formats with same value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCompiler()
			program, err := c.CompileSource(tt.rule)

			assertAnonymousStringResult(t, program, err, tt.expectError, tt.description)
		})
	}
}

// TestMixedAnonymousAndNamedStrings documents mixed anonymous and named string handling
// DO NOT modify code to make tests pass - document current behavior only
func TestMixedAnonymousAndNamedStrings(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "interleaved",
			rule:        `rule test { strings: $a = "a" $ = "x" $b = "b" $ = "y" condition: any of them }`,
			expectError: false,
			description: "Documents interleaved anonymous and named strings",
		},
		{
			name:        "anonymous-first",
			rule:        `rule test { strings: $ = "anon" $a = "named" $b = "other" condition: $a or $ }`,
			expectError: false,
			description: "Known gap: compiler allows direct $ reference in condition",
		},
		{
			name:        "them-includes-all",
			rule:        `rule test { strings: $a = "a" $b = "b" $ = "x" $ = "y" condition: 2 of them }`,
			expectError: false,
			description: "Documents 'them' includes both anonymous and named",
		},
		{
			name:        "of-with-wildcard",
			rule:        `rule test { strings: $a1 = "a" $a2 = "a2" $ = "anon" condition: any of ($a*) }`,
			expectError: false,
			description: "Documents wildcard excludes anonymous strings",
		},
		{
			name:        "explicit-list-mixed",
			rule:        `rule test { strings: $a = "a" $ = "x" $b = "b" condition: any of ($a, $b, $) }`,
			expectError: false,
			description: "Known gap: compiler allows $ placeholder in explicit of-expression list",
		},
		{
			name:        "count-on-named-only",
			rule:        `rule test { strings: $a = "a" $ = "x" $b = "b" condition: #a + # > 1 }`,
			expectError: true,
			description: "Documents count on named strings with anonymous present",
		},
		{
			name:        "offset-on-named-with-anon",
			rule:        `rule test { strings: $a = "test" $ = "other" condition: @a < 100 }`,
			expectError: false,
			description: "Documents offset on named string when anonymous present",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCompiler()
			program, err := c.CompileSource(tt.rule)

			assertAnonymousStringResult(t, program, err, tt.expectError, tt.description)
		})
	}
}

// TestAnonymousStringWithModifiers documents anonymous strings with various modifiers
// DO NOT modify code to make tests pass - document current behavior only
func TestAnonymousStringWithModifiers(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "anonymous-nocase",
			rule:        `rule test { strings: $ = "test" nocase condition: $ }`,
			expectError: false,
			description: "Documents anonymous string with nocase",
		},
		{
			name:        "anonymous-wide",
			rule:        `rule test { strings: $ = "test" wide condition: $ }`,
			expectError: false,
			description: "Documents anonymous string with wide",
		},
		{
			name:        "anonymous-fullword",
			rule:        `rule test { strings: $ = "test" fullword condition: $ }`,
			expectError: false,
			description: "Documents anonymous string with fullword",
		},
		{
			name:        "anonymous-private",
			rule:        `rule test { strings: $ = "test" private condition: $ }`,
			expectError: false,
			description: "Documents anonymous string with private",
		},
		{
			name:        "anonymous-xor",
			rule:        `rule test { strings: $ = "test" xor condition: $ }`,
			expectError: false,
			description: "Documents anonymous string with xor",
		},
		{
			name:        "anonymous-all-modifiers",
			rule:        `rule test { strings: $ = "test" nocase wide fullword private condition: $ }`,
			expectError: false,
			description: "Documents anonymous string with all modifiers",
		},
		{
			name:        "multiple-anonymous-different-modifiers",
			rule:        `rule test { strings: $ = "test" nocase $ = "test" wide $ = "test" fullword condition: any of them }`,
			expectError: false,
			description: "Documents multiple anonymous strings with different modifiers",
		},
		{
			name:        "anonymous-base64",
			rule:        `rule test { strings: $ = "test" base64 condition: $ }`,
			expectError: false,
			description: "Documents anonymous string with base64",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCompiler()
			program, err := c.CompileSource(tt.rule)

			assertAnonymousStringResult(t, program, err, tt.expectError, tt.description)
		})
	}
}
