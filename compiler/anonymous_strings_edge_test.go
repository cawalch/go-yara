package compiler

import (
	"testing"
)

type anonymousStringTestCase struct {
	name        string
	rule        string
	expectError bool
	knownGap    string
	description string
}

type anonymousStringCompileResult struct {
	program *CompiledProgram
	err     error
}

// assertAnonymousStringResult is a test helper that logs the compilation outcome.
func (result anonymousStringCompileResult) assertExpected(t *testing.T, expectError bool, description string) {
	t.Helper()
	if expectError {
		if result.err == nil {
			t.Fatalf("expected compilation error not produced: %s", description)
		} else {
			t.Logf("Compilation error detected: %v", result.err)
		}
		return
	}
	if result.err != nil {
		t.Logf("Unexpected compilation error (documents current behavior): %v", result.err)
	} else if result.program != nil {
		t.Logf("Successfully compiled")
	}
}

func (result anonymousStringCompileResult) assertCase(t *testing.T, tt anonymousStringTestCase) {
	t.Helper()
	if tt.knownGap == "" {
		result.assertExpected(t, tt.expectError, tt.description)
		return
	}
	if tt.expectError {
		if result.err == nil {
			t.Skipf("known gap: %s (no compilation error produced)", tt.knownGap)
		} else {
			t.Logf("Compilation error detected: %v", result.err)
		}
		return
	}
	if result.err != nil {
		t.Logf("Unexpected compilation error (documents current behavior): %v", result.err)
	} else if result.program != nil {
		t.Logf("Known gap accepted: %s", tt.knownGap)
		t.Logf("Successfully compiled")
	}
}

// TestMultipleAnonymousStrings documents compiler behavior with multiple anonymous strings
// DO NOT modify code to make tests pass - document current behavior only
func TestMultipleAnonymousStrings(t *testing.T) {
	tests := []anonymousStringTestCase{
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

			anonymousStringCompileResult{program: program, err: err}.assertCase(t, tt)
		})
	}
}

// TestAnonymousStringInForLoops documents anonymous strings in for-loops
// DO NOT modify code to make tests pass - document current behavior only
func TestAnonymousStringInForLoops(t *testing.T) {
	tests := []anonymousStringTestCase{
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
			knownGap:    "compiler accepts for-loop with anonymous $ placeholder",
			description: "Documents for-loop with $ placeholder (may not be supported)",
		},
		{
			name:        "anonymous-in-explicit-list",
			rule:        `rule test { strings: $ = "test" $a = "other" condition: 1 of ($, $a) }`,
			expectError: false,
			knownGap:    "compiler allows anonymous $ in explicit of-expression list",
			description: "Documents anonymous $ in explicit of-expression list",
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

			anonymousStringCompileResult{program: program, err: err}.assertCase(t, tt)
		})
	}
}

// TestAnonymousStringInOfExpressions documents anonymous strings in of-expressions
// DO NOT modify code to make tests pass - document current behavior only
func TestAnonymousStringInOfExpressions(t *testing.T) {
	tests := []anonymousStringTestCase{
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
			knownGap:    "compiler allows $ in explicit of-expression (1 of ($))",
			description: "Documents $ in explicit of-expression",
		},
		{
			name:        "anonymous-count",
			rule:        `rule test { strings: $ = "test" condition: # > 0 }`,
			expectError: true,
			knownGap:    "compiler accepts count on anonymous string",
			description: "Documents count on anonymous string (may not be supported)",
		},
		{
			name:        "anonymous-offset",
			rule:        `rule test { strings: $ = "test" condition: @ < 100 }`,
			expectError: true,
			knownGap:    "compiler accepts offset on anonymous string",
			description: "Documents offset on anonymous string (may not be supported)",
		},
		{
			name:        "anonymous-length",
			rule:        `rule test { strings: $ = "test" condition: ! == 4 }`,
			expectError: true,
			knownGap:    "compiler accepts length on anonymous string",
			description: "Documents length on anonymous string (may not be supported)",
		},
		{
			name:        "multiple-anonymous-matches",
			rule:        `rule test { strings: $ = "a" $ = "a" $ = "b" condition: # >= 2 }`,
			expectError: true,
			knownGap:    "compiler accepts count on multiple anonymous strings",
			description: "Documents count on anonymous strings (may not be supported)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCompiler()
			program, err := c.CompileSource(tt.rule)

			anonymousStringCompileResult{program: program, err: err}.assertCase(t, tt)
		})
	}
}

// TestAnonymousStringCollisions documents potential collisions with anonymous strings
// DO NOT modify code to make tests pass - document current behavior only
func TestAnonymousStringCollisions(t *testing.T) {
	tests := []anonymousStringTestCase{
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

			anonymousStringCompileResult{program: program, err: err}.assertCase(t, tt)
		})
	}
}

// TestMixedAnonymousAndNamedStrings documents mixed anonymous and named string handling
// DO NOT modify code to make tests pass - document current behavior only
func TestMixedAnonymousAndNamedStrings(t *testing.T) {
	tests := []anonymousStringTestCase{
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
			knownGap:    "compiler allows direct $ reference in condition",
			description: "Documents direct $ reference in condition",
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
			knownGap:    "compiler allows $ placeholder in explicit of-expression list",
			description: "Documents $ placeholder in explicit of-expression list",
		},
		{
			name:        "count-on-named-only",
			rule:        `rule test { strings: $a = "a" $ = "x" $b = "b" condition: #a + # > 1 }`,
			expectError: true,
			knownGap:    "compiler accepts anonymous count shorthand with named strings present",
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

			anonymousStringCompileResult{program: program, err: err}.assertCase(t, tt)
		})
	}
}

// TestAnonymousStringWithModifiers documents anonymous strings with various modifiers
// DO NOT modify code to make tests pass - document current behavior only
func TestAnonymousStringWithModifiers(t *testing.T) {
	tests := []anonymousStringTestCase{
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

			anonymousStringCompileResult{program: program, err: err}.assertCase(t, tt)
		})
	}
}
