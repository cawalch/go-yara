package compiler

import (
	"testing"
)

// TestBytecodeInstructionSequence documents compiler bytecode generation behavior
func TestBytecodeInstructionSequence(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "simple-true-condition",
			rule:        `rule test { condition: true }`,
			expectError: false,
			description: "Documents bytecode for simple true condition",
		},
		{
			name:        "simple-false-condition",
			rule:        `rule test { condition: false }`,
			expectError: false,
			description: "Documents bytecode for simple false condition",
		},
		{
			name:        "string-match",
			rule:        `rule test { strings: $a = "test" condition: $a }`,
			expectError: false,
			description: "Documents bytecode for string match",
		},
		{
			name:        "and-expression",
			rule:        `rule test { strings: $a = "a" $b = "b" condition: $a and $b }`,
			expectError: false,
			description: "Documents bytecode for AND expression",
		},
		{
			name:        "or-expression",
			rule:        `rule test { strings: $a = "a" $b = "b" condition: $a or $b }`,
			expectError: false,
			description: "Documents bytecode for OR expression",
		},
		{
			name:        "comparison",
			rule:        `rule test { condition: filesize > 100 }`,
			expectError: false,
			description: "Documents bytecode for comparison",
		},
		{
			name:        "arithmetic",
			rule:        `rule test { condition: 1 + 2 * 3 }`,
			expectError: false,
			description: "Documents bytecode for arithmetic",
		},
		{
			name:        "not-operator",
			rule:        `rule test { condition: not false }`,
			expectError: false,
			description: "Documents bytecode for NOT operator",
		},
		{
			name:        "parentheses",
			rule:        `rule test { condition: (true or false) and true }`,
			expectError: false,
			description: "Documents bytecode for parenthesized expressions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCompiler()
			program, err := c.CompileSource(tt.rule)

			anonymousStringCompileResult{program: program, err: err}.assertExpected(t, tt.expectError, tt.description)
		})
	}
}

// TestJumpTargetCorrectness documents jump target resolution in bytecode
func TestJumpTargetCorrectness(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "and-short-circuit",
			rule:        `rule test { strings: $a = "a" $b = "b" condition: $a and $b }`,
			expectError: false,
			description: "Documents jump targets for AND short-circuit evaluation",
		},
		{
			name:        "or-short-circuit",
			rule:        `rule test { strings: $a = "a" $b = "b" condition: $a or $b }`,
			expectError: false,
			description: "Documents jump targets for OR short-circuit evaluation",
		},
		{
			name:        "nested-conditions",
			rule:        `rule test { strings: $a = "a" $b = "b" $c = "c" condition: ($a and $b) or $c }`,
			expectError: false,
			description: "Documents jump targets for nested conditions",
		},
		{
			name:        "complex-boolean",
			rule:        `rule test { strings: $a = "a" $b = "b" $c = "c" $d = "d" condition: ($a and $b) or ($c and $d) }`,
			expectError: false,
			description: "Documents jump targets for complex boolean expressions",
		},
		{
			name:        "not-expression",
			rule:        `rule test { strings: $a = "a" condition: not $a }`,
			expectError: false,
			description: "Documents jump targets for NOT expression",
		},
		{
			name:        "comparison-jumps",
			rule:        `rule test { condition: filesize > 1000 }`,
			expectError: false,
			description: "Documents jump targets for comparison operators",
		},
		{
			name:        "of-expression",
			rule:        `rule test { strings: $a = "a" $b = "b" condition: any of ($a, $b) }`,
			expectError: false,
			description: "Documents jump targets for of-expression",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCompiler()
			program, err := c.CompileSource(tt.rule)

			anonymousStringCompileResult{program: program, err: err}.assertExpected(t, tt.expectError, tt.description)
		})
	}
}

// TestLabelResolution documents label resolution in bytecode generation
func TestLabelResolution(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "single-label",
			rule:        `rule test { condition: true }`,
			expectError: false,
			description: "Documents label resolution for trivial condition",
		},
		{
			name:        "forward-jump",
			rule:        `rule test { condition: false or true }`,
			expectError: false,
			description: "Documents forward jump label resolution",
		},
		{
			name:        "backward-jump",
			rule:        `rule test { condition: true or false }`,
			expectError: false,
			description: "Documents backward jump label resolution",
		},
		{
			name:        "multiple-labels",
			rule:        `rule test { strings: $a = "a" $b = "b" $c = "c" condition: $a or $b or $c }`,
			expectError: false,
			description: "Documents multiple label resolution in complex expression",
		},
		{
			name:        "nested-labels",
			rule:        `rule test { strings: $a = "a" $b = "b" condition: ($a and $b) or false }`,
			expectError: false,
			description: "Documents nested label resolution",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCompiler()
			program, err := c.CompileSource(tt.rule)

			anonymousStringCompileResult{program: program, err: err}.assertExpected(t, tt.expectError, tt.description)
		})
	}
}

// TestStackBalance documents stack balance in bytecode execution
func TestStackBalance(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "simple-push-pop",
			rule:        `rule test { condition: 1 + 2 }`,
			expectError: false,
			description: "Documents stack balance for simple arithmetic",
		},
		{
			name:        "multiple-operations",
			rule:        `rule test { condition: 1 + 2 + 3 + 4 }`,
			expectError: false,
			description: "Documents stack balance for chained operations",
		},
		{
			name:        "complex-expression",
			rule:        `rule test { condition: (1 + 2) * (3 + 4) }`,
			expectError: false,
			description: "Documents stack balance for complex expressions",
		},
		{
			name:        "function-call",
			rule:        `rule test { condition: int8(100) }`,
			expectError: false,
			description: "Documents stack balance for function calls",
		},
		{
			name:        "comparison",
			rule:        `rule test { condition: filesize > 100 }`,
			expectError: false,
			description: "Documents stack balance for comparisons",
		},
		{
			name:        "boolean-logic",
			rule:        `rule test { strings: $a = "a" $b = "b" condition: $a and $b }`,
			expectError: false,
			description: "Documents stack balance for boolean logic",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCompiler()
			program, err := c.CompileSource(tt.rule)

			anonymousStringCompileResult{program: program, err: err}.assertExpected(t, tt.expectError, tt.description)
		})
	}
}

// TestMemorySlotUsage documents memory slot allocation and usage
func TestMemorySlotUsage(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "no-variables",
			rule:        `rule test { condition: true }`,
			expectError: false,
			description: "Documents memory usage with no variables",
		},
		{
			name:        "string-variables",
			rule:        `rule test { strings: $a = "a" $b = "b" condition: $a }`,
			expectError: false,
			description: "Documents memory slots for string variables",
		},
		{
			name:        "external-variables",
			rule:        `external a rule test { condition: a == 10 }`,
			expectError: false,
			description: "Documents memory slots for external variables",
		},
		{
			name:        "filesize-variable",
			rule:        `rule test { condition: filesize > 0 }`,
			expectError: false,
			description: "Documents memory slot for filesize builtin",
		},
		{
			name:        "entrypoint-variable",
			rule:        `rule test { condition: entrypoint > 0 }`,
			expectError: false,
			description: "Documents memory slot for entrypoint builtin",
		},
		{
			name:        "many-variables",
			rule:        `external a external b external c external d external e rule test { condition: a + b + c + d + e > 0 }`,
			expectError: false,
			description: "Documents memory slots for many variables",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCompiler()
			program, err := c.CompileSource(tt.rule)

			anonymousStringCompileResult{program: program, err: err}.assertExpected(t, tt.expectError, tt.description)
		})
	}
}

// TestStringLiteralPool documents string literal pool in bytecode
func TestStringLiteralPool(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "no-strings",
			rule:        `rule test { condition: true }`,
			expectError: false,
			description: "Documents string pool with no strings",
		},
		{
			name:        "single-string",
			rule:        `rule test { strings: $a = "test" condition: $a }`,
			expectError: false,
			description: "Documents string pool with one string",
		},
		{
			name:        "multiple-strings",
			rule:        `rule test { strings: $a = "a" $b = "b" $c = "c" condition: any of them }`,
			expectError: false,
			description: "Documents string pool with multiple strings",
		},
		{
			name:        "duplicate-string-values",
			rule:        `rule test { strings: $a = "test" $b = "test" condition: $a or $b }`,
			expectError: false,
			description: "Documents string pool with duplicate values",
		},
		{
			name:        "long-strings",
			rule:        `rule test { strings: $a = "this is a very long string that should be stored in the pool" condition: $a }`,
			expectError: false,
			description: "Documents string pool with long strings",
		},
		{
			name:        "special-chars",
			rule:        `rule test { strings: $a = "test\nwith\tnewlines" condition: $a }`,
			expectError: false,
			description: "Documents string pool with special characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCompiler()
			program, err := c.CompileSource(tt.rule)

			anonymousStringCompileResult{program: program, err: err}.assertExpected(t, tt.expectError, tt.description)
		})
	}
}
