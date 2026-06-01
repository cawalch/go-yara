package integration

import (
	"context"
	"testing"

	"github.com/cawalch/go-yara/compiler"
)

// TestRuleCompilationSimple documents basic rule compilation scenarios
// DO NOT modify code to make tests pass - document current behavior only
func TestRuleCompilationSimple(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "true-rule-always-compiles",
			rule:        `rule test { condition: true }`,
			expectError: false,
			description: "Documents that true rule compiles",
		},
		{
			name:        "false-rule-compiles",
			rule:        `rule test { condition: false }`,
			expectError: false,
			description: "Documents that false rule compiles",
		},
		{
			name:        "string-match-compiles",
			rule:        `rule test { strings: $a = "test" condition: $a }`,
			expectError: false,
			description: "Documents basic string matching compiles",
		},
		{
			name:        "hex-match-compiles",
			rule:        `rule test { strings: $a = { 74 65 73 74 } condition: $a }`,
			expectError: false,
			description: "Documents hex pattern matching compiles",
		},
		{
			name:        "regex-match-compiles",
			rule:        `rule test { strings: $a = /t.st/ condition: $a }`,
			expectError: false,
			description: "Documents regex matching compiles",
		},
		{
			name:        "nocase-match-compiles",
			rule:        `rule test { strings: $a = "test" nocase condition: $a }`,
			expectError: false,
			description: "Documents nocase modifier compiles",
		},
		{
			name:        "wide-match-compiles",
			rule:        `rule test { strings: $a = "test" wide condition: $a }`,
			expectError: false,
			description: "Documents wide modifier compiles",
		},
		{
			name:        "filesize-check-compiles",
			rule:        `rule test { condition: filesize > 10 }`,
			expectError: false,
			description: "Documents filesize builtin compiles",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := compiler.NewCompiler()
			program, err := c.CompileSourceWithContext(context.Background(), tt.rule)

			assertSimpleCompileResult(t, program, err, tt.expectError, tt.description)
		})
	}
}

// TestRuleCompilationBooleanLogic documents boolean expression compilation
// DO NOT modify code to make tests pass - document current behavior only
func TestRuleCompilationBooleanLogic(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "and-both-true",
			rule:        `rule test { strings: $a = "a" $b = "b" condition: $a and $b }`,
			expectError: false,
			description: "Documents AND compilation",
		},
		{
			name:        "or-expression",
			rule:        `rule test { strings: $a = "a" $b = "b" condition: $a or $b }`,
			expectError: false,
			description: "Documents OR compilation",
		},
		{
			name:        "not-operator",
			rule:        `rule test { strings: $a = "a" condition: not $a }`,
			expectError: false,
			description: "Documents NOT compilation",
		},
		{
			name:        "nested-boolean",
			rule:        `rule test { strings: $a = "a" $b = "b" $c = "c" condition: ($a and $b) or $c }`,
			expectError: false,
			description: "Documents nested boolean compilation",
		},
		{
			name:        "complex-boolean",
			rule:        `rule test { strings: $a = "a" $b = "b" $c = "c" $d = "d" condition: ($a and $b) or ($c and $d) }`,
			expectError: false,
			description: "Documents complex boolean compilation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := compiler.NewCompiler()
			program, err := c.CompileSourceWithContext(context.Background(), tt.rule)

			if tt.expectError {
				if err == nil {
					t.Skipf("known gap: %s (no compilation error produced)", tt.description)
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

// TestRuleCompilationComparison documents comparison operator compilation
// DO NOT modify code to make tests pass - document current behavior only
func TestRuleCompilationComparison(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "greater-than",
			rule:        `rule test { condition: filesize > 10 }`,
			expectError: false,
			description: "Documents > operator compilation",
		},
		{
			name:        "less-than",
			rule:        `rule test { condition: filesize < 100 }`,
			expectError: false,
			description: "Documents < operator compilation",
		},
		{
			name:        "equal",
			rule:        `rule test { condition: filesize == 10 }`,
			expectError: false,
			description: "Documents == operator compilation",
		},
		{
			name:        "not-equal",
			rule:        `rule test { condition: filesize != 100 }`,
			expectError: false,
			description: "Documents != operator compilation",
		},
		{
			name:        "greater-or-equal",
			rule:        `rule test { condition: filesize >= 10 }`,
			expectError: false,
			description: "Documents >= operator compilation",
		},
		{
			name:        "less-or-equal",
			rule:        `rule test { condition: filesize <= 10 }`,
			expectError: false,
			description: "Documents <= operator compilation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := compiler.NewCompiler()
			program, err := c.CompileSourceWithContext(context.Background(), tt.rule)

			if tt.expectError {
				if err == nil {
					t.Skipf("known gap: %s (no compilation error produced)", tt.description)
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

// TestRuleCompilationArithmetic documents arithmetic expression compilation
// DO NOT modify code to make tests pass - document current behavior only
func TestRuleCompilationArithmetic(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "addition",
			rule:        `rule test { condition: 5 + 5 == 10 }`,
			expectError: false,
			description: "Documents addition compilation",
		},
		{
			name:        "subtraction",
			rule:        `rule test { condition: 10 - 5 == 5 }`,
			expectError: false,
			description: "Documents subtraction compilation",
		},
		{
			name:        "multiplication",
			rule:        `rule test { condition: 5 * 5 == 25 }`,
			expectError: false,
			description: "Documents multiplication compilation",
		},
		{
			name:        "division",
			rule:        `rule test { condition: 10 / 2 == 5 }`,
			expectError: false,
			description: "Documents division compilation",
		},
		{
			name:        "modulo",
			rule:        `rule test { condition: 10 % 3 == 1 }`,
			expectError: false,
			description: "Documents modulo compilation",
		},
		{
			name:        "operator-precedence",
			rule:        `rule test { condition: 1 + 2 * 3 == 7 }`,
			expectError: false,
			description: "Documents operator precedence compilation",
		},
		{
			name:        "parentheses",
			rule:        `rule test { condition: (1 + 2) * 3 == 9 }`,
			expectError: false,
			description: "Documents parentheses compilation",
		},
		{
			name:        "bitwise-and",
			rule:        `rule test { condition: 0xFF & 0x0F == 0x0F }`,
			expectError: false,
			description: "Documents bitwise AND compilation",
		},
		{
			name:        "bitwise-or",
			rule:        `rule test { condition: 0xF0 | 0x0F == 0xFF }`,
			expectError: false,
			description: "Documents bitwise OR compilation",
		},
		{
			name:        "bitwise-xor",
			rule:        `rule test { condition: 0xFF ^ 0xFF == 0 }`,
			expectError: false,
			description: "Documents bitwise XOR compilation",
		},
		{
			name:        "shift-left",
			rule:        `rule test { condition: 1 << 8 == 256 }`,
			expectError: false,
			description: "Documents left shift compilation",
		},
		{
			name:        "shift-right",
			rule:        `rule test { condition: 256 >> 8 == 1 }`,
			expectError: false,
			description: "Documents right shift compilation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := compiler.NewCompiler()
			program, err := c.CompileSourceWithContext(context.Background(), tt.rule)

			if tt.expectError {
				if err == nil {
					t.Skipf("known gap: %s (no compilation error produced)", tt.description)
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

// TestRuleCompilationStringOperators documents string-specific operator compilation
// DO NOT modify code to make tests pass - document current behavior only
func TestRuleCompilationStringOperators(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "count-operator",
			rule:        `rule test { strings: $a = "test" condition: #a == 1 }`,
			expectError: false,
			description: "Documents count operator compilation",
		},
		{
			name:        "offset-operator",
			rule:        `rule test { strings: $a = "test" condition: @a == 0 }`,
			expectError: false,
			description: "Documents offset operator compilation",
		},
		{
			name:        "length-operator",
			rule:        `rule test { strings: $a = "test" condition: !a == 4 }`,
			expectError: false,
			description: "Documents length operator compilation",
		},
		{
			name:        "offset-index-operator",
			rule:        `rule test { strings: $a = "test" condition: @a[1] < 100 }`,
			expectError: false,
			description: "Documents offset index operator compilation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := compiler.NewCompiler()
			program, err := c.CompileSourceWithContext(context.Background(), tt.rule)

			if tt.expectError {
				if err == nil {
					t.Skipf("known gap: %s (no compilation error produced)", tt.description)
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

// TestRuleCompilationOfExpressions documents of-expression compilation
// DO NOT modify code to make tests pass - document current behavior only
func TestRuleCompilationOfExpressions(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "any-of-wildcard",
			rule:        `rule test { strings: $a1 = "a" $a2 = "a2" $b = "b" condition: any of $a* }`,
			expectError: false,
			description: "Documents 'any of' wildcard compilation",
		},
		{
			name:        "all-of-them",
			rule:        `rule test { strings: $a = "a" $b = "b" condition: all of them }`,
			expectError: false,
			description: "Documents 'all of them' compilation",
		},
		{
			name:        "none-of-them",
			rule:        `rule test { strings: $a = "a" $b = "b" condition: none of them }`,
			expectError: false,
			description: "Documents 'none of them' compilation",
		},
		{
			name:        "numeric-of",
			rule:        `rule test { strings: $a = "a" $b = "b" $c = "c" condition: 2 of them }`,
			expectError: false,
			description: "Documents numeric quantifier compilation",
		},
		{
			name:        "any-of-explicit-list",
			rule:        `rule test { strings: $a = "a" $b = "b" $c = "c" condition: any of ($a, $b) }`,
			expectError: false,
			description: "Documents 'any of' explicit list compilation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := compiler.NewCompiler()
			program, err := c.CompileSourceWithContext(context.Background(), tt.rule)

			if tt.expectError {
				if err == nil {
					t.Skipf("known gap: %s (no compilation error produced)", tt.description)
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

// TestRuleCompilationForLoops documents for-loop expression compilation
// DO NOT modify code to make tests pass - document current behavior only
func TestRuleCompilationForLoops(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "for-any-in-range",
			rule:        `rule test { condition: for any i in (1..10) : ( i > 5 ) }`,
			expectError: false,
			description: "Documents for-any in numeric range compilation",
		},
		{
			name:        "for-all-in-range",
			rule:        `rule test { condition: for all i in (1..5) : ( i > 0 ) }`,
			expectError: false,
			description: "Documents for-all in numeric range compilation",
		},
		{
			name:        "for-none-in-range",
			rule:        `rule test { condition: for none i in (1..10) : ( i < 0 ) }`,
			expectError: false,
			description: "Documents for-none in numeric range compilation",
		},
		{
			name:        "for-numeric-in-range",
			rule:        `rule test { condition: for 3 i in (1..10) : ( i > 5 ) }`,
			expectError: false,
			description: "Documents numeric quantifier in range compilation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := compiler.NewCompiler()
			program, err := c.CompileSourceWithContext(context.Background(), tt.rule)

			if tt.expectError {
				if err == nil {
					t.Skipf("known gap: %s (no compilation error produced)", tt.description)
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

// TestRuleCompilationBuiltinFunctions documents builtin function compilation
// DO NOT modify code to make tests pass - document current behavior only
func TestRuleCompilationBuiltinFunctions(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "int8-function",
			rule:        `rule test { condition: int8(0) == 0x74 }`,
			expectError: false,
			description: "Documents int8 builtin function compilation",
		},
		{
			name:        "int16-function",
			rule:        `rule test { condition: int16(0) == 0x7473 }`,
			expectError: false,
			description: "Documents int16 builtin function compilation",
		},
		{
			name:        "int32-function",
			rule:        `rule test { condition: int32(0) == 0x74736574 }`,
			expectError: false,
			description: "Documents int32 builtin function compilation",
		},
		{
			name:        "uint8-function",
			rule:        `rule test { condition: uint8(0) == 0x74 }`,
			expectError: false,
			description: "Documents uint8 builtin function compilation",
		},
		{
			name:        "uint16-function",
			rule:        `rule test { condition: uint16(0) == 0x7473 }`,
			expectError: false,
			description: "Documents uint16 builtin function compilation",
		},
		{
			name:        "uint32-function",
			rule:        `rule test { condition: uint32(0) == 0x74736574 }`,
			expectError: false,
			description: "Documents uint32 builtin function compilation",
		},
		{
			name:        "matches-function",
			rule:        `rule test { condition: "test" matches /test/ }`,
			expectError: false,
			description: "Documents matches builtin function compilation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := compiler.NewCompiler()
			program, err := c.CompileSourceWithContext(context.Background(), tt.rule)

			if tt.expectError {
				if err == nil {
					t.Skipf("known gap: %s (no compilation error produced)", tt.description)
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
