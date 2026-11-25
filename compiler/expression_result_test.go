package compiler

import (
	"context"
	"fmt"
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

func TestComparisonExpressionResults(t *testing.T) {
	for _, test := range []struct {
		condition string
		want      bool
	}{
		{`("x" == "x") == true`, true},
		{`("x" == "y") != false`, false},
		{`not ("x" == "y") == true`, true},
		{`(1.0 < 2.0) == true`, true},
		{`(1.0 < 2.0) != (3 < 4)`, false},
		{`(1 - 1.5) == -0.5`, true},
		{`(1.5 - 1) == 0.5`, true},
		{`(3 / 2.0) == 1.5`, true},
		{`(3.0 / 2) == 1.5`, true},
		{`(1 + 1.5) == (1.5 + 1)`, true},
		{`(2 * 1.5) == (1.5 * 2)`, true},
		{`(1 == 1.0) == true`, true},
		{`(1.0 == 1) == true`, true},
		{`(1 != 1.0) == false`, true},
		{`first < second`, true},
		{`first == second`, false},
		{`x == x`, true},
		{`x != y`, true},
		{`x < y`, true},
		{`x > y`, false},
		{`x <= x`, true},
		{`x >= y`, false},
		{`(for any first in ("beta") : ((for any first in ("alpha") : (first == x)) and first == second)) and first == x`, true},
		{`for any of them : ($ == true)`, true},
	} {
		t.Run(test.condition, func(t *testing.T) {
			program, err := NewCompiler().CompileSource(`external x external y global first="alpha" global second="beta" rule r { strings: $a="needle" condition: ` + test.condition + ` }`)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := program.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := UnmarshalCompiledProgram(encoded)
			if err != nil {
				t.Fatal(err)
			}
			for _, candidate := range []*CompiledProgram{program, loaded} {
				scanner := candidate.NewScanner(WithExternalVariables(map[string]any{"x": "alpha", "y": "beta"}))
				matched, err := scanner.Matches([]byte("needle"))
				scanner.Close()
				if err != nil || matched != test.want {
					t.Fatalf("Matches = (%v, %v), want %v", matched, err, test.want)
				}
			}
		})
	}
}

func TestStringOrderingUsesUnsignedBytes(t *testing.T) {
	for _, tc := range []struct {
		name, left, op, right string
		want                  bool
	}{
		{"max_before_ascii", "\xff", "<", "a", false},
		{"high_bit_before_ascii", "\x80", "<", "a", false},
		{"max_after_ascii", "\xff", ">", "a", true},
		{"max_before_control", "\xff", "<", "\x01", false},
		{"high_bit_after_ascii", "\x80", ">", "a", true},
		{"adjacent_high_bytes", "\x80", "<", "\x81", true},
		{"max_at_most_ascii", "\xff", "<=", "a", false},
		{"high_bit_at_least_ascii", "\x80", ">=", "a", true},
		{"equal_high_bytes", "\xff", "<=", "\xff", true},
		{"high_byte_after_prefix", "x\x80", ">", "xa", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("literal", func(t *testing.T) {
				source := fmt.Sprintf(`rule r { condition: %q %s %q }`, tc.left, tc.op, tc.right)
				program, err := NewCompiler().CompileSourceWithContext(context.Background(), source)
				if err != nil {
					t.Fatal(err)
				}
				got, err := program.Matches(nil)
				if err != nil || got != tc.want {
					t.Fatalf("Matches() = (%t, %v), want %t", got, err, tc.want)
				}
			})
			t.Run("external", func(t *testing.T) {
				source := `external left external right rule r { condition: left ` + tc.op + ` right }`
				program, err := NewCompiler().CompileSourceWithContext(context.Background(), source)
				if err != nil {
					t.Fatal(err)
				}
				scanner := program.NewScanner(WithExternalVariables(map[string]any{"left": tc.left, "right": tc.right}))
				defer scanner.Close()
				got, err := scanner.Matches(nil)
				if err != nil || got != tc.want {
					t.Fatalf("Matches() = (%t, %v), want %t", got, err, tc.want)
				}
			})
		})
	}
}

func TestFloatGlobalExpressionResult(t *testing.T) {
	compiler := NewCompiler()
	program, err := compiler.compileParseWithContext(context.Background(), `global a=0 rule r { condition: a + 0.5 == 2.0 and -(a + 0.5) == -2.0 }`)
	if err != nil {
		t.Fatal(err)
	}
	program.GlobalVariables[0].Value = &ast.Literal{Type: token.FloatLit, Value: 1.5}
	rules, err := newRuleCompiler().CompileProgram(program)
	if err != nil {
		t.Fatal(err)
	}
	scanner := NewCompiledProgram(rules).NewScanner()
	defer scanner.Close()
	matched, err := scanner.Matches(nil)
	if err != nil || !matched {
		t.Fatalf("Matches = (%v, %v), want true", matched, err)
	}
}
