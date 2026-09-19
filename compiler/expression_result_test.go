package compiler

import (
	"context"
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

func TestFloatGlobalExpressionResult(t *testing.T) {
	compiler := NewCompiler()
	program, err := compiler.compileParseWithContext(context.Background(), `global a=0 rule r { condition: a + 0.5 == 2.0 and -(a + 0.5) == -2.0 }`)
	if err != nil {
		t.Fatal(err)
	}
	program.GlobalVariables[0].Value = &ast.Literal{Type: token.FloatLit, Value: 1.5}
	rules, err := NewRuleCompiler().CompileProgram(program)
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
