package compiler

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRegressionRules(t *testing.T) {
	cases := []struct {
		name     string
		ruleFile string
		dataFile string
		expected bool
	}{
		{
			name:     "at_operator",
			ruleFile: "test_at_operator.yar",
			dataFile: "test_at_data.txt",
			expected: true,
		},
		{
			name:     "in_operator",
			ruleFile: "test_in_operator.yar",
			dataFile: "test_at_data.txt",
			expected: true,
		},
		{
			name:     "xor_modifier",
			ruleFile: "test_xor_modifier.yar",
			dataFile: "test_xor_correct.txt",
			expected: true,
		},
		{
			name:     "comprehensive",
			ruleFile: "test_comprehensive.yar",
			dataFile: "test_comprehensive_data.bin",
			expected: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rulePath := filepath.Join("..", "test_regression", "rules", tc.ruleFile)
			dataPath := filepath.Join("..", "test_regression", "data", tc.dataFile)

			ruleSource, err := os.ReadFile(rulePath)
			if err != nil {
				t.Fatalf("read rule: %v", err)
			}
			data, err := os.ReadFile(dataPath)
			if err != nil {
				t.Fatalf("read data: %v", err)
			}

			compiler := NewCompiler()
			program, err := compiler.CompileSource(string(ruleSource))
			if err != nil {
				t.Fatalf("compile rule: %v", err)
			}
			if len(program.Rules) == 0 {
				t.Fatalf("no compiled rules for %s", tc.ruleFile)
			}

			for _, rule := range program.Rules {
				ok, err := evaluateRule(rule, program, data)
				if err != nil {
					t.Fatalf("evaluate %s: %v", rule.Name, err)
				}
				if ok != tc.expected {
					t.Fatalf("rule %s matched=%v, expected %v", rule.Name, ok, tc.expected)
				}
			}
		})
	}
}

func evaluateRule(rule *CompiledRule, program *CompiledProgram, data []byte) (bool, error) {
	ctx := BuildMatchContext(rule, data)
	defer ctx.Release() // Cleanup

	interp := NewInterpreter(rule.Bytecode)
	defer interp.Release() // Cleanup

	interp.SetCompiledRules(program.Rules)
	interp.SetCurrentRule(rule.Name)
	interp.SetMatchContext(ctx)
	if err := interp.Execute(); err != nil {
		return false, err
	}
	stack := interp.GetStack()
	if len(stack) == 0 {
		return false, nil
	}
	top := stack[len(stack)-1]
	switch top.Type {
	case ValueTypeInt:
		return top.IntVal != 0, nil
	case ValueTypeDouble:
		return top.DoubleVal != 0, nil
	case ValueTypeString:
		return interp.GetString(top) != "", nil
	default:
		return false, nil
	}
}
