package compiler

import (
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

// BenchmarkInterpreterAllocation measures the cost of creating and initializing
// an interpreter and match context repeatedly, simulating the per-file scan overhead.
func BenchmarkInterpreterAllocation(b *testing.B) {
	// Setup a minimal valid rule to execute
	rule := &ast.Rule{
		Name: "benchmark_rule",
		Condition: &ast.Literal{
			Type:  token.TRUE,
			Value: true,
		},
	}

	// Create a single compiled rule
	compiler := NewRuleCompiler()
	compiledRule, err := compiler.CompileRule(rule)
	if err != nil {
		b.Fatalf("failed to compile rule: %v", err)
	}

	data := []byte("test data")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// This simulates the hot path of scanning a file:
		// 1. Build MatchContext (allocates)
		// 2. Create Interpreter (allocates)
		// 3. Initialize and Execute

		ctx := BuildMatchContext(compiledRule, data)
		interp := NewInterpreter(compiledRule.Bytecode)
		interp.SetCompiledRules([]*CompiledRule{compiledRule})
		interp.SetCurrentRule(compiledRule.Name)
		interp.SetMatchContext(ctx)

		if err := interp.Execute(); err != nil {
			b.Fatalf("execution failed: %v", err)
		}

		interp.Release()
		ctx.Release()
	}
}
