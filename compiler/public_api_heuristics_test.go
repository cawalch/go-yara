package compiler

import (
	"context"
	"testing"
)

func TestPublicMemoryUsageHeuristics(t *testing.T) {
	c := NewCompiler()
	program, err := c.CompileSourceWithContext(context.Background(), `
rule small {
	condition:
		true
}

rule larger {
	strings:
		$a = "alpha"
		$b = "beta"
	condition:
		$a or $b
}
`)
	if err != nil {
		t.Fatalf("CompileSourceWithContext() error = %v", err)
	}
	if len(program.Rules) != 2 {
		t.Fatalf("compiled rules = %d, want 2", len(program.Rules))
	}

	smallUsage := program.Rules[0].GetMemoryUsage()
	largerUsage := program.Rules[1].GetMemoryUsage()
	if smallUsage <= 0 {
		t.Fatalf("small rule memory heuristic = %d, want positive", smallUsage)
	}
	if largerUsage <= smallUsage {
		t.Fatalf("larger rule memory heuristic = %d, want > small rule %d", largerUsage, smallUsage)
	}

	wantTotal := smallUsage + largerUsage
	if got := program.GetTotalMemoryUsage(); got != wantTotal {
		t.Fatalf("GetTotalMemoryUsage() = %d, want sum of rule estimates %d", got, wantTotal)
	}
}
