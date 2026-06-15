package compiler

import (
	"context"
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
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

func TestPublicComplexityHeuristics(t *testing.T) {
	cc := NewConditionCompiler(NewEmitter(), nil)

	literal := &ast.Literal{Type: token.TRUE, Value: true}
	identifier := &ast.Identifier{Name: "external"}
	expr := &ast.BinaryOp{Left: identifier, Op: token.AND, Right: literal}

	if got := cc.EstimateComplexity(literal); got != 1 {
		t.Fatalf("literal complexity = %d, want 1", got)
	}
	if got := cc.EstimateComplexity(identifier); got != 2 {
		t.Fatalf("identifier complexity = %d, want 2", got)
	}
	if got := cc.EstimateComplexity(expr); got <= cc.EstimateComplexity(identifier) {
		t.Fatalf("binary expression complexity = %d, want greater than identifier", got)
	}
}

func TestPublicPatternQualityHeuristic(t *testing.T) {
	sc := NewStringCompiler(NewEmitter())

	empty := sc.EstimatePatternComplexity(nil, nil)
	repeated := sc.EstimatePatternComplexity([]byte("aaaa"), nil)
	selective := sc.EstimatePatternComplexity([]byte("aZ9!"), nil)

	if empty != 0 {
		t.Fatalf("empty pattern quality = %d, want 0", empty)
	}
	if selective <= repeated {
		t.Fatalf("selective pattern quality = %d, want > repeated pattern %d", selective, repeated)
	}
}
