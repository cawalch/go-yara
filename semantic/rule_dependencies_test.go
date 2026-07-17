package semantic

import (
	"context"
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/parser"
)

func TestSemanticErrorsCarryRuleName(t *testing.T) {
	program, err := parser.New(lexer.New(`
rule bad { condition: missing_identifier }
rule good { condition: true }
`)).ParseRulesWithContext(context.Background())
	if err != nil {
		t.Fatalf("ParseRulesWithContext() error = %v", err)
	}

	errs := NewValidator().ValidateProgram(program)
	if len(errs) == 0 {
		t.Fatal("ValidateProgram() errors is empty")
	}
	for _, err := range errs {
		semanticErr, ok := err.(*Error)
		if !ok {
			t.Fatalf("ValidateProgram() error type = %T, want *Error", err)
		}
		if semanticErr.Rule != "bad" {
			t.Fatalf("semantic error rule = %q, want bad", semanticErr.Rule)
		}
	}
}

func TestRuleDependenciesRecognizesRemovedRules(t *testing.T) {
	program, err := parser.New(lexer.New(`
rule dependent { condition: removed }
rule independent { condition: true }
`)).ParseRulesWithContext(context.Background())
	if err != nil {
		t.Fatalf("ParseRulesWithContext() error = %v", err)
	}

	dependencies := RuleDependencies(program, "removed")
	if got := dependencies["dependent"]; len(got) != 1 || got[0] != "removed" {
		t.Fatalf("dependent dependencies = %v, want [removed]", got)
	}
	if got := dependencies["independent"]; len(got) != 0 {
		t.Fatalf("independent dependencies = %v, want none", got)
	}
}
