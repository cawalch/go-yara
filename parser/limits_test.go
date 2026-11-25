package parser

import (
	"strings"
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
)

func TestNestedQuantifiersRespectRecursionLimit(t *testing.T) {
	source := "rule r { condition: " + strings.Repeat("for ", 40) + "any of them : (true) }"
	p := NewWithOptions(lexer.New(source), Options{MaxRecursionDepth: 8})
	if _, err := p.ParseRules(); err == nil || !strings.Contains(err.Error(), "recursion depth") {
		t.Fatalf("ParseRules() error = %v, want recursion depth error", err)
	}
}

func TestDefaultParserRecursionLimit(t *testing.T) {
	source := "rule r { condition: " + strings.Repeat("(", 1100) + "true" + strings.Repeat(")", 1100) + " }"
	p := New(lexer.New(source))
	if _, err := p.ParseRules(); err == nil || !strings.Contains(err.Error(), "recursion depth") {
		t.Fatalf("ParseRules() error = %v, want recursion depth error", err)
	}
}

func TestBinaryExpressionChainLimit(t *testing.T) {
	for _, operand := range []string{"true", "unknown"} {
		source := "rule r { condition: " + strings.Repeat(operand+" and ", maxBinaryOperators+1) + "true }"
		p := New(lexer.New(source))
		if _, err := p.ParseRules(); err == nil || !strings.Contains(err.Error(), "binary operators") {
			t.Fatalf("ParseRules() error = %v, want binary operator limit", err)
		}
	}
}

func TestQuantifierTargetListIsBounded(t *testing.T) {
	var target strings.Builder
	for i := 0; i <= maxQuantifierTargets; i++ {
		if i > 0 {
			target.WriteString(",")
		}
		target.WriteString("$a")
	}
	source := "rule r { strings: $a = \"x\" condition: any of (" + target.String() + ") }"
	p := New(lexer.New(source))
	if _, err := p.ParseRules(); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("ParseRules() error = %v, want target-list limit error", err)
	}
}
