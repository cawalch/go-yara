package compiler

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/cawalch/go-yara/ast"
)

func TestBooleanRoutingInputBudgets(t *testing.T) {
	pattern := func(value string) *ast.String { return &ast.String{Pattern: &ast.TextString{Value: value}} }
	short := pattern("ROUTING_LITERAL_0123456789")
	repeated := func(n int) []*ast.String {
		result := make([]*ast.String, n)
		for i := range result {
			result[i] = short
		}
		return result
	}
	for _, test := range []struct {
		name  string
		count int
	}{{"rules", 4096}, {"patterns", 8192}, {"source", 1 << 20}} {
		t.Run(test.name, func(t *testing.T) {
			for _, extra := range []int{0, 1} {
				program := &CompiledProgram{}
				switch test.name {
				case "rules":
					for i := 0; i < test.count+extra; i++ {
						program.Rules = append(program.Rules, &CompiledRule{booleanPatterns: repeated(1)})
					}
				case "patterns":
					program.Rules = []*CompiledRule{{booleanPatterns: repeated(test.count / 2)}, {booleanPatterns: repeated(test.count/2 + extra)}}
				case "source":
					program.Rules = []*CompiledRule{{booleanPatterns: []*ast.String{pattern(strings.Repeat("x", test.count/2))}}, {booleanPatterns: []*ast.String{pattern(strings.Repeat("x", test.count/2+extra))}}}
				}
				if got := program.booleanRoutingInput(); got != (extra == 0) {
					t.Fatalf("limit + %d accepted=%v", extra, got)
				}
			}
		})
	}
}

func TestBooleanRoutingBuildLimitFallback(t *testing.T) {
	var source strings.Builder
	for i := 0; i < 4097; i++ {
		fmt.Fprintf(&source, `rule r%d { strings: $a="x" condition: $a }`+"\n", i)
	}
	overRules := compileBooleanRouting(t, source.String())
	overPatterns := compileBooleanRouting(t, booleanRoutingSource())
	overSource := compileBooleanRouting(t, booleanRoutingSource())
	// Expand private construction metadata only; normal compiled rules remain valid.
	overPatterns.Rules[0].booleanPatterns = make([]*ast.String, 8193)
	for i := range overPatterns.Rules[0].booleanPatterns {
		overPatterns.Rules[0].booleanPatterns[i] = overPatterns.Rules[1].booleanPatterns[0]
	}
	overSource.Rules[0].booleanPatterns = []*ast.String{{Pattern: &ast.TextString{Value: strings.Repeat("x", (1<<20)+1)}}}
	for _, test := range []struct {
		name     string
		program  *CompiledProgram
		positive string
	}{{"rules", overRules, "x"}, {"patterns", overPatterns, "event code00_SHARED_0123456789ABCDE"}, {"source", overSource, "event code00_SHARED_0123456789ABCDE"}} {
		t.Run(test.name, func(t *testing.T) {
			if test.program.booleanRoutingInput() {
				t.Fatal("over-limit metadata passed preflight")
			}
			var wg sync.WaitGroup
			for i := 0; i < 4; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					scanner := NewScanner(test.program, WithBooleanRouting())
					defer scanner.Close()
					if scanner.booleanRouting != nil {
						t.Error("over-limit plan activated")
						return
					}
					for _, input := range []string{test.positive, "", test.positive} {
						got, err := scanner.Matches([]byte(input))
						if err != nil || got != (input != "") {
							t.Errorf("fallback %q = %v,%v", input, got, err)
							return
						}
					}
				}()
			}
			wg.Wait()
		})
	}
}

func TestBooleanRoutingConverterBudgetIsCumulative(t *testing.T) {
	source := &ast.String{Pattern: &ast.TextString{Value: "ROUTING_LITERAL_0123456789"}}
	for _, resource := range []string{"work", "material"} {
		t.Run(resource, func(t *testing.T) {
			probe := newWordRoutingConverter()
			if _, ok := probe.pattern(source); !ok {
				t.Fatal("small pattern declined")
			}
			conversion := newWordRoutingConverter()
			if resource == "work" {
				conversion.work = 2 * (conversion.work - probe.work)
			} else {
				conversion.material = 2 * (conversion.material - probe.material)
			}
			for i := 0; i < 3; i++ {
				_, ok := conversion.pattern(source)
				if ok != (i < 2) {
					t.Fatalf("pattern %d accepted=%v", i, ok)
				}
			}
			if _, ok := conversion.pattern(&ast.String{Pattern: &ast.TextString{Value: "x"}}); ok {
				t.Fatal("exhausted converter accepted another pattern")
			}
			if _, ok := newWordRoutingConverter().pattern(source); !ok {
				t.Fatal("budget exhaustion leaked into a fresh conversion")
			}
		})
	}
}

func TestBooleanRoutingModifierBudget(t *testing.T) {
	conversion := newWordRoutingConverter()
	conversion.work = 2
	pattern := &ast.String{
		Pattern: &ast.TextString{Value: "x"},
		Modifiers: []ast.StringModifier{
			{Type: ast.StringModifierNocase}, {Type: ast.StringModifierASCII}, {Type: ast.StringModifierNocase},
		},
	}
	if _, ok := conversion.pattern(pattern); ok || conversion.material != 0 {
		t.Fatal("modifier budget was not exhausted before pattern conversion")
	}
}
