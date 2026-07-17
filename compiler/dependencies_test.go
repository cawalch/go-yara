package compiler

import (
	"reflect"
	"testing"
)

func TestCompiledProgramDependencyQueries(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule base { condition: true }
rule middle { condition: base }
rule top { condition: middle and base }
rule independent { condition: true }
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}

	tests := []struct {
		name string
		got  []string
		want []string
	}{
		{name: "base dependencies", got: program.RuleDependencies("base"), want: []string{}},
		{name: "middle dependencies", got: program.RuleDependencies("middle"), want: []string{"base"}},
		{name: "top dependencies", got: program.RuleDependencies("top"), want: []string{"base", "middle"}},
		{name: "base dependents", got: program.RuleDependents("base"), want: []string{"middle", "top"}},
		{name: "middle dependents", got: program.RuleDependents("middle"), want: []string{"top"}},
		{name: "unknown dependencies", got: program.RuleDependencies("unknown"), want: nil},
	}
	for _, test := range tests {
		if !reflect.DeepEqual(test.got, test.want) {
			t.Errorf("%s = %v, want %v", test.name, test.got, test.want)
		}
	}

	graph := program.DependencyGraph()
	graph["top"][0] = "mutated"
	if got := program.RuleDependencies("top"); !reflect.DeepEqual(got, []string{"base", "middle"}) {
		t.Fatalf("DependencyGraph returned aliased state; top = %v", got)
	}
}
