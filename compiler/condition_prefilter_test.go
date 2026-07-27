package compiler

import (
	"errors"
	"fmt"
	"testing"
)

func TestConditionRequiresStringMatch(t *testing.T) {
	tests := []struct {
		name      string
		condition string
		want      bool
	}{
		{name: "direct string", condition: "$a", want: true},
		{name: "string and dynamic", condition: "$a and filesize > 0", want: true},
		{name: "string or dynamic", condition: "$a or filesize > 0", want: false},
		{name: "negated string", condition: "not $a", want: false},
		{name: "any of them", condition: "any of them", want: true},
		{name: "all of them", condition: "all of them", want: true},
		{name: "none of them", condition: "none of them", want: false},
		{name: "positive count", condition: "#a > 0", want: true},
		{name: "zero count", condition: "#a == 0", want: false},
		{name: "summed counts", condition: "#a + #b >= 1", want: true},
		{name: "fixed offset", condition: "$a at 0", want: true},
		{name: "fixed range", condition: "$a in (0..10)", want: true},
		{name: "dynamic offset", condition: "$a at filesize", want: false},
		{name: "dynamic set offset", condition: "any of them at filesize", want: false},
		{name: "for any string", condition: "for any of them : ($)", want: false},
		{name: "for all strings", condition: "for all of them : ($)", want: false},
		{name: "for none string", condition: "for none of them : ($)", want: false},
		{name: "for all negated", condition: "for all of them : (not $)", want: false},
		{name: "possibly empty all set", condition: "all of ($missing*)", want: false},
		{name: "filesize only", condition: "filesize > 0", want: false},
		{name: "always true", condition: "true", want: false},
		{name: "always false", condition: "false", want: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := fmt.Sprintf(`
rule test {
    strings:
        $a = "alpha"
        $b = "beta"
    condition:
        %s
}
`, test.condition)
			program, err := NewCompiler().CompileSource(source)
			if err != nil {
				t.Fatalf("CompileSource() error = %v", err)
			}
			got := program.Rules[0].RequiresStringMatch
			if got != test.want {
				t.Fatalf("RequiresStringMatch = %v, want %v", got, test.want)
			}
		})
	}
}

func TestConditionRequiresStringMatchIsConservativeForDependencies(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule base {
    condition:
        true
}

rule guarded_and {
    strings:
        $a = "alpha"
    condition:
        base and $a
}

rule guarded_or {
    strings:
        $a = "alpha"
    condition:
        base or $a
}
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}
	if program.Rules[0].RequiresStringMatch {
		t.Fatal("stringless dependency base was marked RequiresStringMatch")
	}
	if !program.Rules[1].RequiresStringMatch {
		t.Fatal("dependency conjunction was not marked RequiresStringMatch")
	}
	if program.Rules[2].RequiresStringMatch {
		t.Fatal("dependency disjunction was marked RequiresStringMatch")
	}
}

func TestConditionRequiresStringMatchPreservesModuleErrors(t *testing.T) {
	failingModule := Module{
		Name: "fail",
		Functions: map[string]ModuleFunction{
			"check": {
				Signatures: []ModuleSignature{{}},
				ReturnType: ModuleBoolean,
				Evaluate: func(ModuleContext, []ModuleValue) (ModuleValue, error) {
					return ModuleValue{}, errors.New("module failure")
				},
			},
		},
	}
	compiler := NewCompiler(WithModule(failingModule))
	program, err := compiler.CompileSource(`
import "fail"

rule error_before_string {
    strings:
        $a = "alpha"
    condition:
        fail.check() and $a
}

rule short_circuit_before_error {
    strings:
        $b = "beta"
    condition:
        $b and fail.check()
}
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}
	if program.Rules[0].RequiresStringMatch {
		t.Fatal("module call evaluated before a string gate was marked RequiresStringMatch")
	}
	if !program.Rules[1].RequiresStringMatch {
		t.Fatal("unreachable module call after a string gate prevented RequiresStringMatch")
	}

	firstOnly, err := compiler.CompileSource(`
import "fail"
rule test {
    strings:
        $a = "alpha"
    condition:
        fail.check() and $a
}
`)
	if err != nil {
		t.Fatalf("first CompileSource() error = %v", err)
	}
	if _, err := firstOnly.Scan([]byte("clean")); err == nil {
		t.Fatal("module error before the string gate was suppressed")
	}

	secondOnly, err := compiler.CompileSource(`
import "fail"
rule test {
    strings:
        $a = "alpha"
    condition:
        $a and fail.check()
}
`)
	if err != nil {
		t.Fatalf("second CompileSource() error = %v", err)
	}
	result, err := secondOnly.Scan([]byte("clean"))
	if err != nil {
		t.Fatalf("short-circuited Scan() error = %v", err)
	}
	if result.RuleResults["test"] {
		t.Fatal("short-circuited rule unexpectedly matched")
	}
}
