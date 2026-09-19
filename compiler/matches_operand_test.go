package compiler

import (
	"strings"
	"testing"
)

func TestMatchesOperandKinds(t *testing.T) {
	for _, test := range []struct {
		condition string
		data      string
		want      bool
	}{
		{`marker matches /^\$a$/`, "needle", true},
		{`constant matches /^\$a$/`, "needle", true},
		{`"$a" matches /^\$a$/`, "needle", true},
		{`marker matches /needle/`, "needle", false},
		{`for any value in ("$a", "other") : (value matches /^\$a$/)`, "", true},
		{`for any value in ("$a") : ($ matches /^\$a$/)`, "", true},
		{`for any value in ($a) : (value matches /needle/)`, "needle", true},
		{`for any value in ($a) : (value matches /needle/)`, "", false},
		{`$a matches /needle/`, "needle", true},
		{`$a matches /needle/`, "", false},
		{`for any of them : ($ matches /needle/)`, "needle", true},
		{`for all of them : ($ matches /needle/)`, "needle other", false},
	} {
		t.Run(test.condition+"/"+test.data, func(t *testing.T) {
			program, err := NewCompiler().CompileSource(`external marker
			global constant = "$a"
			rule r { strings: $a = "needle" $b = "other" condition: ` + test.condition + ` }`)
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
				scanner := candidate.NewScanner(WithExternalVariables(map[string]any{"marker": "$a"}))
				matched, err := scanner.Matches([]byte(test.data))
				scanner.Close()
				if err != nil || matched != test.want {
					t.Fatalf("Matches = %v, %v; want %v", matched, err, test.want)
				}
			}
		})
	}
}

func TestMatchesRejectsNestedLoopBindings(t *testing.T) {
	for _, operand := range []string{"inner", "outer", "$"} {
		source := `rule r { strings: $a="needle" condition: for any outer in ($a) : (for any inner in ("$a") : (` + operand + ` matches /needle/)) }`
		_, err := NewCompiler().CompileSource(source)
		if err == nil || !strings.Contains(err.Error(), "MATCHES on nested loop variables") {
			t.Fatalf("%s: expected unsupported nested binding, got %v", operand, err)
		}
	}
}
