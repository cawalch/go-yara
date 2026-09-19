package compiler

import (
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
		{`for any outer in ($a) : (for any inner in ("$a") : (outer matches /needle/ and inner matches /^\$a$/))`, "needle", true},
		{`for any outer in ("$a") : (for any inner in ($a) : (outer matches /^\$a$/ and inner matches /needle/))`, "needle", true},
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

func TestMatchesPreservesLoopAndDeclaredValues(t *testing.T) {
	for _, condition := range []string{
		`(for any s in ("value") : (s matches /value/)) and marker matches /needle/`,
		`(for any s in ("value") : (s matches /value/)) and constant matches /needle/`,
		`for any outer in ("needle") : ((for any inner in ("other") : (true)) and outer matches /needle/)`,
		`for any s in ("needle") : ((for any s in ("other") : (s matches /other/)) and s matches /needle/)`,
		`for any s in ("outer") : ((for any s in ("middle") : ((for any s in ("inner") : (s matches /inner/)) and s matches /middle/)) and s matches /outer/)`,
	} {
		t.Run(condition, func(t *testing.T) {
			program, err := NewCompiler().CompileSource(`external marker global constant = "needle" rule r { condition: ` + condition + ` }`)
			if err != nil {
				t.Fatal(err)
			}
			scanner := program.NewScanner(WithExternalVariables(map[string]any{"marker": "needle"}))
			defer scanner.Close()
			for range 2 {
				matched, err := scanner.Matches(nil)
				if err != nil || !matched {
					t.Fatalf("Matches = %v, %v; want true", matched, err)
				}
			}
		})
	}
}
