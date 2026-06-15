package compiler

import "testing"

func TestGlobalVariableConditions(t *testing.T) {
	tests := []struct {
		name   string
		source string
		rule   string
	}{
		{
			name: "integer global",
			source: `
global threshold = 1
rule global_var { condition: threshold }`,
			rule: "global_var",
		},
		{
			name: "string global",
			source: `
global expected = "alpha"
rule global_string { condition: expected == "alpha" }`,
			rule: "global_string",
		},
		{
			name: "boolean global",
			source: `
global enabled = true
rule global_bool { condition: enabled }`,
			rule: "global_bool",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			program, err := NewCompiler().CompileSource(tt.source)
			if err != nil {
				t.Fatalf("CompileSource() error = %v", err)
			}

			result, err := program.Scan([]byte("irrelevant"))
			if err != nil {
				t.Fatalf("Scan() error = %v", err)
			}
			if !result.RuleResults[tt.rule] {
				t.Fatalf("RuleResults[%q] = false, want true", tt.rule)
			}
		})
	}
}

func TestGlobalVariableSlotsDoNotCollideWithStringsOrExternals(t *testing.T) {
	source := `
external gate
global threshold = 1
rule combined {
	strings:
		$a = "alpha"
	condition:
		$a and gate and threshold == 1
}`

	program, err := NewCompiler().CompileSource(source)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}

	scanner := NewScanner(program, WithExternalVariables(map[string]any{"gate": true}))
	defer scanner.Close()

	result, err := scanner.Scan([]byte("alpha"))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if !result.RuleResults["combined"] {
		t.Fatalf("RuleResults[combined] = false, want true")
	}
}
