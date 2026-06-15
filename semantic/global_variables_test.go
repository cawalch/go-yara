package semantic

import "testing"

func TestValidatorCollectsGlobalVariables(t *testing.T) {
	input := `
global threshold = 1
global expected = "alpha"
global enabled = true
rule uses_globals {
	condition:
		threshold == 1 and expected == "alpha" and enabled
}`

	errs, err := parseAndValidateProgram(t, input)
	if err != nil {
		t.Fatalf("parseAndValidateProgram() error = %v", err)
	}
	if len(errs) > 0 {
		t.Fatalf("ValidateProgram() unexpected errors: %v", errs)
	}
}
