package semantic

import (
	"strings"
	"testing"
)

func TestValidateCaptureAndEvidenceDeclarations(t *testing.T) {
	valid := `
rule valid {
    strings:
        $pair = /user=([^ ]+) secret=([^ ]+)/ capture(username = 1, secret = 2)
    evidence:
        credential = (username, secret) within 4KB of secret
    condition:
        $pair
}
`
	errs, err := parseAndValidateProgram(t, valid)
	if err != nil {
		t.Fatalf("parseAndValidateProgram() error = %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("ValidateProgram() errors = %v", errs)
	}

	invalid := `
rule invalid {
    strings:
        $pair = /(value)/ private capture(secret = 2)
    evidence:
        credential = (secret, username, username) within 10 of endpoint
    condition:
        $pair
}
`
	errs, err = parseAndValidateProgram(t, invalid)
	if err != nil {
		t.Fatalf("parseAndValidateProgram() error = %v", err)
	}
	joined := make([]string, len(errs))
	for index, semanticErr := range errs {
		joined[index] = semanticErr.Error()
	}
	message := strings.Join(joined, "\n")
	for _, want := range []string{"private and capture", "out of range", "undeclared capture", "repeats field", "not in its field list"} {
		if !strings.Contains(message, want) {
			t.Errorf("semantic errors do not contain %q:\n%s", want, message)
		}
	}
}
