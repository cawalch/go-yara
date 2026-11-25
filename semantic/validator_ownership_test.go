package semantic

import (
	"errors"
	"testing"
)

func TestValidatorReturnsOwnedErrorSnapshots(t *testing.T) {
	v := &Validator{errors: []error{errors.New("first")}}
	snapshot := v.GetErrors()
	snapshot[0] = errors.New("mutated")

	if got := v.errors[0].Error(); got != "first" {
		t.Fatalf("validator error mutated through snapshot: %q", got)
	}
}
