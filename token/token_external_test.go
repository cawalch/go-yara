package token

import "testing"

func TestExternalTokenString(t *testing.T) {
	if got := EXTERNAL.String(); got != "EXTERNAL" {
		t.Fatalf("EXTERNAL.String() = %q, want EXTERNAL", got)
	}
}
