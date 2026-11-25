package regex

import (
	"strings"
	"testing"
)

func TestRegexAlternationBranchLimit(t *testing.T) {
	source := strings.Repeat("a|", maxRegexAlternationBranches+1) + "b"
	if _, err := NewParser(0).Parse(source); err == nil || !strings.Contains(err.Error(), "alternation branch") {
		t.Fatalf("Parse(long alternation) error = %v, want branch limit", err)
	}
}
