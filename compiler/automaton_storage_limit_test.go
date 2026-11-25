package compiler

import (
	"strings"
	"testing"
)

func TestAutomatonPatternStorageLimits(t *testing.T) {
	ac := newacAutomaton()
	tooLong := make([]byte, maxAutomatonPatternLength+1)
	if err := ac.AddStringWithFlags("$a", tooLong, false, false, 0); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("AddStringWithFlags(oversize) error = %v, want limit error", err)
	}

	if _, err := deserializeAutomaton([]acStringInfo{{Identifier: "$a", Data: tooLong}}); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("deserializeAutomaton(oversize) error = %v, want limit error", err)
	}

	infos := make([]acStringInfo, 0, maxAutomatonPatternBytes/maxAutomatonPatternLength+1)
	pattern := make([]byte, maxAutomatonPatternLength)
	for len(infos)*maxAutomatonPatternLength <= maxAutomatonPatternBytes {
		infos = append(infos, acStringInfo{Identifier: "$a", Data: pattern})
	}
	if _, err := deserializeAutomaton(infos); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("deserializeAutomaton(total oversize) error = %v, want limit error", err)
	}
}
