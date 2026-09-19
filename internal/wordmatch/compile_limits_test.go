package wordmatch

import (
	"errors"
	"testing"
)

func TestCompileInputLimits(t *testing.T) {
	for _, rules := range [][]Rule{
		make([]Rule, 4097),
		{{All: make([]Pattern, 8193)}},
		{{All: []Pattern{{Any: make([]Sequence, 16385)}}}},
		{{All: []Pattern{{Any: []Sequence{make(Sequence, 65537)}}}}},
		{{All: []Pattern{{Any: []Sequence{{{Literal: make([]byte, (1<<20)+1)}}}}}}},
	} {
		if _, err := CompileRouted(rules); !errors.Is(err, ErrIneligible) {
			t.Fatalf("oversized input: %v", err)
		}
	}
	// Shared input still consumes the cumulative owned-copy budget per occurrence.
	literal := make([]byte, 1<<19)
	rules := []Rule{{All: []Pattern{{Any: []Sequence{{{Literal: literal}}}}}}, {All: []Pattern{{Any: []Sequence{{{Literal: literal}}}}}}}
	if !boundedInput(rules) {
		t.Fatal("exact literal limit rejected")
	}
	rules = append(rules, rules[0])
	if boundedInput(rules) {
		t.Fatal("literal budget reset between rules")
	}
	if allocations := testing.AllocsPerRun(10, func() {
		if _, err := CompileRouted(rules); !errors.Is(err, ErrIneligible) {
			t.Fatal(err)
		}
	}); allocations > 4 {
		t.Fatalf("rejection allocated owned input: %.0f allocations", allocations)
	}
}
