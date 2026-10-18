package compiler

import (
	"bytes"
	"math"
	"testing"
)

// Residual gremlins survivors for scanner_pattern.go are classified at the
// bottom of this file per the #311 acceptance criteria.

func TestPackFastScanKeyBoundaries(t *testing.T) {
	key, ok := packFastScanKey(1, 2)
	if !ok || key != (uint64(1)<<32|2) {
		t.Fatalf("packFastScanKey(1,2) = (%d,%v), want (%d,true)", key, ok, uint64(1)<<32|2)
	}
	if _, ok := packFastScanKey(-1, 0); ok {
		t.Fatal("negative rule index accepted")
	}
	if _, ok := packFastScanKey(0, -1); ok {
		t.Fatal("negative string index accepted")
	}
	if _, ok := packFastScanKey(math.MaxUint32, 0); !ok {
		t.Fatal("MaxUint32 rule index rejected")
	}
	if _, ok := packFastScanKey(0, math.MaxUint32); !ok {
		t.Fatal("MaxUint32 string index rejected")
	}
}

func TestNormalizeExternalUint(t *testing.T) {
	if _, err := normalizeExternalUint(math.MaxInt64); err != nil {
		t.Fatalf("normalizeExternalUint(MaxInt64) = %v, want nil", err)
	}
	if _, err := normalizeExternalUint(math.MaxInt64 + 1); err == nil {
		t.Fatal("normalizeExternalUint(MaxInt64+1) = nil, want error")
	}
}

func TestNormalizeExternalValue(t *testing.T) {
	for _, value := range []any{true, int64(-5), uint64(5), float64(1.5), "text"} {
		if _, err := normalizeExternalValue(value); err != nil {
			t.Fatalf("normalizeExternalValue(%T) = %v, want nil", value, err)
		}
	}
	if _, err := normalizeExternalValue(struct{}{}); err == nil {
		t.Fatal("normalizeExternalValue(struct{}) = nil, want error")
	}
}

func TestCloneExternalValues(t *testing.T) {
	if got := cloneExternalValues(nil); got != nil {
		t.Fatalf("cloneExternalValues(nil) = %v, want nil", got)
	}
	values := map[string]externalValue{"a": {valueType: ValueTypeInt, intVal: 1}}
	cloned := cloneExternalValues(values)
	if len(cloned) != 1 || cloned["a"].intVal != 1 {
		t.Fatalf("cloneExternalValues = %v", cloned)
	}
	cloned["a"] = externalValue{valueType: ValueTypeInt, intVal: 2}
	if values["a"].intVal != 1 {
		t.Fatal("cloneExternalValues returned a shared map")
	}
}

func TestShouldUseFixedRegexDispatch(t *testing.T) {
	if shouldUseFixedRegexDispatch(nil, nil) {
		t.Fatal("nil inputs reported dispatch")
	}
	dispatch := &fixedRegexDispatch{}
	dispatch.buckets['a'] = []int{0}
	if !shouldUseFixedRegexDispatch([]byte("aaaa"), dispatch) {
		t.Fatal("dense routed sample did not select dispatch")
	}
	if shouldUseFixedRegexDispatch([]byte("zzzz"), dispatch) {
		t.Fatal("empty routed sample selected dispatch")
	}
	sixteen := append([]byte("a"), bytes.Repeat([]byte("z"), 15)...)
	if !shouldUseFixedRegexDispatch(sixteen, dispatch) {
		t.Fatal("one routed pattern per 16 samples did not select dispatch")
	}
	large := append([]byte("a"), bytes.Repeat([]byte("z"), 4095)...)
	if shouldUseFixedRegexDispatch(large, dispatch) {
		t.Fatal("sparse large sample selected dispatch")
	}
}

func sharedAutomatonProgram() *CompiledProgram {
	program := &CompiledProgram{
		sharedLookup:    []sharedAutomatonEntry{{Kind: StringKindRegex}},
		sharedAutomaton: &acAutomaton{states: []acState{{}}},
	}
	program.sharedAutomaton.rootBytes = []byte{'a'}
	program.sharedAutomaton.states[0].transitions['a'] = 1
	return program
}

func TestShouldUseSharedPatternAutomaton(t *testing.T) {
	if shouldUseSharedPatternAutomaton(nil, nil) {
		t.Fatal("nil inputs reported shared automaton")
	}
	program := sharedAutomatonProgram()
	dense := append([]byte("aa"), bytes.Repeat([]byte("z"), 62)...)
	if shouldUseSharedPatternAutomaton(dense, program) {
		t.Fatal("dense roots selected the shared automaton")
	}
	if !shouldUseSharedPatternAutomaton(bytes.Repeat([]byte("z"), 64), program) {
		t.Fatal("sparse roots did not select the shared automaton")
	}
	if !shouldUseSharedPatternAutomaton(bytes.Repeat([]byte("z"), 512), program) {
		t.Fatal("sparse long sample did not select the shared automaton")
	}
}

func TestShouldUseSharedPatternAutomatonNoRootBytes(t *testing.T) {
	program := &CompiledProgram{
		sharedLookup:    []sharedAutomatonEntry{{Kind: StringKindRegex}},
		sharedAutomaton: &acAutomaton{states: []acState{{}}},
	}
	if shouldUseSharedPatternAutomaton([]byte("abc"), program) {
		t.Fatal("empty root bytes selected the shared automaton")
	}
}
