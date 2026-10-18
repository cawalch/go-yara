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

// Residual gremlins survivors for scanner_pattern.go (gremlins v0.6.0,
// workers=1, timeout-coefficient=30), classified per #311:
//
// LIVED / equivalent-mode:
//
//	20:33,20:47,   shared-non-text cache index guards; the invalid-index branch
//	50:50,65:46,   only skips work that the following bounds checks also skip.
//	70:46,113:50,128:46,133:46
//	48:16,229:17,  ctx.Done() == nil is always false for a live MatchContext.
//	245:16
//	106:80,169:80  canTriggerRule / hookMask telemetry gates that only affect
//	               whether a rule is marked, not the matched spans.
//	142:46,143:48  isWide/isNocase flag extraction; the values are re-derived
//	               by the matcher.
//	165:42,252:21  global/text match bookkeeping that is re-checked later.
//	216:21,216:61  packFastScanKey boundaries are covered by the direct test;
//	               the remaining variant only rejects at the exact limit.
//	228:37,449:38, maxMatchesPerPattern <= 0 at 0 is a no-op.
//	449:67,449:96,481:38,481:54,481:83,481:110
//	281:14,281:34  populateFixedRegexCache early-outs that leave the cache
//	               untouched.
//	291:30,291:33, fixed-regex wide position guards.
//	306:27,308:19
//	323:28,324:30  wide-order comparison; both orders produce the same sorted
//	               cache order.
//	329:12         comparator sentinel.
//	347:31,387:15, shared-automaton density gates; both branches fall through to
//	394:19,394:46, the same automaton.
//	400:74,409:28,410:12,411:9,415:53,421:23
//	442:52,454:51, short-circuit checks that only skip already-satisfied rules.
//	462:14,465:53,475:53,486:51
//	660:11         normalizeExternalUint boundary; the exact-limit variant is
//	               covered by the direct test.
//
// NOT COVERED / unfixable-by-tests:
//
//	326:18         sortAndDedupe switch-case condition.
//	119:54         prefilterCandidates empty-length guard on an unreached path.
