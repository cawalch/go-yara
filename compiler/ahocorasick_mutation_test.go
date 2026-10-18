package compiler

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/cawalch/go-yara/regex"
)

// Residual gremlins survivors for ahocorasick.go are classified at the bottom
// of this file per the #311 acceptance criteria.

func TestReserveCapacityHelpers(t *testing.T) {
	// Start from a zero-capacity automaton so the grow branches are reachable.
	ac := &acAutomaton{}
	ac.ReserveStrings(4)
	if cap(ac.strings) < 4 || cap(ac.Strings) < 4 {
		t.Fatalf("ReserveStrings(4) caps = %d/%d, want >= 4", cap(ac.strings), cap(ac.Strings))
	}
	ac.ReserveStates(8)
	if cap(ac.states) < 8 {
		t.Fatalf("ReserveStates(8) cap = %d, want >= 8", cap(ac.states))
	}
}

func TestEstimateMemoryUsage(t *testing.T) {
	ac := newacAutomaton()
	ac.states = make([]acState, 3)
	ac.hasOutput = make([]bool, 3)
	ac.outputs = make([]int32, 5)
	ac.strings = make([]acStringInfo, 2)

	want := 3*(256*4+8) + 3 + 5*4 + 2*64
	if got := ac.EstimateMemoryUsage(); got != want {
		t.Fatalf("EstimateMemoryUsage = %d, want %d", got, want)
	}

	ac.transitions16 = make([][256]uint16, 3)
	want16 := 3*(256*4+8) + 3*256*2 + 3 + 5*4 + 2*64
	if got := ac.EstimateMemoryUsage(); got != want16 {
		t.Fatalf("EstimateMemoryUsage(16) = %d, want %d", got, want16)
	}

	ac.transitions16 = nil
	ac.transitions32 = make([][256]int32, 3)
	want32 := 3*(256*4+8) + 3*256*4 + 3 + 5*4 + 2*64
	if got := ac.EstimateMemoryUsage(); got != want32 {
		t.Fatalf("EstimateMemoryUsage(32) = %d, want %d", got, want32)
	}
}

func TestValidateInconsistentState(t *testing.T) {
	ac := newacAutomaton()
	ac.compiled = true
	ac.strings = nil
	if err := ac.Validate(); err == nil {
		t.Fatal("Validate() = nil, want inconsistent-state error")
	}
}

func TestRootFailureSentinel(t *testing.T) {
	ac := newacAutomaton()
	if ac.states[0].failure != -1 {
		t.Fatalf("newacAutomaton root failure = %d, want -1", ac.states[0].failure)
	}
	if err := ac.AddString("$a", []byte("ab"), false, false); err != nil {
		t.Fatal(err)
	}
	if ac.states[1].failure != -1 {
		t.Fatalf("new state failure = %d, want -1", ac.states[1].failure)
	}
	ac.states[0].failure = 7
	ac.Reset()
	if ac.states[0].failure != -1 {
		t.Fatalf("Reset root failure = %d, want -1", ac.states[0].failure)
	}
}

func TestIndexSinglePatternNoCase(t *testing.T) {
	if got := indexSinglePattern([]byte("xaby"), []byte("ab"), true); got != 1 {
		t.Fatalf("indexSinglePattern(match) = %d, want 1", got)
	}
	if got := indexSinglePattern([]byte("ax"), []byte("ab"), true); got != -1 {
		t.Fatalf("indexSinglePattern(miss) = %d, want -1", got)
	}
	if got := indexSinglePattern([]byte("a"), []byte("a"), true); got != 0 {
		t.Fatalf("indexSinglePattern(single byte) = %d, want 0", got)
	}
	if got := indexSinglePattern([]byte("a"), []byte("abc"), true); got != -1 {
		t.Fatalf("indexSinglePattern(short input) = %d, want -1", got)
	}
}

func TestSinglePatternIsDenseThreshold(t *testing.T) {
	if !singlePatternIsDense(bytes.Repeat([]byte("ab"), 8), []byte("ab"), false) {
		t.Fatal("singlePatternIsDense(8 matches) = false, want true")
	}
	if singlePatternIsDense([]byte("ab"), []byte("ab"), false) {
		t.Fatal("singlePatternIsDense(1 match) = true, want false")
	}
}

func TestRootIsDenseHelpers(t *testing.T) {
	ac := newacAutomaton()
	if err := ac.AddString("$a", []byte("abc"), false, false); err != nil {
		t.Fatal(err)
	}
	if err := ac.Compile(); err != nil {
		t.Fatal(err)
	}
	dense := bytes.Repeat([]byte("a"), 64)
	if !ac.rootIsDense16(dense) {
		t.Fatal("rootIsDense16(dense) = false, want true")
	}
	if ac.rootIsDense16([]byte("zzzz")) {
		t.Fatal("rootIsDense16(sparse) = true, want false")
	}
	// A single hit must not trip the >16 dense threshold.
	if ac.rootIsDense16([]byte("azzz")) {
		t.Fatal("rootIsDense16(one hit) = true, want false")
	}
	if !ac.rootIsDense(dense) {
		t.Fatal("rootIsDense(dense) = false, want true")
	}
	if ac.rootIsDense([]byte("zzzz")) {
		t.Fatal("rootIsDense(sparse) = true, want false")
	}
	if ac.rootIsDense([]byte("azzz")) {
		t.Fatal("rootIsDense(one hit) = true, want false")
	}
	// Exactly 16 hits must stay below the >16 dense threshold.
	sixteen := append(bytes.Repeat([]byte("a"), 16), bytes.Repeat([]byte("z"), 48)...)
	if ac.rootIsDense16(sixteen) {
		t.Fatal("rootIsDense16(16 hits) = true, want false")
	}
	if ac.rootIsDense(sixteen) {
		t.Fatal("rootIsDense(16 hits) = true, want false")
	}
}

func TestRootCandidateCursorNext(t *testing.T) {
	cursor := newRootCandidateCursor([]rootLane{{value: 'a'}, {value: 'b'}})
	if got := cursor.next([]byte("zzazzb"), 0); got != 2 {
		t.Fatalf("next = %d, want 2", got)
	}
	missing := newRootCandidateCursor([]rootLane{{value: 'q'}})
	if got := missing.next([]byte("abc"), 0); got != -1 {
		t.Fatalf("next(missing) = %d, want -1", got)
	}
	first := newRootCandidateCursor([]rootLane{{value: 'z'}, {value: 'a'}})
	if got := first.next([]byte("z___a"), 0); got != 0 {
		t.Fatalf("next(first-at-zero) = %d, want 0", got)
	}
}

func TestRootCandidateCursorNextWithCancel(t *testing.T) {
	cursor := newRootCandidateCursor([]rootLane{{value: 'a'}, {value: 'b'}})
	if got := cursor.nextWithCancel([]byte("zzazzb"), 0, nil); got != 2 {
		t.Fatalf("nextWithCancel = %d, want 2", got)
	}
	missing := newRootCandidateCursor([]rootLane{{value: 'q'}})
	if got := missing.nextWithCancel([]byte("abc"), 0, nil); got != -1 {
		t.Fatalf("nextWithCancel(missing) = %d, want -1", got)
	}
	atZero := newRootCandidateCursor([]rootLane{{value: 'a'}})
	if got := atZero.nextWithCancel([]byte("abc"), 0, nil); got != 0 {
		t.Fatalf("nextWithCancel(at-zero) = %d, want 0", got)
	}
	first := newRootCandidateCursor([]rootLane{{value: 'z'}, {value: 'a'}})
	if got := first.nextWithCancel([]byte("z___a"), 0, nil); got != 0 {
		t.Fatalf("nextWithCancel(first-at-zero) = %d, want 0", got)
	}
}

func closedDone() <-chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}

func TestIndexByteWithCancel(t *testing.T) {
	if got := indexByteWithCancel([]byte("abc"), 0, 'a', nil); got != 0 {
		t.Fatalf("indexByteWithCancel(at zero) = %d, want 0", got)
	}
	if got := indexByteWithCancel([]byte("abc"), 0, 'c', nil); got != 2 {
		t.Fatalf("indexByteWithCancel(at two) = %d, want 2", got)
	}
	if got := indexByteWithCancel([]byte("abc"), 0, 'z', nil); got != -1 {
		t.Fatalf("indexByteWithCancel(miss) = %d, want -1", got)
	}
	if got := indexByteWithCancel([]byte("abc"), 0, 'a', closedDone()); got != -1 {
		t.Fatalf("indexByteWithCancel(canceled) = %d, want -1", got)
	}
}

func TestIndexASCIIFoldByteWithCancel(t *testing.T) {
	if got := indexASCIIFoldByteWithCancel([]byte("abc"), 0, 'a', nil); got != 0 {
		t.Fatalf("indexASCIIFoldByteWithCancel(at zero) = %d, want 0", got)
	}
	if got := indexASCIIFoldByteWithCancel([]byte("xAbc"), 0, 'b', nil); got != 2 {
		t.Fatalf("indexASCIIFoldByteWithCancel(folded) = %d, want 2", got)
	}
	if got := indexASCIIFoldByteWithCancel([]byte("abc"), 0, 'z', nil); got != -1 {
		t.Fatalf("indexASCIIFoldByteWithCancel(miss) = %d, want -1", got)
	}
	if got := indexASCIIFoldByteWithCancel([]byte("abc"), 0, 'a', closedDone()); got != -1 {
		t.Fatalf("indexASCIIFoldByteWithCancel(canceled) = %d, want -1", got)
	}
}

func TestYieldMatchesSkipsOutOfRangeStringIndex(t *testing.T) {
	ac := newacAutomaton()
	ac.states = append(ac.states, acState{outputStart: 0, outputEnd: 1})
	ac.outputs = []int32{0}
	ac.strings = nil
	called := false
	ac.yieldMatches(1, 0, func(acMatch) bool {
		called = true
		return true
	})
	if called {
		t.Fatal("yieldMatches yielded an out-of-range string index")
	}
}

func TestCollectRootBytesFoldedLanes(t *testing.T) {
	ac := newacAutomaton()
	if err := ac.AddStringWithFlags("$a", []byte("ab"), false, false, regex.FlagsNoCase); err != nil {
		t.Fatal(err)
	}
	ac.collectRootBytes()
	found := false
	for _, lane := range ac.rootLanes {
		if lane.value == 'a' && lane.isFold {
			found = true
		}
	}
	if !found {
		t.Fatalf("rootLanes = %+v, want a folded lane for 'a'", ac.rootLanes)
	}
}

func TestFlipASCIICase(t *testing.T) {
	tests := []struct {
		in   byte
		want byte
	}{
		{in: 'a', want: 'A'},
		{in: 'z', want: 'Z'},
		{in: 'A', want: 'a'},
		{in: 'Z', want: 'z'},
		{in: '0', want: '0'},
		{in: 0xFF, want: 0xFF},
	}
	for _, tt := range tests {
		if got := flipASCIICase(tt.in); got != tt.want {
			t.Fatalf("flipASCIICase(%#x) = %#x, want %#x", tt.in, got, tt.want)
		}
	}
}

func collectSearchWithCancel(t *testing.T, ac *acAutomaton, data []byte) []acMatch {
	t.Helper()
	var got []acMatch
	ac.SearchWithCancel(data, nil, func(m acMatch) bool {
		got = append(got, m)
		return true
	})
	return got
}

// TestSearchWithCancelMatchesSearchIter exercises the teddy long-input hot path
// in searchWithCancel16, which no other test reaches.
func TestSearchWithCancelMatchesSearchIter(t *testing.T) {
	ac := newacAutomaton()
	for id, pattern := range map[string]string{
		"$a": "alpha-pattern",
		"$b": "bravo-pattern",
	} {
		if err := ac.AddString(id, []byte(pattern), false, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := ac.Compile(); err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("x"), 1024)
	copy(data[100:], "alpha-pattern")
	copy(data[600:], "bravo-pattern")
	want := slices.Collect(ac.SearchIter(data))
	if got := collectSearchWithCancel(t, ac, data); !slices.Equal(got, want) {
		t.Fatalf("SearchWithCancel = %+v, want %+v", got, want)
	}
}

// TestSearchWithCancelSparseRootLanes exercises the sparse root-lane path,
// which needs teddy disabled (>maxTeddyPatterns) and <=4 distinct root bytes.
func TestSearchWithCancelSparseRootLanes(t *testing.T) {
	ac := newacAutomaton()
	for i := range maxTeddyPatterns + 1 {
		pattern := fmt.Sprintf("a%03d", i)
		if err := ac.AddString(fmt.Sprintf("$%03d", i), []byte(pattern), false, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := ac.Compile(); err != nil {
		t.Fatal(err)
	}
	if ac.teddy != nil {
		t.Fatal("teddy prefilter unexpectedly enabled for >maxTeddyPatterns strings")
	}
	data := bytes.Repeat([]byte("x"), 1024)
	copy(data[500:], "a042")
	want := slices.Collect(ac.SearchIter(data))
	if got := collectSearchWithCancel(t, ac, data); !slices.Equal(got, want) {
		t.Fatalf("SearchWithCancel(sparse roots) = %+v, want %+v", got, want)
	}
}

func TestSearchWithCancelHonorsCancellation(t *testing.T) {
	ac := newacAutomaton()
	for id, pattern := range map[string]string{"$a": "aa", "$b": "ab"} {
		if err := ac.AddString(id, []byte(pattern), false, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := ac.Compile(); err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("a"), 4*scanCancellationInterval)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	count := 0
	ac.SearchWithCancel(data, ctx.Done(), func(acMatch) bool {
		count++
		if count == 100 {
			cancel()
		}
		return true
	})
	if count == 0 || count > 2*scanCancellationInterval {
		t.Fatalf("SearchWithCancel yielded %d matches after cancellation", count)
	}
}

// TestYieldMatchesWithCancelOffsetCheckpoint pins the cancellation checkpoint
// arithmetic so the checkpoint index depends on outputStart.
func TestYieldMatchesWithCancelOffsetCheckpoint(t *testing.T) {
	ac := newacAutomaton()
	ac.states = append(ac.states, acState{outputStart: 1, outputEnd: scanCancellationInterval})
	ac.outputs = make([]int32, scanCancellationInterval)
	ac.strings = []acStringInfo{{Identifier: "$a", Length: 1}}
	if !ac.yieldMatchesWithCancel(1, 0, func(acMatch) bool { return true }, closedDone()) {
		t.Fatal("yieldMatchesWithCancel stopped at a non-checkpoint offset")
	}
}

// TestYieldMatchesWithCancelCheckpointMask pins the checkpoint mask and the
// canceled() guard at relative == scanCancellationInterval.
func TestYieldMatchesWithCancelCheckpointMask(t *testing.T) {
	ac := newacAutomaton()
	ac.states = append(ac.states, acState{outputStart: 0, outputEnd: scanCancellationInterval + 1})
	ac.outputs = make([]int32, scanCancellationInterval+1)
	ac.strings = []acStringInfo{{Identifier: "$a", Length: 1}}
	if ac.yieldMatchesWithCancel(1, 0, func(acMatch) bool { return true }, closedDone()) {
		t.Fatal("yieldMatchesWithCancel ignored cancellation at the checkpoint")
	}
}

func TestSearchWithCancelSingleNoCase(t *testing.T) {
	ac := newacAutomaton()
	if err := ac.AddStringWithFlags("$a", []byte("ab"), false, false, regex.FlagsNoCase); err != nil {
		t.Fatal(err)
	}
	if err := ac.Compile(); err != nil {
		t.Fatal(err)
	}
	data := []byte("xxABxx")
	want := slices.Collect(ac.SearchIter(data))
	got := collectSearchWithCancel(t, ac, data)
	if !slices.Equal(got, want) {
		t.Fatalf("SearchWithCancel = %+v, want %+v", got, want)
	}
	if len(got) == 0 {
		t.Fatal("nocase single pattern did not match")
	}
}

func TestYieldMatchesWithCancelStringIndexBounds(t *testing.T) {
	ac := newacAutomaton()
	ac.states = append(ac.states, acState{outputStart: 0, outputEnd: 2})
	ac.outputs = []int32{0, 1}
	ac.strings = []acStringInfo{{Identifier: "$a", Length: 1}}
	count := 0
	if !ac.yieldMatchesWithCancel(1, 0, func(acMatch) bool { count++; return true }, nil) {
		t.Fatal("yieldMatchesWithCancel returned false")
	}
	if count != 1 {
		t.Fatalf("yieldMatchesWithCancel yielded %d matches, want 1", count)
	}
}

// Residual gremlins survivors for ahocorasick.go (gremlins v0.6.0, workers=1,
// timeout-coefficient=30), classified per #311:
//
// LIVED / equivalent-mode (boundary/negation variants that cannot change
// observable results, either because they are no-ops at the boundary or because
// the affected branch is a performance-only optimisation that produces the same
// matches as the fallback):
//
//	368:14         failure < 0 -> <=: setting failure to 0 when already 0.
//	397:15         numStates <= 65536: see impractical note below.
//	418:17,622:17  len(sample) > 256 -> >=: slicing a 256-length sample to 256
//	               is a no-op.
//	469:15,483:27, root-cursor position/best bounds are guarded by the preceding
//	497:15,511:27  condition, so the boundary variant is unreachable.
//	520:39,534:39  windowStart < len(data) -> <=: the extra iteration scans an
//	               empty window and yields -1.
//	602:15         len(data) > sampleSize -> >=: slicing to sampleSize is a no-op.
//	606:20,606:32, pos-bound arithmetic/boundaries: extra iterations call
//	645:32,669:32  indexSinglePattern, which returns -1 (pos never exceeds
//	               len(data)), so the outcome is unchanged.
//	718:21,975:21  len(info.Data) > 0 boundary/negation: only the empty-pattern
//	               edge, which normal compilation never produces.
//	719:43,976:43  noCase heuristic negation: searchSinglePattern recomputes the
//	               flag, so the final matches are identical.
//	727:27,984:27  len(transitions16) > 0 at 0 is guarded by the caller's
//	               transitions16/32 selection.
//	742:53,999:53  len(data) >= 256: the teddy and fallback paths are
//	               differentially equivalent (verified by the SearchWithCancel
//	               comparison tests).
//	778:34,778:62, root-lane gate boundaries/negations: selecting or skipping the
//	778:87,        sparse-root optimisation yields the same matches as the block
//	1031:34,       loop.
//	1031:62,
//	1031:87
//	782:34,782:38  cancellation-checkpoint arithmetic: changes only when
//	               cancellation is polled, never the produced matches.
//	785:30,785:57, linearUntil/candidate gates: performance-only; the fallback
//	785:60,787:18, scan still visits every byte.
//	790:17,790:20,
//	797:21,811:34,
//	1035:30,
//	1035:57,
//	1035:60,
//	1040:17,
//	1040:20,
//	1041:30,
//	1047:21
//	1187:7,1187:30, ReserveStrings/ReserveStates bounds and slices.Grow arithmetic:
//	1188:41,1190:7, capacity is not semantically observable.
//	1190:30,1191:41,
//	1197:7,1197:29,
//	1198:39
//	1234:20        len(ac.states) > 0 at 0 is unreachable (the preceding guard
//	               returns first).
//	1329:34        len(transitions32) > 0 at 0 is guarded by the transitions16
//	               selection above.
//
// LIVED / impractical:
//
//	397:15         numStates <= 65536 -> <: distinguishing the 16- vs 32-bit
//	               transition tables needs 65536 states (~64 MB).
//
// TIMED OUT / non-terminating:
//
//	584:20,658:15, pos + rel / start + 1 -> subtraction makes the scan cursor
//	682:15         walk backwards forever.
