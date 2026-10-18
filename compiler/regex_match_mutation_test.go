package compiler

import (
	"slices"
	"testing"

	"github.com/cawalch/go-yara/regex"
)

// Residual gremlins survivors for regex_match.go are classified at the bottom
// of this file per the #311 acceptance criteria.

func TestLeadingGapRegexCandidateStartsGuards(t *testing.T) {
	if starts, ok := leadingGapRegexCandidateStarts([]byte("abc"), nil, 0, nil); ok || starts != nil {
		t.Fatalf("nil plan = (%v, %v), want (nil,false)", starts, ok)
	}
	if starts, ok := leadingGapRegexCandidateStarts([]byte("abc"), &regexLeadingGapPlan{}, 0, nil); ok || starts != nil {
		t.Fatalf("empty plan = (%v, %v), want (nil,false)", starts, ok)
	}
}

func TestUnboundedRegexAlternativePresent(t *testing.T) {
	atoms := []regexPrefilterAtom{{data: []byte("ab"), maxOffset: -1}}
	if !unboundedRegexAlternativePresent([]byte("xaby"), atoms, 0, nil) {
		t.Fatal("present atom not detected")
	}
	if !unboundedRegexAlternativePresent([]byte("aby"), atoms, 0, nil) {
		t.Fatal("atom at offset 0 not detected")
	}
	if unboundedRegexAlternativePresent([]byte("zzz"), atoms, 0, nil) {
		t.Fatal("absent atom reported present")
	}
}

func TestNewRegexMatchBatch(t *testing.T) {
	ctx := matchContextPool.Get().(*MatchContext)
	defer ctx.Release()
	ctx.Reset([]byte("abc"))

	if bs := newRegexMatchBatch(ctx, RegexPattern{}); bs == nil {
		t.Fatal("newRegexMatchBatch(empty pattern) = nil, want a batch")
	}
	fixed := RegexPattern{fixedByteSets: []regex.ByteSet{regex.NewByteSet([]byte{'a'})}}
	if bs := newRegexMatchBatch(ctx, fixed); bs != nil {
		t.Fatal("newRegexMatchBatch(fixed byte sets) != nil, want nil")
	}
}

func TestExecRegexMatchAtFixedMiss(t *testing.T) {
	pattern := RegexPattern{fixedByteSets: []regex.ByteSet{regex.NewByteSet([]byte{'a'})}}
	matched, start, end := execRegexMatchAt(nil, pattern, []byte("zzz"), 0, false, 0, nil)
	if matched || start != -1 || end != -1 {
		t.Fatalf("execRegexMatchAt = (%v,%d,%d), want (false,-1,-1)", matched, start, end)
	}
}

func TestRegexAtomCandidateStarts(t *testing.T) {
	pattern := RegexPattern{atomMinOffset: 0, atomMaxOffset: 0}
	starts, ok := regexAtomCandidateStarts([]byte("xaby"), []byte("ab"), pattern, 0, false, nil)
	if !ok || !slices.Equal(starts, []int{1}) {
		t.Fatalf("regexAtomCandidateStarts = (%v, %v), want ([1], true)", starts, ok)
	}
	unbounded := RegexPattern{atomMinOffset: 0, atomMaxOffset: -1}
	if _, ok := regexAtomCandidateStarts([]byte("xaby"), []byte("ab"), unbounded, 0, false, nil); ok {
		t.Fatal("unbounded atom reported ok")
	}
}

func TestRegexAtomCandidateStartsAtLimit(t *testing.T) {
	// Exactly max(1024, len/4) atom matches must still succeed.
	data := make([]byte, 0, 2048)
	for range 1024 {
		data = append(data, 'a', 'b')
	}
	pattern := RegexPattern{atomMinOffset: 0, atomMaxOffset: 0}
	starts, ok := regexAtomCandidateStarts(data, []byte("ab"), pattern, 0, false, nil)
	if !ok || len(starts) != 1024 {
		t.Fatalf("regexAtomCandidateStarts(at limit) = (%d starts, %v), want (1024, true)", len(starts), ok)
	}
}

// Residual gremlins survivors for regex_match.go (gremlins v0.6.0, workers=1,
// timeout-coefficient=30), classified per #311:
//
// LIVED / equivalent-mode:
//
//	43:17,43:66,   addRegexMatchesCached prefix/atom dispatch guards; the
//	78:62,94:37    fallthrough still reaches the same matcher.
//	127:48,163:14, index++/checkpoint++ are no-ops when done is nil.
//	177:16,358:13,396:49
//	154:30,347:53, capacity arithmetic is not observable.
//	159:51,293:24, loop bounds whose extra iteration finds no occurrence.
//	166:20,166:39, suffix/gap bounds guarded by the range checks that follow.
//	169:27,170:20, gap-length arithmetic and gapMax >= 0 at 0.
//	173:35,180:22,195:17
//	241:21,272:16, alternative-cursor bounds guarded by the preceding clause.
//	272:21,300:51,330:18,348:26
//	362:32,362:45  candidate-selection bounds guarded by `candidate < 0`.
//	402:17         searchFrom > len(data) at equality: the next index returns -1.
//	424:20,424:32  linear-scan bound; the extra position yields no match.
//	445:9,445:49,  addRegexMatchAt maxMatchSpan guard; ctx is never nil on this
//	453:20,455:12  path, and the boundary only shifts an equivalent scan window.
//	465:32,480:18, newRegexMatchBatch/execRegexMatchAt sentinel returns; the
//	480:22         covered variants are killed by the fixed-byte-set tests.
//	523:27,527:30, regexAtomCandidateStarts bounds/limits.
//	530:40,530:55,530:79,535:11,539:22,542:21
//
// NOT COVERED / not exercised:
//
//	446:35         ctx.maxMatchSpan truncation (needs a live VM pattern with a
//	               span bound).
//	474:17,474:21  cancellation early-return inside execRegexMatchAt.
//
// TIMED OUT / non-terminating:
//
//	159:51,159:96,164:66,257:39,264:18,295:17,298:34,359:16,366:16,372:28,
//	401:27  negated cursor bounds / `return -1` -> 1 walk the candidate cursor
//	backwards forever.
