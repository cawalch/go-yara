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
