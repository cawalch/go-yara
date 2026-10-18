package compiler

import (
	"bytes"
	"testing"

	"github.com/cawalch/go-yara/regex"
)

// Residual gremlins survivors for atom_prefilter.go are classified at the
// bottom of this file per the #311 acceptance criteria.

func TestBetterRegexPrefilterAtomOrdering(t *testing.T) {
	tests := []struct {
		name      string
		candidate regexPrefilterAtom
		current   regexPrefilterAtom
		want      bool
	}{
		{
			name:      "unbounded candidate loses to bounded current",
			candidate: regexPrefilterAtom{data: []byte("abcd"), maxOffset: -1},
			current:   regexPrefilterAtom{data: []byte("wxyz"), maxOffset: 0},
			want:      false,
		},
		{
			name:      "zero-offset bounded candidate beats wider current",
			candidate: regexPrefilterAtom{data: []byte("abcd"), minOffset: 0, maxOffset: 0},
			current:   regexPrefilterAtom{data: []byte("wxyz"), minOffset: 0, maxOffset: 5},
			want:      true,
		},
		{
			name:      "equal score narrower candidate wins",
			candidate: regexPrefilterAtom{data: []byte("abcd"), minOffset: 0, maxOffset: 0, score: 5},
			current:   regexPrefilterAtom{data: []byte("wxyz"), minOffset: 0, maxOffset: 5, score: 5},
			want:      true,
		},
		{
			name:      "lower score candidate loses",
			candidate: regexPrefilterAtom{data: []byte("abcd"), minOffset: 0, maxOffset: 0, score: 3},
			current:   regexPrefilterAtom{data: []byte("wxyz"), minOffset: 0, maxOffset: 0, score: 5},
			want:      false,
		},
		{
			name:      "candidate width uses subtraction",
			candidate: regexPrefilterAtom{data: []byte("abcd"), minOffset: 2, maxOffset: 3, score: 5},
			current:   regexPrefilterAtom{data: []byte("wxyz"), minOffset: 0, maxOffset: 3, score: 5},
			want:      true,
		},
		{
			name:      "current width uses subtraction",
			candidate: regexPrefilterAtom{data: []byte("abcd"), minOffset: 0, maxOffset: 3, score: 5},
			current:   regexPrefilterAtom{data: []byte("wxyz"), minOffset: 2, maxOffset: 3, score: 5},
			want:      false,
		},
		{
			name:      "equal width falls through",
			candidate: regexPrefilterAtom{data: []byte("abcd"), minOffset: 0, maxOffset: 3, score: 5},
			current:   regexPrefilterAtom{data: []byte("wxyz"), minOffset: 1, maxOffset: 4, score: 5},
			want:      true,
		},
		{
			name:      "narrower candidate wins",
			candidate: regexPrefilterAtom{data: []byte("abcd"), minOffset: 0, maxOffset: 1, score: 5},
			current:   regexPrefilterAtom{data: []byte("wxyz"), minOffset: 0, maxOffset: 3, score: 5},
			want:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := betterRegexPrefilterAtom(tt.candidate, tt.current); got != tt.want {
				t.Fatalf("betterRegexPrefilterAtom() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBetterRegexByteSetPrefilterOrdering(t *testing.T) {
	tests := []struct {
		name      string
		candidate regexByteSetPrefilter
		current   regexByteSetPrefilter
		want      bool
	}{
		{
			name:      "zero-offset bounded candidate beats wider current",
			candidate: regexByteSetPrefilter{count: 1, minOffset: 0, maxOffset: 0},
			current:   regexByteSetPrefilter{count: 1, minOffset: 0, maxOffset: 5},
			want:      true,
		},
		{
			name:      "unbounded candidate loses to zero-offset bounded current",
			candidate: regexByteSetPrefilter{count: 1, maxOffset: -1},
			current:   regexByteSetPrefilter{count: 1, maxOffset: 0},
			want:      false,
		},
		{
			name:      "both bounded compares count",
			candidate: regexByteSetPrefilter{count: 5, minOffset: 0, maxOffset: 0},
			current:   regexByteSetPrefilter{count: 3, minOffset: 0, maxOffset: 0},
			want:      false,
		},
		{
			name:      "wider candidate loses on equal count",
			candidate: regexByteSetPrefilter{count: 3, minOffset: 0, maxOffset: 5},
			current:   regexByteSetPrefilter{count: 3, minOffset: 0, maxOffset: 0},
			want:      false,
		},
		{
			name:      "smaller count wins",
			candidate: regexByteSetPrefilter{count: 3, minOffset: 0, maxOffset: 0},
			current:   regexByteSetPrefilter{count: 5, minOffset: 0, maxOffset: 0},
			want:      true,
		},
		{
			name:      "candidate width uses subtraction",
			candidate: regexByteSetPrefilter{count: 3, minOffset: 2, maxOffset: 3},
			current:   regexByteSetPrefilter{count: 3, minOffset: 0, maxOffset: 3},
			want:      true,
		},
		{
			name:      "current width uses subtraction",
			candidate: regexByteSetPrefilter{count: 3, minOffset: 0, maxOffset: 3},
			current:   regexByteSetPrefilter{count: 3, minOffset: 2, maxOffset: 3},
			want:      false,
		},
		{
			name:      "equal width falls through",
			candidate: regexByteSetPrefilter{count: 3, minOffset: 0, maxOffset: 3},
			current:   regexByteSetPrefilter{count: 3, minOffset: 1, maxOffset: 4},
			want:      true,
		},
		{
			name:      "narrower candidate wins",
			candidate: regexByteSetPrefilter{count: 3, minOffset: 0, maxOffset: 1},
			current:   regexByteSetPrefilter{count: 3, minOffset: 0, maxOffset: 3},
			want:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := betterRegexByteSetPrefilter(tt.candidate, tt.current); got != tt.want {
				t.Fatalf("betterRegexByteSetPrefilter() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSelectLeadingGapRegexPlanBounds(t *testing.T) {
	fullValues := make([]byte, maxRegexByteSetSize)
	for i := range fullValues {
		fullValues[i] = byte(i)
	}
	tests := []struct {
		name string
		plan regex.LeadingByteGapPlan
		want bool
	}{
		{
			name: "gap set at max size is accepted",
			plan: regex.LeadingByteGapPlan{
				GapSet:     regex.NewByteSet(fullValues),
				AtomGroups: [][]regex.LiteralAtom{{{Data: []byte("abcd")}}},
			},
			want: true,
		},
		{
			name: "narrow offsets with positive minimum are accepted",
			plan: regex.LeadingByteGapPlan{
				GapSet:     regex.NewByteSet([]byte{'a'}),
				AtomGroups: [][]regex.LiteralAtom{{{Data: []byte("abcd"), MinOffset: 40, MaxOffset: 60}}},
			},
			want: true,
		},
		{
			name: "offset width exactly at the limit is accepted",
			plan: regex.LeadingByteGapPlan{
				GapSet:     regex.NewByteSet([]byte{'a'}),
				AtomGroups: [][]regex.LiteralAtom{{{Data: []byte("abcd"), MinOffset: 0, MaxOffset: maxLeadingGapAtomOffsetWidth}}},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, ok := selectLeadingGapRegexPlan(tt.plan); ok != tt.want {
				t.Fatalf("selectLeadingGapRegexPlan() ok = %v, want %v", ok, tt.want)
			}
		})
	}
}

func TestSelectMandatoryRegexByteSetAtomFullSize(t *testing.T) {
	values := make([]byte, maxRegexByteSetSize)
	for i := range values {
		values[i] = byte(i)
	}
	atoms := []regex.ByteSetAtom{{Set: regex.NewByteSet(values)}}
	if _, ok := selectMandatoryRegexByteSetAtom(atoms, 0); !ok {
		t.Fatalf("byte set of exactly maxRegexByteSetSize (%d) rejected", maxRegexByteSetSize)
	}
}

func TestSelectSharedRegexAtomsPrefixLengthBoundary(t *testing.T) {
	// atomASCIINoCase is set and the atom is long enough, but the prefix is
	// exactly minPrefilterAtomLength, so the normal prefix selection must win.
	pattern := RegexPattern{
		atom:            []byte("zz"),
		atomMinOffset:   0,
		atomMaxOffset:   0,
		atomASCIINoCase: true,
		prefix:          []byte("ab"),
	}
	atoms := selectSharedRegexAtoms(pattern)
	if len(atoms) != 1 || !bytes.Equal(atoms[0].data, []byte("ab")) || atoms[0].asciiNoCase {
		t.Fatalf("selectSharedRegexAtoms = %+v, want prefix atom %q without ascii folding", atoms, "ab")
	}
}

func TestSelectSharedRegexAtomsTwoByteFallbackAtom(t *testing.T) {
	pattern := RegexPattern{atom: []byte("zz"), atomMinOffset: 1, atomMaxOffset: 1}
	atoms := selectSharedRegexAtoms(pattern)
	if len(atoms) != 1 || !bytes.Equal(atoms[0].data, []byte("zz")) || atoms[0].minOffset != 1 {
		t.Fatalf("selectSharedRegexAtoms = %+v, want atom %q at offset 1", atoms, "zz")
	}
}

func TestSelectHexAtomTieBreaks(t *testing.T) {
	equal := []HexPatternToken{
		{Kind: HexTokenByte, Value: 'a'}, {Kind: HexTokenByte, Value: 'b'},
		{Kind: HexTokenWildcard},
		{Kind: HexTokenByte, Value: 'c'}, {Kind: HexTokenByte, Value: 'd'},
	}
	atom, ok := selectHexAtom(equal)
	if !ok || !bytes.Equal(atom.data, []byte("cd")) {
		t.Fatalf("selectHexAtom(equal tie) = (%v, %v), want cd", atom, ok)
	}

	lower := []HexPatternToken{
		{Kind: HexTokenByte, Value: '0'}, {Kind: HexTokenByte, Value: 'a'},
		{Kind: HexTokenWildcard},
		{Kind: HexTokenByte, Value: 'a'}, {Kind: HexTokenByte, Value: 'a'},
	}
	atom, ok = selectHexAtom(lower)
	if !ok || !bytes.Equal(atom.data, []byte("0a")) {
		t.Fatalf("selectHexAtom(score tie) = (%v, %v), want 0a", atom, ok)
	}
}

func TestSelectHexAtomMaskedExact(t *testing.T) {
	tokens := []HexPatternToken{
		{Kind: HexTokenMasked, Mask: 0xFF, Value: 'a'},
		{Kind: HexTokenMasked, Mask: 0xFF, Value: 'b'},
	}
	atom, ok := selectHexAtom(tokens)
	if !ok || !bytes.Equal(atom.data, []byte("ab")) {
		t.Fatalf("selectHexAtom(masked) = (%v, %v), want ab", atom, ok)
	}
}

func TestSelectHexAtomZeroJumpBoundary(t *testing.T) {
	tokens := []HexPatternToken{
		{Kind: HexTokenByte, Value: 0xAA}, {Kind: HexTokenByte, Value: 0xBB},
		{Kind: HexTokenJump, Min: 0, Max: 0},
		{Kind: HexTokenByte, Value: 0xCC}, {Kind: HexTokenByte, Value: 0xDD},
	}
	atom, ok := selectHexAtom(tokens)
	if !ok || !bytes.Equal(atom.data, []byte{0xCC, 0xDD}) {
		t.Fatalf("selectHexAtom(zero jump) = (%v, %v), want CCDD", atom, ok)
	}
}

func TestSelectHexAtomAltAndFinalBoundaries(t *testing.T) {
	alt := []HexPatternToken{
		{Kind: HexTokenByte, Value: 0xAA}, {Kind: HexTokenByte, Value: 0xBB},
		{Kind: HexTokenAlt, Alternatives: [][]HexPatternToken{{{Kind: HexTokenByte, Value: 0xCC}}}},
	}
	if _, ok := selectHexAtom(alt); !ok {
		t.Fatal("2-byte run before alternative rejected")
	}
	final := []HexPatternToken{
		{Kind: HexTokenByte, Value: 0xAA}, {Kind: HexTokenByte, Value: 0xBB},
	}
	if _, ok := selectHexAtom(final); !ok {
		t.Fatal("2-byte final run rejected")
	}
}

func TestSortAndDedupeMatchSpansOrderAndBoundary(t *testing.T) {
	got := sortAndDedupeMatchSpans([]matchSpan{{Offset: 0, Length: 3}, {Offset: 0, Length: 5}})
	if len(got) != 1 || got[0].Length != 3 {
		t.Fatalf("sortAndDedupeMatchSpans = %v, want single length-3 span", got)
	}
	got = sortAndDedupeMatchSpans([]matchSpan{{Offset: 4, Length: 2}, {Offset: 4, Length: 2}})
	if len(got) != 1 {
		t.Fatalf("sortAndDedupeMatchSpans(two duplicates) = %v, want one span", got)
	}
}

func TestResetPrefilterCandidatesBounds(t *testing.T) {
	s := &Scanner{}
	s.prefilterCandidates = make([][]int, 2, 4)
	s.prefilterCandidates[0] = []int{1, 2}
	s.touchedPrefilterCandidates = []int{0, 2}
	s.resetPrefilterCandidates(2)
	if len(s.prefilterCandidates[0]) != 0 {
		t.Fatalf("candidate 0 not reset: %v", s.prefilterCandidates[0])
	}
}

// Residual gremlins survivors for atom_prefilter.go (gremlins v0.6.0,
// workers=1, timeout-coefficient=30), classified per #311:
//
// LIVED / equivalent-mode:
//
//	183:25,201:25  cacheIndex = -1 sentinel: -1 -> 1 is unobservable because
//	               callers only test cacheIndex < 0 vs an assigned index.
//	231:25,232:23, buildFixedRegexDispatch skip guards: boundary variants only
//	235:24         affect entries later dropped by the remaining checks.
//	309:31,333:36, score sentinel -1: every real atom scores >= 2, so the first
//	623:31         candidate always replaces the sentinel.
//	391:27         len(atoms) > 0 is always true when reached (each alternative
//	               must yield an atom).
//	466:28         wide maxOffset >= 0 at 0 doubles to 0.
//	475:30,483:26, unreachable boundaries guarded by the preceding != checks.
//	489:26,528:26,
//	534:26
//	563:50         atom-length guard on the fast path is shadowed by the
//	               fallback atom selection, which builds an identical atom.
//	1014:25        start >= len(data) at equality: matchLinearHexPattern returns
//	               false/zero-length, which the next guard discards.
//
// LIVED / not exercised (scanner-internal; end-to-end path is covered by
// TestSharedNonTextPrefilterMatchesLocalEngines and
// TestSharedRegexPrefilterUsesCompleteAlternativeAtomSet, which compare against
// the linear matcher):
//
//	716:17,720:51,721:65,730:16,732:18,740:56,747:49,758:24,774:16,801:23,
//	807:23,812:43  alternativeAtom group handling inside
//	               populateNonTextPrefilterCache.
//	880:25,883:30,885:59,886:28,899:16,903:9,907:32,914:21,916:13,925:64,
//	932:26,932:47  appendRegexPrefilterMatches candidate-verification bounds.
//
// NOT COVERED / unfixable-by-tests:
//
//	602:*,604:*,606:*  prefilterAtomScore `switch { case ... }` arms; Go emits
//	                   no coverage block for a case expression.
//	832:*,834:*,836:*,838:*  sortAndDedupeMatchSpans switch cases, same reason.
//	837:11             `return -1` is reached by
//	                   TestSortAndDedupeMatchSpansOrderAndBoundary; only the
//	                   case condition itself is uninstrumented.
//	703:16,708:16,712:16,741:17,787:16  touchedIndex++ in malformed-entry guard
//	                   branches not reached by the suite.
//
// TIMED OUT / non-terminating:
//
//	746:22,747:49,778:21,779:48  negated touchedIndex/groupEnd loop bounds spin
//	                   forever once the cursor cannot advance past groupEnd.
