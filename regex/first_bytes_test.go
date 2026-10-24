package regex

import (
	"strings"
	"testing"
)

func TestMandatoryByteSetAtoms(t *testing.T) {
	tests := []struct {
		pattern   string
		contains  string
		rejects   string
		count     int
		minOffset int
		maxOffset int
		want      bool
	}{
		{pattern: "[a-z]{2}", contains: "az", rejects: "A0", count: 26},
		{pattern: "a?b", contains: "b", rejects: "ac", count: 1, maxOffset: 1},
		{pattern: "a*b", contains: "b", rejects: "ac", count: 1, maxOffset: -1},
		{pattern: "a+b", contains: "a", rejects: "b", count: 1},
		{pattern: ".{2}[a-z]{2}", contains: "az", rejects: "A0", count: 26, minOffset: 2, maxOffset: 2},
		{pattern: "foo|bar", count: 2, minOffset: 2, maxOffset: 2, want: true},
		{pattern: ".*", want: false},
		{pattern: "a{0}", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			parsed, err := NewParser(ParserFlagEnableStrictEscapeSequences).Parse(tt.pattern)
			if err != nil {
				t.Fatal(err)
			}
			atoms := MandatoryByteSetAtoms(parsed)
			if !tt.want && tt.count == 0 {
				if len(atoms) != 0 {
					t.Fatalf("MandatoryByteSetAtoms(%q) = %+v, want none", tt.pattern, atoms)
				}
				return
			}
			for _, atom := range atoms {
				if atom.Set.Count() != tt.count || atom.MinOffset != tt.minOffset || atom.MaxOffset != tt.maxOffset {
					continue
				}
				for i := range len(tt.contains) {
					if !atom.Set.Contains(tt.contains[i]) {
						t.Fatalf("atom for %q does not contain %#x", tt.pattern, tt.contains[i])
					}
				}
				for i := range len(tt.rejects) {
					if atom.Set.Contains(tt.rejects[i]) {
						t.Fatalf("atom for %q unexpectedly contains %#x", tt.pattern, tt.rejects[i])
					}
				}
				return
			}
			t.Fatalf("MandatoryByteSetAtoms(%q) = %+v, missing count=%d offsets=[%d,%d]", tt.pattern, atoms, tt.count, tt.minOffset, tt.maxOffset)
		})
	}
}

func TestByteSetASCIIFolded(t *testing.T) {
	set := byteSetOf('a').ASCIIFolded()
	if !set.Contains('a') || !set.Contains('A') || set.Count() != 2 {
		t.Fatalf("folded set count=%d, a=%v, A=%v", set.Count(), set.Contains('a'), set.Contains('A'))
	}
}

func TestByteSetContiguousRange(t *testing.T) {
	set := predicateByteSet(func(value byte) bool { return value >= 'a' && value <= 'z' })
	lower, upper, ok := set.ContiguousRange()
	if !ok || lower != 'a' || upper != 'z' {
		t.Fatalf("ContiguousRange() = [%#x, %#x], %v", lower, upper, ok)
	}
	set.add('0')
	if _, _, ok := set.ContiguousRange(); ok {
		t.Fatal("disjoint set reported as contiguous")
	}
}

func TestFixedByteSets(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		flags   Flags
		counts  []int
		want    bool
	}{
		{name: "class sequence", pattern: "[ab]{2}[0-9]", counts: []int{2, 2, 10}, want: true},
		{name: "nocase negation", pattern: "[a][^b]", flags: FlagsNoCase, counts: []int{2, 254}, want: true},
		{name: "dot excludes newline", pattern: ".", counts: []int{255}, want: true},
		{name: "dotall includes newline", pattern: ".", flags: FlagsDotAll, counts: []int{256}, want: true},
		{name: "variable repeat", pattern: "[a]{2,3}", want: false},
		{name: "alternation", pattern: "a|b", want: false},
		{name: "anchor", pattern: "^[ab]", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := NewParser(ParserFlagEnableStrictEscapeSequences).Parse(tt.pattern)
			if err != nil {
				t.Fatal(err)
			}
			sets, ok := FixedByteSets(parsed, tt.flags)
			if ok != tt.want {
				t.Fatalf("FixedByteSets(%q) ok = %v, want %v", tt.pattern, ok, tt.want)
			}
			if !tt.want {
				return
			}
			if len(sets) != len(tt.counts) {
				t.Fatalf("FixedByteSets(%q) length = %d, want %d", tt.pattern, len(sets), len(tt.counts))
			}
			for index, wantCount := range tt.counts {
				if got := sets[index].Count(); got != wantCount {
					t.Fatalf("FixedByteSets(%q)[%d].Count() = %d, want %d", tt.pattern, index, got, wantCount)
				}
			}
			if tt.name == "nocase negation" {
				if !sets[0].Contains('a') || !sets[0].Contains('A') {
					t.Fatal("nocase positive class did not include both ASCII cases")
				}
				if sets[1].Contains('b') || sets[1].Contains('B') {
					t.Fatal("nocase negated class did not exclude both ASCII cases")
				}
			}
		})
	}
}

// TestByteSetContiguousRangeBoundaries pins the inclusive [0,255] endpoint
// handling in ContiguousRange. The lower/upper scan guards are only observable
// when the set's minimum or maximum member sits exactly on a byte boundary, so
// the interior ranges used elsewhere never exercise them.
func TestByteSetContiguousRangeBoundaries(t *testing.T) {
	tests := []struct {
		name  string
		set   ByteSet
		lower byte
		upper byte
		want  bool
	}{
		{name: "single zero", set: byteSetOf(0), lower: 0, upper: 0, want: true},
		{name: "single 255", set: byteSetOf(255), lower: 255, upper: 255, want: true},
		{name: "full set", set: fullByteSet(), lower: 0, upper: 255, want: true},
		{name: "zero pair", set: NewByteSet([]byte{0, 1}), lower: 0, upper: 1, want: true},
		{name: "255 pair", set: NewByteSet([]byte{254, 255}), lower: 254, upper: 255, want: true},
		{name: "disjoint endpoints", set: NewByteSet([]byte{0, 255}), want: false},
		{name: "empty", set: ByteSet{}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lower, upper, ok := tt.set.ContiguousRange()
			if ok != tt.want {
				t.Fatalf("ContiguousRange() ok = %v, want %v", ok, tt.want)
			}
			if !tt.want {
				return
			}
			if lower != tt.lower || upper != tt.upper {
				t.Fatalf("ContiguousRange() = [%#x, %#x], want [%#x, %#x]", lower, upper, tt.lower, tt.upper)
			}
		})
	}
}

// TestByteSetASCIIFoldedCaseBoundaries covers both ends of the fold loop. The
// 'z'/'Z' end is the loop bound, so a boundary mutation there silently drops
// the last letter from every folded class.
func TestByteSetASCIIFoldedCaseBoundaries(t *testing.T) {
	tests := []struct {
		name string
		set  ByteSet
	}{
		{name: "lower z", set: byteSetOf('z')},
		{name: "upper Z", set: byteSetOf('Z')},
		{name: "lower a", set: byteSetOf('a')},
		{name: "upper A", set: byteSetOf('A')},
		{name: "already folded", set: NewByteSet([]byte{'z', 'Z'})},
		{name: "non letter", set: byteSetOf('0')},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			folded := tt.set.ASCIIFolded()
			switch tt.name {
			case "lower z", "upper Z":
				if !folded.Contains('z') || !folded.Contains('Z') || folded.Count() != 2 {
					t.Fatalf("ASCIIFolded() = z:%v Z:%v count:%d, want z/Z count 2",
						folded.Contains('z'), folded.Contains('Z'), folded.Count())
				}
			case "lower a", "upper A":
				if !folded.Contains('a') || !folded.Contains('A') || folded.Count() != 2 {
					t.Fatalf("ASCIIFolded() = a:%v A:%v count:%d, want a/A count 2",
						folded.Contains('a'), folded.Contains('A'), folded.Count())
				}
			case "already folded":
				if folded.Count() != 2 {
					t.Fatalf("ASCIIFolded() count = %d, want 2", folded.Count())
				}
			case "non letter":
				if folded.Count() != 1 || !folded.Contains('0') {
					t.Fatalf("ASCIIFolded() count = %d, want unchanged single '0'", folded.Count())
				}
			}
		})
	}
}

// TestFixedByteSetsSequenceCapBoundaries pins the exact 256-byte specialization
// cap: the cap must accept a sequence of exactly maxFixedByteSetSequenceLength
// bytes and reject one byte more, and the concat/range budget arithmetic must
// reject child sets that would exceed the remaining budget.
func TestFixedByteSetsSequenceCapBoundaries(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    bool
		wantLen int
	}{
		{name: "range at cap", pattern: "a{256}", want: true, wantLen: 256},
		{name: "range over cap", pattern: "a{257}", want: false},
		{name: "range count over budget", pattern: "(abcdefghij){30}", want: false},
		{name: "concat exactly at cap", pattern: strings.Repeat("a", 254) + "(ab)", want: true, wantLen: 256},
		{name: "concat over cap via group", pattern: strings.Repeat("a", 255) + "(ab)", want: false},
		{name: "empty tail at budget zero", pattern: strings.Repeat("a", 256) + "()", want: true, wantLen: 256},
		{name: "range then empty tail", pattern: "a{256}()", want: true, wantLen: 256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := NewParser(ParserFlagEnableStrictEscapeSequences).Parse(tt.pattern)
			if err != nil {
				t.Fatal(err)
			}
			sets, ok := FixedByteSets(parsed, 0)
			if ok != tt.want {
				t.Fatalf("FixedByteSets(%d bytes) ok = %v, want %v", len(tt.pattern), ok, tt.want)
			}
			if !tt.want {
				return
			}
			if len(sets) != tt.wantLen {
				t.Fatalf("FixedByteSets(%d bytes) len = %d, want %d", len(tt.pattern), len(sets), tt.wantLen)
			}
		})
	}
}

// TestUsefulByteSetAtomSizeCap pins the inclusive maxUsefulByteSetSize bound.
func TestUsefulByteSetAtomSizeCap(t *testing.T) {
	atSize := func(n int) []byte {
		values := make([]byte, n)
		for i := range values {
			values[i] = byte(i)
		}
		return values
	}
	if got := usefulByteSetAtom(NewByteSet(atSize(maxUsefulByteSetSize))); len(got) != 1 {
		t.Fatalf("usefulByteSetAtom(%d bytes) = %d atoms, want 1", maxUsefulByteSetSize, len(got))
	}
	if got := usefulByteSetAtom(NewByteSet(atSize(maxUsefulByteSetSize + 1))); len(got) != 0 {
		t.Fatalf("usefulByteSetAtom(%d bytes) = %d atoms, want 0", maxUsefulByteSetSize+1, len(got))
	}
	if got := usefulByteSetAtom(ByteSet{}); len(got) != 0 {
		t.Fatalf("usefulByteSetAtom(empty) = %d atoms, want 0", len(got))
	}
}

// TestMaskedByteSet pins masked-literal set expansion, including the all-zero
// mask edge where every candidate matches.
func TestMaskedByteSet(t *testing.T) {
	set := maskedByteSet(0xA0, 0xF0, false)
	if set.Count() != 16 {
		t.Fatalf("maskedByteSet(0xA0, 0xF0, false).Count() = %d, want 16", set.Count())
	}
	for value := 0xA0; value <= 0xAF; value++ {
		if !set.Contains(byte(value)) {
			t.Fatalf("maskedByteSet(0xA0, 0xF0, false) missing %#x", value)
		}
	}
	if set.Contains(0xB0) {
		t.Fatal("maskedByteSet(0xA0, 0xF0, false) unexpectedly contains 0xB0")
	}

	negated := maskedByteSet(0xA0, 0xF0, true)
	if negated.Count() != 240 {
		t.Fatalf("maskedByteSet(0xA0, 0xF0, true).Count() = %d, want 240", negated.Count())
	}
	if negated.Contains(0xA5) {
		t.Fatal("maskedByteSet(0xA0, 0xF0, true) unexpectedly contains 0xA5")
	}

	if got := maskedByteSet(0x00, 0x00, false).Count(); got != 256 {
		t.Fatalf("maskedByteSet zero mask .Count() = %d, want 256", got)
	}
	if got := maskedByteSet(0x00, 0x00, true).Count(); got != 0 {
		t.Fatalf("maskedByteSet zero mask negated .Count() = %d, want 0", got)
	}
}

func TestFirstByteSet(t *testing.T) {
	tests := []struct {
		pattern  string
		flags    Flags
		wantOK   bool
		contains []byte
		rejects  []byte
		count    int
	}{
		{pattern: "foo", wantOK: true, contains: []byte{'f'}, rejects: []byte{'o', 'b'}, count: 1},
		{pattern: "foo|bar", wantOK: true, contains: []byte{'f', 'b'}, rejects: []byte{'o', 'a'}, count: 2},
		{pattern: "[0-9]+", wantOK: true, contains: []byte{'0', '5', '9'}, rejects: []byte{'a', 'Z'}, count: 10},
		{pattern: `\w+`, wantOK: true, contains: []byte{'a', 'Z', '0', '_'}, rejects: []byte{' ', '-', '.'}},
		{pattern: `\s*abc`, wantOK: true, contains: []byte{' ', '\t', 'a'}, rejects: []byte{'b', 'c', 'z'}},
		{pattern: "^abc", wantOK: true, contains: []byte{'a'}, rejects: []byte{'b', '^'}, count: 1},
		{pattern: "abc", flags: FlagsNoCase, wantOK: true, contains: []byte{'a', 'A'}, rejects: []byte{'b', 'B'}, count: 2},
		{pattern: "a*", wantOK: false},
		{pattern: "(foo)?", wantOK: false},
		{pattern: ".*foo", wantOK: false},
		{pattern: "a{0,2}b", wantOK: true, contains: []byte{'a', 'b'}, rejects: []byte{'c'}, count: 2},
	}

	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			parsed, err := NewParser(ParserFlagEnableStrictEscapeSequences).Parse(tt.pattern)
			if err != nil {
				t.Fatal(err)
			}
			set, ok := FirstByteSet(parsed, tt.flags)
			if ok != tt.wantOK {
				t.Fatalf("FirstByteSet(%q) ok = %v, want %v", tt.pattern, ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if tt.count > 0 && set.Count() != tt.count {
				t.Fatalf("FirstByteSet(%q) count = %d, want %d", tt.pattern, set.Count(), tt.count)
			}
			for _, b := range tt.contains {
				if !set.Contains(b) {
					t.Fatalf("FirstByteSet(%q) missing %#x", tt.pattern, b)
				}
			}
			for _, b := range tt.rejects {
				if set.Contains(b) {
					t.Fatalf("FirstByteSet(%q) unexpectedly contains %#x", tt.pattern, b)
				}
			}
		})
	}
}

func TestReversePrefixAnalysis(t *testing.T) {
	parser := NewParser(ParserFlagEnableStrictEscapeSequences)

	t.Run("class repeat directly preceding atom", func(t *testing.T) {
		parsed, err := parser.Parse("prefix[0-9]{2,10}needle")
		if err != nil {
			t.Fatal(err)
		}
		info := ReversePrefixAnalysis(parsed, []byte("needle"), 0)
		if !info.HasPrecedingByteSet || !info.PrecedingByteSet.Contains('5') || info.PrecedingByteSet.Contains('a') {
			t.Fatalf("PrecedingByteSet = %+v, want [0-9]", info.PrecedingByteSet)
		}
		if !info.HasPrefixRepeat || info.PrefixRepeatMin != 2 || info.PrefixRepeatMax != 10 {
			t.Fatalf("PrefixRepeat = %+v, want min=2 max=10", info)
		}
		if len(info.ExactPrefixSuffix) != 0 {
			t.Fatalf("ExactPrefixSuffix = %q, want empty", info.ExactPrefixSuffix)
		}
	})

	t.Run("exact prefix preceding atom", func(t *testing.T) {
		parsed, err := parser.Parse("prefix_xyz_needle")
		if err != nil {
			t.Fatal(err)
		}
		info := ReversePrefixAnalysis(parsed, []byte("needle"), 0)
		if !info.HasPrecedingByteSet || !info.PrecedingByteSet.Contains('_') || info.PrecedingByteSet.Contains('z') {
			t.Fatalf("PrecedingByteSet = %+v, want '_'", info.PrecedingByteSet)
		}
		if string(info.ExactPrefixSuffix) != "prefix_xyz_" {
			t.Fatalf("ExactPrefixSuffix = %q, want 'prefix_xyz_'", string(info.ExactPrefixSuffix))
		}
		if info.HasPrefixRepeat {
			t.Fatal("unexpected prefix repeat")
		}
	})

	t.Run("repeat then exact prefix preceding atom", func(t *testing.T) {
		parsed, err := parser.Parse("prefix[0-9]{3,8}_test")
		if err != nil {
			t.Fatal(err)
		}
		info := ReversePrefixAnalysis(parsed, []byte("test"), 0)
		if !info.HasPrecedingByteSet || !info.PrecedingByteSet.Contains('_') {
			t.Fatalf("PrecedingByteSet = %+v, want '_'", info.PrecedingByteSet)
		}
		if string(info.ExactPrefixSuffix) != "_" {
			t.Fatalf("ExactPrefixSuffix = %q, want '_'", string(info.ExactPrefixSuffix))
		}
		if !info.HasPrefixRepeat || info.PrefixRepeatMin != 3 || info.PrefixRepeatMax != 8 {
			t.Fatalf("PrefixRepeat = %+v, want min=3 max=8", info)
		}
		if !info.PrefixRepeatClass.Contains('7') || info.PrefixRepeatClass.Contains('x') {
			t.Fatalf("PrefixRepeatClass does not match digits")
		}
	})

	t.Run("plus repeat preceding atom", func(t *testing.T) {
		parsed, err := parser.Parse("[a-z]+needle")
		if err != nil {
			t.Fatal(err)
		}
		info := ReversePrefixAnalysis(parsed, []byte("needle"), 0)
		if !info.HasPrecedingByteSet || !info.PrecedingByteSet.Contains('m') {
			t.Fatalf("PrecedingByteSet = %+v, want [a-z]", info.PrecedingByteSet)
		}
		if !info.HasPrefixRepeat || info.PrefixRepeatMin != 1 || info.PrefixRepeatMax != -1 {
			t.Fatalf("PrefixRepeat = %+v, want min=1 max=-1", info)
		}
	})

	t.Run("atom at pattern start has no prefix", func(t *testing.T) {
		parsed, err := parser.Parse("needle[0-9]+")
		if err != nil {
			t.Fatal(err)
		}
		info := ReversePrefixAnalysis(parsed, []byte("needle"), 0)
		if info.HasPrecedingByteSet || info.HasPrefixRepeat || len(info.ExactPrefixSuffix) > 0 {
			t.Fatalf("info = %+v, want all empty", info)
		}
	})

	t.Run("disambiguate repeated atoms with minOffset", func(t *testing.T) {
		parsed, err := parser.Parse("foo_needle_bar_needle")
		if err != nil {
			t.Fatal(err)
		}
		// First atom "needle" has minOffset = 4 ("foo_")
		first := ReversePrefixAnalysisWithOffset(parsed, []byte("needle"), 4, 0)
		if string(first.ExactPrefixSuffix) != "foo_" {
			t.Fatalf("first ExactPrefixSuffix = %q, want 'foo_'", string(first.ExactPrefixSuffix))
		}
		// Second atom "needle" has minOffset = 15 ("foo_needle_bar_")
		second := ReversePrefixAnalysisWithOffset(parsed, []byte("needle"), 15, 0)
		if string(second.ExactPrefixSuffix) != "foo_needle_bar_" {
			t.Fatalf("second ExactPrefixSuffix = %q, want 'foo_needle_bar_'", string(second.ExactPrefixSuffix))
		}
	})
}

// Mutation-test classification for regex/first_bytes.go (gremlins v0.6.0,
// --workers 1). After this hardening pass: 63 killed, 9 lived, 2 timed out,
// 0 not covered (100% mutant coverage).
//
// Equivalent-mode survivors (no test can distinguish them):
//   - ContiguousRange 67:12 / 71:12 (lower < 256, upper >= 0): a non-empty set
//     always has a member in [0,255], so both scans terminate inside the byte
//     range before the guard bound can matter.
//   - fixedByteSets 124:58 / 125:40 (remaining-len(sets) -> remaining+len):
//     the child-budget invariant (a successful child never returns more than
//     its budget) makes the inflated budget and the widened comparison
//     unobservable; the explicit length guard at line 125 rejects overflow.
//   - NodeRange 143:44 (len(childSets)*count in make cap): slice capacity is
//     not observable.
//   - predicateByteSet 264:24 / maskedByteSet 253:32 (value < 256 -> <=): the
//     extra iteration only re-tests byte(0), which is idempotent for a set add.
//
// Non-terminating mutants (gremlins TIMED OUT, not test gaps, not defects):
//   - predicateByteSet 264:36 and maskedByteSet 253:48 (value++ -> value--):
//     the loop counter runs negative forever.
