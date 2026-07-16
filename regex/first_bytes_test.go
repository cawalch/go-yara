package regex

import "testing"

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
