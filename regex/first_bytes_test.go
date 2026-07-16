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
