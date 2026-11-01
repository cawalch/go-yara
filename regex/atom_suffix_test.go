package regex

import "testing"

func TestRepeatedAtomSuffixBounds(t *testing.T) {
	for _, tc := range []struct {
		pattern, atom string
		suffix        int
	}{
		{`(ab|aba)+`, "ab", -1},
		{`(ab|aba)+?`, "ab", -1},
		{`(ab|aba){2,4}`, "ab", 10},
		{`(ab){2,4}`, "ab", 6},
		{`(ab){2,4}`, "abab", 4},
		{`(ab){3}`, "ab", 4},
		{`(ab){3}`, "ababab", 0},
		{`((ab|aba){1,2}){2,3}`, "ab", 16},
		{`(a+bc){1}`, "bc", 0},
		{`(ab){2,}`, "abab", -1},
	} {
		t.Run(tc.pattern+tc.atom, func(t *testing.T) {
			parsed, err := NewParser(0).Parse(tc.pattern)
			if err != nil {
				t.Fatal(err)
			}
			for range 2 { // Cached analysis must remain immutable across calls.
				atoms := MandatoryLiteralAtoms(parsed)
				found := false
				for _, atom := range atoms {
					if string(atom.Data) == tc.atom {
						found = true
						if atom.MaxSuffix != tc.suffix {
							t.Fatalf("atom=%+v want suffix=%d", atom, tc.suffix)
						}
					}
				}
				if !found {
					t.Fatalf("missing %q: %+v", tc.atom, atoms)
				}
			}
		})
	}
}

func TestFoldedAndAlternativeAtomSuffixBounds(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		folded  bool
		suffix  int
	}{
		{`([Aa][Bb])+`, true, -1},
		{`([Aa][Bb]){2,4}ZZ`, true, 8},
		{`(ab|cd)+ZZ`, false, -1},
		{`(ab|cd){2,4}ZZ`, false, 8},
		{`(ab|cd)EF[0-9]{20}`, false, 20},
		{`((ab|cd){1,2}){2,3}ZZ`, false, 12},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			parsed, err := NewParser(0).Parse(tc.pattern)
			if err != nil {
				t.Fatal(err)
			}
			groups := RequiredLiteralAlternationAtoms(parsed, 2)
			if tc.folded {
				groups = [][]LiteralAtom{MandatoryASCIIFoldedLiteralAtoms(parsed)}
			}
			if len(groups) == 0 {
				t.Fatal("no atoms")
			}
			for _, group := range groups {
				if len(group) == 0 {
					t.Fatal("empty group")
				}
				for _, atom := range group {
					if atom.MaxSuffix != tc.suffix {
						t.Fatalf("atom=%+v want suffix=%d", atom, tc.suffix)
					}
				}
			}
		})
	}
}

func TestLiteralCoverSuffixBounds(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		suffix  int
	}{
		{`(ab|cd)+`, -1}, {`(ab|cd){2,4}`, 6},
		{`(ab|cd)[0-9]{20}`, 20}, {`((ab|cd){1,2}){2,3}`, 10},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			parsed, err := NewParser(0).Parse(tc.pattern)
			if err != nil {
				t.Fatal(err)
			}
			groups := LiteralAtomCover(parsed, 2)
			if len(groups) != 2 {
				t.Fatalf("groups=%+v", groups)
			}
			for _, group := range groups {
				for _, atom := range group {
					if atom.MaxSuffix != tc.suffix {
						t.Fatalf("atom=%+v want suffix=%d", atom, tc.suffix)
					}
				}
			}
		})
	}
}
