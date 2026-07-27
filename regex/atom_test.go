package regex

import (
	"slices"
	"testing"
)

func TestMandatoryLiteralAtoms(t *testing.T) {
	tests := []struct {
		name      string
		pattern   string
		data      string
		minOffset int
		maxOffset int
	}{
		{name: "bounded class prefix", pattern: "[a-z]{1,8}family_marker", data: "family_marker", minOffset: 1, maxOffset: 8},
		{name: "bounded any prefix", pattern: ".{0,8}family_marker", data: "family_marker", minOffset: 0, maxOffset: 8},
		{name: "unbounded prefix", pattern: ".*family_marker", data: "family_marker", minOffset: 0, maxOffset: -1},
		{name: "variable literal prefix", pattern: "x{2,4}family_marker", data: "family_marker", minOffset: 2, maxOffset: 4},
		{name: "alternation before tail", pattern: "(x|long)family_marker", data: "family_marker", minOffset: 1, maxOffset: 4},
		{name: "common alternation atom", pattern: "alpha_marker|beta_marker", data: "a_marker", minOffset: 3, maxOffset: 4},
		{name: "required repeat", pattern: "[0-9](ab)+[A-Z]", data: "ab", minOffset: 1, maxOffset: 1},
		{name: "fixed repeat joins literal", pattern: "[0-9]ab{2}cd", data: "abbcd", minOffset: 1, maxOffset: 1},
		{name: "singleton class repeat", pattern: "[a]{2}[0-9]", data: "aa", minOffset: 0, maxOffset: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := NewParser(ParserFlagEnableStrictEscapeSequences).Parse(tt.pattern)
			if err != nil {
				t.Fatal(err)
			}
			atoms := MandatoryLiteralAtoms(parsed)
			for _, atom := range atoms {
				if string(atom.Data) == tt.data && atom.MinOffset == tt.minOffset && atom.MaxOffset == tt.maxOffset {
					return
				}
			}
			t.Fatalf("MandatoryLiteralAtoms(%q) = %+v, missing %q at [%d,%d]", tt.pattern, atoms, tt.data, tt.minOffset, tt.maxOffset)
		})
	}
}

func TestMandatoryLiteralAtomsRejectsOptionalLiterals(t *testing.T) {
	patterns := []string{
		"(family_marker)?",
		"family_marker|unrelated",
		"[a-z]+",
		".*",
	}
	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			parsed, err := NewParser(ParserFlagEnableStrictEscapeSequences).Parse(pattern)
			if err != nil {
				t.Fatal(err)
			}
			atoms := MandatoryLiteralAtoms(parsed)
			for _, atom := range atoms {
				if len(atom.Data) >= 2 {
					t.Fatalf("MandatoryLiteralAtoms(%q) returned unsafe atom %+v", pattern, atom)
				}
			}
		})
	}
}

func TestMandatoryLiteralAtomsDoesNotMutateResults(t *testing.T) {
	parsed, err := NewParser(ParserFlagEnableStrictEscapeSequences).Parse("[a-z]{1,8}family_marker")
	if err != nil {
		t.Fatal(err)
	}
	first := MandatoryLiteralAtoms(parsed)
	second := MandatoryLiteralAtoms(parsed)
	if !slices.EqualFunc(first, second, func(left, right LiteralAtom) bool {
		return slices.Equal(left.Data, right.Data) && left.MinOffset == right.MinOffset && left.MaxOffset == right.MaxOffset
	}) {
		t.Fatalf("analysis changed between calls: first=%+v second=%+v", first, second)
	}
}

func TestMandatoryASCIIFoldedLiteralAtoms(t *testing.T) {
	tests := []struct {
		name      string
		pattern   string
		data      string
		minOffset int
		maxOffset int
	}{
		{
			name:      "pure case-pair run",
			pattern:   `"[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]":`,
			data:      "password",
			minOffset: 1,
			maxOffset: 1,
		},
		{
			name:      "variable required prefix",
			pattern:   `(x|long)[Pp][Aa][Ss][Ss]`,
			data:      "pass",
			minOffset: 1,
			maxOffset: 4,
		},
		{
			name:      "required repeat",
			pattern:   `([Aa][Bb])+`,
			data:      "ab",
			minOffset: 0,
			maxOffset: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := NewParser(ParserFlagEnableStrictEscapeSequences).Parse(test.pattern)
			if err != nil {
				t.Fatal(err)
			}
			atoms := MandatoryASCIIFoldedLiteralAtoms(parsed)
			for _, atom := range atoms {
				if string(atom.Data) == test.data &&
					atom.MinOffset == test.minOffset &&
					atom.MaxOffset == test.maxOffset {
					return
				}
			}
			t.Fatalf(
				"MandatoryASCIIFoldedLiteralAtoms(%q) = %+v, missing %q at [%d,%d]",
				test.pattern,
				atoms,
				test.data,
				test.minOffset,
				test.maxOffset,
			)
		})
	}
}

func TestMandatoryASCIIFoldedLiteralAtomsRejectsUnsafeRuns(t *testing.T) {
	for _, pattern := range []string{
		`[Pp0][Aa][Ss][Ss][Ww][Oo][Rr][Dd]`,
		`([Pp][Aa][Ss][Ss])?`,
		`([Pp][Aa][Ss][Ss]|other)`,
		`[^Pp][Aa][Ss][Ss]`,
	} {
		t.Run(pattern, func(t *testing.T) {
			parsed, err := NewParser(ParserFlagEnableStrictEscapeSequences).Parse(pattern)
			if err != nil {
				t.Fatal(err)
			}
			for _, atom := range MandatoryASCIIFoldedLiteralAtoms(parsed) {
				if len(atom.Data) >= 2 {
					t.Fatalf(
						"MandatoryASCIIFoldedLiteralAtoms(%q) returned unsafe atom %+v",
						pattern,
						atom,
					)
				}
			}
		})
	}
}

func TestLiteralAlternatives(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    []string
	}{
		{name: "nested alternation", pattern: "(cardholder|nameoncard|expiry|expiration)\\b", want: []string{"cardholder", "nameoncard", "expiry", "expiration"}},
		{name: "leading assertion", pattern: "\\b(foo|bar)", want: []string{"foo", "bar"}},
		{name: "singleton classes", pattern: "(foo|[b][a][r])", want: []string{"foo", "bar"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := NewParser(ParserFlagEnableStrictEscapeSequences).Parse(tt.pattern)
			if err != nil {
				t.Fatal(err)
			}
			got := LiteralAlternatives(parsed)
			if len(got) != len(tt.want) {
				t.Fatalf("LiteralAlternatives(%q) = %+v, want %v", tt.pattern, got, tt.want)
			}
			for index, want := range tt.want {
				if string(got[index].Data) != want || got[index].MinOffset != 0 || got[index].MaxOffset != 0 {
					t.Errorf("alternative %d = %+v, want %q at [0,0]", index, got[index], want)
				}
			}
		})
	}
}

func TestLiteralAlternativesRejectsIncompleteCoverage(t *testing.T) {
	patterns := []string{
		"prefix(foo|bar)",
		"(foo|bar)suffix",
		"(foo|b.r)",
		"(foo|)",
		"foo",
	}
	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			parsed, err := NewParser(ParserFlagEnableStrictEscapeSequences).Parse(pattern)
			if err != nil {
				t.Fatal(err)
			}
			if got := LiteralAlternatives(parsed); got != nil {
				t.Fatalf("LiteralAlternatives(%q) = %+v, want nil", pattern, got)
			}
		})
	}
}

func TestAlternativeMandatoryLiteralAtoms(t *testing.T) {
	parsed, err := NewParser(ParserFlagEnableStrictEscapeSequences).Parse(
		"(cardholder|card[-_ ]?holder|nameoncard|name[-_ ]on[-_ ]card)\\b",
	)
	if err != nil {
		t.Fatal(err)
	}
	alternatives := AlternativeMandatoryLiteralAtoms(parsed)
	if len(alternatives) != 4 {
		t.Fatalf("alternative groups = %+v, want 4", alternatives)
	}
	foundVariableOffset := false
	for branch, atoms := range alternatives {
		foundUseful := false
		for _, atom := range atoms {
			if len(atom.Data) >= 2 && atom.MaxOffset >= 0 {
				foundUseful = true
			}
			if atom.MaxOffset > atom.MinOffset {
				foundVariableOffset = true
			}
		}
		if !foundUseful {
			t.Errorf("branch %d has no useful bounded atom: %+v", branch, atoms)
		}
	}
	if !foundVariableOffset {
		t.Fatal("expected at least one variable-offset branch atom")
	}
}

func TestAlternativeMandatoryLiteralAtomsRequiresEveryBranch(t *testing.T) {
	for _, pattern := range []string{
		"prefix(foo|bar)",
		"(foo|bar)suffix",
		"(foo|[a-z]+)",
		"foo",
	} {
		t.Run(pattern, func(t *testing.T) {
			parsed, err := NewParser(ParserFlagEnableStrictEscapeSequences).Parse(pattern)
			if err != nil {
				t.Fatal(err)
			}
			if got := AlternativeMandatoryLiteralAtoms(parsed); got != nil {
				t.Fatalf("AlternativeMandatoryLiteralAtoms(%q) = %+v, want nil", pattern, got)
			}
		})
	}
}

func TestLiteralAtomCoverFindsRequiredNestedAlternation(t *testing.T) {
	tests := []struct {
		name      string
		pattern   string
		want      []string
		minOffset int
		maxOffset int
	}{
		{
			name:      "unbounded leading class",
			pattern:   `["'#.\[]\s*(cardnumber|cvv|cardholder)\b`,
			want:      []string{"cardnumber", "cvv", "cardholder"},
			minOffset: 1,
			maxOffset: -1,
		},
		{
			name:      "required repeat",
			pattern:   `(alpha|beta)+`,
			want:      []string{"alpha", "beta"},
			maxOffset: 0,
		},
		{
			name:      "prefer bounded required sibling",
			pattern:   `(alpha|beta).*(gamma|delta)`,
			want:      []string{"alpha", "beta"},
			maxOffset: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := NewParser(ParserFlagEnableStrictEscapeSequences).Parse(tt.pattern)
			if err != nil {
				t.Fatal(err)
			}
			cover := LiteralAtomCover(parsed, 2)
			if len(cover) != len(tt.want) {
				t.Fatalf("LiteralAtomCover(%q) = %+v, want %v", tt.pattern, cover, tt.want)
			}
			for index, want := range tt.want {
				found := false
				for _, atom := range cover[index] {
					if string(atom.Data) == want && atom.MinOffset == tt.minOffset && atom.MaxOffset == tt.maxOffset {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("group %d = %+v, missing %q at [%d,%d]", index, cover[index], want, tt.minOffset, tt.maxOffset)
				}
			}
		})
	}
}

func TestLiteralAtomCoverRejectsOptionalOrIncompleteBranches(t *testing.T) {
	for _, pattern := range []string{
		`(alpha|beta)?`,
		`(alpha|[a-z]+)`,
		`[a-z]*`,
	} {
		t.Run(pattern, func(t *testing.T) {
			parsed, err := NewParser(ParserFlagEnableStrictEscapeSequences).Parse(pattern)
			if err != nil {
				t.Fatal(err)
			}
			if cover := LiteralAtomCover(parsed, 2); cover != nil {
				t.Fatalf("LiteralAtomCover(%q) = %+v, want nil", pattern, cover)
			}
		})
	}
}

func TestRequiredLiteralAlternationAtomsPreservesNestedBranches(t *testing.T) {
	parsed, err := NewParser(ParserFlagEnableStrictEscapeSequences).Parse(
		`"(phone|phone_number|mobile)":"[0-9]{7}"`,
	)
	if err != nil {
		t.Fatal(err)
	}
	alternatives := RequiredLiteralAlternationAtoms(parsed, 2)
	if len(alternatives) != 3 {
		t.Fatalf("required alternation groups = %+v, want 3", alternatives)
	}
	for index, want := range []string{"phone", "phone_number", "mobile"} {
		found := false
		for _, atom := range alternatives[index] {
			if string(atom.Data) == want && atom.MinOffset == 1 && atom.MaxOffset == 1 {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("group %d = %+v, missing %q at [1,1]", index, alternatives[index], want)
		}
	}
}

func TestRequiredLiteralAlternationAtomsRejectsIncompleteBranches(t *testing.T) {
	for _, pattern := range []string{
		`(phone|)`,
		`(a|mobile)`,
		`(phone|[a-z]+)`,
		`(phone|mobile)?`,
	} {
		t.Run(pattern, func(t *testing.T) {
			parsed, err := NewParser(ParserFlagEnableStrictEscapeSequences).Parse(pattern)
			if err != nil {
				t.Fatal(err)
			}
			if got := RequiredLiteralAlternationAtoms(parsed, 2); got != nil {
				t.Fatalf("RequiredLiteralAlternationAtoms(%q) = %+v, want nil", pattern, got)
			}
		})
	}
}
