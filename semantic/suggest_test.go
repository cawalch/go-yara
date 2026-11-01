package semantic

import (
	"strings"
	"testing"
)

func TestBoundedIdentifierDistance(t *testing.T) {
	words := []string{""}
	level := []string{""}
	for range 3 {
		var next []string
		for _, prefix := range level {
			for _, r := range "ab$λ" {
				next = append(next, prefix+string(r))
			}
		}
		words = append(words, next...)
		level = next
	}
	words = append(words, strings.Repeat("a", 80), strings.Repeat("a", 79)+"b", strings.Repeat("ab", 40), strings.Repeat("ba", 40))
	var distance identifierDistance
	for _, a := range words {
		for _, b := range words {
			want := referenceIdentifierDistance(a, b)
			for limit := 0; limit <= 3; limit++ {
				got := distance.bounded([]rune(a), []rune(b), limit)
				if got != min(want, limit+1) {
					t.Fatalf("%q/%q limit=%d: got %d want %d", a, b, limit, got, min(want, limit+1))
				}
			}
		}
	}
}

func TestIdentifierSuggestionParity(t *testing.T) {
	cases := []struct {
		target     string
		candidates []string
	}{
		{"payload", []string{"PAYLOAD", "$payload"}},
		{"$PAYLOAD", []string{"payload", "$payload"}},
		{"PAYLOAD", []string{"$payload", "payload"}},
		{"a", []string{"", "$", "b", "$a"}},
		{"$", []string{"", "a", "$$"}},
		{"café", []string{"cafe", "cafè", "CAFÉ"}},
		{"KſİΣ", []string{"ksiσ", "kſİς", "Kſİσ"}},
		{"\xffa", []string{"\xfea", "�a", "a"}},
		{strings.Repeat("a", 256), []string{strings.Repeat("a", 255) + "b", "$" + strings.Repeat("a", 256)}},
	}
	for _, target := range []string{"abc", "abcd", "abcdefg", "abcdefgh"} {
		candidates := []string{"$" + target + "x", target + "y", target + "zz", target[:len(target)-1]}
		// Exercise the existing unstable sort's ties with more than its small-sort
		// threshold; selecting the first minimum instead would change diagnostics.
		for _, r := range "xyz0123456789" {
			candidates = append(candidates, target[:len(target)-1]+string(r))
		}
		cases = append(cases, struct {
			target     string
			candidates []string
		}{target, candidates})
	}
	for _, tc := range cases {
		got, gotOK := findSimilarIdentifier(tc.target, tc.candidates)
		want, wantOK := referenceSimilarIdentifier(tc.target, tc.candidates)
		if got != want || gotOK != wantOK {
			t.Fatalf("target=%q: got %q/%v want %q/%v", tc.target, got, gotOK, want, wantOK)
		}
	}
}

func FuzzIdentifierSuggestions(f *testing.F) {
	f.Add("paylaod", "$payload\x00payload\x00filesize")
	f.Add("$PAYLOAD", "payload\x00$payload\x00PAYLOAD")
	f.Add("KſİΣ", "ksiσ\x00kſİς\x00Kſİσ")
	f.Add("\xffa", "\xfea\x00�a\x00a")
	f.Add("abcdefgh", "abcdxfgh\x00abcxefgh\x00abcdefg\x00$abcdefghx")
	f.Fuzz(func(t *testing.T, target, blob string) {
		if len(target) > 128 || len(blob) > 1024 {
			return
		}
		candidates := strings.Split(blob, "\x00")
		if len(candidates) > 32 {
			return
		}
		got, gotOK := findSimilarIdentifier(target, candidates)
		want, wantOK := referenceSimilarIdentifier(target, candidates)
		if got != want || gotOK != wantOK {
			t.Fatalf("%q %q: got %q/%v want %q/%v", target, candidates, got, gotOK, want, wantOK)
		}
	})
}
