package regex

import (
	"testing"
)

func TestLiteralSuffix(t *testing.T) {
	tests := []struct {
		pattern string
		want    string
	}{
		{"a+b", "b"},
		{".*suffix", "suffix"},
		{"prefix.*middle.*end", "end"},
		{"a?b", "b"},
		{"a|b", ""}, // alternation can match a or b
		{"a*", ""},  // optional
		{"needle", "needle"},
		{"^a+$", ""}, // ends with $
	}

	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			ast, err := NewParser(0).Parse(tt.pattern)
			if err != nil {
				t.Fatal(err)
			}
			code, err := Compile(ast)
			if err != nil {
				t.Fatal(err)
			}
			got := LiteralSuffix(code)
			if string(got) != tt.want {
				t.Fatalf("LiteralSuffix(%q) = %q, want %q", tt.pattern, got, tt.want)
			}
		})
	}
}

func TestIndexASCIIFold(t *testing.T) {
	if got := indexASCIIFold([]byte("abcDef"), []byte("dEf")); got != 3 {
		t.Fatalf("indexASCIIFold = %d, want 3", got)
	}
	if got := indexASCIIFold([]byte("abcDef"), []byte("xyz")); got != -1 {
		t.Fatalf("indexASCIIFold = %d, want -1", got)
	}
}

func TestContainsWideBytes(t *testing.T) {
	data := []byte{'h', 0, 'e', 0, 'l', 0, 'l', 0, 'o', 0}
	if !containsWideBytes(data, []byte("ell")) {
		t.Fatal("containsWideBytes failed")
	}
	if containsWideBytes(data, []byte("world")) {
		t.Fatal("containsWideBytes false positive")
	}
}

func TestNodeMaxLengthMatchesAtomAnalysis(t *testing.T) {
	patterns := []string{
		`abc`, `a.c`, `a*`, `a+`, `(ab)+`, `(a|bcd|ef)`, `a{2,5}`, `a{3,}`, `(ab){2,4}x`,
		`[a-z]{12}`, `\d+\.\d+`, `^start$`, `\bword\b`, `a.{0,32}b`, `x(y|)z`, `(a*)*`,
		`tok_[0-9a-f]{16,32}`, `a{0}`, `(?:)`, `(a|b|c|d){1,3}e*`, `.{2,}z`,
	}
	for _, pattern := range patterns {
		parsed, err := NewParser(0).Parse(pattern)
		if err != nil {
			continue
		}
		if got, want := ASTMaxLength(parsed), analyzeAtoms(parsed.Root).maxLength; got != want {
			t.Errorf("%q: ASTMaxLength = %d, analyzeAtoms = %d", pattern, got, want)
		}
	}
}
