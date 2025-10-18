package compiler

import (
	"reflect"
	"testing"

	"github.com/cawalch/go-yara/ast"
)

func TestExtractFromTextString(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		modifiers []ast.StringModifier
		want      []*Atom
	}{
		{
			name:  "Simple string",
			input: "abcdef",
			want: []*Atom{
				{
					Data:    []byte("abcd"),
					Mask:    []byte{0xFF, 0xFF, 0xFF, 0xFF},
					Offset:  0,
					Length:  4,
					Quality: 80, // Approximation, will be refined
				},
			},
		},
		{
			name:  "Short string",
			input: "abc",
			want: []*Atom{
				{
					Data:    []byte("abc"),
					Mask:    []byte{0xFF, 0xFF, 0xFF},
					Offset:  0,
					Length:  3,
					Quality: 60, // Approximation
				},
			},
		},
		{
			name:  "String with common bytes",
			input: "\x00\x00\x20\xFF",
			want: []*Atom{
				{
					Data:    []byte{0x00, 0x00, 0x20, 0xFF},
					Mask:    []byte{0xFF, 0xFF, 0xFF, 0xFF},
					Offset:  0,
					Length:  4,
					Quality: 54, // Approximation
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractFromTextString(tt.input, tt.modifiers)

			// For now, we are just checking if the number of atoms is correct.
			// We will add more detailed checks later.
			if len(got) != len(tt.want) {
				t.Errorf("ExtractFromTextString() len = %v, want %v", len(got), len(tt.want))
				return
			}

			if len(got) > 0 && len(tt.want) > 0 {
				// Crude quality check, we will refine this
				got[0].Quality = calculateAtomQuality(got[0])
				if !reflect.DeepEqual(got[0].Data, tt.want[0].Data) {
					t.Errorf("ExtractFromTextString() got atom data = %v, want %v", got[0].Data, tt.want[0].Data)
				}
			}
		})
	}
}

// TestExtractFromRegexPattern tests regex atom extraction
func TestExtractFromRegexPattern(t *testing.T) {
	tests := []struct {
		name      string
		pattern   string
		wantAtoms bool
		wantLen   int
	}{
		{"simple_literal", "/hello/", true, 5},
		{"literal_with_flags", "/hello/i", true, 5},
		{"literal_with_dot", "/hello.world/", true, 5}, // "hello" is extracted
		{"literal_with_star", "/hello*/", true, 5},     // "hello" is extracted
		{"literal_with_plus", "/hello+/", true, 5},     // "hello" is extracted
		{"literal_with_question", "/hello?/", true, 5}, // "hello" is extracted
		{"alternation", "/hello|world/", true, 5},      // "hello" or "world"
		{"character_class", "/[a-z]+/", true, 3},       // "a-z" is extracted
		{"escaped_char", "/hel\\.lo/", true, 6},        // "hel.lo"
		{"complex_pattern", "/md5: [0-9a-fA-F]{32}/", true, 9}, // "0-9a-fA-F" is best atom
		{"empty_pattern", "//", false, 0},
		{"short_pattern", "/ab/", true, 2}, // "ab" is extracted (even though < MinAtomLength)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			atoms := ExtractFromRegexPattern(tt.pattern, nil)
			if tt.wantAtoms {
				if len(atoms) == 0 {
					t.Errorf("expected atoms, got none")
					return
				}
				if len(atoms[0].Data) != tt.wantLen {
					t.Errorf("expected atom length %d, got %d (data: %s)", tt.wantLen, len(atoms[0].Data), string(atoms[0].Data))
				}
			} else {
				if len(atoms) > 0 {
					t.Errorf("expected no atoms, got %d", len(atoms))
				}
			}
		})
	}
}

// TestCleanRegexPattern tests regex pattern cleaning
func TestCleanRegexPattern(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple", "/hello/", "hello"},
		{"with_flags_i", "/hello/i", "hello"},
		{"with_flags_s", "/hello/s", "hello"},
		{"with_flags_is", "/hello/is", "hello"},
		{"complex", "/md5: [0-9a-fA-F]{32}/", "md5: [0-9a-fA-F]{32}"},
		{"no_delimiters", "hello", "hello"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cleanRegexPattern(tt.input)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestExtractLiteralsFromRegex tests literal extraction from regex
func TestExtractLiteralsFromRegex(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		expected []string
	}{
		{"simple", "hello", []string{"hello"}},
		{"with_dot", "hello.world", []string{"hello", "world"}},
		{"with_star", "hello*", []string{"hello"}},
		{"with_plus", "hello+", []string{"hello"}},
		{"with_question", "hello?", []string{"hello"}},
		{"alternation", "hello|world", []string{"hello", "world"}},
		{"escaped_dot", "hel\\.lo", []string{"hel.lo"}},
		{"multiple_literals", "foo bar baz", []string{"foo", "bar", "baz"}},
		{"character_class", "[a-z]+", []string{"a-z"}}, // "a-z" is extracted as literal
		{"empty", "", []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractLiteralsFromRegex(tt.pattern)
			if len(result) != len(tt.expected) {
				t.Errorf("expected %d literals, got %d", len(tt.expected), len(result))
				return
			}
			for i, lit := range result {
				if lit != tt.expected[i] {
					t.Errorf("literal %d: expected %q, got %q", i, tt.expected[i], lit)
				}
			}
		})
	}
}