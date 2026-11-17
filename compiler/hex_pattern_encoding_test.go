package compiler

import (
	"bytes"
	"testing"
)

func TestHexPatternByteEncoding(t *testing.T) {
	for _, tc := range []struct {
		name, source string
		want         []byte
	}{
		{"bytes", `{ 60 E8 00 ff }`, []byte{0x60, 0xe8, 0, 0xff}},
		{"comments", "{ 41 /* ignored */ 42 // ignored\n43 }", []byte("ABC")},
		{"masks and negation", `{ 41 ~42 A? ?B ?? }`, []byte{0x41, 0x42, 0xa0, 0x0b, 0}},
		{"bounded jump", `{ 41 [1-3] 42 }`, []byte{0x41, 0xff, 1, 0, 3, 0, 0x42}},
		{"fixed jump", `{ 41 [256] 42 }`, []byte{0x41, 0xff, 0, 1, 0, 1, 0x42}},
		{"unbounded jump", `{ 41 [4-] 42 }`, []byte{0x41, 0xff, 4, 0, 0xff, 0xff, 0x42}},
		{"fully unbounded jump", `{ 41 [-] 42 }`, []byte{0x41, 0xff, 0, 0, 0xff, 0xff, 0x42}},
		{"legacy low 16 bits", `{ 41 [65536-65537] 42 }`, []byte{0x41, 0xff, 0, 0, 1, 0, 0x42}},
		{"first branch", `{ 41 ( 42 43 | 44 ) 45 }`, []byte("ABCE")},
		{"nested first branch", `{ 41 ( 42 ( 43 | 44 ) 45 | 46 ) 47 }`, []byte("ABCEG")},
		{"nested at branch start", `{ 41 ( ( 42 | 43 ) 44 | 45 ) 46 }`, []byte("ABDF")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pattern, err := newStringCompiler().parseHexPattern(tc.source)
			if err != nil {
				t.Fatal(err)
			}
			got := encodeHexPatternBytes(pattern.Tokens)
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("got %x, want %x", got, tc.want)
			}
		})
	}
}

func TestNestedHexEncodingSerialization(t *testing.T) {
	program, err := NewCompiler().CompileSource(`rule nested {
		strings: $a = { 41 ( 42 ( 43 | 44 ) 45 | 46 ) 47 }
		condition: $a
	}`)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := program.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := UnmarshalCompiledProgram(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []*CompiledProgram{program, loaded} {
		if got := p.Rules[0].GetStrings()["$a"]; !bytes.Equal(got, []byte("ABCEG")) {
			t.Fatalf("representative bytes = %x, want ABCEG", got)
		}
		for _, data := range []string{"ABCEG", "ABDEG", "AFG"} {
			matches := FindHexMatches(p.Rules[0].HexPatterns["$a"], []byte(data))
			if len(matches) != 1 || matches[0].Offset != 0 || matches[0].Length != len(data) {
				t.Fatalf("data %q: matches %v", data, matches)
			}
		}
	}
	// Older serialized programs retain their legacy summary bytes; matching
	// still uses the complete typed pattern.
	program.Rules[0].Strings["$a"] = []byte("ABG")
	encoded, err = program.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err = UnmarshalCompiledProgram(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.Rules[0].GetStrings()["$a"]; !bytes.Equal(got, []byte("ABG")) {
		t.Fatalf("legacy representative bytes = %x, want ABG", got)
	}
	matches := FindHexMatches(loaded.Rules[0].HexPatterns["$a"], []byte("ABDEG"))
	if len(matches) != 1 || matches[0].Offset != 0 || matches[0].Length != 5 {
		t.Fatalf("legacy summary changed typed matching: %v", matches)
	}
}

func TestIsHexDigit(t *testing.T) {
	tests := []struct {
		name     string
		input    byte
		expected bool
	}{
		{"digit_0", '0', true},
		{"digit_9", '9', true},
		{"lower_a", 'a', true},
		{"lower_f", 'f', true},
		{"upper_A", 'A', true},
		{"upper_F", 'F', true},
		{"non_hex_g", 'g', false},
		{"non_hex_G", 'G', false},
		{"space", ' ', false},
		{"dash", '-', false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isHexDigit(tt.input)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}
