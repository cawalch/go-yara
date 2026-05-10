package compiler

import (
	"testing"
)

func TestHexPatternMatching(t *testing.T) {
	sc := NewStringCompiler(NewEmitter())
	tests := []struct {
		name    string
		pattern string
		data    []byte
		expect  int
	}{
		{
			name:    "wildcard",
			pattern: "{ 41 ?? 43 }",
			data:    []byte{0x41, 0x99, 0x43},
			expect:  1,
		},
		{
			name:    "masked",
			pattern: "{ A? }",
			data:    []byte{0xAF},
			expect:  1,
		},
		{
			name:    "jump",
			pattern: "{ 41 [1-2] 43 }",
			data:    []byte{0x41, 0x99, 0x43},
			expect:  1,
		},
		{
			name:    "alternative",
			pattern: "{ 41 ( 42 | 43 ) }",
			data:    []byte{0x41, 0x43},
			expect:  1,
		},
		{
			name:    "xor_single_key",
			pattern: "{ 41 42 }",
			data:    []byte{0x40, 0x43},
			expect:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hexPattern, err := sc.parseHexPattern(tt.pattern)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if tt.name == "xor_single_key" {
				hexPattern.XorKeys = []byte{0x01}
			}
			matches := FindHexMatches(hexPattern, tt.data)
			if len(matches) != tt.expect {
				t.Fatalf("matches %d, want %d", len(matches), tt.expect)
			}
		})
	}
}

// generateData creates a byte slice of the given size with deterministic content.
func generateData(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % 251) // prime for variety
	}
	return data
}

// BenchmarkFindHexMatches_Simple benchmarks a simple 4-byte literal pattern.
func BenchmarkFindHexMatches_Simple(b *testing.B) {
	sc := NewStringCompiler(NewEmitter())
	pat, _ := sc.parseHexPattern("{ DE AD BE EF }")
	data := generateData(100_000)

	b.ResetTimer()
	for b.Loop() {
		FindHexMatches(pat, data)
	}
}

// BenchmarkFindHexMatches_Jump benchmarks a pattern with a jump (variable gap).
func BenchmarkFindHexMatches_Jump(b *testing.B) {
	sc := NewStringCompiler(NewEmitter())
	pat, _ := sc.parseHexPattern("{ 0A 0B [2-4] 0C 0D }")
	data := generateData(100_000)

	b.ResetTimer()
	for b.Loop() {
		FindHexMatches(pat, data)
	}
}

// BenchmarkFindHexMatches_Alt benchmarks a pattern with alternatives.
func BenchmarkFindHexMatches_Alt(b *testing.B) {
	sc := NewStringCompiler(NewEmitter())
	pat, _ := sc.parseHexPattern("{ 0A ( 1A | 2A | 3A ) 0B }")
	data := generateData(100_000)

	b.ResetTimer()
	for b.Loop() {
		FindHexMatches(pat, data)
	}
}

// BenchmarkFindHexMatches_Wildcard benchmarks a pattern with wildcards.
func BenchmarkFindHexMatches_Wildcard(b *testing.B) {
	sc := NewStringCompiler(NewEmitter())
	pat, _ := sc.parseHexPattern("{ 0A ?? ?? 0B }")
	data := generateData(100_000)

	b.ResetTimer()
	for b.Loop() {
		FindHexMatches(pat, data)
	}
}

// BenchmarkFindHexMatches_Xor benchmarks XOR matching with a single key.
func BenchmarkFindHexMatches_Xor(b *testing.B) {
	sc := NewStringCompiler(NewEmitter())
	pat, _ := sc.parseHexPattern("{ DE AD BE EF }")
	pat.XorKeys = []byte{0x42}
	data := generateData(100_000)

	b.ResetTimer()
	for b.Loop() {
		FindHexMatches(pat, data)
	}
}

// BenchmarkFindHexMatches_XorWide benchmarks XOR matching with 256 keys.
func BenchmarkFindHexMatches_XorWide(b *testing.B) {
	sc := NewStringCompiler(NewEmitter())
	pat, _ := sc.parseHexPattern("{ DE AD BE EF }")
	keys := make([]byte, 256)
	for i := range keys {
		keys[i] = byte(i)
	}
	pat.XorKeys = keys
	data := generateData(100_000)

	b.ResetTimer()
	for b.Loop() {
		FindHexMatches(pat, data)
	}
}

// BenchmarkFindHexMatches_NoAnchor benchmarks a pattern with no anchor byte
// (wildcard-only prefix), forcing brute-force fallback.
func BenchmarkFindHexMatches_NoAnchor(b *testing.B) {
	sc := NewStringCompiler(NewEmitter())
	pat, _ := sc.parseHexPattern("{ ?? ?? DE AD }")
	data := generateData(100_000)

	b.ResetTimer()
	for b.Loop() {
		FindHexMatches(pat, data)
	}
}

// BenchmarkFindHexMatches_Complex benchmarks a realistic complex hex pattern.
func BenchmarkFindHexMatches_Complex(b *testing.B) {
	sc := NewStringCompiler(NewEmitter())
	pat, _ := sc.parseHexPattern("{ 50 45 00 00 [0-2] 4C 01 }")
	data := generateData(100_000)

	b.ResetTimer()
	for b.Loop() {
		FindHexMatches(pat, data)
	}
}

// TestFindHexMatchesAdditional tests edge cases for the optimized matcher.
func TestFindHexMatchesAdditional(t *testing.T) {
	sc := NewStringCompiler(NewEmitter())

	tests := []struct {
		name    string
		pattern string
		xorKeys []byte
		data    []byte
		expect  int
	}{
		{
			name:    "no_match_in_data",
			pattern: "{ DE AD BE EF }",
			data:    []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
			expect:  0,
		},
		{
			name:    "match_at_start",
			pattern: "{ 41 42 43 }",
			data:    []byte{0x41, 0x42, 0x43, 0x00, 0x00},
			expect:  1,
		},
		{
			name:    "match_at_end",
			pattern: "{ 41 42 43 }",
			data:    []byte{0x00, 0x00, 0x41, 0x42, 0x43},
			expect:  1,
		},
		{
			name:    "multiple_matches",
			pattern: "{ 41 42 }",
			data:    []byte{0x41, 0x42, 0x00, 0x41, 0x42},
			expect:  2,
		},
		{
			name:    "wildcard_prefix_no_anchor",
			pattern: "{ ?? 41 42 }",
			data:    []byte{0xFF, 0x41, 0x42, 0x00},
			expect:  1,
		},
		{
			name:    "xor_match",
			pattern: "{ 41 42 }",
			xorKeys: []byte{0x01},
			data:    []byte{0x40, 0x43},
			expect:  1,
		},
		{
			name:    "xor_no_match",
			pattern: "{ DE AD }",
			xorKeys: []byte{0x42},
			data:    []byte{0x00, 0x01, 0x02},
			expect:  0,
		},
		{
			name:    "nested_alt",
			pattern: "{ 41 ( 42 | 43 ) ( 44 | 45 ) }",
			data:    []byte{0x41, 0x43, 0x45},
			expect:  1,
		},
		{
			name:    "jump_zero",
			pattern: "{ 41 [0-1] 42 }",
			data:    []byte{0x41, 0x42},
			expect:  1, // only [0] works: 41 42 matches at start=0
		},
		{
			name:    "empty_data",
			pattern: "{ 41 42 }",
			data:    []byte{},
			expect:  0,
		},
		{
			name:    "single_byte_data",
			pattern: "{ 41 }",
			data:    []byte{0x41},
			expect:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hexPattern, err := sc.parseHexPattern(tt.pattern)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if tt.xorKeys != nil {
				hexPattern.XorKeys = tt.xorKeys
			}
			matches := FindHexMatches(hexPattern, tt.data)
			if len(matches) != tt.expect {
				t.Fatalf("matches %d, want %d (matches: %v)", len(matches), tt.expect, matches)
			}
		})
	}
}

// TestFindAnchorByte tests the anchor byte extraction logic.
func TestFindAnchorByte(t *testing.T) {
	sc := NewStringCompiler(NewEmitter())

	tests := []struct {
		name     string
		pattern  string
		wantOK   bool
		wantByte byte
	}{
		{
			name:     "first_byte_literal",
			pattern:  "{ DE AD BE EF }",
			wantOK:   true,
			wantByte: 0xDE,
		},
		{
			name:     "wildcard_prefix",
			pattern:  "{ ?? DE AD }",
			wantOK:   true,
			wantByte: 0xDE, // finds anchor after wildcard
		},
		{
			name:     "after_jump",
			pattern:  "{ [2-4] DE AD }",
			wantOK:   true,
			wantByte: 0xDE,
		},
		{
			name:    "only_wildcards",
			pattern: "{ ?? ?? ?? }",
			wantOK:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hexPattern, err := sc.parseHexPattern(tt.pattern)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			anchor := findAnchorByte(hexPattern.Tokens)
			if anchor.ok != tt.wantOK {
				t.Fatalf("ok=%v, want %v", anchor.ok, tt.wantOK)
			}
			if tt.wantOK && anchor.byteVal != tt.wantByte {
				t.Fatalf("byte=0x%02X, want 0x%02X", anchor.byteVal, tt.wantByte)
			}
		})
	}
}
