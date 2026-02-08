package compiler

import "testing"

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
