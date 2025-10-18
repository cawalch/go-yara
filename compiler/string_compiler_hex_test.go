package compiler

import (
	"testing"
)

// TestParseHexString tests hex string parsing
func TestParseHexString(t *testing.T) {
	sc := &StringCompiler{
		emitter:       &Emitter{},
		stringOffsets: make(map[string]int),
		patternData:   make(map[string][]byte),
	}

	tests := []struct {
		name     string
		input    string
		minLen   int
		maxLen   int
	}{
		{"simple_hex", "60 E8 00 00", 4, 4},
		{"hex_with_spaces", "60 E8 00 00 00 00 58 83", 8, 8},
		{"hex_with_comments", "60 E8 /* comment */ 00 00", 4, 4},
		{"hex_with_line_comments", "60 E8 // comment\n00 00", 4, 4},
		{"empty", "", 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sc.parseHexString(tt.input)
			if len(result) < tt.minLen || len(result) > tt.maxLen {
				t.Errorf("expected length between %d and %d, got %d", tt.minLen, tt.maxLen, len(result))
			}
		})
	}
}

// TestTokenizeHexString tests hex string tokenization
func TestTokenizeHexString(t *testing.T) {
	sc := &StringCompiler{
		emitter:       &Emitter{},
		stringOffsets: make(map[string]int),
		patternData:   make(map[string][]byte),
	}

	tests := []struct {
		name           string
		input          string
		expectedTokens int
	}{
		{"single_byte", "60", 1},
		{"multiple_bytes", "60 E8 00 00", 4},
		{"wildcard", "60 ?? E8", 3},
		{"masked_byte_x", "60 A? E8", 3},
		{"masked_byte_y", "60 ?A E8", 3},
		{"jump", "60 [1-3] E8", 3},
		{"alternatives", "60 (E8|E9) 00", 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := sc.tokenizeHexString(tt.input)
			if len(tokens) != tt.expectedTokens {
				t.Errorf("expected %d tokens, got %d", tt.expectedTokens, len(tokens))
			}
		})
	}
}

// TestParseHexByte tests hex byte parsing
func TestParseHexByte(t *testing.T) {
	sc := &StringCompiler{
		emitter:       &Emitter{},
		stringOffsets: make(map[string]int),
		patternData:   make(map[string][]byte),
	}

	tests := []struct {
		name     string
		input    string
		expected byte
	}{
		{"simple_hex", "60", 0x60},
		{"uppercase", "FF", 0xFF},
		{"lowercase", "ab", 0xAB},
		{"mixed_case", "aB", 0xAB},
		{"zero", "00", 0x00},
		{"masked_x", "A?", 0xA0},
		{"masked_y", "?A", 0x0A},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sc.parseHexByte(tt.input)
			if result != tt.expected {
				t.Errorf("expected 0x%02X, got 0x%02X", tt.expected, result)
			}
		})
	}
}

// TestParseJump tests jump range parsing
func TestParseJump(t *testing.T) {
	sc := &StringCompiler{
		emitter:       &Emitter{},
		stringOffsets: make(map[string]int),
		patternData:   make(map[string][]byte),
	}

	tests := []struct {
		name     string
		input    string
		minVal   int
		maxVal   int
	}{
		{"single_value", "5", 5, 5},
		{"range", "1-3", 1, 3},
		{"range_large", "10-100", 10, 100},
		{"range_infinite", "5-", 5, 65535},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sc.parseJump(tt.input)
			if result["min"] != tt.minVal {
				t.Errorf("expected min %d, got %d", tt.minVal, result["min"])
			}
			if result["max"] != tt.maxVal {
				t.Errorf("expected max %d, got %d", tt.maxVal, result["max"])
			}
		})
	}
}

// TestParseAlternatives tests alternatives parsing
func TestParseAlternatives(t *testing.T) {
	sc := &StringCompiler{
		emitter:       &Emitter{},
		stringOffsets: make(map[string]int),
		patternData:   make(map[string][]byte),
	}

	tests := []struct {
		name     string
		input    string
		numAlts  int
	}{
		{"two_alternatives", "60 E8 | 60 E9", 2},
		{"three_alternatives", "60 | E8 | E9", 3},
		{"alternatives_with_spaces", "60 E8 | 60 E9 | 60 EA", 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sc.parseAlternatives(tt.input)
			if len(result) != tt.numAlts {
				t.Errorf("expected %d alternatives, got %d", tt.numAlts, len(result))
			}
		})
	}
}

// TestIsHexDigit tests hex digit detection
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

// TestComplexHexPatterns tests complex hex patterns
func TestComplexHexPatterns(t *testing.T) {
	sc := &StringCompiler{
		emitter:       &Emitter{},
		stringOffsets: make(map[string]int),
		patternData:   make(map[string][]byte),
	}

	tests := []struct {
		name  string
		input string
	}{
		{"yara_sample", "60 E8 00 00 00 00 58 83 E8 3D 50 8D B8"},
		{"with_wildcards", "E2 34 ?? C8 A? FB"},
		{"with_jumps", "F4 23 [4-6] 62 B4"},
		{"with_alternatives", "F4 23 (62 B4 | 56) 45"},
		{"complex_mix", "60 ?? [1-3] (E8 | E9) 00 00"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sc.parseHexString(tt.input)
			if len(result) == 0 {
				t.Errorf("expected non-empty result")
			}
		})
	}
}

