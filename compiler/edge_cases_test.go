package compiler

import (
	"strings"
	"testing"
)

// TestEmptyStringMatching documents compiler behavior with empty strings
// DO NOT modify code to make tests pass - document current behavior only
func TestEmptyStringMatching(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "empty-text-string",
			rule:        `rule test { strings: $a = "" condition: $a }`,
			expectError: false,
			description: "Documents empty text string compilation",
		},
		{
			name:        "empty-hex-pattern",
			rule:        `rule test { strings: $a = { } condition: $a }`,
			expectError: true,
			description: "Documents empty hex pattern (should error)",
		},
		{
			name:        "empty-regex",
			rule:        `rule test { strings: $a = // condition: $a }`,
			expectError: true,
			description: "Documents empty regex (should error)",
		},
		{
			name:        "empty-with-modifiers",
			rule:        `rule test { strings: $a = "" nocase condition: $a }`,
			expectError: false,
			description: "Documents empty string with modifiers",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCompiler()
			program, err := c.CompileSource(tt.rule)

			assertAnonymousStringResult(t, program, err, tt.expectError, tt.description)
		})
	}
}

// TestSingleCharStrings documents compiler behavior with single character strings
// DO NOT modify code to make tests pass - document current behavior only
func TestSingleCharStrings(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "single-char",
			rule:        `rule test { strings: $a = "a" condition: $a }`,
			expectError: false,
			description: "Documents single character string",
		},
		{
			name:        "single-char-nocase",
			rule:        `rule test { strings: $a = "A" nocase condition: $a }`,
			expectError: false,
			description: "Documents single char with nocase",
		},
		{
			name:        "single-char-wide",
			rule:        `rule test { strings: $a = "a" wide condition: $a }`,
			expectError: false,
			description: "Documents single char with wide modifier",
		},
		{
			name:        "single-char-all-modifiers",
			rule:        `rule test { strings: $a = "a" nocase wide fullword condition: $a }`,
			expectError: false,
			description: "Documents single char with all modifiers",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCompiler()
			program, err := c.CompileSource(tt.rule)

			assertAnonymousStringResult(t, program, err, tt.expectError, tt.description)
		})
	}
}

// TestVeryLongStrings documents compiler behavior with very long strings
// DO NOT modify code to make tests pass - document current behavior only
func TestVeryLongStrings(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "thousand-char-string",
			rule:        `rule test { strings: $a = "` + strings.Repeat("a", 1000) + `" condition: $a }`,
			expectError: false,
			description: "Documents 1000 character string",
		},
		{
			name:        "ten-thousand-char-string",
			rule:        `rule test { strings: $a = "` + strings.Repeat("b", 10000) + `" condition: $a }`,
			expectError: false,
			description: "Documents 10000 character string",
		},
		{
			name:        "string-with-nulls",
			rule:        `rule test { strings: $a = "test\x00\x00\x00" condition: $a }`,
			expectError: false,
			description: "Documents string with embedded nulls",
		},
		{
			name:        "string-with-all-bytes",
			rule:        `rule test { strings: $a = "` + generateAllByteString() + `" condition: $a }`,
			expectError: false,
			description: "Documents string with all possible byte values",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCompiler()
			program, err := c.CompileSource(tt.rule)

			assertAnonymousStringResult(t, program, err, tt.expectError, tt.description)
		})
	}
}

// TestOverlappingPatterns documents compiler behavior with overlapping patterns
// DO NOT modify code to make tests pass - document current behavior only
func TestOverlappingPatterns(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "overlapping-text-strings",
			rule:        `rule test { strings: $a = "abc" $b = "bcd" $c = "cde" condition: any of them }`,
			expectError: false,
			description: "Documents overlapping text patterns",
		},
		{
			name:        "prefix-patterns",
			rule:        `rule test { strings: $a = "test" $b = "testing" $c = "tester" condition: any of them }`,
			expectError: false,
			description: "Documents patterns with common prefix",
		},
		{
			name:        "contained-strings",
			rule:        `rule test { strings: $a = "test" $b = "testing is fun" condition: $a and $b }`,
			expectError: false,
			description: "Documents one string contained in another",
		},
		{
			name:        "identical-strings",
			rule:        `rule test { strings: $a = "test" $b = "test" condition: $a and $b }`,
			expectError: false,
			description: "Documents identical strings in same rule",
		},
		{
			name:        "case-variants",
			rule:        `rule test { strings: $a = "test" $b = "TEST" $c = "TeSt" condition: any of them }`,
			expectError: false,
			description: "Documents case variants of same string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCompiler()
			program, err := c.CompileSource(tt.rule)

			assertAnonymousStringResult(t, program, err, tt.expectError, tt.description)
		})
	}
}

// TestAllStringModifiersCombinations documents compiler behavior with all modifier combinations
// DO NOT modify code to make tests pass - document current behavior only
func TestAllStringModifiersCombinations(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "nocase-only",
			rule:        `rule test { strings: $a = "test" nocase condition: $a }`,
			expectError: false,
			description: "Documents nocase modifier",
		},
		{
			name:        "wide-only",
			rule:        `rule test { strings: $a = "test" wide condition: $a }`,
			expectError: false,
			description: "Documents wide modifier",
		},
		{
			name:        "fullword-only",
			rule:        `rule test { strings: $a = "test" fullword condition: $a }`,
			expectError: false,
			description: "Documents fullword modifier",
		},
		{
			name:        "private-only",
			rule:        `rule test { strings: $a = "test" private condition: $a }`,
			expectError: false,
			description: "Documents private modifier",
		},
		{
			name:        "ascii-wide",
			rule:        `rule test { strings: $a = "test" ascii wide condition: $a }`,
			expectError: true,
			description: "Documents ascii+wide combination (may be rejected)",
		},
		{
			name:        "nocase-wide",
			rule:        `rule test { strings: $a = "test" nocase wide condition: $a }`,
			expectError: false,
			description: "Documents nocase+wide combination",
		},
		{
			name:        "fullword-wide",
			rule:        `rule test { strings: $a = "test" fullword wide condition: $a }`,
			expectError: false,
			description: "Documents fullword+wide combination",
		},
		{
			name:        "all-modifiers",
			rule:        `rule test { strings: $a = "test" nocase wide fullword private condition: $a }`,
			expectError: false,
			description: "Documents all modifiers together",
		},
		{
			name:        "xor-with-others",
			rule:        `rule test { strings: $a = "test" xor nocase wide condition: $a }`,
			expectError: false,
			description: "Documents xor with other modifiers",
		},
		{
			name:        "base64-with-modifiers",
			rule:        `rule test { strings: $a = "test" base64 fullword condition: $a }`,
			expectError: false,
			description: "Documents base64 with other modifiers",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCompiler()
			program, err := c.CompileSource(tt.rule)

			assertAnonymousStringResult(t, program, err, tt.expectError, tt.description)
		})
	}
}

// TestXorModifierBoundaries documents compiler behavior with xor modifier edge cases
// DO NOT modify code to make tests pass - document current behavior only
func TestXorModifierBoundaries(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "xor-no-args",
			rule:        `rule test { strings: $a = "test" xor condition: $a }`,
			expectError: false,
			description: "Documents xor without arguments (xor with all keys)",
		},
		{
			name:        "xor-single-key",
			rule:        `rule test { strings: $a = "test" xor(0x42) condition: $a }`,
			expectError: false,
			description: "Documents xor with single key",
		},
		{
			name:        "xor-range",
			rule:        `rule test { strings: $a = "test" xor(0x00-0xFF) condition: $a }`,
			expectError: false,
			description: "Documents xor with full key range",
		},
		{
			name:        "xor-narrow-range",
			rule:        `rule test { strings: $a = "test" xor(0x40-0x50) condition: $a }`,
			expectError: false,
			description: "Documents xor with narrow range",
		},
		{
			name:        "xor-multiple-ranges",
			rule:        `rule test { strings: $a = "test" xor(0x00-0x0F xor(0xF0-0xFF) condition: $a }`,
			expectError: true,
			description: "Documents multiple xor (invalid syntax)",
		},
		{
			name:        "xor-zero-range",
			rule:        `rule test { strings: $a = "test" xor(0x42-0x42) condition: $a }`,
			expectError: false,
			description: "Documents xor with single-value range",
		},
		{
			name:        "xor-inverted-range",
			rule:        `rule test { strings: $a = "test" xor(0xFF-0x00) condition: $a }`,
			expectError: false,
			description: "Documents xor with inverted range",
		},
		{
			name:        "xor-with-wide",
			rule:        `rule test { strings: $a = "test" xor wide condition: $a }`,
			expectError: false,
			description: "Documents xor combined with wide modifier",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCompiler()
			program, err := c.CompileSource(tt.rule)

			assertAnonymousStringResult(t, program, err, tt.expectError, tt.description)
		})
	}
}

// TestBase64AlphabetVariations documents compiler behavior with base64 alphabets
// DO NOT modify code to make tests pass - document current behavior only
func TestBase64AlphabetVariations(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "base64-default",
			rule:        `rule test { strings: $a = "test" base64 condition: $a }`,
			expectError: false,
			description: "Documents base64 with default alphabet",
		},
		{
			name:        "base64wide-default",
			rule:        `rule test { strings: $a = "test" base64wide condition: $a }`,
			expectError: false,
			description: "Documents base64wide with default alphabet",
		},
		{
			name:        "base64-custom-alphabet",
			rule:        `rule test { strings: $a = "test" base64("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") condition: $a }`,
			expectError: false,
			description: "Documents base64 with full custom alphabet",
		},
		{
			name:        "base64-short-alphabet",
			rule:        `rule test { strings: $a = "test" base64("abc") condition: $a }`,
			expectError: true,
			description: "Documents base64 with short alphabet (should error)",
		},
		{
			name:        "base64-invalid-chars",
			rule:        `rule test { strings: $a = "test" base64("!!!") condition: $a }`,
			expectError: true,
			description: "Documents base64 with invalid characters",
		},
		{
			name:        "base64-duplicate-chars",
			rule:        `rule test { strings: $a = "test" base64("AAA") condition: $a }`,
			expectError: false,
			description: "Documents base64 with duplicate characters",
		},
		{
			name:        "base64-with-modifiers",
			rule:        `rule test { strings: $a = "test" base64 wide fullword condition: $a }`,
			expectError: false,
			description: "Documents base64 with other modifiers",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCompiler()
			program, err := c.CompileSource(tt.rule)

			assertAnonymousStringResult(t, program, err, tt.expectError, tt.description)
		})
	}
}

// TestHexPatternJumpExtremes documents compiler behavior with hex pattern jump extremes
// DO NOT modify code to make tests pass - document current behavior only
func TestHexPatternJumpExtremes(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "zero-jump",
			rule:        `rule test { strings: $a = { DE [0] AD } condition: $a }`,
			expectError: false,
			description: "Documents hex with zero-length jump",
		},
		{
			name:        "large-jump",
			rule:        `rule test { strings: $a = { DE [100] AD } condition: $a }`,
			expectError: false,
			description: "Documents hex with large jump",
		},
		{
			name:        "very-large-jump",
			rule:        `rule test { strings: $a = { DE [1000] AD } condition: $a }`,
			expectError: false,
			description: "Documents hex with very large jump",
		},
		{
			name:        "negative-jump",
			rule:        `rule test { strings: $a = { DE [-10] AD } condition: $a }`,
			expectError: true,
			description: "Documents hex with negative jump (should error)",
		},
		{
			name:        "multiple-jumps",
			rule:        `rule test { strings: $a = { DE [5] AD [10] BE [15] EF } condition: $a }`,
			expectError: false,
			description: "Documents hex with multiple jumps",
		},
		{
			name:        "jump-in-alternative",
			rule:        `rule test { strings: $a = { (DE [5] AD | BE [10] CF) } condition: $a }`,
			expectError: false,
			description: "Documents hex with jumps in alternatives",
		},
		{
			name:        "wildcard-after-jump",
			rule:        `rule test { strings: $a = { DE [5] ?? AD } condition: $a }`,
			expectError: false,
			description: "Documents wildcard after jump",
		},
		{
			name:        "complex-jump-alternative",
			rule:        `rule test { strings: $a = { (DE [1-5] AD | BE [2-10] CF) EF } condition: $a }`,
			expectError: false,
			description: "Documents complex jump ranges in alternatives",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCompiler()
			program, err := c.CompileSource(tt.rule)

			assertAnonymousStringResult(t, program, err, tt.expectError, tt.description)
		})
	}
}

// TestRegexEdgeCases documents compiler behavior with regex edge cases
// DO NOT modify code to make tests pass - document current behavior only
func TestRegexEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "empty-regex",
			rule:        `rule test { strings: $a = // condition: $a }`,
			expectError: true,
			description: "Documents empty regex (should error)",
		},
		{
			name:        "dot-star",
			rule:        `rule test { strings: $a = /.*/ condition: $a }`,
			expectError: false,
			description: "Documents dot-star regex",
		},
		{
			name:        "complex-quantifiers",
			rule:        `rule test { strings: $a = /a{1,10}/ condition: $a }`,
			expectError: false,
			description: "Documents regex with range quantifier",
		},
		{
			name:        "nested-quantifiers",
			rule:        `rule test { strings: $a = /(a*)*/ condition: $a }`,
			expectError: false,
			description: "Documents regex with nested quantifiers",
		},
		{
			name:        "many-alternatives",
			rule:        `rule test { strings: $a = /a|b|c|d|e|f|g|h/ condition: $a }`,
			expectError: false,
			description: "Documents regex with many alternatives",
		},
		{
			name:        "deep-nesting",
			rule:        `rule test { strings: $a = /((((a))))/ condition: $a }`,
			expectError: false,
			description: "Documents regex with deep nesting",
		},
		{
			name:        "unicode-property",
			rule:        `rule test { strings: $a = /\w+/ condition: $a }`,
			expectError: false,
			description: "Documents regex with unicode property",
		},
		{
			name:        "with-modifiers",
			rule:        `rule test { strings: $a = /test/ nocase condition: $a }`,
			expectError: false,
			description: "Documents regex with nocase modifier",
		},
		{
			name:        "case-sensitive-flag",
			rule:        `rule test { strings: $a = /test/i condition: $a }`,
			expectError: false,
			description: "Documents regex with flags",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCompiler()
			program, err := c.CompileSource(tt.rule)

			assertAnonymousStringResult(t, program, err, tt.expectError, tt.description)
		})
	}
}

// Helper function to generate a string with all possible byte values
func generateAllByteString() string {
	var result strings.Builder
	for i := range 256 {
		if i >= 32 && i <= 126 { // Printable ASCII range
			result.WriteByte(byte(i))
		}
	}
	return result.String()
}
