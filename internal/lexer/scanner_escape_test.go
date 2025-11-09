package lexer

import (
	"fmt"
	"testing"
)

// Test hexDigitValue function
func TestHexDigitValue(t *testing.T) {
	// Helper function to generate test cases for a range of characters
	generateRangeTests := func(namePrefix string, start, end byte, expectedFunc func(byte) int) []struct {
		name     string
		input    byte
		expected int
	} {
		var tests []struct {
			name     string
			input    byte
			expected int
		}
		for i := start; i <= end; i++ {
			tests = append(tests, struct {
				name     string
				input    byte
				expected int
			}{
				name:     fmt.Sprintf("%s %c", namePrefix, i),
				input:    i,
				expected: expectedFunc(i),
			})
		}
		return tests
	}

	// Generate valid digit tests (0-9)
	digitTests := generateRangeTests("digit", '0', '9', func(b byte) int { return int(b - '0') })

	// Generate valid lowercase hex tests (a-f)
	lowerHexTests := generateRangeTests("lowercase", 'a', 'f', func(b byte) int { return 10 + int(b - 'a') })

	// Generate valid uppercase hex tests (A-F)
	upperHexTests := generateRangeTests("uppercase", 'A', 'F', func(b byte) int { return 10 + int(b - 'A') })

	// Specific boundary and special invalid cases
	invalidTests := []struct {
		name     string
		input    byte
		expected int
	}{
		// Boundary cases
		{"just before 0", '/', 0},
		{"just after 9", ':', 0},
		{"just before a", '`', 0},
		{"just after f", 'g', 0},
		{"just before A", '@', 0},
		{"just after F", 'G', 0},

		// Common whitespace
		{"space", ' ', 0},
		{"tab", '\t', 0},
		{"newline", '\n', 0},
		{"carriage return", '\r', 0},

		// Common punctuation
		{"exclamation", '!', 0},
		{"at symbol", '@', 0},
		{"hash", '#', 0},
		{"dollar", '$', 0},
		{"percent", '%', 0},
		{"caret", '^', 0},
		{"ampersand", '&', 0},
		{"asterisk", '*', 0},

		// Extended range
		{"delete", 127, 0},
		{"extended char 128", 128, 0},
		{"extended char 255", 255, 0},
		{"null", 0, 0},
	}

	// Combine all test cases
	allTests := append(append(digitTests, lowerHexTests...), append(upperHexTests, invalidTests...)...)

	for _, tt := range allTests {
		t.Run(tt.name, func(t *testing.T) {
			result := hexDigitValue(tt.input)
			if result != tt.expected {
				t.Errorf("hexDigitValue(%q) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}

// Test processEscapeSequences function
func TestProcessEscapeSequences(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// Empty input
		{"empty string", "", ""},

		// No escape sequences
		{"no escapes", "hello world", "hello world"},
		{"no escapes with quotes", `hello "world"`, `hello "world"`},

		// Basic escape sequences
		{"newline escape", `hello\nworld`, "hello\nworld"},
		{"tab escape", `hello\tworld`, "hello\tworld"},
		{"carriage return escape", `hello\rworld`, "hello\rworld"},
		{"backslash escape", `hello\\world`, `hello\world`},
		{"quote escape", `hello\"world`, `hello"world`},

		// Hex escape sequences - valid
		{"hex escape lowercase", `\x61\x62\x63`, "abc"},
		{"hex escape uppercase", `\x41\x42\x43`, "ABC"},
		{"hex escape mixed case", `\x61\x42\x63`, "aBc"},
		{"hex escape zero", `\x00\x30`, "\x000"},

		// Hex escape sequences - invalid (should be kept as-is)
		{"invalid hex - missing digits", `\x`, `\x`},
		{"invalid hex - one digit", `\x1`, `\x1`},
		{"invalid hex - invalid chars", `\xgg`, `\xgg`},
		{"invalid hex - mixed valid/invalid", `\x41g`, "Ag"},

		// Multiple escape sequences
		{"multiple escapes", `line1\nline2\tTabbed\r\nEnd`, "line1\nline2\tTabbed\r\nEnd"},

		// Escape at end of string
		{"escape at end", `hello\n`, "hello\n"},
		{"incomplete escape at end", `hello\`, `hello\`},

		// Backslash not followed by escape character
		{"unknown escape", `hello\z`, `hello\z`},
		{"backslash before letter", `hello\zworld`, `hello\zworld`},

		// Complex string with mixed content
		{"complex string", `Path: "C:\Program Files\test"\nVersion: \x31\x2E\x30`, `Path: "C:\Program Files` + "\t" + `est"` + "\nVersion: 1.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processEscapeSequences(tt.input)
			if result != tt.expected {
				t.Errorf("processEscapeSequences(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
