package lexer

import (
	"testing"
)

// Test hexDigitValue function
func TestHexDigitValue(t *testing.T) {
	tests := []struct {
		name     string
		input    byte
		expected int
	}{
		// Valid digits 0-9
		{"digit 0", '0', 0},
		{"digit 1", '1', 1},
		{"digit 2", '2', 2},
		{"digit 3", '3', 3},
		{"digit 4", '4', 4},
		{"digit 5", '5', 5},
		{"digit 6", '6', 6},
		{"digit 7", '7', 7},
		{"digit 8", '8', 8},
		{"digit 9", '9', 9},

		// Valid lowercase hex a-f
		{"lowercase a", 'a', 10},
		{"lowercase b", 'b', 11},
		{"lowercase c", 'c', 12},
		{"lowercase d", 'd', 13},
		{"lowercase e", 'e', 14},
		{"lowercase f", 'f', 15},

		// Valid uppercase hex A-F
		{"uppercase A", 'A', 10},
		{"uppercase B", 'B', 11},
		{"uppercase C", 'C', 12},
		{"uppercase D", 'D', 13},
		{"uppercase E", 'E', 14},
		{"uppercase F", 'F', 15},

		// Invalid characters - should return 0
		// Boundary cases (characters just outside valid ranges)
		{"just before 0", '/', 0},
		{"just after 9", ':', 0},
		{"just before a", '`', 0},
		{"just after f", 'g', 0},
		{"just before A", '@', 0},
		{"just after F", 'G', 0},

		// Other invalid characters
		{"space", ' ', 0},
		{"tab", '\t', 0},
		{"newline", '\n', 0},
		{"carriage return", '\r', 0},
		{"exclamation", '!', 0},
		{"at symbol", '@', 0},
		{"hash", '#', 0},
		{"dollar", '$', 0},
		{"percent", '%', 0},
		{"caret", '^', 0},
		{"ampersand", '&', 0},
		{"asterisk", '*', 0},
		{"left paren", '(', 0},
		{"right paren", ')', 0},
		{"minus", '-', 0},
		{"plus", '+', 0},
		{"equals", '=', 0},
		{"left brace", '{', 0},
		{"right brace", '}', 0},
		{"left bracket", '[', 0},
		{"right bracket", ']', 0},
		{"backslash", '\\', 0},
		{"pipe", '|', 0},
		{"semicolon", ';', 0},
		{"colon", ':', 0},
		{"single quote", '\'', 0},
		{"double quote", '"', 0},
		{"comma", ',', 0},
		{"period", '.', 0},
		{"less than", '<', 0},
		{"greater than", '>', 0},
		{"question mark", '?', 0},
		{"tilde", '~', 0},
		{"backtick", '`', 0},
		{"underscore", '_', 0},

		// Extended ASCII range (partial)
		{"delete", 127, 0},
		{"extended char 128", 128, 0},
		{"extended char 200", 200, 0},
		{"extended char 255", 255, 0},

		// Null character
		{"null", 0, 0},
	}

	for _, tt := range tests {
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