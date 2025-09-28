package lexer_test

import (
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func TestUnterminatedString_ErrorToken(t *testing.T) {
	// New behavior: emit ILLEGAL token containing offending text (including the leading quote)
	l := lexer.New("\"unterminated")
	tok := l.NextToken()
	if tok.Type != token.ILLEGAL {
		t.Fatalf("expected ILLEGAL token for unterminated string, got %v", tok.Type)
	}
	if tok.Literal != "\"unterminated" {
		t.Fatalf("expected literal '\"unterminated', got %q", tok.Literal)
	}
}

func TestStringEscapeSequences(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"newline", "\"line1\\nline2\"", "line1\nline2"},
		{"tab", "\"col1\\tcol2\"", "col1\tcol2"},
		{"carriage_return", "\"line1\\rline2\"", "line1\rline2"},
		{"backslash", "\"path\\\\file\"", "path\\file"},
		{"quote", "\"say \\\"hello\\\"\"", "say \"hello\""},
		{"hex_sequence", "\"char\\x41B\"", "charAB"},
		{"hex_lowercase", "\"char\\x61\"", "chara"},
		{"hex_uppercase", "\"char\\x41\"", "charA"},
		{"multiple_escapes", "\"\\n\\t\\r\\\\\\\"\"", "\n\t\r\\\""},
		{"mixed_content", "\"Hello\\nWorld\\t!\"", "Hello\nWorld\t!"},
		{"hex_at_end", "\"test\\x00\"", "test\x00"},
		{"hex_at_start", "\"\\x48ello\"", "Hello"},
		{"consecutive_hex", "\"\\x41\\x42\\x43\"", "ABC"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)
			tok := l.NextToken()

			if tok.Type != token.STRING_LIT {
				t.Fatalf("expected STRING_LIT token, got %v", tok.Type)
			}

			if tok.Literal != tt.expected {
				t.Fatalf("expected literal %q, got %q", tt.expected, tok.Literal)
			}
		})
	}
}

func TestUnterminatedStringWithEscapes(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"with_newline_escape", "\"test\\n"},
		{"with_tab_escape", "\"test\\t"},
		{"with_backslash_escape", "\"test\\\\"},
		{"with_quote_escape", "\"test\\\""},
		{"with_hex_escape", "\"test\\x41"},
		{"with_multiple_escapes", "\"test\\n\\t\\r"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)
			tok := l.NextToken()

			if tok.Type != token.ILLEGAL {
				t.Fatalf("expected ILLEGAL token for unterminated string, got %v", tok.Type)
			}

			if tok.Literal != tt.input {
				t.Fatalf("expected literal %q, got %q", tt.input, tok.Literal)
			}
		})
	}
}

func TestValidateStringEscapes(t *testing.T) {
	tests := []struct {
		name        string
		literal     string
		expectError bool
		errorCount  int
	}{
		{"valid_newline", "line1\\nline2", false, 0},
		{"valid_tab", "col1\\tcol2", false, 0},
		{"valid_carriage_return", "line1\\rline2", false, 0},
		{"valid_backslash", "path\\\\file", false, 0},
		{"valid_quote", "say \\\"hello\\\"", false, 0},
		{"valid_hex", "char\\x41B", false, 0},
		{"valid_multiple", "\\n\\t\\r\\\\\\\"", false, 0},

		{"invalid_escape", "test\\z", true, 1},
		{"invalid_hex_short", "test\\x4", true, 1},
		{"invalid_hex_non_hex", "test\\xGH", true, 1},
		{"multiple_invalid", "\\z\\x4\\xGH", true, 3},
		{"mixed_valid_invalid", "\\n\\z\\t", true, 1},

		{"trailing_backslash", "test\\", true, 1},
		{"hex_at_end_incomplete", "test\\x", true, 1},
		{"hex_one_char", "test\\x4", true, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pos := token.Position{Line: 1, Column: 1}
			errors := lexer.ValidateStringEscapes(tt.literal, pos)

			if tt.expectError {
				if len(errors) == 0 {
					t.Fatalf("expected %d errors, got none", tt.errorCount)
				}
				if len(errors) != tt.errorCount {
					t.Fatalf("expected %d errors, got %d: %v", tt.errorCount, len(errors), errors)
				}
			} else if len(errors) > 0 {
				t.Fatalf("expected no errors, got %d: %v", len(errors), errors)
			}
		})
	}
}
