package lexer

import (
	"testing"
)

func TestLexer_readIllegalSequence(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "single illegal character",
			input:    "?rule",
			expected: "?",
		},
		{
			name:     "multiple illegal characters",
			input:    "???rule",
			expected: "???",
		},
		{
			name:     "stray closing block comment",
			input:    "*/rule",
			expected: "*/",
		},
		{
			name:     "illegal sequence ending with space",
			input:    "??? rule",
			expected: "???",
		},
		{
			name:     "illegal sequence ending with newline",
			input:    "???\nrule",
			expected: "???",
		},
		{
			name:     "illegal sequence ending with letter",
			input:    "???rule",
			expected: "???",
		},
		{
			name:     "illegal sequence ending with digit",
			input:    "???123rule",
			expected: "???",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := New(tt.input)

			// Position at the first illegal character
			result := l.readIllegalSequence()

			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func Test_isHexDigit(t *testing.T) {
	tests := []struct {
		ch       byte
		expected bool
	}{
		{'0', true},
		{'9', true},
		{'a', true},
		{'f', true},
		{'A', true},
		{'F', true},
		{'g', false},
		{'G', false},
		{'z', false},
		{'Z', false},
		{'@', false},
		{'[', false},
	}

	for _, tt := range tests {
		result := isHexDigit(tt.ch)
		if result != tt.expected {
			t.Errorf("isHexDigit(%c) = %v, expected %v", tt.ch, result, tt.expected)
		}
	}
}

func Test_isLetter(t *testing.T) {
	tests := []struct {
		ch       byte
		expected bool
	}{
		{'a', true},
		{'z', true},
		{'A', true},
		{'Z', true},
		{'_', true},
		{'0', false},
		{'9', false},
		{'@', false},
		{'[', false},
		{' ', false},
		{'\n', false},
		{'\t', false},
	}

	for _, tt := range tests {
		result := isLetter(tt.ch)
		if result != tt.expected {
			t.Errorf("isLetter(%c) = %v, expected %v", tt.ch, result, tt.expected)
		}
	}
}

func Test_isDigit(t *testing.T) {
	tests := []struct {
		ch       byte
		expected bool
	}{
		{'0', true},
		{'9', true},
		{'1', true},
		{'5', true},
		{'a', false},
		{'A', false},
		{'_', false},
		{'@', false},
		{'[', false},
		{' ', false},
		{'\n', false},
		{'\t', false},
	}

	for _, tt := range tests {
		result := isDigit(tt.ch)
		if result != tt.expected {
			t.Errorf("isDigit(%c) = %v, expected %v", tt.ch, result, tt.expected)
		}
	}
}

func Test_startsKnownToken(t *testing.T) {
	tests := []struct {
		ch       byte
		expected bool
	}{
		{'+', true},
		{'-', true},
		{':', true},
		{',', true},
		{'.', true},
		{'(', true},
		{')', true},
		{'{', true},
		{'}', true},
		{'=', true},
		{'!', true},
		{'<', true},
		{'>', true},
		{'"', true},
		{'/', true},
		{'$', true},
		{'#', true},
		{'a', false},
		{'A', false},
		{'_', false},
		{'0', false},
		{'9', false},
		{'@', false},
		{'[', false},
		{' ', false},
		{'\n', false},
		{'\t', false},
	}

	for _, tt := range tests {
		result := startsKnownToken(tt.ch)
		if result != tt.expected {
			t.Errorf("startsKnownToken(%c) = %v, expected %v", tt.ch, result, tt.expected)
		}
	}
}

func TestLexer_ch(t *testing.T) {
	l := New("hello")
	if l.ch() != 'h' {
		t.Errorf("Expected 'h', got %c", l.ch())
	}
}

func TestLexer_peekChar(t *testing.T) {
	l := New("hello")
	if l.peekChar() != 'e' {
		t.Errorf("Expected 'e', got %c", l.peekChar())
	}

	// peekChar should not advance position
	if l.ch() != 'h' {
		t.Errorf("Expected current char still 'h', got %c", l.ch())
	}
}

func TestLexer_position(t *testing.T) {
	l := New("hello")
	if l.position() != 0 {
		t.Errorf("Expected position 0, got %d", l.position())
	}

	// Read one character
	l.readChar()
	if l.position() != 1 {
		t.Errorf("Expected position 1 after readChar, got %d", l.position())
	}
}