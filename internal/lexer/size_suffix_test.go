package lexer_test

import (
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func TestSizeSuffix_Basic(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"kilobytes lowercase", "1KB", "1KB"},
		{"kilobytes uppercase", "1kb", "1kb"},
		{"kilobytes mixed", "1Kb", "1Kb"},
		{"kilobytes mixed2", "1kB", "1kB"},
		{"megabytes lowercase", "100MB", "100MB"},
		{"megabytes uppercase", "100mb", "100mb"},
		{"megabytes mixed", "100Mb", "100Mb"},
		{"megabytes mixed2", "100mB", "100mB"},
		{"large number KB", "1024KB", "1024KB"},
		{"large number MB", "512MB", "512MB"},
		{"single digit", "5KB", "5KB"},
		{"zero", "0KB", "0KB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			helper.AssertSingleToken(tt.input, token.SIZE_LIT, tt.expected)
		})
	}
}

func TestSizeSuffix_WithHexIntegers(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"hex KB lowercase", "0x100KB", "0x100KB"},
		{"hex KB uppercase", "0x100kb", "0x100kb"},
		{"hex MB lowercase", "0xFFMB", "0xFFMB"},
		{"hex MB uppercase", "0xFFmb", "0xFFmb"},
		{"hex with X uppercase", "0X1000KB", "0X1000KB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			helper.AssertSingleToken(tt.input, token.SIZE_LIT, tt.expected)
		})
	}
}

func TestSizeSuffix_EdgeCases(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	// Test cases where size suffix is not present
	tests := []struct {
		name     string
		input    string
		expected []token.Token
	}{
		{
			name:  "number followed by K only",
			input: "100K",
			expected: []token.Token{
				{Type: token.INTEGER_LIT, Literal: "100"},
				{Type: token.IDENTIFIER, Literal: "K"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "number followed by B only",
			input: "100B",
			expected: []token.Token{
				{Type: token.INTEGER_LIT, Literal: "100"},
				{Type: token.IDENTIFIER, Literal: "B"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "number followed by space then KB",
			input: "100 KB",
			expected: []token.Token{
				{Type: token.INTEGER_LIT, Literal: "100"},
				{Type: token.IDENTIFIER, Literal: "KB"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "hex number followed by space then KB",
			input: "0x100 KB",
			expected: []token.Token{
				{Type: token.HEX_INTEGER_LIT, Literal: "0x100"},
				{Type: token.IDENTIFIER, Literal: "KB"},
				{Type: token.EOF, Literal: ""},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			helper.AssertTokenSequence(tt.input, tt.expected)
		})
	}
}

func TestSizeSuffix_VsRegularNumbers(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	// Test that regular numbers still work
	helper.AssertSingleToken("123", token.INTEGER_LIT, "123")
	helper.AssertSingleToken("0x123", token.HEX_INTEGER_LIT, "0x123")

	// Test that size literals are properly distinguished
	helper.AssertSingleToken("123KB", token.SIZE_LIT, "123KB")
	helper.AssertSingleToken("0x123MB", token.SIZE_LIT, "0x123MB")
}

func TestSizeSuffix_InYARARule(t *testing.T) {
	helper := lexer.NewTestHelper(t)
	input := `rule TestRule {
		meta:
			max_size = 1MB
			min_size = 100KB
		strings:
			$a = "test"
		condition:
			$a and filesize < 10MB and filesize > 0x100KB
	}`

	tokens := helper.CollectTokens(input)
	sizeLiteralCount := 0
	sizeLiterals := []string{}

	for _, tok := range tokens {
		if tok.Type == token.SIZE_LIT {
			sizeLiteralCount++
			sizeLiterals = append(sizeLiterals, tok.Literal)
		}
	}

	expectedSizeLiterals := []string{"1MB", "100KB", "10MB", "0x100KB"}
	if sizeLiteralCount != len(expectedSizeLiterals) {
		t.Errorf("Expected %d size literal tokens, got %d", len(expectedSizeLiterals), sizeLiteralCount)
	}

	for i, expected := range expectedSizeLiterals {
		if i >= len(sizeLiterals) || sizeLiterals[i] != expected {
			t.Errorf("Expected size literal[%d] to be %q, got %q", i, expected, sizeLiterals[i])
		}
	}
}

func TestSizeSuffix_WithOperators(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	// Test size literals with various operators
	helper.AssertTokenSequence("filesize < 1MB", lexer.CreateTokenSequence(
		token.FILESIZE, "filesize",
		token.LT, "<",
		token.SIZE_LIT, "1MB",
	))

	helper.AssertTokenSequence("size == 100KB", lexer.CreateTokenSequence(
		token.IDENTIFIER, "size",
		token.EQ, "==",
		token.SIZE_LIT, "100KB",
	))

	helper.AssertTokenSequence("filesize > 0x100KB", lexer.CreateTokenSequence(
		token.FILESIZE, "filesize",
		token.GT, ">",
		token.SIZE_LIT, "0x100KB",
	))
}
