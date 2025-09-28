package lexer_test

import (
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func TestHexInteger_Basic(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple lowercase", "0x1000", "0x1000"},
		{"simple uppercase", "0X1000", "0X1000"},
		{"single digit", "0x1", "0x1"},
		{"all hex digits", "0xABCDEF", "0xABCDEF"},
		{"mixed case", "0xaBcDeF", "0xaBcDeF"},
		{"with numbers", "0x123ABC", "0x123ABC"},
		{"zero", "0x0", "0x0"},
		{"max 32-bit", "0xFFFFFFFF", "0xFFFFFFFF"},
		{"common address", "0x401000", "0x401000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			helper.AssertSingleToken(tt.input, token.HEX_INTEGER_LIT, tt.expected)
		})
	}
}

func TestHexInteger_EdgeCases(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	// Test incomplete hex integers
	tests := []struct {
		name     string
		input    string
		expected []token.Token
	}{
		{
			name:  "just 0x",
			input: "0x",
			expected: []token.Token{
				{Type: token.HEX_INTEGER_LIT, Literal: "0x"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "0x followed by non-hex",
			input: "0xG",
			expected: []token.Token{
				{Type: token.HEX_INTEGER_LIT, Literal: "0x"},
				{Type: token.IDENTIFIER, Literal: "G"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "0x followed by space",
			input: "0x ",
			expected: []token.Token{
				{Type: token.HEX_INTEGER_LIT, Literal: "0x"},
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

func TestHexInteger_VsDecimalInteger(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	// Test that regular decimal integers still work
	helper.AssertSingleToken("123", token.INTEGER_LIT, "123")
	helper.AssertSingleToken("0", token.INTEGER_LIT, "0")
	helper.AssertSingleToken("999", token.INTEGER_LIT, "999")

	// Test that hex integers are properly distinguished
	helper.AssertSingleToken("0x123", token.HEX_INTEGER_LIT, "0x123")
	helper.AssertSingleToken("0X123", token.HEX_INTEGER_LIT, "0X123")
}

func TestHexInteger_InYARARule(t *testing.T) {
	helper := lexer.NewTestHelper(t)
	input := `rule TestRule {
		meta:
			base_address = 0x401000
			entry_point = 0X1000
		strings:
			$a = "test"
		condition:
			$a and pe.entry_point == 0x401000 and filesize > 0xFF
	}`

	tokens := helper.CollectTokens(input)
	hexIntegerCount := 0
	hexIntegers := []string{}

	for _, tok := range tokens {
		if tok.Type == token.HEX_INTEGER_LIT {
			hexIntegerCount++
			hexIntegers = append(hexIntegers, tok.Literal)
		}
	}

	expectedHexIntegers := []string{"0x401000", "0X1000", "0x401000", "0xFF"}
	if hexIntegerCount != len(expectedHexIntegers) {
		t.Errorf("Expected %d hex integer tokens, got %d", len(expectedHexIntegers), hexIntegerCount)
	}

	for i, expected := range expectedHexIntegers {
		if i >= len(hexIntegers) || hexIntegers[i] != expected {
			t.Errorf("Expected hex integer[%d] to be %q, got %q", i, expected, hexIntegers[i])
		}
	}
}

func TestHexInteger_WithOperators(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	// Test hex integers with various operators
	helper.AssertTokenSequence("0x1000 == 0x1000", lexer.CreateTokenSequence(
		token.HEX_INTEGER_LIT, "0x1000",
		token.EQ, "==",
		token.HEX_INTEGER_LIT, "0x1000",
	))

	helper.AssertTokenSequence("pe.entry_point + 0x100", lexer.CreateTokenSequence(
		token.IDENTIFIER, "pe",
		token.DOT, ".",
		token.IDENTIFIER, "entry_point",
		token.PLUS, "+",
		token.HEX_INTEGER_LIT, "0x100",
	))

	helper.AssertTokenSequence("filesize > 0xFF", lexer.CreateTokenSequence(
		token.FILESIZE, "filesize",
		token.GT, ">",
		token.HEX_INTEGER_LIT, "0xFF",
	))
}
