package lexer_test

import (
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func TestArithmeticOperators_Basic(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	tests := []struct {
		name     string
		input    string
		expected token.TokenType
	}{
		{"multiply", "*", token.MULTIPLY},
		{"divide", "/", token.DIVIDE},
		{"modulo", "%", token.MODULO},
		{"plus", "+", token.PLUS},
		{"minus", "-", token.MINUS},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			helper.AssertSingleToken(tt.input, tt.expected, tt.input)
		})
	}
}

func TestArithmeticOperators_InExpressions(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	tests := []struct {
		name     string
		input    string
		expected []token.Token
	}{
		{
			name:  "addition",
			input: "1 + 2",
			expected: []token.Token{
				{Type: token.INTEGER_LIT, Literal: "1"},
				{Type: token.PLUS, Literal: "+"},
				{Type: token.INTEGER_LIT, Literal: "2"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "subtraction",
			input: "5 - 3",
			expected: []token.Token{
				{Type: token.INTEGER_LIT, Literal: "5"},
				{Type: token.MINUS, Literal: "-"},
				{Type: token.INTEGER_LIT, Literal: "3"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "multiplication",
			input: "4 * 6",
			expected: []token.Token{
				{Type: token.INTEGER_LIT, Literal: "4"},
				{Type: token.MULTIPLY, Literal: "*"},
				{Type: token.INTEGER_LIT, Literal: "6"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "division",
			input: "8 / 2",
			expected: []token.Token{
				{Type: token.INTEGER_LIT, Literal: "8"},
				{Type: token.DIVIDE, Literal: "/"},
				{Type: token.INTEGER_LIT, Literal: "2"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "modulo",
			input: "10 % 3",
			expected: []token.Token{
				{Type: token.INTEGER_LIT, Literal: "10"},
				{Type: token.MODULO, Literal: "%"},
				{Type: token.INTEGER_LIT, Literal: "3"},
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

func TestArithmeticOperators_WithHexIntegers(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	tests := []struct {
		name     string
		input    string
		expected []token.Token
	}{
		{
			name:  "hex multiplication",
			input: "0x100 * 0xFF",
			expected: []token.Token{
				{Type: token.HEX_INTEGER_LIT, Literal: "0x100"},
				{Type: token.MULTIPLY, Literal: "*"},
				{Type: token.HEX_INTEGER_LIT, Literal: "0xFF"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "hex division",
			input: "0x1000 / 0x10",
			expected: []token.Token{
				{Type: token.HEX_INTEGER_LIT, Literal: "0x1000"},
				{Type: token.DIVIDE, Literal: "/"},
				{Type: token.HEX_INTEGER_LIT, Literal: "0x10"},
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

func TestArithmeticOperators_WithSizeLiterals(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	tests := []struct {
		name     string
		input    string
		expected []token.Token
	}{
		{
			name:  "size multiplication",
			input: "filesize * 2KB",
			expected: []token.Token{
				{Type: token.FILESIZE, Literal: "filesize"},
				{Type: token.MULTIPLY, Literal: "*"},
				{Type: token.SIZE_LIT, Literal: "2KB"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "size division",
			input: "1MB / 1024",
			expected: []token.Token{
				{Type: token.SIZE_LIT, Literal: "1MB"},
				{Type: token.DIVIDE, Literal: "/"},
				{Type: token.INTEGER_LIT, Literal: "1024"},
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

func TestArithmeticOperators_ComplexExpressions(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	tests := []struct {
		name     string
		input    string
		expected []token.Token
	}{
		{
			name:  "mixed arithmetic",
			input: "1 + 2 * 3 - 4 / 2 % 3",
			expected: []token.Token{
				{Type: token.INTEGER_LIT, Literal: "1"},
				{Type: token.PLUS, Literal: "+"},
				{Type: token.INTEGER_LIT, Literal: "2"},
				{Type: token.MULTIPLY, Literal: "*"},
				{Type: token.INTEGER_LIT, Literal: "3"},
				{Type: token.MINUS, Literal: "-"},
				{Type: token.INTEGER_LIT, Literal: "4"},
				{Type: token.DIVIDE, Literal: "/"},
				{Type: token.INTEGER_LIT, Literal: "2"},
				{Type: token.MODULO, Literal: "%"},
				{Type: token.INTEGER_LIT, Literal: "3"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "arithmetic with parentheses",
			input: "(1 + 2) * (3 - 4)",
			expected: []token.Token{
				{Type: token.LPAREN, Literal: "("},
				{Type: token.INTEGER_LIT, Literal: "1"},
				{Type: token.PLUS, Literal: "+"},
				{Type: token.INTEGER_LIT, Literal: "2"},
				{Type: token.RPAREN, Literal: ")"},
				{Type: token.MULTIPLY, Literal: "*"},
				{Type: token.LPAREN, Literal: "("},
				{Type: token.INTEGER_LIT, Literal: "3"},
				{Type: token.MINUS, Literal: "-"},
				{Type: token.INTEGER_LIT, Literal: "4"},
				{Type: token.RPAREN, Literal: ")"},
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

func TestArithmeticOperators_InYARARule(t *testing.T) {
	helper := lexer.NewTestHelper(t)
	input := `rule TestRule {
		meta:
			size_calc = 1024 * 1024
		strings:
			$a = "test"
		condition:
			$a and filesize > 100KB and
			(filesize / 1024) < 1MB and
			filesize % 2 == 0
	}`

	tokens := helper.CollectTokens(input)
	arithmeticCount := 0
	arithmeticOps := []string{}

	for _, tok := range tokens {
		if tok.Type == token.PLUS || tok.Type == token.MINUS || tok.Type == token.MULTIPLY ||
			tok.Type == token.DIVIDE || tok.Type == token.MODULO {
			arithmeticCount++
			arithmeticOps = append(arithmeticOps, tok.Literal)
		}
	}

	expectedOps := []string{"*", "/", "%"}
	if arithmeticCount != len(expectedOps) {
		t.Errorf("Expected %d arithmetic operators, got %d", len(expectedOps), arithmeticCount)
	}

	for i, expected := range expectedOps {
		if i >= len(arithmeticOps) || arithmeticOps[i] != expected {
			t.Errorf("Expected arithmetic op[%d] to be %q, got %q", i, expected, arithmeticOps[i])
		}
	}
}

func TestArithmeticOperators_VsDivisionVsRegex(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	// Test that division operator is properly distinguished from regex
	helper.AssertTokenSequence("8 / 2", lexer.CreateTokenSequence(
		token.INTEGER_LIT, "8",
		token.DIVIDE, "/",
		token.INTEGER_LIT, "2",
	))

	// Test that regex is still properly recognized
	helper.AssertSingleToken("/pattern/", token.REGEX_LIT, "/pattern/")

	// Test that line comments are still properly handled (should be skipped)
	helper.AssertTokenSequence("8 // comment\n/ 2", lexer.CreateTokenSequence(
		token.INTEGER_LIT, "8",
		token.DIVIDE, "/",
		token.INTEGER_LIT, "2",
	))
}
