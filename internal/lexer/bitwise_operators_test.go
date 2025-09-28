package lexer_test

import (
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func TestBitwiseOperators_Basic(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	tests := []struct {
		name     string
		input    string
		expected token.TokenType
	}{
		{"bitwise_and", "&", token.BITWISE_AND},
		{"bitwise_or", "|", token.BITWISE_OR},
		{"bitwise_xor", "^", token.BITWISE_XOR},
		{"bitwise_not", "~", token.BITWISE_NOT},
		{"left_shift", "<<", token.LEFT_SHIFT},
		{"right_shift", ">>", token.RIGHT_SHIFT},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			helper.AssertSingleToken(tt.input, tt.expected, tt.input)
		})
	}
}

func TestBitwiseOperators_InExpressions(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	tests := []struct {
		name     string
		input    string
		expected []token.Token
	}{
		{
			name:  "bitwise and expression",
			input: "value & 0xFF",
			expected: []token.Token{
				{Type: token.IDENTIFIER, Literal: "value"},
				{Type: token.BITWISE_AND, Literal: "&"},
				{Type: token.HEX_INTEGER_LIT, Literal: "0xFF"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "bitwise or expression",
			input: "flags | 0x01",
			expected: []token.Token{
				{Type: token.IDENTIFIER, Literal: "flags"},
				{Type: token.BITWISE_OR, Literal: "|"},
				{Type: token.HEX_INTEGER_LIT, Literal: "0x01"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "bitwise xor expression",
			input: "data ^ 0xAA",
			expected: []token.Token{
				{Type: token.IDENTIFIER, Literal: "data"},
				{Type: token.BITWISE_XOR, Literal: "^"},
				{Type: token.HEX_INTEGER_LIT, Literal: "0xAA"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "bitwise not expression",
			input: "~value",
			expected: []token.Token{
				{Type: token.BITWISE_NOT, Literal: "~"},
				{Type: token.IDENTIFIER, Literal: "value"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "left shift expression",
			input: "size << 2",
			expected: []token.Token{
				{Type: token.IDENTIFIER, Literal: "size"},
				{Type: token.LEFT_SHIFT, Literal: "<<"},
				{Type: token.INTEGER_LIT, Literal: "2"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "right shift expression",
			input: "filesize >> 10",
			expected: []token.Token{
				{Type: token.FILESIZE, Literal: "filesize"},
				{Type: token.RIGHT_SHIFT, Literal: ">>"},
				{Type: token.INTEGER_LIT, Literal: "10"},
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

func TestBitwiseOperators_ComplexExpressions(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	tests := []struct {
		name     string
		input    string
		expected []token.Token
	}{
		{
			name:  "combined bitwise operations",
			input: "(value & 0xFF00) >> 8",
			expected: []token.Token{
				{Type: token.LPAREN, Literal: "("},
				{Type: token.IDENTIFIER, Literal: "value"},
				{Type: token.BITWISE_AND, Literal: "&"},
				{Type: token.HEX_INTEGER_LIT, Literal: "0xFF00"},
				{Type: token.RPAREN, Literal: ")"},
				{Type: token.RIGHT_SHIFT, Literal: ">>"},
				{Type: token.INTEGER_LIT, Literal: "8"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "bitwise with arithmetic",
			input: "~value + 1",
			expected: []token.Token{
				{Type: token.BITWISE_NOT, Literal: "~"},
				{Type: token.IDENTIFIER, Literal: "value"},
				{Type: token.PLUS, Literal: "+"},
				{Type: token.INTEGER_LIT, Literal: "1"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "shift with comparison",
			input: "(size << 1) > 1024",
			expected: []token.Token{
				{Type: token.LPAREN, Literal: "("},
				{Type: token.IDENTIFIER, Literal: "size"},
				{Type: token.LEFT_SHIFT, Literal: "<<"},
				{Type: token.INTEGER_LIT, Literal: "1"},
				{Type: token.RPAREN, Literal: ")"},
				{Type: token.GT, Literal: ">"},
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

func TestBitwiseOperators_ConflictResolution(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	// Test that shift operators don't conflict with comparison operators
	tests := []struct {
		name     string
		input    string
		expected []token.Token
	}{
		{
			name:  "less than vs left shift",
			input: "a < b << c",
			expected: []token.Token{
				{Type: token.IDENTIFIER, Literal: "a"},
				{Type: token.LT, Literal: "<"},
				{Type: token.IDENTIFIER, Literal: "b"},
				{Type: token.LEFT_SHIFT, Literal: "<<"},
				{Type: token.IDENTIFIER, Literal: "c"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "greater than vs right shift",
			input: "a > b >> c",
			expected: []token.Token{
				{Type: token.IDENTIFIER, Literal: "a"},
				{Type: token.GT, Literal: ">"},
				{Type: token.IDENTIFIER, Literal: "b"},
				{Type: token.RIGHT_SHIFT, Literal: ">>"},
				{Type: token.IDENTIFIER, Literal: "c"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "less than or equal vs left shift",
			input: "a <= b << c",
			expected: []token.Token{
				{Type: token.IDENTIFIER, Literal: "a"},
				{Type: token.LE, Literal: "<="},
				{Type: token.IDENTIFIER, Literal: "b"},
				{Type: token.LEFT_SHIFT, Literal: "<<"},
				{Type: token.IDENTIFIER, Literal: "c"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "greater than or equal vs right shift",
			input: "a >= b >> c",
			expected: []token.Token{
				{Type: token.IDENTIFIER, Literal: "a"},
				{Type: token.GE, Literal: ">="},
				{Type: token.IDENTIFIER, Literal: "b"},
				{Type: token.RIGHT_SHIFT, Literal: ">>"},
				{Type: token.IDENTIFIER, Literal: "c"},
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

func TestBitwiseOperators_InYARARule(t *testing.T) {
	helper := lexer.NewTestHelper(t)
	input := `rule BitwiseTest {
		meta:
			mask = 0xFF00
		strings:
			$a = "test"
		condition:
			$a and
			uint32(0) & 0xFF00 == 0x4D00 and
			(filesize >> 10) < 1024 and
			~uint16(2) == 0xFFFF and
			(flags | 0x01) != 0
	}`

	tokens := helper.CollectTokens(input)
	bitwiseCount := 0
	bitwiseOps := []string{}

	for _, tok := range tokens {
		if tok.Type == token.BITWISE_AND || tok.Type == token.BITWISE_OR ||
			tok.Type == token.BITWISE_XOR || tok.Type == token.BITWISE_NOT ||
			tok.Type == token.LEFT_SHIFT || tok.Type == token.RIGHT_SHIFT {
			bitwiseCount++
			bitwiseOps = append(bitwiseOps, tok.Literal)
		}
	}

	expectedOps := []string{"&", ">>", "~", "|"}
	if bitwiseCount != len(expectedOps) {
		t.Errorf("Expected %d bitwise operators, got %d", len(expectedOps), bitwiseCount)
	}

	for i, expectedOp := range expectedOps {
		if i < len(bitwiseOps) && bitwiseOps[i] != expectedOp {
			t.Errorf("Expected bitwise operator %q at position %d, got %q", expectedOp, i, bitwiseOps[i])
		}
	}
}
