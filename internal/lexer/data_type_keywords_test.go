package lexer_test

import (
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func TestDataTypeKeywords_Basic(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	tests := []struct {
		name     string
		input    string
		expected token.TokenType
	}{
		// Little-endian data types
		{"int8", "int8", token.INT8},
		{"int16", "int16", token.INT16},
		{"int32", "int32", token.INT32},
		{"uint8", "uint8", token.UINT8},
		{"uint16", "uint16", token.UINT16},
		{"uint32", "uint32", token.UINT32},
		// Big-endian data types
		{"int8be", "int8be", token.INT8BE},
		{"int16be", "int16be", token.INT16BE},
		{"int32be", "int32be", token.INT32BE},
		{"uint8be", "uint8be", token.UINT8BE},
		{"uint16be", "uint16be", token.UINT16BE},
		{"uint32be", "uint32be", token.UINT32BE},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			helper.AssertSingleToken(tt.input, tt.expected, tt.input)
		})
	}
}

func TestDataTypeKeywords_CaseSensitive(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	// Test that data type keywords are case-sensitive (only lowercase recognized)
	tests := []struct {
		name     string
		input    string
		expected token.TokenType
	}{
		{"uint32_lowercase", "uint32", token.UINT32},
		{"UINT32_uppercase", "UINT32", token.IDENTIFIER}, // Should be identifier, not keyword
		{"Uint32_mixed", "Uint32", token.IDENTIFIER},     // Should be identifier, not keyword
		{"int16be_lowercase", "int16be", token.INT16BE},
		{"INT16BE_uppercase", "INT16BE", token.IDENTIFIER}, // Should be identifier, not keyword
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			helper.AssertSingleToken(tt.input, tt.expected, tt.input)
		})
	}
}

func TestDataTypeKeywords_InFunctionCalls(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	tests := []struct {
		name     string
		input    string
		expected []token.Token
	}{
		{
			name:  "uint32 function call",
			input: "uint32(0)",
			expected: []token.Token{
				{Type: token.UINT32, Literal: "uint32"},
				{Type: token.LPAREN, Literal: "("},
				{Type: token.IntegerLit, Literal: "0"},
				{Type: token.RPAREN, Literal: ")"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "int16be function call with hex",
			input: "int16be(0x1000)",
			expected: []token.Token{
				{Type: token.INT16BE, Literal: "int16be"},
				{Type: token.LPAREN, Literal: "("},
				{Type: token.HexIntegerLit, Literal: "0x1000"},
				{Type: token.RPAREN, Literal: ")"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "uint8 function call with variable",
			input: "uint8(offset)",
			expected: []token.Token{
				{Type: token.UINT8, Literal: "uint8"},
				{Type: token.LPAREN, Literal: "("},
				{Type: token.IDENTIFIER, Literal: "offset"},
				{Type: token.RPAREN, Literal: ")"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "int32 function call with expression",
			input: "int32(entrypoint + 4)",
			expected: []token.Token{
				{Type: token.INT32, Literal: "int32"},
				{Type: token.LPAREN, Literal: "("},
				{Type: token.ENTRYPOINT, Literal: "entrypoint"},
				{Type: token.PLUS, Literal: "+"},
				{Type: token.IntegerLit, Literal: "4"},
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

func TestDataTypeKeywords_InExpressions(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	tests := []struct {
		name     string
		input    string
		expected []token.Token
	}{
		{
			name:  "data type in comparison",
			input: "uint32(0) == 0x5A4D",
			expected: []token.Token{
				{Type: token.UINT32, Literal: "uint32"},
				{Type: token.LPAREN, Literal: "("},
				{Type: token.IntegerLit, Literal: "0"},
				{Type: token.RPAREN, Literal: ")"},
				{Type: token.EQ, Literal: "=="},
				{Type: token.HexIntegerLit, Literal: "0x5A4D"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "data type with bitwise operation",
			input: "uint16(2) & 0xFF00",
			expected: []token.Token{
				{Type: token.UINT16, Literal: "uint16"},
				{Type: token.LPAREN, Literal: "("},
				{Type: token.IntegerLit, Literal: "2"},
				{Type: token.RPAREN, Literal: ")"},
				{Type: token.BitwiseAnd, Literal: "&"},
				{Type: token.HexIntegerLit, Literal: "0xFF00"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "big-endian data type",
			input: "int16be(offset) > 0",
			expected: []token.Token{
				{Type: token.INT16BE, Literal: "int16be"},
				{Type: token.LPAREN, Literal: "("},
				{Type: token.IDENTIFIER, Literal: "offset"},
				{Type: token.RPAREN, Literal: ")"},
				{Type: token.GT, Literal: ">"},
				{Type: token.IntegerLit, Literal: "0"},
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

func TestDataTypeKeywords_AllTypesInSequence(t *testing.T) {
	input := "int8 int16 int32 uint8 uint16 uint32 int8be int16be int32be uint8be uint16be uint32be"

	expected := []token.TokenType{
		token.INT8,
		token.INT16,
		token.INT32,
		token.UINT8,
		token.UINT16,
		token.UINT32,
		token.INT8BE,
		token.INT16BE,
		token.INT32BE,
		token.UINT8BE,
		token.UINT16BE,
		token.UINT32BE,
		token.EOF,
	}

	l := lexer.New(input)
	for i, expectedType := range expected {
		tok := l.NextToken()
		if tok.Type != expectedType {
			t.Errorf("token %d: expected type %v, got %v", i, expectedType, tok.Type)
		}
	}
}

func TestDataTypeKeywords_InYARARule(t *testing.T) {
	helper := lexer.NewTestHelper(t)
	input := `rule DataTypeTest {
		meta:
			description = "Test data type functions"
		strings:
			$a = "test"
		condition:
			$a and
			uint32(0) == 0x5A4D and
			int16be(entrypoint + 4) > 0 and
			(uint16(2) & 0xFF00) == 0x4D00 and
			uint8(filesize - 1) != 0x00
	}`

	tokens := helper.CollectTokens(input)
	dataTypeCount := 0
	dataTypeOps := []string{}

	for _, tok := range tokens {
		switch tok.Type {
		case token.INT8, token.INT16, token.INT32, token.UINT8, token.UINT16, token.UINT32,
			token.INT8BE, token.INT16BE, token.INT32BE, token.UINT8BE, token.UINT16BE, token.UINT32BE:
			dataTypeCount++
			dataTypeOps = append(dataTypeOps, tok.Literal)
		}
	}

	expectedOps := []string{"uint32", "int16be", "uint16", "uint8"}
	if dataTypeCount != len(expectedOps) {
		t.Errorf("Expected %d data type functions, got %d", len(expectedOps), dataTypeCount)
	}

	for i, expectedOp := range expectedOps {
		if i < len(dataTypeOps) && dataTypeOps[i] != expectedOp {
			t.Errorf("Expected data type function %q at position %d, got %q", expectedOp, i, dataTypeOps[i])
		}
	}
}

func TestDataTypeKeywords_WithStringModifiers(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	// Test that data type keywords don't conflict with string modifiers
	input := `"test" ascii uint32(0) wide`

	expected := []token.Token{
		{Type: token.StringLit, Literal: `test`},
		{Type: token.ASCII, Literal: "ascii"},
		{Type: token.UINT32, Literal: "uint32"},
		{Type: token.LPAREN, Literal: "("},
		{Type: token.IntegerLit, Literal: "0"},
		{Type: token.RPAREN, Literal: ")"},
		{Type: token.WIDE, Literal: "wide"},
		{Type: token.EOF, Literal: ""},
	}

	helper.AssertTokenSequence(input, expected)
}
