package token

import (
	"testing"
)

// Test TokenType String method
func TestTokenTypeString(t *testing.T) {
	tests := []struct {
		tokenType TokenType
		expected  string
	}{
		{RULE, "RULE"},
		{META, "META"},
		{STRINGS, "STRINGS"},
		{CONDITION, "CONDITION"},
		{AND, "AND"},
		{OR, "OR"},
		{NOT, "NOT"},
		{ALL, "ALL"},
		{ANY, "ANY"},
		{NONE, "NONE"},
		{OF, "OF"},
		{TRUE, "TRUE"},
		{FALSE, "FALSE"},
		{NOCASE, "NOCASE"},
		{WIDE, "WIDE"},
		{ASCII, "ASCII"},
		{FULLWORD, "FULLWORD"},
		{PRIVATE, "PRIVATE"},
		{XOR, "XOR"},
		{BASE64, "BASE64"},
		{BASE64WIDE, "BASE64WIDE"},
		{BITWISE_AND, "BITWISE_AND"},
		{BITWISE_OR, "BITWISE_OR"},
		{BITWISE_XOR, "BITWISE_XOR"},
		{BITWISE_NOT, "BITWISE_NOT"},
		{LEFT_SHIFT, "LEFT_SHIFT"},
		{RIGHT_SHIFT, "RIGHT_SHIFT"},
		{INT8, "INT8"},
		{INT16, "INT16"},
		{INT32, "INT32"},
		{UINT8, "UINT8"},
		{UINT16, "UINT16"},
		{UINT32, "UINT32"},
		{INT8BE, "INT8BE"},
		{INT16BE, "INT16BE"},
		{INT32BE, "INT32BE"},
		{UINT8BE, "UINT8BE"},
		{UINT16BE, "UINT16BE"},
		{UINT32BE, "UINT32BE"},
		{FILESIZE, "FILESIZE"},
		{ENTRYPOINT, "ENTRYPOINT"},
		{FOR, "FOR"},
		{IN, "IN"},
		{AT, "AT"},
		{THEM, "THEM"},
		{DEFINED, "DEFINED"},
		{GLOBAL, "GLOBAL"},
		{IMPORT, "IMPORT"},
		{INCLUDE, "INCLUDE"},
		{CONTAINS, "CONTAINS"},
		{ICONTAINS, "ICONTAINS"},
		{STARTSWITH, "STARTSWITH"},
		{ISTARTSWITH, "ISTARTSWITH"},
		{ENDSWITH, "ENDSWITH"},
		{IENDSWITH, "IENDSWITH"},
		{IEQUALS, "IEQUALS"},
		{MATCHES, "MATCHES"},
		{HASH, "HASH"},
		{PLUS, "PLUS"},
		{MINUS, "MINUS"},
		{MULTIPLY, "MULTIPLY"},
		{DIVIDE, "DIVIDE"},
		{MODULO, "MODULO"},
		{ASSIGN, "ASSIGN"},
		{EQ, "EQ"},
		{NEQ, "NEQ"},
		{LT, "LT"},
		{LE, "LE"},
		{GT, "GT"},
		{GE, "GE"},
		{COLON, "COLON"},
		{COMMA, "COMMA"},
		{DOT, "DOT"},
		{IDENTIFIER, "IDENTIFIER"},
		{STRING_IDENTIFIER, "STRING_IDENTIFIER"},
		{INTEGER_LIT, "INTEGER_LIT"},
		{HEX_INTEGER_LIT, "HEX_INTEGER_LIT"},
		{SIZE_LIT, "SIZE_LIT"},
		{STRING_LIT, "STRING_LIT"},
		{HEX_STRING_LIT, "HEX_STRING_LIT"},
		{REGEX_LIT, "REGEX_LIT"},
		{LBRACE, "LBRACE"},
		{RBRACE, "RBRACE"},
		{LPAREN, "LPAREN"},
		{RPAREN, "RPAREN"},
		{LBRACKET, "LBRACKET"},
		{RBRACKET, "RBRACKET"},
		{ILLEGAL, "ILLEGAL"},
		{EOF, "EOF"},
		{TokenType(999), "UNKNOWN(999)"}, // Test unknown token type
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.tokenType.String()
			if result != tt.expected {
				t.Errorf("TokenType(%d).String() = %v, want %v", int(tt.tokenType), result, tt.expected)
			}
		})
	}
}

// Test Token String method
func TestTokenString(t *testing.T) {
	tests := []struct {
		name     string
		token    Token
		expected string
	}{
		{
			name: "regular token",
			token: Token{
				Type:    IDENTIFIER,
				Literal: "test",
				Pos:     Position{Line: 1, Column: 5},
			},
			expected: "{IDENTIFIER \"test\" @ 1:5}",
		},
		{
			name: "EOF token",
			token: Token{
				Type: EOF,
				Pos:  Position{Line: 10, Column: 20},
			},
			expected: "{EOF \"\" @ 10:20}",
		},
		{
			name: "string literal token",
			token: Token{
				Type:    STRING_LIT,
				Literal: "hello world",
				Pos:     Position{Line: 2, Column: 10},
			},
			expected: "{STRING_LIT \"hello world\" @ 2:10}",
		},
		{
			name: "number token",
			token: Token{
				Type:    INTEGER_LIT,
				Literal: "42",
				Pos:     Position{Line: 3, Column: 15},
			},
			expected: "{INTEGER_LIT \"42\" @ 3:15}",
		},
		{
			name: "token with quotes in literal",
			token: Token{
				Type:    STRING_LIT,
				Literal: "hello \"world\"",
				Pos:     Position{Line: 4, Column: 8},
			},
			expected: "{STRING_LIT \"hello \\\"world\\\"\" @ 4:8}",
		},
		{
			name: "empty literal token",
			token: Token{
				Type:    IDENTIFIER,
				Literal: "",
				Pos:     Position{Line: 1, Column: 1},
			},
			expected: "{IDENTIFIER \"\" @ 1:1}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.token.String()
			if result != tt.expected {
				t.Errorf("Token.String() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// Test Position struct
func TestPosition(t *testing.T) {
	pos := Position{
		Filename: "test.yar",
		Offset:   100,
		Line:     5,
		Column:   10,
	}

	if pos.Filename != "test.yar" {
		t.Errorf("Expected Filename to be 'test.yar', got %s", pos.Filename)
	}

	if pos.Offset != 100 {
		t.Errorf("Expected Offset to be 100, got %d", pos.Offset)
	}

	if pos.Line != 5 {
		t.Errorf("Expected Line to be 5, got %d", pos.Line)
	}

	if pos.Column != 10 {
		t.Errorf("Expected Column to be 10, got %d", pos.Column)
	}
}