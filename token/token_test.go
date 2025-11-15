package token

import (
	"fmt"
	"testing"
)

// Test Type String method
func TestTypeString(t *testing.T) {
	// Define test cases with logical grouping
	testGroups := map[string][]struct {
		tokenType Type
		expected  string
	}{
		"RuleStructure": {
			{RULE, "RULE"}, {META, "META"}, {STRINGS, "STRINGS"}, {CONDITION, "CONDITION"},
		},
		"LogicalOperators": {
			{AND, "AND"}, {OR, "OR"}, {NOT, "NOT"}, {ALL, "ALL"}, {ANY, "ANY"}, {NONE, "NONE"}, {OF, "OF"},
		},
		"BooleanLiterals": {
			{TRUE, "TRUE"}, {FALSE, "FALSE"},
		},
		"StringModifiers": {
			{NOCASE, "NOCASE"}, {WIDE, "WIDE"}, {ASCII, "ASCII"}, {FULLWORD, "FULLWORD"},
			{PRIVATE, "PRIVATE"}, {XOR, "XOR"}, {BASE64, "BASE64"}, {BASE64WIDE, "BASE64WIDE"},
		},
		"BitwiseOperators": {
			{BitwiseAnd, "BITWISE_AND"}, {BitwiseOr, "BITWISE_OR"}, {BitwiseXor, "BITWISE_XOR"},
			{BitwiseNot, "BITWISE_NOT"}, {LeftShift, "LEFT_SHIFT"}, {RightShift, "RIGHT_SHIFT"},
		},
		"IntegerTypes": {
			{INT8, "INT8"}, {INT16, "INT16"}, {INT32, "INT32"}, {UINT8, "UINT8"}, {UINT16, "UINT16"}, {UINT32, "UINT32"},
			{INT8BE, "INT8BE"}, {INT16BE, "INT16BE"}, {INT32BE, "INT32BE"}, {UINT8BE, "UINT8BE"}, {UINT16BE, "UINT16BE"}, {UINT32BE, "UINT32BE"},
		},
		"SpecialVariables": {
			{FILESIZE, "FILESIZE"}, {ENTRYPOINT, "ENTRYPOINT"}, {FOR, "FOR"}, {IN, "IN"}, {AT, "AT"},
			{THEM, "THEM"}, {DEFINED, "DEFINED"}, {GLOBAL, "GLOBAL"}, {IMPORT, "IMPORT"}, {INCLUDE, "INCLUDE"},
		},
		"StringOperations": {
			{CONTAINS, "CONTAINS"}, {ICONTAINS, "ICONTAINS"}, {STARTSWITH, "STARTSWITH"}, {ISTARTSWITH, "ISTARTSWITH"},
			{ENDSWITH, "ENDSWITH"}, {IENDSWITH, "IENDSWITH"}, {IEQUALS, "IEQUALS"}, {MATCHES, "MATCHES"}, {HASH, "HASH"},
		},
		"ArithmeticOperators": {
			{PLUS, "PLUS"}, {MINUS, "MINUS"}, {MULTIPLY, "MULTIPLY"}, {DIVIDE, "DIVIDE"}, {MODULO, "MODULO"},
		},
		"ComparisonOperators": {
			{ASSIGN, "ASSIGN"}, {EQ, "EQ"}, {NEQ, "NEQ"}, {LT, "LT"}, {LE, "LE"}, {GT, "GT"}, {GE, "GE"},
		},
		"Punctuation": {
			{COLON, "COLON"}, {COMMA, "COMMA"}, {DOT, "DOT"},
		},
		"IdentifiersAndLiterals": {
			{IDENTIFIER, "IDENTIFIER"}, {StringIdentifier, "StringIdentifier"}, {IntegerLit, "IntegerLit"},
			{HexIntegerLit, "HexIntegerLit"}, {SizeLit, "SizeLit"}, {StringLit, "StringLit"},
			{HexStringLit, "HexStringLit"}, {RegexLit, "RegexLit"},
		},
		"BracketsAndBraces": {
			{LBRACE, "LBRACE"}, {RBRACE, "RBRACE"}, {LPAREN, "LPAREN"}, {RPAREN, "RPAREN"}, {LBRACKET, "LBRACKET"}, {RBRACKET, "RBRACKET"},
		},
		"SpecialTokens": {
			{ILLEGAL, "ILLEGAL"}, {EOF, "EOF"},
		},
		"UnknownToken": {
			{Type(999), "UNKNOWN(999)"}, // Test unknown token type
		},
	}

	for groupName, tests := range testGroups {
		t.Run(groupName, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.expected, func(t *testing.T) {
					result := tt.tokenType.String()
					if result != tt.expected {
						t.Errorf("Type(%d).String() = %v, want %v", int(tt.tokenType), result, tt.expected)
					}
				})
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
				Type:    StringLit,
				Literal: "hello world",
				Pos:     Position{Line: 2, Column: 10},
			},
			expected: "{StringLit \"hello world\" @ 2:10}",
		},
		{
			name: "number token",
			token: Token{
				Type:    IntegerLit,
				Literal: "42",
				Pos:     Position{Line: 3, Column: 15},
			},
			expected: "{IntegerLit \"42\" @ 3:15}",
		},
		{
			name: "token with quotes in literal",
			token: Token{
				Type:    StringLit,
				Literal: "hello \"world\"",
				Pos:     Position{Line: 4, Column: 8},
			},
			expected: "{StringLit \"hello \\\"world\\\"\" @ 4:8}",
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

// ExamplePosition demonstrates creating and using a Position struct.
func ExamplePosition() {
	pos := Position{
		Filename: "rule.yar",
		Offset:   50,
		Line:     3,
		Column:   8,
	}
	fmt.Printf("Position: %s:%d:%d (offset %d)\n", pos.Filename, pos.Line, pos.Column, pos.Offset)
	// Output: Position: rule.yar:3:8 (offset 50)
}

// ExampleType_String demonstrates the String method on Type.
func ExampleType_String() {
	fmt.Println(RULE.String())
	fmt.Println(IDENTIFIER.String())
	fmt.Println(EOF.String())
	// Output:
	// RULE
	// IDENTIFIER
	// EOF
}

// ExampleToken_String demonstrates the String method on Token.
func ExampleToken_String() {
	tok := Token{
		Type:    IDENTIFIER,
		Literal: "example",
		Pos:     Position{Line: 1, Column: 5},
	}
	fmt.Println(tok.String())
	// Output: {IDENTIFIER "example" @ 1:5}
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
