// Package token defines the token types and structures used by the YARA lexer.
package token

import "fmt"

// Position represents a position in the source code.
type Position struct {
	Filename string // Filename is the name of the file containing this position.
	Offset   int    // Offset is the byte offset from the start of the file.
	Line     int    // Line is the 1-based line number.
	Column   int    // Column is the 1-based column number.
}

// TokenType represents the type of a lexical token.
type TokenType int

// Token types for YARA language constructs.
const (
	RULE   TokenType = iota
	LENGTH TokenType = iota
	META
	STRINGS
	CONDITION
	AND
	OR
	NOT
	ALL
	ANY
	NONE
	OF
	TRUE
	FALSE
	// String modifiers
	NOCASE
	WIDE
	ASCII
	FULLWORD
	PRIVATE
	XOR
	BASE64
	BASE64WIDE
	// Bitwise operators
	BITWISE_AND
	BITWISE_OR
	BITWISE_XOR
	BITWISE_NOT
	LEFT_SHIFT
	RIGHT_SHIFT
	// Data type functions
	INT8
	INT16
	INT32
	UINT8
	UINT16
	UINT32
	INT8BE
	INT16BE
	INT32BE
	UINT8BE
	UINT16BE
	UINT32BE
	// File operations
	FILESIZE
	ENTRYPOINT
	// Control flow keywords
	FOR
	IN
	AT
	THEM
	DEFINED
	// Rule modifiers
	GLOBAL
	// Import system
	IMPORT
	INCLUDE
	// String operations
	CONTAINS
	ICONTAINS
	STARTSWITH
	ISTARTSWITH
	ENDSWITH
	IENDSWITH
	IEQUALS
	MATCHES
	HASH
	PLUS
	MINUS
	MULTIPLY
	DIVIDE
	MODULO
	ASSIGN
	EQ
	NEQ
	LT
	LE
	GT
	GE
	COLON
	COMMA
	DOT
	IDENTIFIER
	STRING_IDENTIFIER
	INTEGER_LIT
	HEX_INTEGER_LIT
	FLOAT_LIT
	SIZE_LIT
	STRING_LIT
	HEX_STRING_LIT
	REGEX_LIT
	LBRACE
	RBRACE
	LPAREN
	RPAREN
	LBRACKET
	RBRACKET
	ILLEGAL
	EOF
)

// Token represents a lexical token with its type, literal value, and position.
type Token struct {
	Type    TokenType // Type is the type of the token.
	Literal string    // Literal is the literal value of the token.
	Pos     Position  // Pos is the position of the token in the source.
}

var tokenTypeNames = map[TokenType]string{
	RULE:              "RULE",
	META:              "META",
	STRINGS:           "STRINGS",
	CONDITION:         "CONDITION",
	AND:               "AND",
	OR:                "OR",
	NOT:               "NOT",
	ALL:               "ALL",
	ANY:               "ANY",
	NONE:              "NONE",
	OF:                "OF",
	TRUE:              "TRUE",
	FALSE:             "FALSE",
	NOCASE:            "NOCASE",
	WIDE:              "WIDE",
	ASCII:             "ASCII",
	FULLWORD:          "FULLWORD",
	PRIVATE:           "PRIVATE",
	XOR:               "XOR",
	BASE64:            "BASE64",
	BASE64WIDE:        "BASE64WIDE",
	BITWISE_AND:       "BITWISE_AND",
	BITWISE_OR:        "BITWISE_OR",
	BITWISE_XOR:       "BITWISE_XOR",
	BITWISE_NOT:       "BITWISE_NOT",
	LEFT_SHIFT:        "LEFT_SHIFT",
	RIGHT_SHIFT:       "RIGHT_SHIFT",
	INT8:              "INT8",
	INT16:             "INT16",
	INT32:             "INT32",
	UINT8:             "UINT8",
	UINT16:            "UINT16",
	UINT32:            "UINT32",
	INT8BE:            "INT8BE",
	INT16BE:           "INT16BE",
	INT32BE:           "INT32BE",
	UINT8BE:           "UINT8BE",
	UINT16BE:          "UINT16BE",
	UINT32BE:          "UINT32BE",
	FILESIZE:          "FILESIZE",
	ENTRYPOINT:        "ENTRYPOINT",
	FOR:               "FOR",
	IN:                "IN",
	AT:                "AT",
	THEM:              "THEM",
	DEFINED:           "DEFINED",
	GLOBAL:            "GLOBAL",
	IMPORT:            "IMPORT",
	INCLUDE:           "INCLUDE",
	CONTAINS:          "CONTAINS",
	ICONTAINS:         "ICONTAINS",
	STARTSWITH:        "STARTSWITH",
	ISTARTSWITH:       "ISTARTSWITH",
	ENDSWITH:          "ENDSWITH",
	IENDSWITH:         "IENDSWITH",
	IEQUALS:           "IEQUALS",
	MATCHES:           "MATCHES",
	HASH:              "HASH",
	LENGTH:            "LENGTH",
	PLUS:              "PLUS",
	MINUS:             "MINUS",
	MULTIPLY:          "MULTIPLY",
	DIVIDE:            "DIVIDE",
	MODULO:            "MODULO",
	ASSIGN:            "ASSIGN",
	EQ:                "EQ",
	NEQ:               "NEQ",
	LT:                "LT",
	LE:                "LE",
	GT:                "GT",
	GE:                "GE",
	COLON:             "COLON",
	COMMA:             "COMMA",
	DOT:               "DOT",
	IDENTIFIER:        "IDENTIFIER",
	STRING_IDENTIFIER: "STRING_IDENTIFIER",
	INTEGER_LIT:       "INTEGER_LIT",
	HEX_INTEGER_LIT:   "HEX_INTEGER_LIT",
	FLOAT_LIT:         "FLOAT_LIT",
	SIZE_LIT:          "SIZE_LIT",
	STRING_LIT:        "STRING_LIT",
	HEX_STRING_LIT:    "HEX_STRING_LIT",
	REGEX_LIT:         "REGEX_LIT",
	LBRACE:            "LBRACE",
	RBRACE:            "RBRACE",
	LPAREN:            "LPAREN",
	RPAREN:            "RPAREN",
	LBRACKET:          "LBRACKET",
	RBRACKET:          "RBRACKET",
	ILLEGAL:           "ILLEGAL",
	EOF:               "EOF",
}

// String returns a string representation of the token type.
func (tt TokenType) String() string {
	if name, ok := tokenTypeNames[tt]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", int(tt))
}

// String returns a string representation of the token for debugging.
func (t Token) String() string {
	return fmt.Sprintf("{%v %q @ %d:%d}", t.Type, t.Literal, t.Pos.Line, t.Pos.Column)
}
