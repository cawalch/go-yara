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

// Type represents the type of a lexical token.
type Type int

// Token types for YARA language constructs.
const (
	RULE   Type = iota
	LENGTH Type = iota
	META
	STRINGS
	EVIDENCE
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
	// NOCASE string modifier
	NOCASE
	WIDE
	ASCII
	FULLWORD
	PRIVATE
	XOR
	BASE64
	BASE64WIDE
	CAPTURE
	// BitwiseAnd bitwise AND operator
	BitwiseAnd
	BitwiseOr
	BitwiseXor
	BitwiseNot
	LeftShift
	RightShift
	// INT8 data type function
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
	// Additional data types (missing from current implementation)
	INT64
	UINT64
	INT64BE
	UINT64BE
	// FILESIZE file operation
	FILESIZE
	ENTRYPOINT
	// STRING_COUNT string count operator (#)
	StringCount
	// STRING_LENGTH string match length operator (!)
	StringLength
	// FOR control flow keyword
	FOR
	IN
	AT
	WITHIN
	THEM
	DEFINED
	// GLOBAL rule modifier
	GLOBAL
	EXTERNAL
	// IMPORT import system
	IMPORT
	INCLUDE
	// CONTAINS string operation
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
	PERCENT
	IntDivide
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
	StringIdentifier
	IntegerLit
	HexIntegerLit
	OctalIntegerLit
	FloatLit
	SizeLit
	StringLit
	HexStringLit
	RegexLit
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
	Type    Type     // Type is the type of the token.
	Literal string   // Literal is the literal value of the token.
	Pos     Position // Pos is the position of the token in the source.
}

var tokenTypeNames = map[Type]string{
	RULE:             "RULE",
	META:             "META",
	STRINGS:          "STRINGS",
	EVIDENCE:         "EVIDENCE",
	CONDITION:        "CONDITION",
	AND:              "AND",
	OR:               "OR",
	NOT:              "NOT",
	ALL:              "ALL",
	ANY:              "ANY",
	NONE:             "NONE",
	OF:               "OF",
	TRUE:             "TRUE",
	FALSE:            "FALSE",
	NOCASE:           "NOCASE",
	WIDE:             "WIDE",
	ASCII:            "ASCII",
	FULLWORD:         "FULLWORD",
	PRIVATE:          "PRIVATE",
	XOR:              "XOR",
	BASE64:           "BASE64",
	BASE64WIDE:       "BASE64WIDE",
	CAPTURE:          "CAPTURE",
	BitwiseAnd:       "BITWISE_AND",
	BitwiseOr:        "BITWISE_OR",
	BitwiseXor:       "BITWISE_XOR",
	BitwiseNot:       "BITWISE_NOT",
	LeftShift:        "LEFT_SHIFT",
	RightShift:       "RIGHT_SHIFT",
	INT8:             "INT8",
	INT16:            "INT16",
	INT32:            "INT32",
	UINT8:            "UINT8",
	UINT16:           "UINT16",
	UINT32:           "UINT32",
	INT8BE:           "INT8BE",
	INT16BE:          "INT16BE",
	INT32BE:          "INT32BE",
	UINT8BE:          "UINT8BE",
	UINT16BE:         "UINT16BE",
	UINT32BE:         "UINT32BE",
	INT64:            "int64",
	UINT64:           "uint64",
	INT64BE:          "int64be",
	UINT64BE:         "uint64be",
	FILESIZE:         "FILESIZE",
	ENTRYPOINT:       "ENTRYPOINT",
	StringCount:      "#",
	StringLength:     "!",
	FOR:              "FOR",
	IN:               "IN",
	AT:               "AT",
	WITHIN:           "WITHIN",
	THEM:             "THEM",
	DEFINED:          "DEFINED",
	GLOBAL:           "GLOBAL",
	IMPORT:           "IMPORT",
	INCLUDE:          "INCLUDE",
	CONTAINS:         "CONTAINS",
	ICONTAINS:        "ICONTAINS",
	STARTSWITH:       "STARTSWITH",
	ISTARTSWITH:      "ISTARTSWITH",
	ENDSWITH:         "ENDSWITH",
	IENDSWITH:        "IENDSWITH",
	IEQUALS:          "IEQUALS",
	MATCHES:          "MATCHES",
	HASH:             "HASH",
	LENGTH:           "LENGTH",
	PLUS:             "PLUS",
	MINUS:            "MINUS",
	MULTIPLY:         "MULTIPLY",
	DIVIDE:           "DIVIDE",
	MODULO:           "MODULO",
	PERCENT:          "PERCENT",
	IntDivide:        "IntDivide",
	ASSIGN:           "ASSIGN",
	EQ:               "EQ",
	NEQ:              "NEQ",
	LT:               "LT",
	LE:               "LE",
	GT:               "GT",
	GE:               "GE",
	COLON:            "COLON",
	COMMA:            "COMMA",
	DOT:              "DOT",
	IDENTIFIER:       "IDENTIFIER",
	StringIdentifier: "StringIdentifier",
	IntegerLit:       "IntegerLit",
	HexIntegerLit:    "HexIntegerLit",
	OctalIntegerLit:  "OctalIntegerLit",
	FloatLit:         "FloatLit",
	SizeLit:          "SizeLit",
	StringLit:        "StringLit",
	HexStringLit:     "HexStringLit",
	RegexLit:         "RegexLit",
	LBRACE:           "LBRACE",
	RBRACE:           "RBRACE",
	LPAREN:           "LPAREN",
	RPAREN:           "RPAREN",
	LBRACKET:         "LBRACKET",
	RBRACKET:         "RBRACKET",
	ILLEGAL:          "ILLEGAL",
	EOF:              "EOF",
}

// String returns a string representation of the token type.
func (tt Type) String() string {
	if name, ok := tokenTypeNames[tt]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", int(tt))
}

// String returns a string representation of the token for debugging.
func (t Token) String() string {
	return fmt.Sprintf("{%v %q @ %d:%d}", t.Type, t.Literal, t.Pos.Line, t.Pos.Column)
}
