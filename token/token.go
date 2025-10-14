// Package token defines the token types and structures used by the YARA lexer.
package token

// Position represents a position in the source code.
type Position struct {
	Filename string
	Offset   int
	Line     int
	Column   int
}

// TokenType represents the type of a lexical token.
type TokenType int

// Token types for YARA language constructs.
const (
	RULE TokenType = iota
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
	// String modifiers (Phase 2)
	NOCASE
	WIDE
	ASCII
	FULLWORD
	PRIVATE
	XOR
	BASE64
	BASE64WIDE
	// Bitwise operators (Phase 3)
	BITWISE_AND
	BITWISE_OR
	BITWISE_XOR
	BITWISE_NOT
	LEFT_SHIFT
	RIGHT_SHIFT
	// Data type functions (Phase 3)
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
	// File operations (Phase 3)
	FILESIZE
	ENTRYPOINT
	// Control flow keywords (Phase 4)
	FOR
	IN
	AT
	THEM
	DEFINED
	// Rule modifiers (Phase 4)
	GLOBAL
	// Import system (Phase 4)
	IMPORT
	INCLUDE
	// String operations (Phase 4)
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
	Type    TokenType
	Literal string
	Pos     Position
}
