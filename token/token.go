// Package token defines the token types and structures used by the YARA lexer.
package token

import "fmt"

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

// String returns a string representation of the token type
func (tt TokenType) String() string {
	switch tt {
	case RULE: return "RULE"
	case META: return "META"
	case STRINGS: return "STRINGS"
	case CONDITION: return "CONDITION"
	case AND: return "AND"
	case OR: return "OR"
	case NOT: return "NOT"
	case ALL: return "ALL"
	case ANY: return "ANY"
	case NONE: return "NONE"
	case OF: return "OF"
	case TRUE: return "TRUE"
	case FALSE: return "FALSE"
	case NOCASE: return "NOCASE"
	case WIDE: return "WIDE"
	case ASCII: return "ASCII"
	case FULLWORD: return "FULLWORD"
	case PRIVATE: return "PRIVATE"
	case XOR: return "XOR"
	case BASE64: return "BASE64"
	case BASE64WIDE: return "BASE64WIDE"
	case BITWISE_AND: return "BITWISE_AND"
	case BITWISE_OR: return "BITWISE_OR"
	case BITWISE_XOR: return "BITWISE_XOR"
	case BITWISE_NOT: return "BITWISE_NOT"
	case LEFT_SHIFT: return "LEFT_SHIFT"
	case RIGHT_SHIFT: return "RIGHT_SHIFT"
	case INT8: return "INT8"
	case INT16: return "INT16"
	case INT32: return "INT32"
	case UINT8: return "UINT8"
	case UINT16: return "UINT16"
	case UINT32: return "UINT32"
	case INT8BE: return "INT8BE"
	case INT16BE: return "INT16BE"
	case INT32BE: return "INT32BE"
	case UINT8BE: return "UINT8BE"
	case UINT16BE: return "UINT16BE"
	case UINT32BE: return "UINT32BE"
	case FILESIZE: return "FILESIZE"
	case ENTRYPOINT: return "ENTRYPOINT"
	case FOR: return "FOR"
	case IN: return "IN"
	case AT: return "AT"
	case THEM: return "THEM"
	case DEFINED: return "DEFINED"
	case GLOBAL: return "GLOBAL"
	case IMPORT: return "IMPORT"
	case INCLUDE: return "INCLUDE"
	case CONTAINS: return "CONTAINS"
	case ICONTAINS: return "ICONTAINS"
	case STARTSWITH: return "STARTSWITH"
	case ISTARTSWITH: return "ISTARTSWITH"
	case ENDSWITH: return "ENDSWITH"
	case IENDSWITH: return "IENDSWITH"
	case IEQUALS: return "IEQUALS"
	case MATCHES: return "MATCHES"
	case HASH: return "HASH"
	case PLUS: return "PLUS"
	case MINUS: return "MINUS"
	case MULTIPLY: return "MULTIPLY"
	case DIVIDE: return "DIVIDE"
	case MODULO: return "MODULO"
	case ASSIGN: return "ASSIGN"
	case EQ: return "EQ"
	case NEQ: return "NEQ"
	case LT: return "LT"
	case LE: return "LE"
	case GT: return "GT"
	case GE: return "GE"
	case COLON: return "COLON"
	case COMMA: return "COMMA"
	case DOT: return "DOT"
	case IDENTIFIER: return "IDENTIFIER"
	case STRING_IDENTIFIER: return "STRING_IDENTIFIER"
	case INTEGER_LIT: return "INTEGER_LIT"
	case HEX_INTEGER_LIT: return "HEX_INTEGER_LIT"
	case SIZE_LIT: return "SIZE_LIT"
	case STRING_LIT: return "STRING_LIT"
	case HEX_STRING_LIT: return "HEX_STRING_LIT"
	case REGEX_LIT: return "REGEX_LIT"
	case LBRACE: return "LBRACE"
	case RBRACE: return "RBRACE"
	case LPAREN: return "LPAREN"
	case RPAREN: return "RPAREN"
	case LBRACKET: return "LBRACKET"
	case RBRACKET: return "RBRACKET"
	case ILLEGAL: return "ILLEGAL"
	case EOF: return "EOF"
	default: return fmt.Sprintf("UNKNOWN(%d)", int(tt))
	}
}

// String returns a string representation of the token for debugging
func (t Token) String() string {
	return fmt.Sprintf("{%v %q @ %d:%d}", t.Type, t.Literal, t.Pos.Line, t.Pos.Column)
}