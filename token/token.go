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

// String formats the position as filename:line:column or line L, column C.
func (p Position) String() string {
	if p.Filename != "" {
		return fmt.Sprintf("%s:%d:%d", p.Filename, p.Line, p.Column)
	}
	if p.Line > 0 || p.Column > 0 {
		return fmt.Sprintf("line %d, column %d", p.Line, p.Column)
	}
	return "0:0"
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
	EXTERNAL:         "EXTERNAL",
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

var tokenDisplayNames = map[Type]string{
	RULE:             "'rule'",
	META:             "'meta'",
	STRINGS:          "'strings'",
	EVIDENCE:         "'evidence'",
	CONDITION:        "'condition'",
	AND:              "'and'",
	OR:               "'or'",
	NOT:              "'not'",
	ALL:              "'all'",
	ANY:              "'any'",
	NONE:             "'none'",
	OF:               "'of'",
	TRUE:             "'true'",
	FALSE:            "'false'",
	NOCASE:           "'nocase'",
	WIDE:             "'wide'",
	ASCII:            "'ascii'",
	FULLWORD:         "'fullword'",
	PRIVATE:          "'private'",
	XOR:              "'xor'",
	BASE64:           "'base64'",
	BASE64WIDE:       "'base64wide'",
	CAPTURE:          "'capture'",
	BitwiseAnd:       "'&'",
	BitwiseOr:        "'|'",
	BitwiseXor:       "'^'",
	BitwiseNot:       "'~'",
	LeftShift:        "'<<'",
	RightShift:       "'>>'",
	INT8:             "'int8'",
	INT16:            "'int16'",
	INT32:            "'int32'",
	UINT8:            "'uint8'",
	UINT16:           "'uint16'",
	UINT32:           "'uint32'",
	INT8BE:           "'int8be'",
	INT16BE:          "'int16be'",
	INT32BE:          "'int32be'",
	UINT8BE:          "'uint8be'",
	UINT16BE:         "'uint16be'",
	UINT32BE:         "'uint32be'",
	INT64:            "'int64'",
	UINT64:           "'uint64'",
	INT64BE:          "'int64be'",
	UINT64BE:         "'uint64be'",
	FILESIZE:         "'filesize'",
	ENTRYPOINT:       "'entrypoint'",
	StringCount:      "'#'",
	StringLength:     "'!'",
	FOR:              "'for'",
	IN:               "'in'",
	AT:               "'at'",
	WITHIN:           "'within'",
	THEM:             "'them'",
	DEFINED:          "'defined'",
	GLOBAL:           "'global'",
	EXTERNAL:         "'external'",
	IMPORT:           "'import'",
	INCLUDE:          "'include'",
	CONTAINS:         "'contains'",
	ICONTAINS:        "'icontains'",
	STARTSWITH:       "'startswith'",
	ISTARTSWITH:      "'istartswith'",
	ENDSWITH:         "'endswith'",
	IENDSWITH:        "'iendswith'",
	IEQUALS:          "'iequals'",
	MATCHES:          "'matches'",
	HASH:             "'hash'",
	LENGTH:           "'length'",
	PLUS:             "'+'",
	MINUS:            "'-'",
	MULTIPLY:         "'*'",
	DIVIDE:           "'/'",
	MODULO:           "'%'",
	PERCENT:          "'%'",
	IntDivide:        "'\\'",
	ASSIGN:           "'='",
	EQ:               "'=='",
	NEQ:              "'!='",
	LT:               "'<'",
	LE:               "'<='",
	GT:               "'>'",
	GE:               "'>='",
	COLON:            "':'",
	COMMA:            "','",
	DOT:              "'.'",
	IDENTIFIER:       "identifier",
	StringIdentifier: "string identifier",
	IntegerLit:       "integer",
	HexIntegerLit:    "hex integer",
	OctalIntegerLit:  "octal integer",
	FloatLit:         "float",
	SizeLit:          "size literal",
	StringLit:        "string literal",
	HexStringLit:     "hex string",
	RegexLit:         "regex literal",
	LBRACE:           "'{'",
	RBRACE:           "'}'",
	LPAREN:           "'('",
	RPAREN:           "')'",
	LBRACKET:         "'['",
	RBRACKET:         "']'",
	ILLEGAL:          "illegal token",
	EOF:              "end of file",
}

// String returns a string representation of the token type.
func (tt Type) String() string {
	if name, ok := tokenTypeNames[tt]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", int(tt))
}

// Display returns a human-readable source form of the token type for diagnostics.
func (tt Type) Display() string {
	if name, ok := tokenDisplayNames[tt]; ok {
		return name
	}
	return tt.String()
}

// String returns a string representation of the token for debugging.
func (t Token) String() string {
	return fmt.Sprintf("{%v %q @ %d:%d}", t.Type, t.Literal, t.Pos.Line, t.Pos.Column)
}

// Display returns a user-facing description of the token for error messages.
func (t Token) Display() string {
	switch t.Type {
	case IDENTIFIER:
		if t.Literal != "" {
			return fmt.Sprintf("identifier %q", t.Literal)
		}
	case StringIdentifier:
		if t.Literal != "" {
			return "string identifier " + t.Literal
		}
	case ILLEGAL:
		if t.Literal != "" {
			return fmt.Sprintf("illegal token %q", t.Literal)
		}
	}
	return t.Type.Display()
}
