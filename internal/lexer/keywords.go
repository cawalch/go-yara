package lexer

import "github.com/cawalch/go-yara/token"

// Keyword lookup and validation functions

// Constants for frequently used keywords to avoid string literals
const (
	KeywordRule      = "rule"
	KeywordStrings   = "strings"
	KeywordCondition = "condition"
)

// keywords maps string identifiers to their corresponding token types
var keywords = map[string]token.TokenType{
	"or":             token.OR,
	"of":             token.OF,
	"and":            token.AND,
	"not":            token.NOT,
	"all":            token.ALL,
	"any":            token.ANY,
	KeywordRule:      token.RULE,
	"meta":           token.META,
	"true":           token.TRUE,
	"none":           token.NONE,
	"false":          token.FALSE,
	KeywordStrings:   token.STRINGS,
	KeywordCondition: token.CONDITION,
	// String modifiers (Phase 2)
	"nocase":     token.NOCASE,
	"wide":       token.WIDE,
	"ascii":      token.ASCII,
	"fullword":   token.FULLWORD,
	"private":    token.PRIVATE,
	"xor":        token.XOR,
	"base64":     token.BASE64,
	"base64wide": token.BASE64WIDE,
	// Data type functions (Phase 3)
	"int8":     token.INT8,
	"int16":    token.INT16,
	"int32":    token.INT32,
	"uint8":    token.UINT8,
	"uint16":   token.UINT16,
	"uint32":   token.UINT32,
	"int8be":   token.INT8BE,
	"int16be":  token.INT16BE,
	"int32be":  token.INT32BE,
	"uint8be":  token.UINT8BE,
	"uint16be": token.UINT16BE,
	"uint32be": token.UINT32BE,
	// File operations (Phase 3)
	"filesize":   token.FILESIZE,
	"entrypoint": token.ENTRYPOINT,
	// Control flow keywords (Phase 4)
	"for":     token.FOR,
	"in":      token.IN,
	"at":      token.AT,
	"them":    token.THEM,
	"defined": token.DEFINED,
	// Rule modifiers (Phase 4)
	"global":   token.GLOBAL,
	"external": token.EXTERNAL,
	// Import system (Phase 4)
	"import":  token.IMPORT,
	"include": token.INCLUDE,
	// String operations (Phase 4)
	"contains":    token.CONTAINS,
	"icontains":   token.ICONTAINS,
	"startswith":  token.STARTSWITH,
	"istartswith": token.ISTARTSWITH,
	"endswith":    token.ENDSWITH,
	"iendswith":   token.IENDSWITH,
	"iequals":     token.IEQUALS,
	"matches":     token.MATCHES,
	"hash":        token.HASH,
	"length":      token.LENGTH,
}

// Interned keyword strings to reduce allocations
var internedKeywords map[string]string

func init() {
	// Pre-intern all keyword strings
	internedKeywords = make(map[string]string, len(keywords))
	for keyword := range keywords {
		internedKeywords[keyword] = keyword
	}
}

// lookupIdent provides a fast path for common keywords using switch statement
// This avoids expensive map lookups for the most frequent keywords
func lookupIdent(ident string) token.TokenType {
	// Fast path for common keywords using switch statement
	// This avoids expensive map lookups for the most frequent keywords
	switch ident {
	case KeywordRule:
		return token.RULE
	case "meta":
		return token.META
	case KeywordStrings:
		return token.STRINGS
	case KeywordCondition:
		return token.CONDITION
	case "and":
		return token.AND
	case "or":
		return token.OR
	case "not":
		return token.NOT
	case "true":
		return token.TRUE
	case "false":
		return token.FALSE
	case "all":
		return token.ALL
	case "any":
		return token.ANY
	case "none":
		return token.NONE
	case "of":
		return token.OF
	// String modifiers
	case "nocase":
		return token.NOCASE
	case "wide":
		return token.WIDE
	case "ascii":
		return token.ASCII
	case "fullword":
		return token.FULLWORD
	case "private":
		return token.PRIVATE
	case "xor":
		return token.XOR
	case "base64":
		return token.BASE64
	case "base64wide":
		return token.BASE64WIDE
	// Data type functions
	case "int8":
		return token.INT8
	case "int16":
		return token.INT16
	case "int32":
		return token.INT32
	case "uint8":
		return token.UINT8
	case "uint16":
		return token.UINT16
	case "uint32":
		return token.UINT32
	case "int8be":
		return token.INT8BE
	case "int16be":
		return token.INT16BE
	case "int32be":
		return token.INT32BE
	case "uint8be":
		return token.UINT8BE
	case "uint16be":
		return token.UINT16BE
	case "uint32be":
		return token.UINT32BE
	// File operations
	case "filesize":
		return token.FILESIZE
	case "entrypoint":
		return token.ENTRYPOINT
	// Control flow keywords
	case "for":
		return token.FOR
	case "in":
		return token.IN
	case "at":
		return token.AT
	case "them":
		return token.THEM
	case "defined":
		return token.DEFINED
	// Rule modifiers
	case "global":
		return token.GLOBAL
	// Import system
	case "import":
		return token.IMPORT
	case "include":
		return token.INCLUDE
	// String operations
	case "contains":
		return token.CONTAINS
	case "icontains":
		return token.ICONTAINS
	case "startswith":
		return token.STARTSWITH
	case "istartswith":
		return token.ISTARTSWITH
	case "endswith":
		return token.ENDSWITH
	case "iendswith":
		return token.IENDSWITH
	case "iequals":
		return token.IEQUALS
	case "matches":
		return token.MATCHES
	case "hash":
		return token.HASH
	case "length":
		return token.LENGTH
	default:
		// Fallback to map for any remaining keywords
		if tokenType, exists := keywords[ident]; exists {
			return tokenType
		}
		return token.IDENTIFIER
	}
}

// ValidateStringEscapes validates escape sequences in a string literal
func ValidateStringEscapes(literal string, startPos token.Position) []Error {
	var errors []Error
	pos := startPos

	for i := 0; i < len(literal); i++ {
		if literal[i] == '\n' {
			pos.Line++
			pos.Column = 1
			continue
		}

		if literal[i] != '\\' {
			pos.Column++
			continue
		}

		// Handle escape sequence
		escapeErrors, newI, newColumn := validateEscapeSequence(literal, i, pos)
		errors = append(errors, escapeErrors...)
		i = newI
		pos.Column = newColumn
	}

	return errors
}

// validateEscapeSequence validates a single escape sequence and returns errors, new index, and new column
func validateEscapeSequence(literal string, i int, pos token.Position) (errors []Error, newIndex, newColumn int) {
	errors = nil // Initialize the named return variable

	if i+1 >= len(literal) {
		// Trailing backslash
		errors = append(errors, Error{
			Position: pos,
			Message:  "trailing backslash in string literal",
		})
		return errors, i, pos.Column
	}

	next := literal[i+1]
	switch next {
	case 'n', 't', 'r', '\\', '"':
		// Valid escape sequences
		return errors, i + 1, pos.Column + 2
	case 'x':
		// Hex escape sequence \xNN
		return validateHexEscape(literal, i, pos)
	default:
		// Invalid escape sequence
		errors = append(errors, Error{
			Position: pos,
			Message:  "invalid escape sequence: \\" + string(next),
		})
		return errors, i + 1, pos.Column + 2
	}
}

// validateHexEscape validates a hex escape sequence \xNN
func validateHexEscape(literal string, i int, pos token.Position) (errors []Error, newIndex, newColumn int) {
	errors = nil // Initialize the named return variable

	if i+3 >= len(literal) {
		// Not enough characters for complete hex sequence
		errors = append(errors, Error{
			Position: pos,
			Message:  "incomplete hex escape sequence",
		})
		return errors, i + 1, pos.Column + 2
	}

	if !isHexDigit(literal[i+2]) {
		// First character after \x is not hex
		errors = append(errors, Error{
			Position: pos,
			Message:  "invalid hex escape sequence",
		})
		return errors, i + 1, pos.Column + 2
	}

	if !isHexDigit(literal[i+3]) {
		// Second character after \x is not hex
		errors = append(errors, Error{
			Position: pos,
			Message:  "incomplete hex escape sequence",
		})
		return errors, i + 2, pos.Column + 3
	}

	// Valid hex sequence
	return errors, i + 3, pos.Column + 4
}
