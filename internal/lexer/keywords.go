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
var keywords = map[string]token.Type{
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
	// Additional 64-bit data types
	"int64":    token.INT64,
	"uint64":   token.UINT64,
	"int64be":  token.INT64BE,
	"uint64be": token.UINT64BE,
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

// lookupIdent provides optimized keyword lookup using map with fallback
func lookupIdent(ident string) token.Type {
	// Direct map lookup for all keywords
	if tokenType, exists := keywords[ident]; exists {
		return tokenType
	}
	return token.IDENTIFIER
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
