// Package regex provides YARA-compatible regular expression core types.
package regex

// Flags mirror libyara's re.h flags for parity and easier cross-checking.
// Keeping the values identical allows comparing encoded artifacts in tests.
// See: yara/libyara/include/yara/re.h

// Flags defines runtime behavior and parser-stage defaults for the regex engine.
type Flags uint32

// Flags constants define runtime behavior and parser-stage defaults.
const (
	FlagsFastRegexp Flags = 0x02
	FlagsBackwards  Flags = 0x04
	FlagsExhaustive Flags = 0x08
	FlagsWide       Flags = 0x10
	FlagsNoCase     Flags = 0x20
	FlagsScan       Flags = 0x40
	FlagsDotAll     Flags = 0x80

	// FlagsGreedy - Parser-stage defaults/overrides captured as flags during parse.
	FlagsGreedy   Flags = 0x400
	// FlagsUngreedy - Parser-stage defaults/overrides captured as flags during parse.
	FlagsUngreedy Flags = 0x800
)

// ParserFlags control parsing behavior. Values are internal and do not need to
// match libyara, but we keep names aligned to improve traceability.
// See: RE_PARSER_FLAG_ENABLE_STRICT_ESCAPE_SEQUENCES

// ParserFlags control parser behavior; names mirror libyara for traceability.
type ParserFlags uint32

// ParserFlagEnableStrictEscapeSequences enables strict escape validation.
// ParserFlagEnableStrictEscapeSequences enables strict escape validation.
const (
	ParserFlagEnableStrictEscapeSequences ParserFlags = 1 << 0
)
