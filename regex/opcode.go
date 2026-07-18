package regex

// Opcodes mirror re.h's RE_OPCODE_* values for parity verification in tests.
// See: yara/libyara/include/yara/re.h

// OpAny and related constants define the regex VM instruction set.
const (
	OpAny              = 0xA0
	OpLiteral          = 0xA2
	OpMaskedLiteral    = 0xA4
	OpClass            = 0xA5
	OpWordChar         = 0xA7
	OpNonWordChar      = 0xA8
	OpSpace            = 0xA9
	OpNonSpace         = 0xAA
	OpDigit            = 0xAB
	OpNonDigit         = 0xAC
	OpMatch            = 0xAD
	OpNotLiteral       = 0xAE
	OpMaskedNotLiteral = 0xAF

	OpMatchAtEnd        = 0xB0
	OpMatchAtStart      = 0xB1
	OpWordBoundary      = 0xB2
	OpNonWordBoundary   = 0xB3
	OpRepeatAnyGreedy   = 0xB4
	OpRepeatAnyUngreedy = 0xB5

	OpSplitA = 0xC0
	OpSplitB = 0xC1
	OpJump   = 0xC2

	OpRepeatStartGreedy   = 0xC3
	OpRepeatEndGreedy     = 0xC4
	OpRepeatStartUngreedy = 0xC5
	OpRepeatEndUngreedy   = 0xC6
	OpSaveStart           = 0xC7
	OpSaveEnd             = 0xC8
)
