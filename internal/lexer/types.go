// Package lexer tokenizes YARA rule syntax for the parser and compiler.
package lexer

import "github.com/cawalch/go-yara/token"

// Pre-allocated single character strings to eliminate allocations
// in ILLEGAL token creation and other single-character literals
var singleCharLiterals [256]string

func init() {
	for i := range 256 {
		singleCharLiterals[i] = string(byte(i))
	}
}

// RecoveryMode defines how the lexer should recover from errors
type RecoveryMode int

const (
	// RecoveryBasic uses basic newline/keyword synchronization (default)
	RecoveryBasic RecoveryMode = iota
	// RecoverySection fast-forwards to the next YARA section keyword
	RecoverySection
)

// Lexer tokenizes YARA rule source code into a stream of tokens.
// It maintains position information and can recover from lexical errors.
type Lexer struct {
	reader         *ReaderFast  // handles character reading and position tracking with optimizations
	errors         []Error      // collected errors during lexing
	recoveryMode   RecoveryMode // error recovery strategy
	lastTokenType  token.Type   // last emitted token type for contextual decisions
	section        sectionMode  // current YARA rule section (meta/strings/condition)
	pendingSection sectionMode  // section keyword seen but colon not yet consumed
}

// New creates a new lexer for the given input string.
// The lexer starts at the beginning of the input with basic error recovery mode.
func New(input string) *Lexer {
	return &Lexer{
		reader:       NewReaderFast(input),
		recoveryMode: RecoveryBasic,
	}
}

// sectionMode tracks which rule section the lexer is currently in.
type sectionMode uint8

const (
	sectionNone sectionMode = iota
	sectionMeta
	sectionStrings
	sectionEvidence
	sectionCondition
)
