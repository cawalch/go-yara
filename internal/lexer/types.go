// Package lexer provides a high-performance lexical analyzer for YARA rule syntax.
//
// The lexer is organized into several focused modules:
//
// Core Components:
//   - Lexer: Main tokenization engine (lexer.go)
//   - Reader: Input reading and position tracking (reader.go, position.go)
//   - Token emission: Centralized token creation (emit.go, token_handlers.go)
//
// Specialized Scanners:
//   - String literals and regex patterns (scanner_string.go)
//   - Hexadecimal strings (scanner_hex.go)
//   - Identifiers and keywords (scanner_ident.go)
//   - Numeric literals (scanner_numeric.go)
//   - Escape sequences (scanner_escape.go)
//
// Performance Optimizations:
//   - Memory pooling for reduced allocations (pooling.go)
//   - String interning for common tokens (pooling.go)
//   - Position caching for efficient seeking (position.go)
//   - Feature flags for experimental optimizations (optimization_flags.go)
//
// Error Handling:
//   - Robust error recovery mechanisms (error_recovery.go)
//   - Detailed error reporting (errors.go)
//
// The lexer maintains zero-allocation fast paths for common operations
// and provides comprehensive error recovery for malformed input.
package lexer

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
	reader       *Reader      // handles character reading and position tracking
	errors       []Error      // collected errors during lexing
	recoveryMode RecoveryMode // error recovery strategy
}

// New creates a new lexer for the given input string.
// The lexer starts at the beginning of the input with basic error recovery mode.
func New(input string) *Lexer {
	return &Lexer{
		reader:       NewReader(input),
		recoveryMode: RecoveryBasic,
	}
}

// NewWithRecovery creates a new lexer with the specified recovery mode
func NewWithRecovery(input string, mode RecoveryMode) *Lexer {
	return &Lexer{
		reader:       NewReader(input),
		recoveryMode: mode,
	}
}
