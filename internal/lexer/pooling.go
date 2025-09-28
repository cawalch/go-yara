package lexer

import (
	"strings"
	"sync"
)

// Pool management and string optimization utilities.
// This module provides memory pooling and string interning optimizations
// to reduce allocations during lexical analysis.

// Pool for byte slices used in escape sequence processing
var byteSlicePool = sync.Pool{
	New: func() interface{} {
		// Pre-allocate with reasonable capacity for most strings
		slice := make([]byte, 0, 256)
		return &slice
	},
}

// Pool for strings.Builder used in string processing
var stringBuilderPool = sync.Pool{
	New: func() interface{} {
		return &strings.Builder{}
	},
}

// String interning for common short literals and keywords
// Limited size to prevent unbounded memory growth
type stringInterner struct {
	cache     map[string]string
	maxSize   int
	maxLength int
}

var globalInterner = &stringInterner{
	cache:     make(map[string]string, 64), // Start small
	maxSize:   128,                         // Maximum number of interned strings
	maxLength: 16,                          // Only intern strings ≤16 bytes
}

// internString returns an interned version of the string if beneficial
func (si *stringInterner) internString(s string) string {
	if !isStringInterningEnabled() {
		return s
	}

	// Only intern short strings to avoid memory bloat
	if len(s) > si.maxLength {
		return s
	}

	// Check if already interned
	if interned, exists := si.cache[s]; exists {
		return interned
	}

	// Don't grow beyond max size to prevent unbounded memory usage
	if len(si.cache) >= si.maxSize {
		return s
	}

	// Intern the string
	si.cache[s] = s
	return s
}
