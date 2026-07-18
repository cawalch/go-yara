package lexer

import (
	"strings"
	"sync"
)

// Pool for strings.Builder used in string processing
var stringBuilderPool = sync.Pool{
	New: func() any {
		return &strings.Builder{}
	},
}

// String interning for common short literals and keywords
// Limited size to prevent unbounded memory growth
// Thread-safe implementation using RWMutex for optimal read performance
type stringInterner struct {
	mu        sync.RWMutex
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
// Thread-safe implementation optimized for read-heavy workloads
func (si *stringInterner) internString(s string) string {
	// Only intern short strings to avoid memory bloat
	if len(s) > si.maxLength {
		return s
	}

	// Fast path: try read lock first for the common case of existing strings
	si.mu.RLock()
	if interned, exists := si.cache[s]; exists {
		si.mu.RUnlock()
		return interned
	}
	si.mu.RUnlock()

	// Slow path: need to potentially write, acquire write lock
	si.mu.Lock()
	defer si.mu.Unlock()

	// Double-check under write lock - another goroutine might have added it
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
