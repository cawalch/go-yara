package lexer

import "strings"

// Escape sequence processing functions

// processEscapeSequences processes escape sequences in a string literal
func processEscapeSequences(s string) string {
	if s == "" {
		return s
	}
	return processEscapeSequencesOptimized(s)
}

// processEscapeSequencesOptimized uses string builder pooling for better performance
func processEscapeSequencesOptimized(s string) string {
	// Quick check: if no escapes, return as-is (potentially interned)
	if !hasEscapeSequence(s) {
		return globalInterner.internString(s)
	}

	// Get a string builder from the pool
	builderPtr, ok := stringBuilderPool.Get().(*strings.Builder)
	if !ok {
		// Fallback if pool returns unexpected type
		builder := &strings.Builder{}
		builderPtr = builder
	}
	builder := builderPtr
	builder.Reset()      // Clear any previous content
	builder.Grow(len(s)) // Pre-allocate capacity

	defer func() {
		// Return to pool, but cap the size to prevent memory bloat
		if builder.Cap() <= 1024 {
			stringBuilderPool.Put(builder)
		}
	}()

	processEscapeSequencesWithBuilder(s, builder)

	// Intern the result if it's short enough
	resultStr := builder.String()
	return globalInterner.internString(resultStr)
}

// hexDigitValue returns the numeric value of a hex digit
func hexDigitValue(ch byte) int {
	switch {
	case ch >= '0' && ch <= '9':
		return int(ch - '0')
	case ch >= 'a' && ch <= 'f':
		return int(ch - 'a' + 10)
	case ch >= 'A' && ch <= 'F':
		return int(ch - 'A' + 10)
	default:
		return 0
	}
}

// hasEscapeSequence checks if a string contains escape sequences
func hasEscapeSequence(s string) bool {
	for i := range len(s) {
		if s[i] == '\\' {
			return true
		}
	}
	return false
}

// processEscapeSequencesWithBuilder processes escape sequences using a string builder
func processEscapeSequencesWithBuilder(s string, builder *strings.Builder) {
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i = processEscapeChar(s, i, func(ch byte) {
				builder.WriteByte(ch)
			})
		} else {
			builder.WriteByte(s[i])
		}
	}
}

// processEscapeChar processes a single escape character and returns the new index
func processEscapeChar(s string, i int, writeFunc func(byte)) int {
	esc := s[i+1]
	if esc == 'x' {
		return processHexEscape(s, i, writeFunc)
	}
	if isSimpleEscape(esc) {
		writeFunc(getSimpleEscapeValue(esc))
		return i + 1
	}
	// Unknown escape sequence, keep as-is
	writeFunc(s[i])
	return i
}

// isSimpleEscape checks if a character is a simple escape sequence
func isSimpleEscape(ch byte) bool {
	return ch == 'n' || ch == 't' || ch == 'r' || ch == '\\' || ch == '"'
}

// getSimpleEscapeValue returns the value for simple escape sequences
func getSimpleEscapeValue(ch byte) byte {
	switch ch {
	case 'n':
		return '\n'
	case 't':
		return '\t'
	case 'r':
		return '\r'
	case '\\':
		return '\\'
	case '"':
		return '"'
	default:
		return ch
	}
}

// processHexEscape processes hex escape sequences like \xNN
func processHexEscape(s string, i int, writeFunc func(byte)) int {
	if i+3 < len(s) && isHexDigit(s[i+2]) && isHexDigit(s[i+3]) {
		high := hexDigitValue(s[i+2])
		low := hexDigitValue(s[i+3])
		writeFunc(byte(high*16 + low))
		return i + 3
	}
	// Invalid hex sequence, keep as-is
	writeFunc(s[i])
	return i
}
