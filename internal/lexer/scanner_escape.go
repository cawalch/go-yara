package lexer

import "strings"

// Escape sequence processing functions

// processEscapeSequences processes escape sequences in a string literal
func processEscapeSequences(s string) string {
	if len(s) == 0 {
		return s
	}

	if isPoolingOptimizationEnabled() {
		return processEscapeSequencesOptimized(s)
	}

	// Original implementation for comparison
	return processEscapeSequencesOriginal(s)
}

// processEscapeSequencesOriginal is the original implementation
func processEscapeSequencesOriginal(s string) string {
	// Get a byte slice from the pool
	resultPtr, ok := byteSlicePool.Get().(*[]byte)
	if !ok {
		// Fallback if pool returns unexpected type
		slice := make([]byte, 0, len(s))
		resultPtr = &slice
	}
	result := (*resultPtr)[:0] // Reset length but keep capacity
	defer func() {
		// Return to pool, but cap the size to prevent memory bloat
		if cap(result) <= 1024 {
			*resultPtr = result
			byteSlicePool.Put(resultPtr)
		}
	}()
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'n':
				result = append(result, '\n')
				i++ // skip the next character
			case 't':
				result = append(result, '\t')
				i++
			case 'r':
				result = append(result, '\r')
				i++
			case '\\':
				result = append(result, '\\')
				i++
			case '"':
				result = append(result, '"')
				i++
			case 'x':
				// Hex escape sequence \xNN
				if i+3 < len(s) && isHexDigit(s[i+2]) && isHexDigit(s[i+3]) {
					high := hexDigitValue(s[i+2])
					low := hexDigitValue(s[i+3])
					result = append(result, byte(high*16+low))
					i += 3 // skip x and two hex digits
				} else {
					// Invalid hex sequence, keep as-is
					result = append(result, s[i])
				}
			default:
				// Unknown escape sequence, keep as-is
				result = append(result, s[i])
			}
		} else {
			result = append(result, s[i])
		}
	}

	// Intern the result if it's short enough
	resultStr := string(result)
	return globalInterner.internString(resultStr)
}

// processEscapeSequencesOptimized uses string builder pooling for better performance
func processEscapeSequencesOptimized(s string) string {
	// Quick check: if no escapes, return as-is (potentially interned)
	hasEscape := false
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			hasEscape = true
			break
		}
	}

	if !hasEscape {
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

	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'n':
				builder.WriteByte('\n')
				i++ // skip the next character
			case 't':
				builder.WriteByte('\t')
				i++
			case 'r':
				builder.WriteByte('\r')
				i++
			case '\\':
				builder.WriteByte('\\')
				i++
			case '"':
				builder.WriteByte('"')
				i++
			case 'x':
				// Hex escape sequence \xNN
				if i+3 < len(s) && isHexDigit(s[i+2]) && isHexDigit(s[i+3]) {
					high := hexDigitValue(s[i+2])
					low := hexDigitValue(s[i+3])
					builder.WriteByte(byte(high*16 + low))
					i += 3 // skip x and two hex digits
				} else {
					// Invalid hex sequence, keep as-is
					builder.WriteByte(s[i])
				}
			default:
				// Unknown escape sequence, keep as-is
				builder.WriteByte(s[i])
			}
		} else {
			builder.WriteByte(s[i])
		}
	}

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
