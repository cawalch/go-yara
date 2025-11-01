package lexer_test

import (
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

// Micro-benchmarks for specific hot paths identified in profiling

// BenchmarkMicro_ReadChar benchmarks the character reading operation
func BenchmarkMicro_ReadChar(b *testing.B) {
	input := "rule test { condition: true }"

	for b.Loop() {
		// Reset lexer position
		l := lexer.New(input)
		// Read characters - this is 14.42% of CPU time
		for range len(input) {
			l.NextToken()
		}
		_ = l // Use the variable to avoid unused variable warning
	}
}

// BenchmarkMicro_KeywordLookup benchmarks keyword lookup operations
func BenchmarkMicro_KeywordLookup(b *testing.B) {
	for b.Loop() {
		// This is using mapaccess2_faststr (5.70% of CPU time)
		// Create a simple lexer to access the internal lookup function
		l := lexer.New("rule")
		_ = l.NextToken() // This will trigger keyword lookup
		_ = l             // Use the variable to avoid unused variable warning
	}
}

// BenchmarkMicro_SkipWhitespace benchmarks whitespace skipping
func BenchmarkMicro_SkipWhitespace(b *testing.B) {
	input := "    rule test { condition: true }"

	for b.Loop() {
		// Reset lexer position
		l := lexer.New(input)
		// Skip whitespace - this is 9.41% of CPU time
		for {
			tok := l.NextToken()
			if tok.Type == token.EOF {
				break
			}
		}
		_ = l // Use the variable to avoid unused variable warning
	}
}

// BenchmarkMicro_IdentifierToken benchmarks identifier token creation
func BenchmarkMicro_IdentifierToken(b *testing.B) {
	input := "my_variable_name another_variable"

	for b.Loop() {
		// Reset lexer position
		l := lexer.New(input)
		// Create identifier tokens - this is 23.36% of CPU time
		for {
			tok := l.NextToken()
			if tok.Type == token.EOF {
				break
			}
		}
		_ = l // Use the variable to avoid unused variable warning
	}
}

// BenchmarkMicro_NumericToken benchmarks numeric token creation
func BenchmarkMicro_NumericToken(b *testing.B) {
	input := "12345 0xFF 1KB 2MB"

	for b.Loop() {
		// Reset lexer position
		l := lexer.New(input)
		// Create numeric tokens - this is 4.05% of CPU time
		for {
			tok := l.NextToken()
			if tok.Type == token.EOF {
				break
			}
		}
		_ = l // Use the variable to avoid unused variable warning
	}
}

// BenchmarkMicro_StringToken benchmarks string token creation
func BenchmarkMicro_StringToken(b *testing.B) {
	input := `"test string" "another string with escapes \"quoted\""`

	for b.Loop() {
		// Reset lexer position
		l := lexer.New(input)
		// Create string tokens - this is 5.54% of CPU time
		for {
			tok := l.NextToken()
			if tok.Type == token.EOF {
				break
			}
		}
		_ = l // Use the variable to avoid unused variable warning
	}
}

// BenchmarkMicro_HexStringToken benchmarks hex string token creation
func BenchmarkMicro_HexStringToken(b *testing.B) {
	input := `{ E2 34 A1 C8 } { ?? A? ?B } { F4 23 [4-6] 62 B4 }`

	for b.Loop() {
		// Reset lexer position
		l := lexer.New(input)
		// Create hex string tokens - this is 4.49% of CPU time
		for {
			tok := l.NextToken()
			if tok.Type == token.EOF {
				break
			}
		}
		_ = l // Use the variable to avoid unused variable warning
	}
}

// BenchmarkMicro_Current benchmarks the character reading operations
func BenchmarkMicro_Current(b *testing.B) {
	input := "rule test { condition: true }"

	for b.Loop() {
		// Reset lexer position
		l := lexer.New(input)
		// Character reading operations - this is 8.34% of CPU time
		for {
			tok := l.NextToken()
			if tok.Type == token.EOF { // EOF
				break
			}
		}
		_ = l // Use the variable to avoid unused variable warning
	}
}
