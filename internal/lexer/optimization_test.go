package lexer_test

import (
	"os"
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

// TestOptimizationFlags tests that the optimization flags work correctly
func TestOptimizationFlags(t *testing.T) {
	// Test with optimization disabled (default)
	input := `"test string with \n escape sequences"`
	l := lexer.New(input)
	tok := l.NextToken()

	if tok.Type != token.STRING_LIT {
		t.Errorf("Expected STRING_LIT, got %v", tok.Type)
	}

	// The actual optimization behavior is tested via benchmarks
	// since the functional behavior should be identical
}

// TestOptimizationFunctionalEquivalence ensures optimized and unoptimized
// paths produce identical results
func TestOptimizationFunctionalEquivalence(t *testing.T) {
	testCases := []string{
		`"simple string"`,
		`"string with \n escape"`,
		`"string with \t tab"`,
		`"string with \x41 hex"`,
		`"complex \n\t\r\\ string"`,
		`"multiple" "strings" "together"`,
	}

	for _, input := range testCases {
		t.Run(input, func(t *testing.T) {
			// Test without optimization
			_ = os.Setenv("YARA_OPT_POOLING", "")
			_ = os.Setenv("YARA_OPT_INTERNING", "")

			l1 := lexer.New(input)
			tokens1 := collectAllTokens(l1)

			// Test with optimization
			_ = os.Setenv("YARA_OPT_POOLING", "1")
			_ = os.Setenv("YARA_OPT_INTERNING", "1")

			l2 := lexer.New(input)
			tokens2 := collectAllTokens(l2)

			// Results should be identical
			if len(tokens1) != len(tokens2) {
				t.Fatalf("Token count mismatch: %d vs %d", len(tokens1), len(tokens2))
			}

			for i, tok1 := range tokens1 {
				tok2 := tokens2[i]
				if tok1.Type != tok2.Type {
					t.Errorf("Token %d type mismatch: %v vs %v", i, tok1.Type, tok2.Type)
				}
				if tok1.Literal != tok2.Literal {
					t.Errorf("Token %d literal mismatch: %q vs %q", i, tok1.Literal, tok2.Literal)
				}
			}
		})
	}

	// Clean up environment
	_ = os.Unsetenv("YARA_OPT_POOLING")
	_ = os.Unsetenv("YARA_OPT_INTERNING")
}

// BenchmarkOptimizationComparison provides a direct comparison
func BenchmarkOptimizationComparison(b *testing.B) {
	input := `"malware" nocase wide "virus" ascii fullword { E2 34 A1 } private /pattern/i base64 `

	b.Run("WithoutOptimization", func(b *testing.B) {
		_ = os.Setenv("YARA_OPT_POOLING", "")
		_ = os.Setenv("YARA_OPT_INTERNING", "")
		b.ReportAllocs()
		b.ResetTimer()

		for range b.N {
			l := lexer.New(input)
			for l.NextToken().Type != token.EOF {
				// Consume tokens
			}
		}
	})

	b.Run("WithOptimization", func(b *testing.B) {
		_ = os.Setenv("YARA_OPT_POOLING", "1")
		_ = os.Setenv("YARA_OPT_INTERNING", "1")
		b.ReportAllocs()
		b.ResetTimer()

		for range b.N {
			l := lexer.New(input)
			for l.NextToken().Type != token.EOF {
				// Consume tokens
			}
		}
	})

	// Clean up
	_ = os.Unsetenv("YARA_OPT_POOLING")
	_ = os.Unsetenv("YARA_OPT_INTERNING")
}

// collectAllTokens is a helper function to collect all tokens from a lexer
func collectAllTokens(l *lexer.Lexer) []token.Token {
	tokens := make([]token.Token, 0, 100) // Pre-allocate with reasonable capacity
	for {
		tok := l.NextToken()
		tokens = append(tokens, tok)
		if tok.Type == token.EOF {
			break
		}
	}
	return tokens
}
