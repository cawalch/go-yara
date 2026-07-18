package lexer

import (
	"testing"

	"github.com/cawalch/go-yara/token"
)

// FuzzLexer tests the complete lexer with various malformed inputs
func FuzzLexer(f *testing.F) {
	// Seed corpus with valid YARA rules and edge cases from existing tests
	f.Add([]byte("rule test { strings: $a = \"hello\" condition: $a }"))
	f.Add([]byte("rule hex_test { strings: $a = { DE AD BE EF } condition: $a }"))
	f.Add([]byte("rule regex_test { strings: $a = /hello.*world/ condition: $a }"))
	f.Add([]byte("rule empty { condition: true }"))
	f.Add([]byte("rule unterminated { strings: $a = \"unclosed string condition: $a }"))
	f.Add([]byte(""))
	f.Add([]byte("invalid syntax"))
	f.Add([]byte("rule test { strings: $a = "))
	f.Add([]byte("\""))
	f.Add([]byte("{"))
	f.Add([]byte("rule { { {"))

	f.Fuzz(func(t *testing.T, input []byte) {
		// Test basic lexer initialization and tokenization
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Lexer panicked (fuzz input triggered crash): %v", r)
			}
		}()

		// Test with recovery mode enabled to catch more edge cases
		l := New(string(input))
		l.SetRecoveryMode(RecoverySection)

		// Tokenize the entire input
		for {
			tok := l.NextToken()
			if tok.Type == token.EOF || tok.Type == token.ILLEGAL {
				break
			}
		}

		// Also test with basic recovery mode
		l2 := New(string(input))
		for {
			tok := l2.NextToken()
			if tok.Type == token.EOF || tok.Type == token.ILLEGAL {
				break
			}
		}
	})
}
