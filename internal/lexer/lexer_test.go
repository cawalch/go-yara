package lexer_test

import (
	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

// collectTokens is a helper function to collect all tokens from a lexer
// This function is kept here for backward compatibility with any remaining tests
func collectTokens(l *lexer.Lexer) []token.Token {
	toks := make([]token.Token, 0, 16) // Pre-allocate with reasonable capacity
	for {
		t := l.NextToken()
		toks = append(toks, t)
		if t.Type == token.EOF {
			break
		}
	}
	return toks
}

// Note: All test functions have been moved to focused test files:
// - basic_tokens_test.go: Basic token parsing tests
// - string_literals_test.go: String literal and escape sequence tests
// - comments_test.go: Comment handling tests
// - boolean_keywords_test.go: Boolean literal and keyword tests
// - error_handling_test.go: Error recovery and illegal token tests
// - integration_test.go: YARA rule integration tests
// - hexstring_test.go: Hexadecimal string tests (already existed)
// - regex_test.go: Regular expression tests (already existed)
// - string_identifier_test.go: String identifier tests (already existed)
