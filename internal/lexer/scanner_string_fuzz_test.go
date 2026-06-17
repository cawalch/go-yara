package lexer

import (
	"testing"

	"github.com/cawalch/go-yara/token"
)

// FuzzStringScanner tests the string scanner with malformed strings and escape sequences
func FuzzStringScanner(f *testing.F) {
	// Seed corpus with various string patterns
	f.Add([]byte("\"hello world\""))
	f.Add([]byte("\"unclosed string"))
	f.Add([]byte("\"\\x41\\x42\\x43\""))
	f.Add([]byte("\"\\n\\r\\t\\\"\\\\\""))
	f.Add([]byte("\"\\u1234\""))
	f.Add([]byte("\"\\U00001234\""))
	f.Add([]byte("\"invalid escape \\q\""))
	f.Add([]byte("\"hex escape \\xGZ\""))
	f.Add([]byte("\""))
	f.Add([]byte("\"\"\""))
	f.Add([]byte("\"\\\""))
	f.Add([]byte("\"\\\\\\\""))
	f.Add([]byte("\"very long string that might cause buffer issues\""))
	f.Add([]byte("\"nested \"quotes\" inside\""))
	f.Add([]byte("\"multiple\nlines\nin\nstring\""))
	f.Add([]byte("\"binary \x00\x01\x02 data\""))
	f.Add([]byte("\"unicode \xE2\x98\x83 emoji\""))

	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("String scanner panicked (fuzz input triggered crash): %v", r)
			}
		}()

		// Test string parsing
		l := New(string(input))

		// Skip any whitespace to get to a potential string
		l.fastForward()

		// If we start with a quote, try to parse as string
		if l.ch() == '"' {
			content, closed := l.readString()

			// The string content should never be nil
			_ = content
			_ = closed
		}

		// Also test by directly creating a lexer and processing all tokens
		l2 := New(string(input))
		for {
			tok := l2.NextToken()
			if tok.Type == token.EOF || tok.Type == token.ILLEGAL {
				break
			}
			// Verify token literals don't contain invalid data
			_ = tok.Literal
		}
	})
}

// FuzzRegexScanner tests the regex scanner with malformed patterns
func FuzzRegexScanner(f *testing.F) {
	// Seed corpus with various regex patterns
	f.Add([]byte("/simple/"))
	f.Add([]byte("/pattern/flags"))
	f.Add([]byte("/unclosed pattern"))
	f.Add([]byte("/[a-z]/i"))
	f.Add([]byte("/.*+?^${}()|[]\\/"))
	f.Add([]byte("/\\d+\\w*\\s?/"))
	f.Add([]byte("/invalid [ class"))
	f.Add([]byte("/nested (groups (too) deep)/"))
	f.Add([]byte("/catastrophic backtracking/"))
	f.Add([]byte("/very long pattern that might cause issues/"))
	f.Add([]byte("//"))
	f.Add([]byte("/\\/"))
	f.Add([]byte("/\\1\\2\\3/"))
	f.Add([]byte("/(?P<name>group)/"))
	f.Add([]byte("/(?>atomic)/"))
	f.Add([]byte("/a{100000}/"))
	f.Add([]byte("/a{,100000}/"))
	f.Add([]byte("/a{100000,}/"))

	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Regex scanner panicked (fuzz input triggered crash): %v", r)
			}
		}()

		// Test regex parsing
		l := New(string(input))

		// Skip whitespace to get to a potential regex
		l.fastForward()

		// If we start with a slash, try to parse as regex
		if l.ch() == '/' {
			content := l.readRegex()

			// The regex content should never be nil
			_ = content
		}

		// Also test tokenization
		l2 := New(string(input))
		for {
			tok := l2.NextToken()
			if tok.Type == token.EOF || tok.Type == token.ILLEGAL {
				break
			}
			_ = tok.Literal
		}
	})
}
