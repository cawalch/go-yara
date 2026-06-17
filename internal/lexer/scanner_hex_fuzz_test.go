package lexer

import (
	"testing"

	"github.com/cawalch/go-yara/token"
)

// FuzzHexScanner tests the hex string scanner with malformed hex patterns
func FuzzHexScanner(f *testing.F) {
	// Seed corpus with various hex string patterns
	f.Add([]byte("{ DE AD BE EF }"))
	f.Add([]byte("{ 00 01 02 03 }"))
	f.Add([]byte("{ DE:AD:BE:EF }"))
	f.Add([]byte("{ DE-AD-BE-EF }"))
	f.Add([]byte("{ DEADBEEF }"))
	f.Add([]byte("{ 4D 5A }"))  // PE header
	f.Add([]byte("{ 7F ELF }")) // ELF header
	f.Add([]byte("{ unclosed"))
	f.Add([]byte("{ }"))
	f.Add([]byte("{ {{ nested } } }"))
	f.Add([]byte("{ invalid hex XX }"))
	f.Add([]byte("{ 1 2 3 4 5 6 7 8 9 A B C D E F }"))
	f.Add([]byte("{ 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F }"))
	f.Add([]byte("{ [0-256] }"))
	f.Add([]byte("{ (DE|AD|BE|EF) }"))
	f.Add([]byte("{ DE AD } { BE EF }"))
	f.Add([]byte("{ very long hex pattern that might cause issues }"))
	f.Add([]byte("{ [0-1000] }"))
	f.Add([]byte("{ (41|42|43)* }"))

	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Hex scanner panicked (fuzz input triggered crash): %v", r)
			}
		}()

		// Test hex string detection and parsing
		l := New(string(input))

		// Skip whitespace to get to a potential hex string
		l.fastForward()

		// If we start with a brace, test hex string detection and parsing
		if l.ch() == '{' {
			// Test isHexStringStart function
			isHex := l.isHexStringStart()
			_ = isHex

			// Test readHexString function
			if isHex {
				content := l.readHexString()
				_ = content
			}
		}

		// Also test tokenization which includes hex string handling
		l2 := New(string(input))
		for {
			tok := l2.NextToken()
			if tok.Type == token.EOF || tok.Type == token.ILLEGAL {
				break
			}
			_ = tok.Literal
		}

		// Test with various positions in the input
		inputStr := string(input)
		for i := 0; i < len(inputStr) && i < 100; i++ {
			l3 := New(inputStr[i:])
			l3.fastForward()
			if l3.ch() == '{' {
				isHex := l3.isHexStringStart()
				if isHex {
					content := l3.readHexString()
					_ = content
				}
			}
		}
	})
}
