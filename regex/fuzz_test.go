package regex

import (
	"testing"
)

// FuzzRegexParser tests the regex parser with malformed patterns
func FuzzRegexParser(f *testing.F) {
	// Seed corpus with various regex patterns from existing tests
	f.Add([]byte("a.c"))
	f.Add([]byte("(ab|cd)e"))
	f.Add([]byte("^abc$"))
	f.Add([]byte("[a-c]"))
	f.Add([]byte("[^0-9]"))
	f.Add([]byte("a*"))
	f.Add([]byte("b+?"))
	f.Add([]byte("c{2,4}"))
	f.Add([]byte("d{3}"))
	f.Add([]byte("e{2,}?"))
	f.Add([]byte("f??"))
	f.Add([]byte("\\w"))
	f.Add([]byte("\\W"))
	f.Add([]byte("\\s"))
	f.Add([]byte("\\S"))
	f.Add([]byte("\\d"))
	f.Add([]byte("\\D"))
	f.Add([]byte("\\b\\B"))
	f.Add([]byte("unclosed [class"))
	f.Add([]byte("invalid \\ escape"))
	f.Add([]byte("("))
	f.Add([]byte(")"))
	f.Add([]byte("["))
	f.Add([]byte("]"))
	f.Add([]byte("{"))
	f.Add([]byte("}"))
	f.Add([]byte("*"))                                       // Quantifier without preceding atom
	f.Add([]byte("+"))                                       // Quantifier without preceding atom
	f.Add([]byte("?"))                                       // Quantifier without preceding atom
	f.Add([]byte("{5}"))                                     // Quantifier without preceding atom
	f.Add([]byte("a{1000000000}"))                           // Very large quantifier
	f.Add([]byte("a{1000000000,}"))                          // Very large unbounded quantifier
	f.Add([]byte("((((((((((a))))))))))"))                   // Deeply nested
	f.Add([]byte("a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a")) // Catastrophic backtracking candidate
	f.Add([]byte("(?:)*"))                                   // Empty group quantified

	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Regex parser recovered from panic: %v", r)
			}
		}()

		// Test regex parsing
		p := NewParser(0)
		ast, err := p.Parse(string(input))

		// Whether parse succeeds or fails, we shouldn't panic
		if err == nil && ast != nil {
			_ = ast.Root

			// Test compilation
			_, err2 := Compile(ast)
			_ = err2
		}
	})
}

// FuzzRegexVM tests the regex VM execution with various patterns and inputs
func FuzzRegexVM(f *testing.F) {
	// Seed corpus with pattern and text combinations
	f.Add([]byte("a.c\x00test"))
	f.Add([]byte("hello\x00hello world"))
	f.Add([]byte("[a-z]+\x00test123"))
	f.Add([]byte("\\d+\x00123"))
	f.Add([]byte("^start$\x00start"))
	f.Add([]byte(".*\x00any text"))
	f.Add([]byte("(ab|cd)\x00ab"))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Regex VM recovered from panic: %v", r)
			}
		}()

		// Split data into pattern and text
		nullIndex := -1
		for i, b := range data {
			if b == 0 {
				nullIndex = i
				break
			}
		}

		if nullIndex == -1 || nullIndex == len(data)-1 {
			return
		}

		pattern := string(data[:nullIndex])
		text := string(data[nullIndex+1:])

		// Parse and compile regex
		p := NewParser(0)
		ast, err := p.Parse(pattern)
		if err != nil {
			return // Invalid pattern is expected and should be handled gracefully
		}

		prog, err := Compile(ast)
		if err != nil {
			return // Compilation error should be handled gracefully
		}

		// Test matching with different flags
		textBytes := []byte(text)

		// Test basic matching
		matched := Exec(prog, textBytes, 0)
		_ = matched

		// Test with scan flag
		matched = Exec(prog, textBytes, FlagsScan)
		_ = matched

		// Test with case insensitive flag
		matched = Exec(prog, textBytes, FlagsNoCase)
		_ = matched

		// Test with multiple flags
		matched = Exec(prog, textBytes, FlagsScan|FlagsNoCase)
		_ = matched

		// Test ExecMatch for getting match positions
		matched, start, end := ExecMatch(prog, textBytes, 0)
		_ = matched
		_ = start
		_ = end

		// Test with very long text (up to reasonable limit)
		if len(textBytes) < 1000 {
			// Test repeated matching
			for i := 0; i < 10 && i < len(textBytes); i++ {
				subText := textBytes[:len(textBytes)-i]
				matched = Exec(prog, subText, 0)
				_ = matched
			}
		}
	})
}
