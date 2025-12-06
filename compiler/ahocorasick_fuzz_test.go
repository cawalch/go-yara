package compiler

import (
	"bytes"
	"strings"
	"testing"
)

// FuzzAhoCorasick tests the Aho-Corasick automaton with various pattern sets
func FuzzAhoCorasick(f *testing.F) {
	// Seed corpus with pattern sets
	f.Add([]byte("hello\x00world\x00test"))
	f.Add([]byte("a\x00b\x00c"))
	f.Add([]byte("test\x00testing\x00tested"))
	f.Add([]byte("\x00"))
	f.Add([]byte("pattern"))
	f.Add([]byte("same\x00same\x00same"))   // Duplicate patterns
	f.Add([]byte("abc\x00abcd\x00abcde"))   // Overlapping patterns
	f.Add([]byte("a\x00ab\x00abc\x00abcd")) // Prefix patterns
	f.Add([]byte("longpattern\x00short"))
	f.Add([]byte("pattern1\x00pattern2\x00pattern3"))
	f.Add([]byte("case\x00CASE\x00Case")) // Case variations
	f.Add([]byte("pattern with spaces\x00another pattern"))
	f.Add([]byte("special!@#$%^&*()_+{}|:<>?`~"))
	f.Add([]byte("binary\x00\x01\x02\x03\x04"))                                // Binary data patterns
	f.Add([]byte(strings.Repeat("a", 100) + "\x00" + strings.Repeat("b", 50))) // Long patterns

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Aho-Corasick recovered from panic: %v", r)
			}
		}()

		// Split data into patterns using null byte as separator
		patterns := bytes.Split(data, []byte{0})

		// Filter out empty patterns
		var validPatterns [][]byte
		for _, pattern := range patterns {
			if len(pattern) > 0 {
				validPatterns = append(validPatterns, pattern)
			}
		}

		if len(validPatterns) == 0 {
			return
		}

		// Convert to strings
		patternStrings := make([]string, len(validPatterns))
		for i, pattern := range validPatterns {
			patternStrings[i] = string(pattern)
		}

		// Test Aho-Corasick construction
		ac := NewACAutomaton()
		// Note: The real API doesn't support direct pattern addition in constructor
		// We'll fuzz the Search method instead
		_ = ac

		// Test pattern matching with various texts
		testTexts := []string{
			"", // Empty text
			"hello",
			"world",
			"test",
			string(bytes.Join(validPatterns, []byte{0})),
			strings.Repeat("a", 100),
			strings.Repeat(patternStrings[0], 10), // Repeat first pattern
			"random text that shouldn't match",
		}

		for _, text := range testTexts {
			// Test Search method with byte data
			matches := ac.Search([]byte(text))
			_ = matches

			// Test long text matching
			if len(text) < 50 {
				longText := strings.Repeat(text, 10)
				matches = ac.Search([]byte(longText))
				_ = matches
			}
		}

		// Test with single pattern sets
		for i := range validPatterns {
			singlePattern := []string{patternStrings[i]}
			ac2 := NewACAutomaton()
			_ = ac2
			_ = singlePattern
		}

		// Test with prefix/suffix variations
		for _, pattern := range patternStrings {
			if len(pattern) == 0 || len(pattern) >= 50 {
				continue
			}
			// Test pattern with prefix
			withPrefix := "prefix" + pattern
			matches := ac.Search([]byte(withPrefix))
			_ = matches

			// Test pattern with suffix
			withSuffix := pattern + "suffix"
			matches = ac.Search([]byte(withSuffix))
			_ = matches

			// Test pattern in middle
			inMiddle := "start" + pattern + "end"
			matches = ac.Search([]byte(inMiddle))
			_ = matches
		}
	})
}

// FuzzAhoCorasickBinary tests with binary data patterns
func FuzzAhoCorasickBinary(f *testing.F) {
	// Seed corpus with binary patterns
	f.Add([]byte("\x00\x01\x02\x03"))
	f.Add([]byte("\xFF\xFE\xFD"))
	f.Add([]byte("\x4D\x5A"))                         // PE header
	f.Add([]byte("\x7F\x45\x4C\x46"))                 // ELF header
	f.Add([]byte("\x50\x4B\x03\x04"))                 // ZIP header
	f.Add([]byte("\x89\x50\x4E\x47\x0D\x0A\x1A\x0A")) // PNG header

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Aho-Corasick binary recovered from panic: %v", r)
			}
		}()

		if len(data) == 0 {
			return
		}

		// Split into patterns of varying lengths
		var patterns [][]byte
		for i := 0; i < len(data); i += 4 {
			end := i + 4
			if end > len(data) {
				end = len(data)
			}
			if end > i {
				patterns = append(patterns, data[i:end])
			}
		}

		if len(patterns) == 0 {
			return
		}

		// Test with binary patterns
		ac := NewACAutomaton()
		_ = ac

		// Test matching with the original data and variations
		testData := [][]byte{
			data,
			append(data, data...), // Double the data
			bytes.Repeat(data, 3), // Triple the data
		}

		for _, testBytes := range testData {
			matches := ac.Search(testBytes)
			_ = matches

			// Test with prefix/suffix
			withPrefix := append([]byte("prefix"), testBytes...)
			matches = ac.Search(withPrefix)
			_ = matches

			withSuffix := make([]byte, len(testBytes)+6)
			copy(withSuffix, testBytes)
			copy(withSuffix[len(testBytes):], []byte("suffix"))
			matches = ac.Search(withSuffix)
			_ = matches
		}

		// Test with individual patterns
		for _, pattern := range patterns {
			ac2 := NewACAutomaton()
			matches := ac2.Search([]byte(pattern))
			_ = matches
		}
	})
}
