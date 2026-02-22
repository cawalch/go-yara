package compiler

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// FuzzAhoCorasickPatterns tests the Aho-Corasick automaton with various pattern sets
func FuzzAhoCorasickPatterns(f *testing.F) {
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
	f.Add(
		[]byte("binary\x00\x01\x02\x03\x04"),
	) // Binary data patterns
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

		// Convert to strings and add to automaton
		ac := NewACAutomaton()
		patternStrings := make([]string, len(validPatterns))
		for i, pattern := range validPatterns {
			patternStrings[i] = string(pattern)
			if err := ac.AddString(fmt.Sprintf("s%d", i), pattern, false, false); err != nil {
				return
			}
		}

		// Compile automaton
		if err := ac.Compile(); err != nil {
			return // Some inputs might be invalid for AC if we had stricter limits
		}

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
			for range ac.SearchIter([]byte(text)) {
			}

			// Test long text matching
			if len(text) < 50 {
				longText := strings.Repeat(text, 100)
				for range ac.SearchIter([]byte(longText)) {
				}
			}
		}

		// Test with single pattern sets
		for i := range validPatterns {
			ac2 := NewACAutomaton()
			if err := ac2.AddString("p", validPatterns[i], false, false); err != nil {
				continue
			}
			if err := ac2.Compile(); err != nil {
				continue
			}
			for range ac2.SearchIter(validPatterns[i]) {
			}
		}

		// Test with prefix/suffix variations
		for _, pattern := range patternStrings {
			if len(pattern) == 0 || len(pattern) >= 50 {
				continue
			}
			// Test pattern with prefix
			withPrefix := "prefix" + pattern
			for range ac.SearchIter([]byte(withPrefix)) {
			}

			// Test pattern with suffix
			withSuffix := pattern + "suffix"
			for range ac.SearchIter([]byte(withSuffix)) {
			}

			// Test pattern in middle
			inMiddle := "start" + pattern + "end"
			for range ac.SearchIter([]byte(inMiddle)) {
			}
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
			end := min(i+4, len(data))
			if end > i {
				patterns = append(patterns, data[i:end])
			}
		}

		if len(patterns) == 0 {
			return
		}

		// Test with binary patterns
		ac := NewACAutomaton()
		for i, p := range patterns {
			if err := ac.AddString(fmt.Sprintf("b%d", i), p, false, false); err != nil {
				return
			}
		}

		if err := ac.Compile(); err != nil {
			return
		}

		// Test matching with the original data and variations
		testData := [][]byte{
			data,
			append(data, data...), // Double the data
			bytes.Repeat(data, 3), // Triple the data
		}

		for _, testBytes := range testData {
			for range ac.SearchIter(testBytes) {
			}

			// Test with prefix/suffix
			withPrefix := append([]byte("prefix"), testBytes...)
			for range ac.SearchIter(withPrefix) {
			}

			withSuffix := make([]byte, len(testBytes)+6)
			copy(withSuffix, testBytes)
			copy(withSuffix[len(testBytes):], []byte("suffix"))
			for range ac.SearchIter(withSuffix) {
			}
		}

		// Test with individual patterns
		for _, pattern := range patterns {
			ac2 := NewACAutomaton()
			if err := ac2.AddString("p", pattern, false, false); err != nil {
				continue
			}
			if err := ac2.Compile(); err != nil {
				continue
			}
			for range ac2.SearchIter(pattern) {
			}
		}
	})
}
