package lexer

import (
	"testing"
)

// identifierTestCase represents a test case for identifier operations
type identifierTestCase struct {
	name     string
	input    string
	start    int
	end      int
	expected int
}

// createTestLexer creates a minimal lexer instance for testing
func createTestLexer(input string) *Lexer {
	return &Lexer{
		reader: NewReaderFast(input),
	}
}

// runIdentifierTests runs multiple identifier test cases with the given function
func runIdentifierTests(t *testing.T, tests []identifierTestCase, testFunc func(*Lexer, string, int, int) int) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lexer := createTestLexer(tt.input)
			result := testFunc(lexer, tt.input, tt.start, tt.end)
			if result != tt.expected {
				t.Errorf("test failed for input %q, start=%d, end=%d: got %d, want %d",
					tt.input, tt.start, tt.end, result, tt.expected)
			}
		})
	}
}

func TestSkipIdentifierInRange(t *testing.T) {
	// Helper to create test cases
	createTest := func(name, input string, start, end, expected int) identifierTestCase {
		return identifierTestCase{name, input, start, end, expected}
	}

	// Basic identifier tests
	basicTests := []identifierTestCase{
		createTest("simple identifier", "hello world", 0, 11, 5),
		createTest("identifier with underscore", "test_var next", 0, 12, 8),
		createTest("identifier with numbers", "var123 other", 0, 12, 6),
		createTest("mixed alphanumeric with underscore", "my_var_123 end", 0, 14, 10),
		createTest("underscore at start", "_test", 0, 5, 5),
		createTest("single character identifier", "a bc", 0, 4, 1),
	}

	// Edge case tests
	edgeTests := []identifierTestCase{
		createTest("start in middle", "hello world test", 6, 16, 11),
		createTest("empty string", "", 0, 0, 0),
		createTest("start beyond end", "hello", 10, 5, 10),
		createTest("identifier at end", "test", 0, 4, 4),
	}

	// Boundary and special case tests
	specialTests := []identifierTestCase{
		createTest("no identifier at start", " 123hello", 0, 9, 0),
		createTest("identifier followed by special char", "test,end", 0, 8, 4),
		createTest("multiple consecutive identifiers", "test more data", 0, 14, 4),
	}

	// Run test groups
	t.Run("Basic", func(t *testing.T) {
		runIdentifierTests(t, basicTests, func(l *Lexer, input string, start, end int) int {
			return l.skipIdentifierInRange(input, start, end)
		})
	})

	t.Run("EdgeCases", func(t *testing.T) {
		runIdentifierTests(t, edgeTests, func(l *Lexer, input string, start, end int) int {
			return l.skipIdentifierInRange(input, start, end)
		})
	})

	t.Run("SpecialCases", func(t *testing.T) {
		runIdentifierTests(t, specialTests, func(l *Lexer, input string, start, end int) int {
			return l.skipIdentifierInRange(input, start, end)
		})
	})
}

// colonTestCase represents a test case for colon-related operations
type colonTestCase struct {
	name       string
	input      string
	colonPos   int
	currentPos int
	expected   bool
}

// runColonTests runs multiple colon test cases with the given function
func runColonTests(t *testing.T, tests []colonTestCase, testFunc func(*Lexer, string, int, int) bool) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lexer := createTestLexer(tt.input)
			result := testFunc(lexer, tt.input, tt.colonPos, tt.currentPos)
			if result != tt.expected {
				t.Errorf("test failed for input %q, colonPos=%d, currentPos=%d: got %v, want %v",
					tt.input, tt.colonPos, tt.currentPos, result, tt.expected)
			}
		})
	}
}

func TestHasTagsAfterColon(t *testing.T) {
	// Helper to create test cases that expect false
	createFalseTests := func(tests []struct {
		name       string
		input      string
		colonPos   int
		currentPos int
	}) []colonTestCase {
		var result []colonTestCase
		for _, test := range tests {
			result = append(result, colonTestCase{
				name:       test.name,
				input:      test.input,
				colonPos:   test.colonPos,
				currentPos: test.currentPos,
				expected:   false,
			})
		}
		return result
	}

	// Basic functionality tests (all expect false)
	basicTests := createFalseTests([]struct {
		name       string
		input      string
		colonPos   int
		currentPos int
	}{
		{"simple tag after colon", "strings: $a = { }", 7, 10},
		{"multiple tags after colon", "strings: $a $b $c = { }", 7, 11},
		{"no tags after colon", "condition: $a > 5", 9, 11},
		{"colon with no content after", "strings:", 7, 8},
		{"whitespace after colon but no tags", "strings: = { }", 7, 9},
	})

	// Edge case tests
	edgeCaseTests := []colonTestCase{
		{"tags with whitespace", "strings: $a\n\t$b = { }", 7, 11, false},
		{"invalid colon position", "strings $a = { }", -1, 8, true}, // Only test that expects true
		{"current position before colon", "strings: $a = { }", 10, 7, false},
	}

	// Malformed tag tests (all expect false)
	malformedTagTests := createFalseTests([]struct {
		name       string
		input      string
		colonPos   int
		currentPos int
	}{
		{"empty input", "", 0, 0},
		{"malformed tag - starts with number", "strings: 123$a = { }", 7, 15},
		{"malformed tag - special characters", "strings: $a-b = { }", 7, 11},
		{"malformed tag - empty tag name", "strings: $= { }", 7, 9},
		{"tag with underscore prefix", "strings: $_test = { }", 7, 12},
		{"tag with numbers in name", "strings: $a123 = { }", 7, 11},
		{"multiple malformed tags", "strings: $a $ 123$b $= { }", 7, 11},
		{"tags with mixed valid and invalid", "strings: $a $b $ $c = { }", 7, 11},
		{"very long tag name", "strings: $very_long_tag_name_123 = { }", 7, 11},
		{"tag at end of input", "strings: $a", 7, 10},
		{"colon at end of input", "strings:", 7, 8},
		{"only whitespace after colon", "strings:   \t\n  ", 7, 14},
	})

	// Test runner function
	runTestGroup := func(t *testing.T, groupName string, tests []colonTestCase) {
		t.Run(groupName, func(t *testing.T) {
			runColonTests(t, tests, func(l *Lexer, input string, colonPos, currentPos int) bool {
				return l.hasTagsAfterColon(input, colonPos, currentPos)
			})
		})
	}

	// Run test groups
	runTestGroup(t, "Basic", basicTests)
	runTestGroup(t, "EdgeCases", edgeCaseTests)
	runTestGroup(t, "MalformedTags", malformedTagTests)
}

// positionTestCase represents a test case for position-based operations
type positionTestCase struct {
	name       string
	input      string
	currentPos int
	expected   int
}

// runPositionTests runs multiple position test cases with the given function
func runPositionTests(t *testing.T, tests []positionTestCase, testFunc func(*Lexer, string, int) int) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lexer := createTestLexer(tt.input)
			result := testFunc(lexer, tt.input, tt.currentPos)
			if result != tt.expected {
				t.Errorf("test failed for input %q, currentPos=%d: got %d, want %d",
					tt.input, tt.currentPos, result, tt.expected)
			}
		})
	}
}

func TestFindRecentColon(t *testing.T) {
	tests := []positionTestCase{
		{
			name:       "colon found nearby",
			input:      "strings: $a = { }",
			currentPos: 12, // position after '$'
			expected:   7,  // position of ':'
		},
		{
			name:       "no colon in range",
			input:      "strings $a = { }",
			currentPos: 12,
			expected:   -1,
		},
		{
			name:       "colon at beginning",
			input:      ": $a = { }",
			currentPos: 8,
			expected:   0,
		},
		{
			name:       "multiple colons, find recent",
			input:      "meta: name = \"test\"\nstrings: $a = { }",
			currentPos: 35, // position in second line
			expected:   27, // position of second ':'
		},
		{
			name:       "colon beyond lookback range",
			input:      "strings" + string(make([]byte, 150)) + ": $a",
			currentPos: 160,
			expected:   157, // colon is within lookback range
		},
		{
			name:       "current position at start",
			input:      ": $a",
			currentPos: 0,
			expected:   -1,
		},
	}

	runPositionTests(t, tests, func(l *Lexer, input string, currentPos int) int {
		return l.findRecentColon(input, currentPos)
	})
}

func TestSkipWhitespaceInRange(t *testing.T) {
	tests := []identifierTestCase{
		{
			name:     "skip spaces",
			input:    "   hello",
			start:    0,
			end:      8,
			expected: 3,
		},
		{
			name:     "skip tabs and newlines",
			input:    "\t\n\r hello",
			start:    0,
			end:      9,
			expected: 4,
		},
		{
			name:     "no whitespace",
			input:    "hello",
			start:    0,
			end:      5,
			expected: 0,
		},
		{
			name:     "mixed whitespace",
			input:    " \t\n hello",
			start:    0,
			end:      9,
			expected: 4,
		},
		{
			name:     "start in middle",
			input:    "a   b",
			start:    1,
			end:      5,
			expected: 4, // skips spaces at positions 1, 2, 3
		},
		{
			name:     "beyond end",
			input:    "hello",
			start:    10,
			end:      5,
			expected: 10,
		},
	}

	runIdentifierTests(t, tests, func(l *Lexer, input string, start, end int) int {
		return l.skipWhitespaceInRange(input, start, end)
	})
}
