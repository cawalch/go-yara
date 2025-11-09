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
	tests := []identifierTestCase{
		{
			name:     "simple identifier",
			input:    "hello world",
			start:    0,
			end:      11,
			expected: 5, // "hello" is 5 characters
		},
		{
			name:     "identifier with underscore",
			input:    "test_var next",
			start:    0,
			end:      12,
			expected: 8, // "test_var" is 8 characters
		},
		{
			name:     "identifier with numbers",
			input:    "var123 other",
			start:    0,
			end:      12,
			expected: 6, // "var123" is 6 characters
		},
		{
			name:     "mixed alphanumeric with underscore",
			input:    "my_var_123 end",
			start:    0,
			end:      14,
			expected: 10, // "my_var_123" is 10 characters
		},
		{
			name:     "start in middle of string",
			input:    "hello world test",
			start:    6, // start at 'w'
			end:      16,
			expected: 11, // "world" is 5 characters, 6 + 5 = 11
		},
		{
			name:     "empty string",
			input:    "",
			start:    0,
			end:      0,
			expected: 0,
		},
		{
			name:     "no identifier at start",
			input:    " 123hello",
			start:    0,
			end:      9,
			expected: 0, // starts with space, not letter/digit/underscore
		},
		{
			name:     "identifier at end of range",
			input:    "test",
			start:    0,
			end:      4,
			expected: 4, // entire string is identifier
		},
		{
			name:     "start beyond end",
			input:    "hello",
			start:    10,
			end:      5,
			expected: 10, // start > end, should return start
		},
		{
			name:     "single character identifier",
			input:    "a bc",
			start:    0,
			end:      4,
			expected: 1, // "a" is 1 character
		},
		{
			name:     "identifier followed by special char",
			input:    "test,end",
			start:    0,
			end:      8,
			expected: 4, // "test" is 4 characters, stops at comma
		},
		{
			name:     "underscore at start of identifier",
			input:    "_test",
			start:    0,
			end:      5,
			expected: 5, // "_test" is 5 characters, all valid identifier chars
		},
		{
			name:     "multiple consecutive identifiers",
			input:    "test more data",
			start:    0,
			end:      14,
			expected: 4, // only skips first identifier "test"
		},
	}

	runIdentifierTests(t, tests, func(l *Lexer, input string, start, end int) int {
		return l.skipIdentifierInRange(input, start, end)
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
	// Basic functionality tests
	basicTests := []colonTestCase{
		{
			name:       "simple tag after colon",
			input:      "strings: $a = { }",
			colonPos:   7,     // position of ':'
			currentPos: 10,    // position of '$'
			expected:   false, // function looks for rule keywords, not $ identifiers
		},
		{
			name:       "multiple tags after colon",
			input:      "strings: $a $b $c = { }",
			colonPos:   7,     // position of ':'
			currentPos: 11,    // position of first '$'
			expected:   false, // function looks for rule keywords, not $ identifiers
		},
		{
			name:       "no tags after colon",
			input:      "condition: $a > 5",
			colonPos:   9,     // position of ':'
			currentPos: 11,    // position of '$'
			expected:   false, // function looks for rule keywords, not $ identifiers
		},
		{
			name:       "colon with no content after",
			input:      "strings:",
			colonPos:   7, // position of ':'
			currentPos: 8, // position after ':'
			expected:   false,
		},
		{
			name:       "whitespace after colon but no tags",
			input:      "strings: = { }",
			colonPos:   7, // position of ':'
			currentPos: 9, // position of '='
			expected:   false,
		},
	}

	// Edge case tests
	edgeCaseTests := []colonTestCase{
		{
			name:       "tags with whitespace",
			input:      "strings: $a\n\t$b = { }",
			colonPos:   7,     // position of ':'
			currentPos: 11,    // position of '$' (first tag)
			expected:   false, // function looks for rule keywords, not $ identifiers
		},
		{
			name:       "invalid colon position",
			input:      "strings $a = { }",
			colonPos:   -1, // invalid position
			currentPos: 8,
			expected:   true, // function doesn't validate colonPos, finds "strings" as identifier
		},
		{
			name:       "current position before colon",
			input:      "strings: $a = { }",
			colonPos:   10, // position after '$'
			currentPos: 7,  // position of ':'
			expected:   false,
		},
	}

	// Malformed tag tests
	malformedTagTests := []colonTestCase{
		{
			name:       "empty input",
			input:      "",
			colonPos:   0,
			currentPos: 0,
			expected:   false,
		},
		{
			name:       "malformed tag - starts with number",
			input:      "strings: 123$a = { }",
			colonPos:   7,     // position of ':'
			currentPos: 15,    // position of '$'
			expected:   false, // 123$a is not a valid identifier
		},
		{
			name:       "malformed tag - special characters",
			input:      "strings: $a-b = { }",
			colonPos:   7,     // position of ':'
			currentPos: 11,    // position of '$'
			expected:   false, // $a-b is not a valid identifier
		},
		{
			name:       "malformed tag - empty tag name",
			input:      "strings: $= { }",
			colonPos:   7,     // position of ':'
			currentPos: 9,     // position of '$'
			expected:   false, // $ is not a valid identifier
		},
		{
			name:       "tag with underscore prefix",
			input:      "strings: $_test = { }",
			colonPos:   7,     // position of ':'
			currentPos: 12,    // position of '$'
			expected:   false, // function looks for rule keywords, not $ identifiers
		},
		{
			name:       "tag with numbers in name",
			input:      "strings: $a123 = { }",
			colonPos:   7,     // position of ':'
			currentPos: 11,    // position of '$'
			expected:   false, // function looks for rule keywords, not $ identifiers
		},
		{
			name:       "multiple malformed tags",
			input:      "strings: $a $ 123$b $= { }",
			colonPos:   7,     // position of ':'
			currentPos: 11,    // position of first '$'
			expected:   false, // contains malformed tags
		},
		{
			name:       "tags with mixed valid and invalid",
			input:      "strings: $a $b $ $c = { }",
			colonPos:   7,     // position of ':'
			currentPos: 11,    // position of first '$'
			expected:   false, // contains empty tag
		},
		{
			name:       "very long tag name",
			input:      "strings: $very_long_tag_name_123 = { }",
			colonPos:   7,     // position of ':'
			currentPos: 11,    // position of '$'
			expected:   false, // function looks for rule keywords, not $ identifiers
		},
		{
			name:       "tag at end of input",
			input:      "strings: $a",
			colonPos:   7,     // position of ':'
			currentPos: 10,    // position of '$'
			expected:   false, // function looks for rule keywords, not $ identifiers
		},
		{
			name:       "colon at end of input",
			input:      "strings:",
			colonPos:   7,     // position of ':'
			currentPos: 8,     // position after ':'
			expected:   false, // no tags after colon
		},
		{
			name:       "only whitespace after colon",
			input:      "strings:   \t\n  ",
			colonPos:   7,     // position of ':'
			currentPos: 14,    // position at end
			expected:   false, // only whitespace, no tags
		},
	}

	// Run test groups
	t.Run("Basic", func(t *testing.T) {
		runColonTests(t, basicTests, func(l *Lexer, input string, colonPos, currentPos int) bool {
			return l.hasTagsAfterColon(input, colonPos, currentPos)
		})
	})

	t.Run("EdgeCases", func(t *testing.T) {
		runColonTests(t, edgeCaseTests, func(l *Lexer, input string, colonPos, currentPos int) bool {
			return l.hasTagsAfterColon(input, colonPos, currentPos)
		})
	})

	t.Run("MalformedTags", func(t *testing.T) {
		runColonTests(t, malformedTagTests, func(l *Lexer, input string, colonPos, currentPos int) bool {
			return l.hasTagsAfterColon(input, colonPos, currentPos)
		})
	})
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
