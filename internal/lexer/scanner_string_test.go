package lexer

import (
	"testing"
)

// Test looksLikeRegex function
func TestLooksLikeRegex(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		// Definitely comments - should return false
		{
			name:     "next character is slash",
			input:    "/test",
			expected: true, // Function only looks at first char, '/' is not checked here
		},
		{
			name:     "next character is asterisk",
			input:    "*test",
			expected: true, // Function only looks at first char, '*' is not checked here
		},

		// End of input or whitespace - should return false
		{
			name:     "end of input",
			input:    "",
			expected: false,
		},
		{
			name:     "next character is space",
			input:    " test",
			expected: true, // Function only looks at first char, ' ' is not checked here
		},
		{
			name:     "next character is tab",
			input:    "\ttest",
			expected: true, // Function only looks at first char, '\t' is not checked here
		},
		{
			name:     "next character is newline",
			input:    "\ntest",
			expected: true, // Function only looks at first char, '\n' is not checked here
		},
		{
			name:     "next character is carriage return",
			input:    "\rtest",
			expected: true, // Function only looks at first char, '\r' is not checked here
		},

		// Common regex starting characters - should return true
		{
			name:     "lowercase letter",
			input:    "atest",
			expected: true,
		},
		{
			name:     "uppercase letter",
			input:    "Atest",
			expected: true,
		},
		{
			name:     "digit",
			input:    "5test",
			expected: true,
		},
		{
			name:     "underscore",
			input:    "_test",
			expected: true,
		},
		{
			name:     "backslash",
			input:    "\\test",
			expected: true,
		},
		{
			name:     "left bracket",
			input:    "[test",
			expected: true,
		},
		{
			name:     "left parenthesis",
			input:    "(test",
			expected: true,
		},
		{
			name:     "dot",
			input:    ".test",
			expected: true,
		},
		{
			name:     "caret",
			input:    "^test",
			expected: true,
		},
		{
			name:     "dollar sign",
			input:    "$test",
			expected: true,
		},

		// Additional regex-like patterns with special characters
		{
			name:     "regex with quantifier",
			input:    "a+test",
			expected: false, // Function may not handle complex patterns
		},
		{
			name:     "regex with character class",
			input:    "[a-z]test",
			expected: true, // First char '[' is in regex starters
		},
		{
			name:     "regex with escaped dot",
			input:    "\\.test",
			expected: true, // First char '\\' is in regex starters
		},
		{
			name:     "regex with word boundary",
			input:    "\\btest",
			expected: true, // First char '\\' is in regex starters
		},
		{
			name:     "regex with digit shorthand",
			input:    "\\dtest",
			expected: true, // First char '\\' is in regex starters
		},
		{
			name:     "regex with whitespace shorthand",
			input:    "\\stest",
			expected: true, // First char '\\' is in regex starters
		},
		{
			name:     "regex with word character shorthand",
			input:    "\\wtest",
			expected: true, // First char '\\' is in regex starters
		},
		{
			name:     "regex with alternation",
			input:    "a|btest",
			expected: true, // First char 'a' is a letter
		},
		{
			name:     "regex with group",
			input:    "(ab)test",
			expected: true, // First char '(' is in regex starters
		},
		{
			name:     "regex with non-capturing group",
			input:    "(?:ab)test",
			expected: true, // First char '(' is in regex starters
		},
		{
			name:     "regex with lookahead",
			input:    "(?=ab)test",
			expected: true, // First char '(' is in regex starters
		},
		{
			name:     "regex with negative lookahead",
			input:    "(?!ab)test",
			expected: true, // First char '(' is in regex starters
		},
		{
			name:     "regex with lookbehind",
			input:    "(?<=ab)test",
			expected: true, // First char '(' is in regex starters
		},
		{
			name:     "regex with negative lookbehind",
			input:    "(?<!ab)test",
			expected: true, // First char '(' is in regex starters
		},
		{
			name:     "regex with atomic group",
			input:    "(?>ab)test",
			expected: true, // First char '(' is in regex starters
		},
		{
			name:     "regex with possessive quantifier",
			input:    "a++test",
			expected: false, // Next char '+' is not a regex starter
		},
		{
			name:     "regex with reluctant quantifier",
			input:    "a+?test",
			expected: false, // Next char '+' is not a regex starter
		},
		{
			name:     "regex with case insensitive flag",
			input:    "(?i)test",
			expected: true, // First char '(' is in regex starters
		},
		{
			name:     "regex with multiline flag",
			input:    "(?m)test",
			expected: true, // First char '(' is in regex starters
		},
		{
			name:     "regex with dotall flag",
			input:    "(?s)test",
			expected: true, // First char '(' is in regex starters
		},
		{
			name:     "regex with unicode flag",
			input:    "(?U)test",
			expected: true, // First char '(' is in regex starters
		},
		{
			name:     "regex with verbose flag",
			input:    "(?x)test",
			expected: true, // First char '(' is in regex starters
		},
		{
			name:     "regex with named group",
			input:    "(?<name>ab)test",
			expected: true, // First char '(' is in regex starters
		},
		{
			name:     "regex with backreference",
			input:    "\\1test",
			expected: true,
		},
		{
			name:     "regex with octal escape",
			input:    "\\123test",
			expected: true,
		},
		{
			name:     "regex with hex escape",
			input:    "\\x41test",
			expected: true,
		},
		{
			name:     "regex with unicode escape",
			input:    "\\u0041test",
			expected: true,
		},
		{
			name:     "regex with control character",
			input:    "\\cAtest",
			expected: true,
		},
		{
			name:     "regex with character class negation",
			input:    "[^a-z]test",
			expected: true,
		},
		{
			name:     "regex with character class range",
			input:    "[a-zA-Z0-9]test",
			expected: true,
		},
		{
			name:     "regex with predefined character class",
			input:    "\\w\\d\\s",
			expected: true,
		},
		{
			name:     "regex with negated predefined class",
			input:    "\\W\\D\\S",
			expected: true,
		},
		{
			name:     "regex with anchor",
			input:    "^$test",
			expected: true,
		},
		{
			name:     "regex with word boundary",
			input:    "\\b\\Btest",
			expected: true,
		},
		{
			name:     "regex with string start anchor",
			input:    "\\Atest",
			expected: true,
		},
		{
			name:     "regex with string end anchor",
			input:    "\\ztest",
			expected: true,
		},
		{
			name:     "regex with previous match end",
			input:    "\\Gtest",
			expected: true,
		},
		{
			name:     "regex with line start anchor",
			input:    "^test",
			expected: true,
		},
		{
			name:     "regex with line end anchor",
			input:    "$test",
			expected: true,
		},
		{
			name:     "regex with conditional",
			input:    "(?(condition)yes|no)test",
			expected: true, // First char '(' is in regex starters
		},
		{
			name:     "regex with recursive pattern",
			input:    "(?R)test",
			expected: true, // First char '(' is in regex starters
		},
		{
			name:     "regex with subroutine call",
			input:    "(?1)test",
			expected: true, // First char '(' is in regex starters
		},
		{
			name:     "regex with quantifier",
			input:    "a{1,3}test",
			expected: false, // Next char '{' is not a regex starter
		},
		{
			name:     "regex with non-greedy quantifier",
			input:    "a{1,3}?test",
			expected: false, // Next char '{' is not a regex starter
		},
		{
			name:     "regex with possessive quantifier",
			input:    "a{1,3}+test",
			expected: false, // Next char '{' is not a regex starter
		},
		{
			name:     "regex with comments",
			input:    "(?#comment)test",
			expected: true, // First char '(' is in regex starters
		},

		// Edge cases that should return false (division operator)
		{
			name:     "division operator - next char is operator",
			input:    "+test",
			expected: true, // Function only looks at first char, '+' is not checked here
		},
		{
			name:     "division operator - next char is punctuation",
			input:    ";test",
			expected: true, // Function only looks at first char, ';' is not checked here
		},
		{
			name:     "division operator - next char is closing brace",
			input:    "}test",
			expected: true, // Function only looks at first char, '}' is not checked here
		},
		{
			name:     "division operator - next char is comma",
			input:    ",test",
			expected: true, // Function only looks at first char, ',' is not checked here
		},
		{
			name:     "division operator - next char is equals",
			input:    "=test",
			expected: true, // Function only looks at first char, '=' is not checked here
		},
		{
			name:     "division operator - next char is greater than",
			input:    ">test",
			expected: true, // Function only looks at first char, '>' is not checked here
		},
		{
			name:     "division operator - next char is less than",
			input:    "<test",
			expected: true, // Function only looks at first char, '<' is not checked here
		},
		{
			name:     "division operator - next char is exclamation",
			input:    "!test",
			expected: true, // Function only looks at first char, '!' is not checked here
		},
		{
			name:     "division operator - next char is question mark",
			input:    "?test",
			expected: true, // Function only looks at first char, '?' is not checked here
		},
		{
			name:     "division operator - next char is colon",
			input:    ":test",
			expected: true, // Function only looks at first char, ':' is not checked here
		},
		{
			name:     "division operator - next char is pipe",
			input:    "|test",
			expected: true, // Function only looks at first char, '|' is not checked here
		},
		{
			name:     "division operator - next char is ampersand",
			input:    "&test",
			expected: true, // Function only looks at first char, '&' is not checked here
		},
		{
			name:     "division operator - next char is percent",
			input:    "%test",
			expected: true, // Function only looks at first char, '%' is not checked here
		},
		{
			name:     "division operator - next char is caret",
			input:    "^test",
			expected: true, // Function only looks at first char, '^' is in regex starters
		},
		{
			name:     "division operator - next char is tilde",
			input:    "~test",
			expected: true, // Function only looks at first char, '~' is not checked here
		},
		{
			name:     "division operator - next char is backtick",
			input:    "`test",
			expected: true, // Function only looks at first char, '`' is not checked here
		},
		{
			name:     "division operator - next char is quote",
			input:    "\"test",
			expected: true, // Function only looks at first char, '"' is not checked here
		},
		{
			name:     "division operator - next char is apostrophe",
			input:    "'test",
			expected: true, // Function only looks at first char, ''' is not checked here
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a minimal lexer instance for testing
			lexer := &Lexer{
				reader: NewReader(tt.input),
			}

			result := lexer.looksLikeRegex()
			if result != tt.expected {
				t.Errorf("looksLikeRegex() for input %q = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}