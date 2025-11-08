package lexer

import (
	"testing"
)

// Helper function to create lexer and test looksLikeRegex
func testLooksLikeRegexCase(t *testing.T, input string, expected bool) {
	lexer := &Lexer{
		reader: NewReaderFast(input),
	}

	result := lexer.looksLikeRegex()
	if result != expected {
		t.Errorf("looksLikeRegex() for input %q = %v, want %v", input, result, expected)
	}
}

// TestLooksLikeRegex_EndOfInput tests end of input and whitespace cases
func TestLooksLikeRegex_EndOfInput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"end of input", "", false},
		{"space", " test", true},
		{"tab", "\ttest", true},
		{"newline", "\ntest", true},
		{"carriage return", "\rtest", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testLooksLikeRegexCase(t, tt.input, tt.expected)
		})
	}
}

// TestLooksLikeRegex_CommonRegexStarters tests common regex starting characters
func TestLooksLikeRegex_CommonRegexStarters(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"lowercase letter", "atest", true},
		{"uppercase letter", "Atest", true},
		{"digit", "5test", true},
		{"underscore", "_test", true},
		{"backslash", "\\test", true},
		{"left bracket", "[test", true},
		{"left parenthesis", "(test", true},
		{"dot", ".test", true},
		{"caret", "^test", true},
		{"dollar sign", "$test", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testLooksLikeRegexCase(t, tt.input, tt.expected)
		})
	}
}

// TestLooksLikeRegex_SpecialPatterns tests regex-like patterns with special characters
func TestLooksLikeRegex_SpecialPatterns(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"regex with quantifier", "a+test", false},
		{"regex with character class", "[a-z]test", true},
		{"regex with escaped dot", "\\.test", true},
		{"regex with word boundary", "\\btest", true},
		{"regex with digit shorthand", "\\dtest", true},
		{"regex with whitespace shorthand", "\\stest", true},
		{"regex with word character shorthand", "\\wtest", true},
		{"regex with alternation", "a|btest", true},
		{"regex with group", "(ab)test", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testLooksLikeRegexCase(t, tt.input, tt.expected)
		})
	}
}

// TestLooksLikeRegex_EdgeCases tests edge cases and special characters
func TestLooksLikeRegex_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"next character is slash", "/test", true},
		{"next character is asterisk", "*test", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testLooksLikeRegexCase(t, tt.input, tt.expected)
		})
	}
}

// TestLooksLikeRegex_AdvancedPatterns tests advanced regex patterns and groups
func TestLooksLikeRegex_AdvancedPatterns(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"regex with non-capturing group", "(?:ab)test", true},
		{"regex with lookahead", "(?=ab)test", true},
		{"regex with negative lookahead", "(?!ab)test", true},
		{"regex with lookbehind", "(?<=ab)test", true},
		{"regex with negative lookbehind", "(?<!ab)test", true},
		{"regex with atomic group", "(?>ab)test", true},
		{"regex with case insensitive flag", "(?i)test", true},
		{"regex with multiline flag", "(?m)test", true},
		{"regex with dotall flag", "(?s)test", true},
		{"regex with unicode flag", "(?U)test", true},
		{"regex with verbose flag", "(?x)test", true},
		{"regex with named group", "(?<name>ab)test", true},
		{"regex with conditional", "(?(condition)yes|no)test", true},
		{"regex with recursive pattern", "(?R)test", true},
		{"regex with subroutine call", "(?1)test", true},
		{"regex with comments", "(?#comment)test", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testLooksLikeRegexCase(t, tt.input, tt.expected)
		})
	}
}

// TestLooksLikeRegex_EscapeSequences tests regex escape sequences
func TestLooksLikeRegex_EscapeSequences(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"regex with backreference", "\\1test", true},
		{"regex with octal escape", "\\123test", true},
		{"regex with hex escape", "\\x41test", true},
		{"regex with unicode escape", "\\u0041test", true},
		{"regex with control character", "\\cAtest", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testLooksLikeRegexCase(t, tt.input, tt.expected)
		})
	}
}

// TestLooksLikeRegex_CharacterClasses tests regex character classes
func TestLooksLikeRegex_CharacterClasses(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"regex with character class negation", "[^a-z]test", true},
		{"regex with character class range", "[a-zA-Z0-9]test", true},
		{"regex with predefined character class", "\\w\\d\\s", true},
		{"regex with negated predefined class", "\\W\\D\\S", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testLooksLikeRegexCase(t, tt.input, tt.expected)
		})
	}
}

// TestLooksLikeRegex_Anchors tests regex anchor patterns
func TestLooksLikeRegex_Anchors(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"regex with anchor", "^$test", true},
		{"regex with word boundary", "\\b\\Btest", true},
		{"regex with string start anchor", "\\Atest", true},
		{"regex with string end anchor", "\\ztest", true},
		{"regex with previous match end", "\\Gtest", true},
		{"regex with line start anchor", "^test", true},
		{"regex with line end anchor", "$test", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testLooksLikeRegexCase(t, tt.input, tt.expected)
		})
	}
}

// TestLooksLikeRegex_NegativeCases tests cases that should not be detected as regex
func TestLooksLikeRegex_NegativeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"regex with possessive quantifier", "a++test", false},
		{"regex with reluctant quantifier", "a+?test", false},
		{"regex with quantifier", "a{1,3}test", false},
		{"regex with non-greedy quantifier", "a{1,3}?test", false},
		{"regex with possessive quantifier braces", "a{1,3}+test", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testLooksLikeRegexCase(t, tt.input, tt.expected)
		})
	}
}

// TestLooksLikeRegex_DivisionOperatorEdgeCases tests division operator edge cases
func TestLooksLikeRegex_DivisionOperatorEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"division operator - next char is operator", "+test", true},
		{"division operator - next char is punctuation", ";test", true},
		{"division operator - next char is closing brace", "}test", true},
		{"division operator - next char is comma", ",test", true},
		{"division operator - next char is equals", "=test", true},
		{"division operator - next char is greater than", ">test", true},
		{"division operator - next char is less than", "<test", true},
		{"division operator - next char is exclamation", "!test", true},
		{"division operator - next char is question mark", "?test", true},
		{"division operator - next char is colon", ":test", true},
		{"division operator - next char is pipe", "|test", true},
		{"division operator - next char is ampersand", "&test", true},
		{"division operator - next char is percent", "%test", true},
		{"division operator - next char is tilde", "~test", true},
		{"division operator - next char is backtick", "`test", true},
		{"division operator - next char is quote", "\"test", true},
		{"division operator - next char is apostrophe", "'test", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testLooksLikeRegexCase(t, tt.input, tt.expected)
		})
	}
}
