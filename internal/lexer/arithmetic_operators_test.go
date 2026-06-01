package lexer_test

import (
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func TestArithmeticOperators_Basic(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	tests := []struct {
		name     string
		input    string
		expected token.Type
	}{
		{"multiply", "*", token.MULTIPLY},
		{"divide", "/", token.DIVIDE},
		{"modulo", "%", token.MODULO},
		{"plus", "+", token.PLUS},
		{"minus", "-", token.MINUS},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			helper.AssertSingleToken(tt.input, tt.expected, tt.input)
		})
	}
}

func TestArithmeticOperators_InExpressions(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	tests := []struct {
		name     string
		input    string
		expected []token.Token
	}{
		{
			name:  "addition",
			input: "1 + 2",
			expected: []token.Token{
				{Type: token.IntegerLit, Literal: "1"},
				{Type: token.PLUS, Literal: "+"},
				{Type: token.IntegerLit, Literal: "2"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "subtraction",
			input: "5 - 3",
			expected: []token.Token{
				{Type: token.IntegerLit, Literal: "5"},
				{Type: token.MINUS, Literal: "-"},
				{Type: token.IntegerLit, Literal: "3"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "multiplication",
			input: "4 * 6",
			expected: []token.Token{
				{Type: token.IntegerLit, Literal: "4"},
				{Type: token.MULTIPLY, Literal: "*"},
				{Type: token.IntegerLit, Literal: "6"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "division",
			input: "8 / 2",
			expected: []token.Token{
				{Type: token.IntegerLit, Literal: "8"},
				{Type: token.DIVIDE, Literal: "/"},
				{Type: token.IntegerLit, Literal: "2"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "modulo",
			input: "10 % 3",
			expected: []token.Token{
				{Type: token.IntegerLit, Literal: "10"},
				{Type: token.MODULO, Literal: "%"},
				{Type: token.IntegerLit, Literal: "3"},
				{Type: token.EOF, Literal: ""},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			helper.AssertTokenSequence(tt.input, tt.expected)
		})
	}
}

func TestArithmeticOperators_WithHexIntegers(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	tests := []struct {
		name     string
		input    string
		expected []token.Token
	}{
		{
			name:  "hex multiplication",
			input: "0x100 * 0xFF",
			expected: []token.Token{
				{Type: token.HexIntegerLit, Literal: "0x100"},
				{Type: token.MULTIPLY, Literal: "*"},
				{Type: token.HexIntegerLit, Literal: "0xFF"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "hex division",
			input: "0x1000 / 0x10",
			expected: []token.Token{
				{Type: token.HexIntegerLit, Literal: "0x1000"},
				{Type: token.DIVIDE, Literal: "/"},
				{Type: token.HexIntegerLit, Literal: "0x10"},
				{Type: token.EOF, Literal: ""},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			helper.AssertTokenSequence(tt.input, tt.expected)
		})
	}
}

func TestArithmeticOperators_WithSizeLiterals(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	tests := []struct {
		name     string
		input    string
		expected []token.Token
	}{
		{
			name:  "size multiplication",
			input: "filesize * 2KB",
			expected: []token.Token{
				{Type: token.FILESIZE, Literal: "filesize"},
				{Type: token.MULTIPLY, Literal: "*"},
				{Type: token.SizeLit, Literal: "2KB"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "size division",
			input: "1MB / 1024",
			expected: []token.Token{
				{Type: token.SizeLit, Literal: "1MB"},
				{Type: token.DIVIDE, Literal: "/"},
				{Type: token.IntegerLit, Literal: "1024"},
				{Type: token.EOF, Literal: ""},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			helper.AssertTokenSequence(tt.input, tt.expected)
		})
	}
}

func TestArithmeticOperators_ComplexExpressions(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	tests := []struct {
		name     string
		input    string
		expected []token.Token
	}{
		{
			name:  "mixed arithmetic",
			input: "1 + 2 * 3 - 4 / 2 % 3",
			expected: []token.Token{
				{Type: token.IntegerLit, Literal: "1"},
				{Type: token.PLUS, Literal: "+"},
				{Type: token.IntegerLit, Literal: "2"},
				{Type: token.MULTIPLY, Literal: "*"},
				{Type: token.IntegerLit, Literal: "3"},
				{Type: token.MINUS, Literal: "-"},
				{Type: token.IntegerLit, Literal: "4"},
				{Type: token.DIVIDE, Literal: "/"},
				{Type: token.IntegerLit, Literal: "2"},
				{Type: token.MODULO, Literal: "%"},
				{Type: token.IntegerLit, Literal: "3"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "arithmetic with parentheses",
			input: "(1 + 2) * (3 - 4)",
			expected: []token.Token{
				{Type: token.LPAREN, Literal: "("},
				{Type: token.IntegerLit, Literal: "1"},
				{Type: token.PLUS, Literal: "+"},
				{Type: token.IntegerLit, Literal: "2"},
				{Type: token.RPAREN, Literal: ")"},
				{Type: token.MULTIPLY, Literal: "*"},
				{Type: token.LPAREN, Literal: "("},
				{Type: token.IntegerLit, Literal: "3"},
				{Type: token.MINUS, Literal: "-"},
				{Type: token.IntegerLit, Literal: "4"},
				{Type: token.RPAREN, Literal: ")"},
				{Type: token.EOF, Literal: ""},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			helper.AssertTokenSequence(tt.input, tt.expected)
		})
	}
}

// arithmeticTestCase represents a test case for arithmetic operator validation
type arithmeticTestCase struct {
	name        string
	description string
	input       string
	expectedOps []string
}

func TestArithmeticOperators_InYARARule(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	tests := []arithmeticTestCase{
		{
			name:        "basic rule with arithmetic",
			description: "Tests basic arithmetic operators in a complete YARA rule",
			input: `rule TestRule {
	meta:
		size_calc = 1024 * 1024
	strings:
		$a = "test"
	condition:
			$a and filesize > 100KB and
			(filesize / 1024) < 1MB and
			filesize % 2 == 0
	}`,
			expectedOps: []string{"*", "/", "%"},
		},
		{
			name:        "complex arithmetic expressions",
			description: "Tests complex arithmetic with parentheses and mixed operations",
			input: `rule ComplexRule {
	strings:
		$a = "test"
	condition:
			$a and (1 + 2) * (3 - 4) / 5 % 6 == 0
	}`,
			expectedOps: []string{"+", "*", "-", "/", "%"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertArithmeticOperators(t, helper, tt.input, tt.expectedOps)
		})
	}
}

// assertArithmeticOperators validates that the input contains the expected arithmetic operators
//
//nolint:revive // argument-limit: test helper
func assertArithmeticOperators(t *testing.T, helper *lexer.TestHelper, input string, expectedOps []string) {
	t.Helper()

	tokens := helper.CollectTokens(input)
	actualOps := extractArithmeticOperators(tokens)

	if len(actualOps) != len(expectedOps) {
		t.Errorf("Expected %d arithmetic operators, got %d. Expected: %v, Actual: %v",
			len(expectedOps), len(actualOps), expectedOps, actualOps)
	}

	for i, expected := range expectedOps {
		if i >= len(actualOps) || actualOps[i] != expected {
			t.Errorf("Expected arithmetic op[%d] to be %q, got %q", i, expected, getOperatorAt(actualOps, i))
		}
	}
}

// extractArithmeticOperators extracts arithmetic operators from a token slice
func extractArithmeticOperators(tokens []token.Token) []string {
	operators := make([]string, 0, 8) // Pre-allocate reasonable capacity
	arithmeticTypes := map[token.Type]bool{
		token.PLUS:     true,
		token.MINUS:    true,
		token.MULTIPLY: true,
		token.DIVIDE:   true,
		token.MODULO:   true,
	}

	for _, tok := range tokens {
		if arithmeticTypes[tok.Type] {
			operators = append(operators, tok.Literal)
		}
	}

	return operators
}

// getOperatorAt safely returns an operator at the given index
func getOperatorAt(operators []string, index int) string {
	if index < len(operators) {
		return operators[index]
	}
	return "<missing>"
}

func TestArithmeticOperators_VsDivisionVsRegex(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	// Test that division operator is properly distinguished from regex
	helper.AssertTokenSequence("8 / 2", lexer.CreateTokenSequence(
		token.IntegerLit, "8",
		token.DIVIDE, "/",
		token.IntegerLit, "2",
	))

	// Test that regex is still properly recognized
	helper.AssertSingleToken("/pattern/", token.RegexLit, "/pattern/")

	// Test that line comments are still properly handled (should be skipped)
	helper.AssertTokenSequence("8 // comment\n/ 2", lexer.CreateTokenSequence(
		token.IntegerLit, "8",
		token.DIVIDE, "/",
		token.IntegerLit, "2",
	))
}
