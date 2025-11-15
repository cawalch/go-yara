package lexer_test

import (
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func TestNextToken_YARAMetaSection(t *testing.T) {
	// Test YARA meta section syntax: meta: key = value
	input := "meta: author = \"test\""
	l := lexer.New(input)

	got := collectTokens(l)
	want := []token.Token{
		{Type: token.META, Literal: "meta"},
		{Type: token.COLON, Literal: ":"},
		{Type: token.IDENTIFIER, Literal: "author"},
		{Type: token.ASSIGN, Literal: "="},
		{Type: token.StringLit, Literal: "test"},
		{Type: token.EOF, Literal: ""},
	}

	if len(got) != len(want) {
		t.Fatalf("token count mismatch: got %d want %d\n%v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].Type != want[i].Type || got[i].Literal != want[i].Literal {
			t.Fatalf("tok[%d]: got {%v %q} want {%v %q}", i, got[i].Type, got[i].Literal, want[i].Type, want[i].Literal)
		}
	}
}

func TestNextToken_YARAConditionSection(t *testing.T) {
	// Test YARA condition section with both : and == operators
	helper := lexer.NewTestHelper(t)
	helper.AssertTokenSequence("condition: 1 == 1 and 2 != 3", lexer.CreateTokenSequence(
		token.CONDITION, "condition",
		token.COLON, ":",
		token.IntegerLit, "1",
		token.EQ, "==",
		token.IntegerLit, "1",
		token.AND, "and",
		token.IntegerLit, "2",
		token.NEQ, "!=",
		token.IntegerLit, "3",
	))
}

func TestNextToken_RegexLiterals_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []token.Token
	}{
		{
			name:  "empty regex",
			input: "//",
			expected: []token.Token{
				{Type: token.RegexLit, Literal: "//"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "empty regex with flags",
			input: "//i",
			expected: []token.Token{
				{Type: token.RegexLit, Literal: "//i"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "regex vs comment disambiguation",
			input: "rule test { condition: // comment\n true }",
			expected: []token.Token{
				{Type: token.RULE, Literal: "rule"},
				{Type: token.IDENTIFIER, Literal: "test"},
				{Type: token.LBRACE, Literal: "{"},
				{Type: token.CONDITION, Literal: "condition"},
				{Type: token.COLON, Literal: ":"},
				{Type: token.TRUE, Literal: "true"},
				{Type: token.RBRACE, Literal: "}"},
				{Type: token.EOF, Literal: ""},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)
			got := collectTokens(l)

			if len(got) != len(tt.expected) {
				t.Fatalf("token count mismatch: got %d want %d\n%v", len(got), len(tt.expected), got)
			}

			for i := range tt.expected {
				if got[i].Type != tt.expected[i].Type || got[i].Literal != tt.expected[i].Literal {
					t.Fatalf("tok[%d]: got {%v %q} want {%v %q}", i, got[i].Type, got[i].Literal, tt.expected[i].Type, tt.expected[i].Literal)
				}
			}
		})
	}
}

func TestYARALike_Header_Condition_WithComparisons(t *testing.T) {
	t.Run("BasicRuleWithTag", testBasicRuleWithTagAndComparisons)
	t.Run("MultipleTagsWithComparisons", testMultipleTagsWithComparisonOperators)
	t.Run("AllComparisonOperators", testRuleWithAllComparisonOperators)
}

// testBasicRuleWithTagAndComparisons tests basic rule structure with tag and comparison operators
func testBasicRuleWithTagAndComparisons(t *testing.T) {
	input := "rule r: tag1 {\n  condition: 1 >= 2 and 3 != 4\n}"
	expected := createBasicRuleTokens("r", []string{"tag1"},
		comparisonTokens("1", token.GE, "2"),
		comparisonTokens("3", token.NEQ, "4"))
	positions := basicRulePositions()

	assertTokenSequenceAndPositions(t, input, expected, positions)
}

// testMultipleTagsWithComparisonOperators tests rule with multiple tags and size/entrypoint comparisons
func testMultipleTagsWithComparisonOperators(t *testing.T) {
	input := "rule test_rule: tag1 tag2 {\n  condition: filesize <= 1MB and entrypoint >= 0x400000\n}"
	expected := createBasicRuleTokens("test_rule", []string{"tag1", "tag2"},
		comparisonTokens("filesize", token.LE, "1MB"),
		comparisonTokens("entrypoint", token.GE, "0x400000"))
	positions := []positionCheck{
		{tokenIndex: 0, line: 1, column: 1, description: "rule token"},
		{tokenIndex: 1, line: 1, column: 6, description: "rule identifier"},
		{tokenIndex: 2, line: 1, column: 15, description: "colon after rule identifier"},
	}

	assertTokenSequenceAndPositions(t, input, expected, positions)
}

// testRuleWithAllComparisonOperators tests rule using all comparison operators
func testRuleWithAllComparisonOperators(t *testing.T) {
	input := "rule comp_test {\n  condition: a == b and c != d and e < f and g > h\n}"
	expected := createRuleWithoutTags("comp_test",
		comparisonTokens("a", token.EQ, "b"),
		comparisonTokens("c", token.NEQ, "d"),
		comparisonTokens("e", token.LT, "f"),
		comparisonTokens("g", token.GT, "h"))
	positions := []positionCheck{
		{tokenIndex: 0, line: 1, column: 1, description: "rule token"},
		{tokenIndex: 1, line: 1, column: 6, description: "rule identifier"},
	}

	assertTokenSequenceAndPositions(t, input, expected, positions)
}

// Helper functions to reduce token creation duplication

// comparisonTokens creates a three-token sequence for binary comparisons
func comparisonTokens(left string, op token.Type, right string) []token.Token {
	return []token.Token{
		{Type: identifierOrKeyword(left), Literal: left},
		{Type: op, Literal: operatorLiteral(op)},
		{Type: identifierOrKeyword(right), Literal: right},
	}
}

// createBasicRuleTokens creates tokens for rules with tags and conditions
func createBasicRuleTokens(ruleName string, tags []string, conditions ...[]token.Token) []token.Token {
	tokens := []token.Token{
		{Type: token.RULE, Literal: "rule"},
		{Type: token.IDENTIFIER, Literal: ruleName},
		{Type: token.COLON, Literal: ":"},
	}

	// Add tags
	for _, tag := range tags {
		tokens = append(tokens, token.Token{Type: token.IDENTIFIER, Literal: tag})
	}

	// Add rule structure
	tokens = append(tokens, token.Token{Type: token.LBRACE, Literal: "{"})
	tokens = append(tokens, token.Token{Type: token.CONDITION, Literal: "condition"})
	tokens = append(tokens, token.Token{Type: token.COLON, Literal: ":"})

	// Add conditions with operators
	for i, condition := range conditions {
		if i > 0 {
			tokens = append(tokens, token.Token{Type: token.AND, Literal: "and"})
		}
		tokens = append(tokens, condition...)
	}

	tokens = append(tokens, token.Token{Type: token.RBRACE, Literal: "}"})
	tokens = append(tokens, token.Token{Type: token.EOF, Literal: ""})

	return tokens
}

// createRuleWithoutTags creates tokens for rules without tags (no colon after rule name)
func createRuleWithoutTags(ruleName string, conditions ...[]token.Token) []token.Token {
	tokens := []token.Token{
		{Type: token.RULE, Literal: "rule"},
		{Type: token.IDENTIFIER, Literal: ruleName},
		{Type: token.LBRACE, Literal: "{"},
	}

	tokens = append(tokens, token.Token{Type: token.CONDITION, Literal: "condition"})
	tokens = append(tokens, token.Token{Type: token.COLON, Literal: ":"})

	// Add conditions with operators
	for i, condition := range conditions {
		if i > 0 {
			tokens = append(tokens, token.Token{Type: token.AND, Literal: "and"})
		}
		tokens = append(tokens, condition...)
	}

	tokens = append(tokens, token.Token{Type: token.RBRACE, Literal: "}"})
	tokens = append(tokens, token.Token{Type: token.EOF, Literal: ""})

	return tokens
}

// basicRulePositions returns common position checks for basic rules
func basicRulePositions() []positionCheck {
	return []positionCheck{
		{tokenIndex: 0, line: 1, column: 1, description: "rule token"},
		{tokenIndex: 1, line: 1, column: 6, description: "rule identifier"},
		{tokenIndex: 2, line: 1, column: 7, description: "colon after rule name"},
	}
}

// identifierOrKeyword returns the appropriate token type for identifiers and keywords
func identifierOrKeyword(lit string) token.Type {
	switch lit {
	case "filesize":
		return token.FILESIZE
	case "entrypoint":
		return token.ENTRYPOINT
	case "1", "2", "3", "4", "5", "6", "7", "8", "9", "0":
		return token.IntegerLit
	case "1MB":
		return token.SizeLit
	case "0x400000":
		return token.HexIntegerLit
	default:
		return token.IDENTIFIER
	}
}

// operatorLiteral returns the literal representation of comparison operators
func operatorLiteral(op token.Type) string {
	switch op {
	case token.EQ:
		return "=="
	case token.NEQ:
		return "!="
	case token.LT:
		return "<"
	case token.LE:
		return "<="
	case token.GT:
		return ">"
	case token.GE:
		return ">="
	default:
		return ""
	}
}

// TestComplexYARARule tests tokenization of a complete YARA rule with all major features
func TestComplexYARARule(t *testing.T) {
	// Test data extracted for better maintainability
	testCase := struct {
		name             string
		input            string
		expectedTokens   []token.Type
		expectedLiterals map[int]string // index -> expected literal
	}{
		name:           "complete_yara_rule",
		input:          getComplexYARARuleInput(),
		expectedTokens: getComplexYARARuleExpectedTokens(),
		expectedLiterals: map[int]string{
			1:  "ComplexRule",
			3:  "tag1",
			4:  "tag2",
			6:  "meta",
			17: "strings",
			28: "condition",
		},
	}

	t.Run(testCase.name, func(t *testing.T) {
		assertTokenization(t, testCase.input, testCase.expectedTokens, testCase.expectedLiterals)
	})
}

// getComplexYARARuleInput returns the test rule input
func getComplexYARARuleInput() string {
	return `rule ComplexRule : tag1 tag2 {
 		meta:
 			author = "test"
 			version = 1
 			enabled = true
 		strings:
 			$a = "malware"
 			$b = { E2 34 A1 C8 }
 			$c = /pattern/i
 		condition:
 			($a and $b) or $c and not false
 	}`
}

// getComplexYARARuleExpectedTokens returns the expected token sequence for the complex rule
func getComplexYARARuleExpectedTokens() []token.Type {
	return []token.Type{
		token.RULE,
		token.IDENTIFIER,
		token.COLON,
		token.IDENTIFIER,
		token.IDENTIFIER,
		token.LBRACE,
		token.META,
		token.COLON,
		token.IDENTIFIER,
		token.ASSIGN,
		token.StringLit,
		token.IDENTIFIER,
		token.ASSIGN,
		token.IntegerLit,
		token.IDENTIFIER,
		token.ASSIGN,
		token.TRUE,
		token.STRINGS,
		token.COLON,
		token.StringIdentifier,
		token.ASSIGN,
		token.StringLit,
		token.StringIdentifier,
		token.ASSIGN,
		token.HexStringLit,
		token.StringIdentifier,
		token.ASSIGN,
		token.RegexLit,
		token.CONDITION,
		token.COLON,
		token.LPAREN,
		token.StringIdentifier,
		token.AND,
		token.StringIdentifier,
		token.RPAREN,
		token.OR,
		token.StringIdentifier,
		token.AND,
		token.NOT,
		token.FALSE,
		token.RBRACE,
		token.EOF,
	}
}

// assertTokenization is a helper function that validates tokenization results
func assertTokenization(t *testing.T, input string, expectedTokens []token.Type, expectedLiterals map[int]string) {
	l := lexer.New(input)
	tokens := collectTokens(l)

	if len(tokens) != len(expectedTokens) {
		t.Fatalf("expected %d tokens, got %d\nActual tokens: %v",
			len(expectedTokens), len(tokens), tokens)
	}

	// Verify token types
	for i, expectedType := range expectedTokens {
		if tokens[i].Type != expectedType {
			t.Fatalf("token[%d]: expected type %v, got %v",
				i, expectedType, tokens[i].Type)
		}
	}

	// Verify specific literals
	for index, expectedLiteral := range expectedLiterals {
		if tokens[index].Literal != expectedLiteral {
			t.Fatalf("token[%d]: expected literal %q, got %q",
				index, expectedLiteral, tokens[index].Literal)
		}
	}
}
