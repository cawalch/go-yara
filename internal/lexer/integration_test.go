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
		{Type: token.STRING_LIT, Literal: "test"},
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
		token.INTEGER_LIT, "1",
		token.EQ, "==",
		token.INTEGER_LIT, "1",
		token.AND, "and",
		token.INTEGER_LIT, "2",
		token.NEQ, "!=",
		token.INTEGER_LIT, "3",
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
				{Type: token.REGEX_LIT, Literal: "//"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "empty regex with flags",
			input: "//i",
			expected: []token.Token{
				{Type: token.REGEX_LIT, Literal: "//i"},
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
func comparisonTokens(left string, op token.TokenType, right string) []token.Token {
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
func identifierOrKeyword(lit string) token.TokenType {
	switch lit {
	case "filesize":
		return token.FILESIZE
	case "entrypoint":
		return token.ENTRYPOINT
	case "1", "2", "3", "4", "5", "6", "7", "8", "9", "0":
		return token.INTEGER_LIT
	case "1MB":
		return token.SIZE_LIT
	case "0x400000":
		return token.HEX_INTEGER_LIT
	default:
		return token.IDENTIFIER
	}
}

// operatorLiteral returns the literal representation of comparison operators
func operatorLiteral(op token.TokenType) string {
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

func TestComplexYARARule(t *testing.T) {
	// Test a more complex YARA rule structure
	input := `rule ComplexRule : tag1 tag2 {
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

	l := lexer.New(input)
	tokens := collectTokens(l)

	// Verify we have the expected structure - rule body should be properly parsed
	expectedTokenTypes := []token.TokenType{
		token.RULE,
		token.IDENTIFIER, // ComplexRule
		token.COLON,
		token.IDENTIFIER, // tag1
		token.IDENTIFIER, // tag2
		token.LBRACE,
		token.META,
		token.COLON,
		token.IDENTIFIER, // author
		token.ASSIGN,
		token.STRING_LIT, // "test"
		token.IDENTIFIER, // version
		token.ASSIGN,
		token.INTEGER_LIT, // 1
		token.IDENTIFIER,  // enabled
		token.ASSIGN,
		token.TRUE, // true
		token.STRINGS,
		token.COLON,
		token.STRING_IDENTIFIER, // $a
		token.ASSIGN,
		token.STRING_LIT,        // "malware"
		token.STRING_IDENTIFIER, // $b
		token.ASSIGN,
		token.HEX_STRING_LIT,    // { E2 34 A1 C8 }
		token.STRING_IDENTIFIER, // $c
		token.ASSIGN,
		token.REGEX_LIT, // /pattern/i
		token.CONDITION,
		token.COLON,
		token.LPAREN,
		token.STRING_IDENTIFIER, // $a
		token.AND,
		token.STRING_IDENTIFIER, // $b
		token.RPAREN,
		token.OR,
		token.STRING_IDENTIFIER, // $c
		token.AND,
		token.NOT,
		token.FALSE,
		token.RBRACE,
		token.EOF,
	}

	if len(tokens) != len(expectedTokenTypes) {
		t.Fatalf("expected %d tokens, got %d\nActual tokens: %v", len(expectedTokenTypes), len(tokens), tokens)
	}

	for i, expectedType := range expectedTokenTypes {
		if tokens[i].Type != expectedType {
			t.Fatalf("token[%d]: expected type %v, got %v", i, expectedType, tokens[i].Type)
		}
	}

	// Verify specific token literals
	if tokens[1].Literal != "ComplexRule" {
		t.Fatalf("expected rule name 'ComplexRule', got %q", tokens[1].Literal)
	}
	if tokens[3].Literal != "tag1" {
		t.Fatalf("expected tag 'tag1', got %q", tokens[3].Literal)
	}
	if tokens[4].Literal != "tag2" {
		t.Fatalf("expected tag 'tag2', got %q", tokens[4].Literal)
	}
	if tokens[6].Literal != "meta" {
		t.Fatalf("expected meta section, got %q", tokens[6].Literal)
	}
	if tokens[17].Literal != "strings" {
		t.Fatalf("expected strings section, got %q", tokens[17].Literal)
	}
	if tokens[28].Literal != "condition" {
		t.Fatalf("expected condition section, got %q", tokens[28].Literal)
	}
}
