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
	input := "rule r: tag1 {\n  condition: 1 >= 2 and 3 != 4\n}"
	l := lexer.New(input)

	got := collectTokens(l)
	want := []token.Token{
		{Type: token.RULE, Literal: "rule"},
		{Type: token.IDENTIFIER, Literal: "r"},
		{Type: token.COLON, Literal: ":"},
		{Type: token.IDENTIFIER, Literal: "tag1"},
		{Type: token.HEX_STRING_LIT, Literal: "{\n  condition: 1 >= 2 and 3 != 4\n}"},
		{Type: token.EOF, Literal: ""},
	}

	if len(got) != len(want) {
		t.Fatalf("token count mismatch: got %d want %d\nGot: %v\nWant: %v", len(got), len(want), got, want)
	}

	for i := range want {
		if got[i].Type != want[i].Type || got[i].Literal != want[i].Literal {
			t.Fatalf("tok[%d]: got {%v %q} want {%v %q}", i, got[i].Type, got[i].Literal, want[i].Type, want[i].Literal)
		}
	}

	// Verify position tracking for the rule token
	if got[0].Pos.Line != 1 || got[0].Pos.Column != 1 {
		t.Fatalf("rule token position: got line %d col %d, want line 1 col 1", got[0].Pos.Line, got[0].Pos.Column)
	}

	// Verify position tracking for the identifier 'r'
	if got[1].Pos.Line != 1 || got[1].Pos.Column != 6 {
		t.Fatalf("identifier 'r' position: got line %d col %d, want line 1 col 6", got[1].Pos.Line, got[1].Pos.Column)
	}

	// Verify position tracking for the colon
	if got[2].Pos.Line != 1 || got[2].Pos.Column != 7 {
		t.Fatalf("colon position: got line %d col %d, want line 1 col 7", got[2].Pos.Line, got[2].Pos.Column)
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

	// Verify we have the expected structure
	expectedTokenTypes := []token.TokenType{
		token.RULE,
		token.IDENTIFIER, // ComplexRule
		token.COLON,
		token.IDENTIFIER,     // tag1
		token.IDENTIFIER,     // tag2
		token.HEX_STRING_LIT, // { ... }
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

	// Verify the hex string contains the expected content
	hexStringToken := tokens[5]
	if hexStringToken.Type != token.HEX_STRING_LIT {
		t.Fatalf("expected HEX_STRING_LIT token, got %v", hexStringToken.Type)
	}

	// The hex string should contain the entire rule body
	expectedSubstrings := []string{"meta:", "strings:", "condition:", "author", "malware", "E2 34 A1 C8", "pattern"}
	for _, substr := range expectedSubstrings {
		if !contains(hexStringToken.Literal, substr) {
			t.Fatalf("hex string token should contain %q, but got: %q", substr, hexStringToken.Literal)
		}
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			containsAt(s, substr, 1))))
}

func containsAt(s, substr string, start int) bool {
	if start >= len(s) {
		return false
	}
	if start+len(substr) <= len(s) && s[start:start+len(substr)] == substr {
		return true
	}
	return containsAt(s, substr, start+1)
}
