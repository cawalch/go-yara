package lexer_test

import (
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func TestNextToken_Basic(t *testing.T) {
	input := "and or == + - ( ) { }"
	l := lexer.New(input)

	got := collectTokens(l)
	want := []token.Token{
		{Type: token.AND, Literal: "and"},
		{Type: token.OR, Literal: "or"},
		{Type: token.EQ, Literal: "=="},
		{Type: token.PLUS, Literal: "+"},
		{Type: token.MINUS, Literal: "-"},
		{Type: token.LPAREN, Literal: "("},
		{Type: token.RPAREN, Literal: ")"},
		{Type: token.HEX_STRING_LIT, Literal: "{ }"}, // { } is now treated as empty hex string
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

func TestNextToken_IdentifiersNumbersStrings(t *testing.T) {
	input := "foo 123 \"bar\"\nAND"
	l := lexer.New(input)

	got := collectTokens(l)
	want := []token.Token{
		{Type: token.IDENTIFIER, Literal: "foo"},
		{Type: token.INTEGER_LIT, Literal: "123"},
		{Type: token.STRING_LIT, Literal: "bar"},
		{Type: token.IDENTIFIER, Literal: "AND"}, // uppercase keyword remains identifier in current lexer
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

func TestNextToken_AssignToken(t *testing.T) {
	l := lexer.New("=")
	tok := l.NextToken()
	if tok.Type != token.ASSIGN || tok.Literal != "=" {
		t.Fatalf("expected ASSIGN token with literal '=', got %v %q", tok.Type, tok.Literal)
	}
}

func TestNextToken_AssignVsEquals(t *testing.T) {
	// Test that single '=' is ASSIGN and double '==' is EQ
	tests := []struct {
		input    string
		expected token.TokenType
		literal  string
	}{
		{"=", token.ASSIGN, "="},
		{"==", token.EQ, "=="},
	}

	for _, tt := range tests {
		l := lexer.New(tt.input)
		tok := l.NextToken()
		if tok.Type != tt.expected || tok.Literal != tt.literal {
			t.Fatalf("input %q: expected %v %q, got %v %q", tt.input, tt.expected, tt.literal, tok.Type, tok.Literal)
		}
	}
}

func TestPunctuationAndComparisons(t *testing.T) {
	helper := lexer.NewTestHelper(t)
	helper.AssertTokenSequence(": , . == != < <= > >=", lexer.CreateTokenSequence(
		token.COLON, ":",
		token.COMMA, ",",
		token.DOT, ".",
		token.EQ, "==",
		token.NEQ, "!=",
		token.LT, "<",
		token.LE, "<=",
		token.GT, ">",
		token.GE, ">=",
	))
}

// positionTestCase represents a test case for position tracking validation
type positionTestCase struct {
	name     string
	input    string
	expected []token.Token
	positions []positionCheck // positions to validate for specific tokens
}

// positionCheck defines the expected position for a token at a given index
type positionCheck struct {
	tokenIndex int
	line       int
	column     int
	description string
}

func TestWhitespace_Newlines_Position(t *testing.T) {
	tests := []positionTestCase{
		{
			name:  "basic rule with newlines",
			input: "rule r {\n  condition and (1 + 2)\n}\n",
			expected: []token.Token{
				{Type: token.RULE, Literal: "rule"},
				{Type: token.IDENTIFIER, Literal: "r"},
				{Type: token.LBRACE, Literal: "{"},
				{Type: token.CONDITION, Literal: "condition"},
				{Type: token.AND, Literal: "and"},
				{Type: token.LPAREN, Literal: "("},
				{Type: token.INTEGER_LIT, Literal: "1"},
				{Type: token.PLUS, Literal: "+"},
				{Type: token.INTEGER_LIT, Literal: "2"},
				{Type: token.RPAREN, Literal: ")"},
				{Type: token.RBRACE, Literal: "}"},
				{Type: token.EOF, Literal: ""},
			},
			positions: []positionCheck{
				{tokenIndex: 0, line: 1, column: 1, description: "rule token"},
				{tokenIndex: 1, line: 1, column: 6, description: "identifier 'r'"},
				{tokenIndex: 3, line: 2, column: 4, description: "condition token"},
			},
		},
		{
			name:  "multiple line rule",
			input: "rule test_rule {\n strings:\n  $a = \"test\"\n condition:\n  $a\n}",
			expected: []token.Token{
				{Type: token.RULE, Literal: "rule"},
				{Type: token.IDENTIFIER, Literal: "test_rule"},
				{Type: token.LBRACE, Literal: "{"},
				{Type: token.STRINGS, Literal: "strings"},
				{Type: token.COLON, Literal: ":"},
				{Type: token.STRING_IDENTIFIER, Literal: "$a"},
				{Type: token.ASSIGN, Literal: "="},
				{Type: token.STRING_LIT, Literal: "test"},
				{Type: token.CONDITION, Literal: "condition"},
				{Type: token.COLON, Literal: ":"},
				{Type: token.STRING_IDENTIFIER, Literal: "$a"},
				{Type: token.RBRACE, Literal: "}"},
				{Type: token.EOF, Literal: ""},
			},
			positions: []positionCheck{
				{tokenIndex: 0, line: 1, column: 1, description: "rule token"},
				{tokenIndex: 3, line: 2, column: 3, description: "strings token"},
				{tokenIndex: 8, line: 4, column: 3, description: "condition token"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertTokenSequenceAndPositions(t, tt.input, tt.expected, tt.positions)
		})
	}
}

// assertTokenSequenceAndPositions validates both token sequence and their positions
func assertTokenSequenceAndPositions(t *testing.T, input string, expectedTokens []token.Token, positions []positionCheck) {
	t.Helper()

	l := lexer.New(input)
	got := collectTokens(l)

	// Validate token sequence
	if len(got) != len(expectedTokens) {
		t.Fatalf("token count mismatch: got %d want %d\nGot: %v\nWant: %v",
			len(got), len(expectedTokens), got, expectedTokens)
	}

	for i := range expectedTokens {
		if got[i].Type != expectedTokens[i].Type || got[i].Literal != expectedTokens[i].Literal {
			t.Fatalf("tok[%d]: got {%v %q} want {%v %q}",
				i, got[i].Type, got[i].Literal, expectedTokens[i].Type, expectedTokens[i].Literal)
		}
	}

	// Validate positions for specified tokens
	for _, posCheck := range positions {
		if posCheck.tokenIndex >= len(got) {
			t.Fatalf("position check index %d out of range for %d tokens",
				posCheck.tokenIndex, len(got))
		}

		token := got[posCheck.tokenIndex]
		if token.Pos.Line != posCheck.line || token.Pos.Column != posCheck.column {
			t.Fatalf("%s position: got line %d col %d, want line %d col %d",
				posCheck.description, token.Pos.Line, token.Pos.Column,
				posCheck.line, posCheck.column)
		}
	}
}

func TestTabsAndCRLF(t *testing.T) {
	input := "\t\tand\r\nor"
	l := lexer.New(input)
	got := collectTokens(l)
	want := []token.Token{
		{Type: token.AND, Literal: "and"},
		{Type: token.OR, Literal: "or"},
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

func TestIllegalUnknownCharacter(t *testing.T) {
	l := lexer.New("?")
	tok := l.NextToken()
	if tok.Type != token.ILLEGAL || tok.Literal != "?" {
		t.Fatalf("expected ILLEGAL token with literal '?', got %v %q", tok.Type, tok.Literal)
	}
}
