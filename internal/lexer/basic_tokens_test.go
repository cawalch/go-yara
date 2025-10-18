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

func TestWhitespace_Newlines_Position(t *testing.T) {
	input := "rule r {\n  condition and (1 + 2)\n}\n"
	l := lexer.New(input)

	got := collectTokens(l)
	want := []token.Token{
		{Type: token.RULE, Literal: "rule"},
		{Type: token.IDENTIFIER, Literal: "r"},
		{Type: token.HEX_STRING_LIT, Literal: "{\n  condition and (1 + 2)\n}"},
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

	// Check that the first token (rule) is at line 1, column 1
	if got[0].Pos.Line != 1 || got[0].Pos.Column != 1 {
		t.Fatalf("rule token position: got line %d col %d, want line 1 col 1", got[0].Pos.Line, got[0].Pos.Column)
	}

	// Check that the identifier 'r' is at line 1, column 6
	if got[1].Pos.Line != 1 || got[1].Pos.Column != 6 {
		t.Fatalf("identifier 'r' position: got line %d col %d, want line 1 col 6", got[1].Pos.Line, got[1].Pos.Column)
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
