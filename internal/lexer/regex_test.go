package lexer_test

import (
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func TestRegexLiterals_BasicAndFlags(t *testing.T) {
	helper := lexer.NewTestHelper(t)
	cases := []struct {
		name  string
		input string
		seq   []token.Token
	}{
		{"simple", "/pattern/", lexer.CreateTokenSequence(token.RegexLit, "/pattern/")},
		{"flag i", "/pattern/i", lexer.CreateTokenSequence(token.RegexLit, "/pattern/i")},
		{"flag s", "/pattern/s", lexer.CreateTokenSequence(token.RegexLit, "/pattern/s")},
		{"flags is", "/pattern/is", lexer.CreateTokenSequence(token.RegexLit, "/pattern/is")},
		{"flags si", "/pattern/si", lexer.CreateTokenSequence(token.RegexLit, "/pattern/si")},
		{"complex", "/md5: [0-9a-fA-F]{32}/", lexer.CreateTokenSequence(token.RegexLit, "/md5: [0-9a-fA-F]{32}/")},
		{"escaped slash", "/path\\/to\\/file/", lexer.CreateTokenSequence(token.RegexLit, "/path\\/to\\/file/")},
		{"alternation", "/state: (on|off)/i", lexer.CreateTokenSequence(token.RegexLit, "/state: (on|off)/i")},
		{"two regexes", "/foo/ /bar/i", lexer.CreateTokenSequence(token.RegexLit, "/foo/", token.RegexLit, "/bar/i")},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(_ *testing.T) {
			helper.AssertTokenSequence(tt.input, tt.seq)
		})
	}
}

func TestRegexLiterals_EdgeCases(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected token.Token
	}{
		{"empty regex", "//", token.Token{Type: token.RegexLit, Literal: "//"}},
		{"regex only flags", "//is", token.Token{Type: token.RegexLit, Literal: "//is"}},
		{"unterminated", "/pattern", token.Token{Type: token.RegexLit, Literal: "/pattern"}},
		{"escaped backslash", "/pattern\\/", token.Token{Type: token.RegexLit, Literal: "/pattern\\/"}},
		{"char class", "/[a-zA-Z0-9]/", token.Token{Type: token.RegexLit, Literal: "/[a-zA-Z0-9]/"}},
		{"quantifiers", "/fo+o*/", token.Token{Type: token.RegexLit, Literal: "/fo+o*/"}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)
			tok := l.NextToken()
			if tok.Type != tt.expected.Type || tok.Literal != tt.expected.Literal {
				t.Fatalf("expected %v %q, got %v %q", tt.expected.Type, tt.expected.Literal, tok.Type, tok.Literal)
			}
		})
	}
}

func TestRegexLiterals_VsComments_AndInYARARule(t *testing.T) {
	helper := lexer.NewTestHelper(t)
	// Vs comments
	cases := []struct {
		name  string
		input string
		seq   []token.Token
	}{
		{"regex then line comment", "/pattern/ // comment", lexer.CreateTokenSequence(token.RegexLit, "/pattern/")},
		{"regex then block comment", "/pattern/ /* comment */", lexer.CreateTokenSequence(token.RegexLit, "/pattern/")},
		{"line comment not regex", "// not a regex", lexer.CreateTokenSequence()},
		{"block comment not regex", "/* not a regex */", lexer.CreateTokenSequence()},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(_ *testing.T) {
			helper.AssertTokenSequence(tt.input, tt.seq)
		})
	}

	// In YARA rule context
	input := `rule RegexRule {
		strings:
			$re1 = /md5: [0-9a-fA-F]{32}/
			$re2 = /state: (on|off)/i
			$re3 = /foo.*bar/s
		condition:
			any of them
	}`
	tokens := helper.CollectTokens(input)
	regexCount := 0
	for _, tok := range tokens {
		if tok.Type == token.RegexLit {
			regexCount++
		}
	}
	if regexCount != 3 {
		t.Errorf("Expected 3 regex literal tokens, got %d", regexCount)
	}
}
