package lexer_test

import (
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

// tokenTestCase represents a single tokenization test case
type tokenTestCase struct {
	name     string
	input    string
	expected []token.Token
}

// assertTokenSequenceForStringOps validates that the lexer produces the expected token sequence for string operations
func assertTokenSequenceForStringOps(t *testing.T, input string, expected []token.Token) {
	l := lexer.New(input)
	for i, expectedToken := range expected {
		tok := l.NextToken()
		if tok.Type != expectedToken.Type {
			t.Fatalf("token[%d] type wrong. expected=%q, got=%q", i, expectedToken.Type, tok.Type)
		}
		if tok.Literal != expectedToken.Literal {
			t.Fatalf("token[%d] literal wrong. expected=%q, got=%q", i, expectedToken.Literal, tok.Literal)
		}
	}
}

func TestStringOperations(t *testing.T) {
	tests := []tokenTestCase{
		{
			name:  "pe sections name contains",
			input: "pe.sections[0].name contains \".text\"",
			expected: []token.Token{
				{Type: token.IDENTIFIER, Literal: "pe"},
				{Type: token.DOT, Literal: "."},
				{Type: token.IDENTIFIER, Literal: "sections"},
				{Type: token.LBRACKET, Literal: "["},
				{Type: token.INTEGER_LIT, Literal: "0"},
				{Type: token.RBRACKET, Literal: "]"},
				{Type: token.DOT, Literal: "."},
				{Type: token.IDENTIFIER, Literal: "name"},
				{Type: token.CONTAINS, Literal: "contains"},
				{Type: token.STRING_LIT, Literal: ".text"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "filename contains malware",
			input: "filename contains \"malware\"",
			expected: []token.Token{
				{Type: token.IDENTIFIER, Literal: "filename"},
				{Type: token.CONTAINS, Literal: "contains"},
				{Type: token.STRING_LIT, Literal: "malware"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "pe version info icontains",
			input: "pe.version_info[\"CompanyName\"] icontains \"microsoft\"",
			expected: []token.Token{
				{Type: token.IDENTIFIER, Literal: "pe"},
				{Type: token.DOT, Literal: "."},
				{Type: token.IDENTIFIER, Literal: "version_info"},
				{Type: token.LBRACKET, Literal: "["},
				{Type: token.STRING_LIT, Literal: "CompanyName"},
				{Type: token.RBRACKET, Literal: "]"},
				{Type: token.ICONTAINS, Literal: "icontains"},
				{Type: token.STRING_LIT, Literal: "microsoft"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "filename startswith",
			input: "filename startswith \"MZ\"",
			expected: []token.Token{
				{Type: token.IDENTIFIER, Literal: "filename"},
				{Type: token.STARTSWITH, Literal: "startswith"},
				{Type: token.STRING_LIT, Literal: "MZ"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "filename istartswith",
			input: "filename istartswith \"mz\"",
			expected: []token.Token{
				{Type: token.IDENTIFIER, Literal: "filename"},
				{Type: token.ISTARTSWITH, Literal: "istartswith"},
				{Type: token.STRING_LIT, Literal: "mz"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "filename endswith",
			input: "filename endswith \".exe\"",
			expected: []token.Token{
				{Type: token.IDENTIFIER, Literal: "filename"},
				{Type: token.ENDSWITH, Literal: "endswith"},
				{Type: token.STRING_LIT, Literal: ".exe"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "filename iendswith",
			input: "filename iendswith \".EXE\"",
			expected: []token.Token{
				{Type: token.IDENTIFIER, Literal: "filename"},
				{Type: token.IENDSWITH, Literal: "iendswith"},
				{Type: token.STRING_LIT, Literal: ".EXE"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "pe version info iequals",
			input: "pe.version_info[\"CompanyName\"] iequals \"Microsoft Corporation\"",
			expected: []token.Token{
				{Type: token.IDENTIFIER, Literal: "pe"},
				{Type: token.DOT, Literal: "."},
				{Type: token.IDENTIFIER, Literal: "version_info"},
				{Type: token.LBRACKET, Literal: "["},
				{Type: token.STRING_LIT, Literal: "CompanyName"},
				{Type: token.RBRACKET, Literal: "]"},
				{Type: token.IEQUALS, Literal: "iequals"},
				{Type: token.STRING_LIT, Literal: "Microsoft Corporation"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "hash md5 matches regex",
			input: "hash.md5(0, filesize) matches /^[a-f0-9]{32}$/",
			expected: []token.Token{
				{Type: token.HASH, Literal: "hash"},
				{Type: token.DOT, Literal: "."},
				{Type: token.IDENTIFIER, Literal: "md5"},
				{Type: token.LPAREN, Literal: "("},
				{Type: token.INTEGER_LIT, Literal: "0"},
				{Type: token.COMMA, Literal: ","},
				{Type: token.FILESIZE, Literal: "filesize"},
				{Type: token.RPAREN, Literal: ")"},
				{Type: token.MATCHES, Literal: "matches"},
				{Type: token.REGEX_LIT, Literal: "/^[a-f0-9]{32}$/"},
				{Type: token.EOF, Literal: ""},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertTokenSequenceForStringOps(t, tt.input, tt.expected)
		})
	}
}
