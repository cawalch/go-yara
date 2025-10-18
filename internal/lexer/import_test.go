package lexer_test

import (
	"fmt"
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func TestImportInclude(t *testing.T) {
	tests := []struct {
		input    string
		expected []token.Token
	}{
		{
			input: "import \"pe\"",
			expected: []token.Token{
				{Type: token.IMPORT, Literal: "import"},
				{Type: token.STRING_LIT, Literal: "pe"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			input: "import \"math\"",
			expected: []token.Token{
				{Type: token.IMPORT, Literal: "import"},
				{Type: token.STRING_LIT, Literal: "math"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			input: "include \"common.yar\"",
			expected: []token.Token{
				{Type: token.INCLUDE, Literal: "include"},
				{Type: token.STRING_LIT, Literal: "common.yar"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			input: "import \"pe\"\nimport \"math\"\ninclude \"utils.yar\"",
			expected: []token.Token{
				{Type: token.IMPORT, Literal: "import"},
				{Type: token.STRING_LIT, Literal: "pe"},
				{Type: token.IMPORT, Literal: "import"},
				{Type: token.STRING_LIT, Literal: "math"},
				{Type: token.INCLUDE, Literal: "include"},
				{Type: token.STRING_LIT, Literal: "utils.yar"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			input: "IMPORT \"pe\"", // Test case sensitivity
			expected: []token.Token{
				{Type: token.IDENTIFIER, Literal: "IMPORT"},
				{Type: token.STRING_LIT, Literal: "pe"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			input: "include", // Just the keyword
			expected: []token.Token{
				{Type: token.INCLUDE, Literal: "include"},
				{Type: token.EOF, Literal: ""},
			},
		},
	}

	for i, tt := range tests {
		t.Run(fmt.Sprintf("test_%d", i), func(t *testing.T) {
			l := lexer.New(tt.input)
			for i, expectedToken := range tt.expected {
				tok := l.NextToken()
				if tok.Type != expectedToken.Type {
					t.Fatalf("tests[%d] - token type wrong. expected=%q, got=%q", i, expectedToken.Type, tok.Type)
				}
				if tok.Literal != expectedToken.Literal {
					t.Fatalf("tests[%d] - literal wrong. expected=%q, got=%q", i, expectedToken.Literal, tok.Literal)
				}
			}
		})
	}
}
