package lexer_test

import (
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func TestControlFlowKeywords(t *testing.T) {
	t.Run("ForLoopPatterns", testForLoopPatterns)
	t.Run("LogicalOperations", testLogicalOperationPatterns)
}

// testForLoopPatterns tests various for-loop control flow patterns
func testForLoopPatterns(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []token.Token
	}{
		{
			name:  "for_all_of_them",
			input: "for all of them : ( $ at pe.entry_point )",
			expected: []token.Token{
				{Type: token.FOR, Literal: "for"},
				{Type: token.ALL, Literal: "all"},
				{Type: token.OF, Literal: "of"},
				{Type: token.THEM, Literal: "them"},
				{Type: token.COLON, Literal: ":"},
				{Type: token.LPAREN, Literal: "("},
				{Type: token.STRING_IDENTIFIER, Literal: "$"},
				{Type: token.AT, Literal: "at"},
				{Type: token.IDENTIFIER, Literal: "pe"},
				{Type: token.DOT, Literal: "."},
				{Type: token.IDENTIFIER, Literal: "entry_point"},
				{Type: token.RPAREN, Literal: ")"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "for_all_i_in_range",
			input: "for all i in (1..#s) : ( uint32(@s[i]) == 0x5A4D )",
			expected: []token.Token{
				{Type: token.FOR, Literal: "for"},
				{Type: token.ALL, Literal: "all"},
				{Type: token.IDENTIFIER, Literal: "i"},
				{Type: token.IN, Literal: "in"},
				{Type: token.LPAREN, Literal: "("},
				{Type: token.INTEGER_LIT, Literal: "1"},
				{Type: token.DOT, Literal: "."},
				{Type: token.DOT, Literal: "."},
				{Type: token.HASH, Literal: "#"},
				{Type: token.IDENTIFIER, Literal: "s"},
				{Type: token.RPAREN, Literal: ")"},
				{Type: token.COLON, Literal: ":"},
				{Type: token.LPAREN, Literal: "("},
				{Type: token.UINT32, Literal: "uint32"},
				{Type: token.LPAREN, Literal: "("},
				{Type: token.AT, Literal: "@"},
				{Type: token.IDENTIFIER, Literal: "s"},
				{Type: token.LBRACKET, Literal: "["},
				{Type: token.IDENTIFIER, Literal: "i"},
				{Type: token.RBRACKET, Literal: "]"},
				{Type: token.RPAREN, Literal: ")"},
				{Type: token.EQ, Literal: "=="},
				{Type: token.HEX_INTEGER_LIT, Literal: "0x5A4D"},
				{Type: token.RPAREN, Literal: ")"},
				{Type: token.EOF, Literal: ""},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertControlFlowTokenSequence(t, tt.input, tt.expected)
		})
	}
}

// testLogicalOperationPatterns tests logical flow control operations
func testLogicalOperationPatterns(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []token.Token
	}{
		{
			name:  "defined_and_them",
			input: "defined pe.entry_point and them",
			expected: []token.Token{
				{Type: token.DEFINED, Literal: "defined"},
				{Type: token.IDENTIFIER, Literal: "pe"},
				{Type: token.DOT, Literal: "."},
				{Type: token.IDENTIFIER, Literal: "entry_point"},
				{Type: token.AND, Literal: "and"},
				{Type: token.THEM, Literal: "them"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "not_defined_or",
			input: "not defined external_var or them",
			expected: []token.Token{
				{Type: token.NOT, Literal: "not"},
				{Type: token.DEFINED, Literal: "defined"},
				{Type: token.IDENTIFIER, Literal: "external_var"},
				{Type: token.OR, Literal: "or"},
				{Type: token.THEM, Literal: "them"},
				{Type: token.EOF, Literal: ""},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertControlFlowTokenSequence(t, tt.input, tt.expected)
		})
	}
}

// assertControlFlowTokenSequence validates that the lexer produces the expected token sequence
func assertControlFlowTokenSequence(t *testing.T, input string, expected []token.Token) {
	l := lexer.New(input)

	for i, expectedToken := range expected {
		tok := l.NextToken()
		if tok.Type != expectedToken.Type {
			t.Errorf("token %d - type wrong. expected=%q, got=%q", i, expectedToken.Type, tok.Type)
			return
		}
		if tok.Literal != expectedToken.Literal {
			t.Errorf("token %d - literal wrong. expected=%q, got=%q", i, expectedToken.Literal, tok.Literal)
			return
		}
	}
}
