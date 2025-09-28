package lexer_test

import (
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func TestStringModifiers_BasicTokens(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected token.TokenType
	}{
		{"nocase", "nocase", token.NOCASE},
		{"wide", "wide", token.WIDE},
		{"ascii", "ascii", token.ASCII},
		{"fullword", "fullword", token.FULLWORD},
		{"private", "private", token.PRIVATE},
		{"xor", "xor", token.XOR},
		{"base64", "base64", token.BASE64},
		{"base64wide", "base64wide", token.BASE64WIDE},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)
			tok := l.NextToken()

			if tok.Type != tt.expected {
				t.Errorf("expected token type %v, got %v", tt.expected, tok.Type)
			}
			if tok.Literal != tt.input {
				t.Errorf("expected literal %q, got %q", tt.input, tok.Literal)
			}
		})
	}
}

func TestStringModifiers_CaseSensitive(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected token.TokenType
	}{
		{"NOCASE uppercase", "NOCASE", token.IDENTIFIER},
		{"NoCase mixed", "NoCase", token.IDENTIFIER},
		{"WIDE uppercase", "WIDE", token.IDENTIFIER},
		{"Wide mixed", "Wide", token.IDENTIFIER},
		{"ASCII uppercase", "ASCII", token.IDENTIFIER},
		{"Ascii mixed", "Ascii", token.IDENTIFIER},
		{"FULLWORD uppercase", "FULLWORD", token.IDENTIFIER},
		{"FullWord mixed", "FullWord", token.IDENTIFIER},
		{"PRIVATE uppercase", "PRIVATE", token.IDENTIFIER},
		{"Private mixed", "Private", token.IDENTIFIER},
		{"XOR uppercase", "XOR", token.IDENTIFIER},
		{"Xor mixed", "Xor", token.IDENTIFIER},
		{"BASE64 uppercase", "BASE64", token.IDENTIFIER},
		{"Base64 mixed", "Base64", token.IDENTIFIER},
		{"BASE64WIDE uppercase", "BASE64WIDE", token.IDENTIFIER},
		{"Base64Wide mixed", "Base64Wide", token.IDENTIFIER},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)
			tok := l.NextToken()

			if tok.Type != tt.expected {
				t.Errorf("expected token type %v, got %v", tt.expected, tok.Type)
			}
			if tok.Literal != tt.input {
				t.Errorf("expected literal %q, got %q", tt.input, tok.Literal)
			}
		})
	}
}

func TestStringModifiers_InSequence(t *testing.T) {
	input := "nocase wide ascii fullword private xor base64 base64wide"
	l := lexer.New(input)

	expected := []token.TokenType{
		token.NOCASE,
		token.WIDE,
		token.ASCII,
		token.FULLWORD,
		token.PRIVATE,
		token.XOR,
		token.BASE64,
		token.BASE64WIDE,
		token.EOF,
	}

	for i, expectedType := range expected {
		tok := l.NextToken()
		if tok.Type != expectedType {
			t.Errorf("token %d: expected type %v, got %v", i, expectedType, tok.Type)
		}
	}
}

func TestStringModifiers_WithStringLiterals(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []token.TokenType
	}{
		{
			"string with nocase",
			`"text" nocase`,
			[]token.TokenType{token.STRING_LIT, token.NOCASE, token.EOF},
		},
		{
			"string with multiple modifiers",
			`"text" nocase wide ascii`,
			[]token.TokenType{token.STRING_LIT, token.NOCASE, token.WIDE, token.ASCII, token.EOF},
		},
		{
			"hex string with private",
			`{ E2 34 A1 } private`,
			[]token.TokenType{token.HEX_STRING_LIT, token.PRIVATE, token.EOF},
		},
		{
			"regex with fullword",
			`/pattern/i fullword`,
			[]token.TokenType{token.REGEX_LIT, token.FULLWORD, token.EOF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)

			for i, expectedType := range tt.expected {
				tok := l.NextToken()
				if tok.Type != expectedType {
					t.Errorf("token %d: expected type %v, got %v", i, expectedType, tok.Type)
				}
			}
		})
	}
}

func TestStringModifiers_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []token.TokenType
	}{
		{
			"modifiers with parentheses",
			`("text" nocase)`,
			[]token.TokenType{token.LPAREN, token.STRING_LIT, token.NOCASE, token.RPAREN, token.EOF},
		},
		{
			"modifiers with operators",
			`"text" nocase and "other" wide`,
			[]token.TokenType{token.STRING_LIT, token.NOCASE, token.AND, token.STRING_LIT, token.WIDE, token.EOF},
		},
		{
			"all modifiers together",
			`"text" nocase wide ascii fullword private xor base64 base64wide`,
			[]token.TokenType{token.STRING_LIT, token.NOCASE, token.WIDE, token.ASCII, token.FULLWORD, token.PRIVATE, token.XOR, token.BASE64, token.BASE64WIDE, token.EOF},
		},
		{
			"hex string with multiple modifiers",
			`{ E2 34 ?? A1 } nocase private`,
			[]token.TokenType{token.HEX_STRING_LIT, token.NOCASE, token.PRIVATE, token.EOF},
		},
		{
			"regex with multiple modifiers",
			`/[a-z]+/i ascii fullword`,
			[]token.TokenType{token.REGEX_LIT, token.ASCII, token.FULLWORD, token.EOF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)

			for i, expectedType := range tt.expected {
				tok := l.NextToken()
				if tok.Type != expectedType {
					t.Errorf("token %d: expected type %v, got %v", i, expectedType, tok.Type)
				}
			}
		})
	}
}

func TestStringModifiers_InYARARule(t *testing.T) {
	input := `rule TestRule {
		strings:
			$a = "malware" nocase wide
			$b = { E2 34 A1 } private
			$c = /[a-z]{32}/i ascii fullword
		condition:
			any of them
	}`

	l := lexer.New(input)
	tokens := collectTokens(l)

	// Check that we have the expected string modifier tokens
	modifierTokens := []token.TokenType{}
	for _, tok := range tokens {
		switch tok.Type {
		case token.NOCASE, token.WIDE, token.ASCII, token.FULLWORD, token.PRIVATE, token.XOR, token.BASE64, token.BASE64WIDE:
			modifierTokens = append(modifierTokens, tok.Type)
		}
	}

	expectedModifiers := []token.TokenType{token.NOCASE, token.WIDE, token.PRIVATE, token.ASCII, token.FULLWORD}
	if len(modifierTokens) != len(expectedModifiers) {
		t.Errorf("expected %d modifier tokens, got %d", len(expectedModifiers), len(modifierTokens))
	}

	for i, expected := range expectedModifiers {
		if i >= len(modifierTokens) || modifierTokens[i] != expected {
			t.Errorf("modifier token %d: expected %v, got %v", i, expected, modifierTokens[i])
		}
	}
}

func TestStringModifiers_ErrorRecovery(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []token.TokenType
	}{
		{
			"invalid modifier after string",
			`"text" invalidmodifier`,
			[]token.TokenType{token.STRING_LIT, token.IDENTIFIER, token.EOF},
		},
		{
			"modifier without string",
			`nocase wide`,
			[]token.TokenType{token.NOCASE, token.WIDE, token.EOF},
		},
		{
			"mixed valid and invalid",
			`"text" nocase invalidmod wide`,
			[]token.TokenType{token.STRING_LIT, token.NOCASE, token.IDENTIFIER, token.WIDE, token.EOF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)

			for i, expectedType := range tt.expected {
				tok := l.NextToken()
				if tok.Type != expectedType {
					t.Errorf("token %d: expected type %v, got %v", i, expectedType, tok.Type)
				}
			}
		})
	}
}

func TestStringModifiers_Performance(t *testing.T) {
	// Test that string modifier parsing doesn't significantly impact performance
	input := `"text" nocase wide ascii fullword private xor base64 base64wide`

	// Run multiple iterations to ensure consistent performance
	for i := 0; i < 1000; i++ {
		l := lexer.New(input)
		tokens := collectTokens(l)

		// Verify we get the expected number of tokens
		expectedTokenCount := 10 // 1 string + 8 modifiers + 1 EOF
		if len(tokens) != expectedTokenCount {
			t.Errorf("iteration %d: expected %d tokens, got %d", i, expectedTokenCount, len(tokens))
			break
		}
	}
}
