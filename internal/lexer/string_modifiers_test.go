package lexer_test

import (
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func TestStringModifiers_CompleteRule(t *testing.T) {
	input := `rule ModifierRule {
		meta:
			author = "go-yara"
			version = "2.0"
			enabled = true
		strings:
			$text1 = "malware" nocase wide
			$text2 = "virus" ascii fullword
			$hex1 = { E2 34 A1 C8 } private
			$hex2 = { ?? 45 [4-6] 89 } nocase
			$regex1 = /[a-z]{32}/i ascii fullword
			$regex2 = /https?:\/\// wide base64
			$combo = "encoded" xor base64wide
		condition:
			any of them and filesize > 100KB and
			($text1 or $text2) and
			all of ($hex*, $regex*)
	}`

	l := lexer.New(input)
	tokens := collectTokens(l)

	// Count string modifier tokens
	modifierCounts := map[token.Type]int{}
	for _, tok := range tokens {
		switch tok.Type {
		case token.NOCASE, token.WIDE, token.ASCII, token.FULLWORD, token.PRIVATE, token.XOR, token.BASE64, token.BASE64WIDE:
			modifierCounts[tok.Type]++
		}
	}

	// Verify we have the expected modifiers
	expectedModifiers := map[token.Type]int{
		token.NOCASE:     2, // $text1 and $hex2
		token.WIDE:       2, // $text1 and $regex2
		token.ASCII:      2, // $text2 and $regex1
		token.FULLWORD:   2, // $text2 and $regex1
		token.PRIVATE:    1, // $hex1
		token.XOR:        1, // $combo
		token.BASE64:     1, // $regex2
		token.BASE64WIDE: 1, // $combo
	}

	for expectedType, expectedCount := range expectedModifiers {
		if modifierCounts[expectedType] != expectedCount {
			t.Errorf("modifier %v: expected %d occurrences, got %d", expectedType, expectedCount, modifierCounts[expectedType])
		}
	}

	// Verify total modifier count
	totalModifiers := 0
	for _, count := range modifierCounts {
		totalModifiers += count
	}
	expectedTotal := 12
	if totalModifiers != expectedTotal {
		t.Errorf("expected %d total modifiers, got %d", expectedTotal, totalModifiers)
	}
}

func TestStringModifiers_AllStringTypes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []token.Type
	}{
		{
			"text string with all modifiers",
			`"text" nocase wide ascii fullword private xor base64 base64wide`,
			[]token.Type{token.StringLit, token.NOCASE, token.WIDE, token.ASCII, token.FULLWORD, token.PRIVATE, token.XOR, token.BASE64, token.BASE64WIDE, token.EOF},
		},
		{
			"hex string with modifiers",
			`{ E2 34 ?? A1 } nocase private`,
			[]token.Type{token.HexStringLit, token.NOCASE, token.PRIVATE, token.EOF},
		},
		{
			"regex with modifiers",
			`/pattern/i ascii fullword`,
			[]token.Type{token.RegexLit, token.ASCII, token.FULLWORD, token.EOF},
		},
		{
			"empty hex string with modifiers",
			`{ } wide`,
			[]token.Type{token.HexStringLit, token.WIDE, token.EOF},
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

func TestStringModifiers_ErrorRecovery(t *testing.T) {
	input := `rule ErrorTest {
		strings:
			$valid = "text" nocase wide
			$invalid = "text" invalidmod
			$recovery = "text" ascii
		condition:
			any of them
	}`

	l := lexer.New(input)
	tokens := collectTokens(l)

	// Count valid modifiers (should still be parsed correctly)
	validModifiers := 0
	identifiers := 0

	for _, tok := range tokens {
		switch tok.Type {
		case token.NOCASE, token.WIDE, token.ASCII, token.FULLWORD, token.PRIVATE, token.XOR, token.BASE64, token.BASE64WIDE:
			validModifiers++
		case token.IDENTIFIER:
			if tok.Literal == "invalidmod" {
				identifiers++
			}
		}
	}

	// Should have 3 valid modifiers: nocase, wide, ascii
	if validModifiers != 3 {
		t.Errorf("expected 3 valid modifiers, got %d", validModifiers)
	}

	// Should have 1 identifier for the invalid modifier
	if identifiers != 1 {
		t.Errorf("expected 1 invalid modifier as identifier, got %d", identifiers)
	}
}
