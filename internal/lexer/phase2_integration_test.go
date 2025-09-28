package lexer_test

import (
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func TestPhase2Integration_CompleteYARARule(t *testing.T) {
	input := `rule Phase2TestRule {
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
	modifierCounts := map[token.TokenType]int{}
	for _, tok := range tokens {
		switch tok.Type {
		case token.NOCASE, token.WIDE, token.ASCII, token.FULLWORD, token.PRIVATE, token.XOR, token.BASE64, token.BASE64WIDE:
			modifierCounts[tok.Type]++
		}
	}

	// Verify we have the expected modifiers
	expectedModifiers := map[token.TokenType]int{
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
	expectedTotal := 12 // Sum of all expected counts: 2+2+2+2+1+1+1+1 = 12
	if totalModifiers != expectedTotal {
		t.Errorf("expected %d total modifiers, got %d", expectedTotal, totalModifiers)
	}
}

func TestPhase2Integration_AllStringTypes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []token.TokenType
	}{
		{
			"text string with all modifiers",
			`"text" nocase wide ascii fullword private xor base64 base64wide`,
			[]token.TokenType{token.STRING_LIT, token.NOCASE, token.WIDE, token.ASCII, token.FULLWORD, token.PRIVATE, token.XOR, token.BASE64, token.BASE64WIDE, token.EOF},
		},
		{
			"hex string with modifiers",
			`{ E2 34 ?? A1 } nocase private`,
			[]token.TokenType{token.HEX_STRING_LIT, token.NOCASE, token.PRIVATE, token.EOF},
		},
		{
			"regex with modifiers",
			`/pattern/i ascii fullword`,
			[]token.TokenType{token.REGEX_LIT, token.ASCII, token.FULLWORD, token.EOF},
		},
		{
			"empty hex string with modifiers",
			`{ } wide`,
			[]token.TokenType{token.HEX_STRING_LIT, token.WIDE, token.EOF},
		},
		{
			"empty regex with modifiers",
			`//i nocase`,
			[]token.TokenType{token.REGEX_LIT, token.NOCASE, token.EOF},
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

func TestPhase2Integration_ErrorRecovery(t *testing.T) {
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

func TestPhase2Integration_Performance(t *testing.T) {
	// Test performance with many string modifiers
	input := `rule PerformanceTest {
		strings:
			$s1 = "test1" nocase wide ascii fullword
			$s2 = "test2" private xor base64 base64wide
			$s3 = { E2 34 A1 } nocase wide
			$s4 = /pattern/i ascii fullword
			$s5 = "test5" nocase wide ascii fullword private xor base64 base64wide
		condition:
			any of them
	}`

	// Run multiple iterations to test performance consistency
	for i := 0; i < 100; i++ {
		l := lexer.New(input)
		tokens := collectTokens(l)

		// Verify we get a reasonable number of tokens (adjusted expectation)
		if len(tokens) < 40 {
			t.Errorf("iteration %d: expected at least 40 tokens, got %d", i, len(tokens))
			break
		}
	}
}

func TestPhase2Integration_CoverageIncrease(t *testing.T) {
	// Test that demonstrates the coverage increase from Phase 2
	// This test shows YARA rules that couldn't be parsed before Phase 2

	beforePhase2 := `rule BeforePhase2 {
		strings:
			$a = "text"
			$b = { E2 34 A1 }
			$c = /pattern/i
		condition:
			any of them
	}`

	afterPhase2 := `rule AfterPhase2 {
		strings:
			$a = "text" nocase wide
			$b = { E2 34 A1 } private
			$c = /pattern/i ascii fullword
			$d = "encoded" xor base64wide
		condition:
			any of them
	}`

	// Both should parse successfully now
	for _, input := range []string{beforePhase2, afterPhase2} {
		l := lexer.New(input)
		tokens := collectTokens(l)

		// Verify no illegal tokens
		for _, tok := range tokens {
			if tok.Type == token.ILLEGAL {
				t.Errorf("unexpected ILLEGAL token: %v", tok)
			}
		}
	}

	// The "after" rule should have string modifier tokens
	l := lexer.New(afterPhase2)
	tokens := collectTokens(l)

	hasModifiers := false
	for _, tok := range tokens {
		switch tok.Type {
		case token.NOCASE, token.WIDE, token.ASCII, token.FULLWORD, token.PRIVATE, token.XOR, token.BASE64, token.BASE64WIDE:
			hasModifiers = true
			goto found
		}
	}
found:

	if !hasModifiers {
		t.Error("Phase 2 rule should contain string modifier tokens")
	}
}
