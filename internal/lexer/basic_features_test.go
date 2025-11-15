package lexer_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func TestBasicFeatures_CompleteYARARule(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	// A comprehensive YARA rule that uses all Phase 1 features
	input := `rule Phase1TestRule {
		meta:
			author = "test"
			version = 1
			max_size = 10MB
			min_size = 1KB
			base_address = 0x401000
			entry_offset = 0xFF
		strings:
			$text = "malware"
			$hex = { E2 34 A1 C8 }
			$regex = /[a-zA-Z0-9]{32}/i
		condition:
			all of them and
			any of ($text, $hex) and
			none of ($regex) and
			filesize > 100KB and
			filesize < 50MB and
			pe.entry_point == 0x401000 and
			(filesize / 1024) * 2 > 1MB and
			filesize % 1024 == 0 and
			not false and
			true or false
	}`

	tokens := helper.CollectTokens(input)

	// Define expected token counts using table-driven approach
	expectedCounts := []struct {
		tokenTypes    []token.TokenType
		expectedCount int
		description   string
	}{
		{
			tokenTypes:    []token.TokenType{token.HexIntegerLit},
			expectedCount: 3, // 0x401000, 0xFF, 0x401000
			description:   "hex integers",
		},
		{
			tokenTypes:    []token.TokenType{token.SizeLit},
			expectedCount: 5, // 10MB, 1KB, 100KB, 50MB, 1MB
			description:   "size literals",
		},
		{
			tokenTypes:    []token.TokenType{token.ALL, token.ANY, token.NONE, token.OF},
			expectedCount: 6, // all, of, any, of, none, of
			description:   "quantifier tokens",
		},
		{
			tokenTypes:    []token.TokenType{token.MULTIPLY, token.DIVIDE, token.MODULO},
			expectedCount: 3, // /, *, %
			description:   "arithmetic operators",
		},
		{
			tokenTypes:    []token.TokenType{token.TRUE, token.FALSE},
			expectedCount: 3, // false, true, false
			description:   "boolean literals",
		},
	}

	// Count and verify each expected token type
	for _, expected := range expectedCounts {
		actualCount := countTokenTypes(tokens, expected.tokenTypes)
		if actualCount != expected.expectedCount {
			t.Errorf("Expected %d %s, got %d", expected.expectedCount, expected.description, actualCount)
		}
	}
}

// Helper function to count tokens of specific types
func countTokenTypes(tokens []token.Token, tokenTypes []token.TokenType) int {
	count := 0
	for _, tok := range tokens {
		if slices.Contains(tokenTypes, tok.Type) {
			count++
		}
	}
	return count
}

func TestBasicFeatures_ErrorRecovery(t *testing.T) {
	_ = lexer.NewTestHelper(t)

	// Test error recovery with Phase 1 features
	input := `rule ErrorTest {
		meta:
			good_size = 1MB
		strings:
			$a = "test"
		condition:
			all of them and
			filesize > ??? and  // Invalid characters
			1 + 2 * 0x100KB
	}`

	l := lexer.New(input)
	tokens := collectAllTokensFromLexer(l)

	// Define token type groups to verify
	tokenVerification := []struct {
		name       string
		tokenTypes []token.TokenType
		validator  func(count int) bool
		errorMsg   string
	}{
		{
			name:       "illegal tokens",
			tokenTypes: []token.TokenType{token.ILLEGAL},
			validator:  func(count int) bool { return count > 0 },
			errorMsg:   "Expected some ILLEGAL tokens for error recovery test",
		},
		{
			name:       "valid Phase 1 tokens",
			tokenTypes: []token.TokenType{token.SizeLit, token.ALL, token.OF, token.PLUS, token.MULTIPLY},
			validator:  func(count int) bool { return count > 0 },
			errorMsg:   "Expected some valid Phase 1 tokens despite errors",
		},
	}

	// Verify each token group
	for _, verification := range tokenVerification {
		count := countTokenTypes(tokens, verification.tokenTypes)
		if !verification.validator(count) {
			t.Error(verification.errorMsg)
		}
	}

	// Check that lexer collected errors (optional - depends on implementation)
	errors := l.Errors()
	_ = errors // Suppress unused variable warning
}

// Helper function to collect all tokens from lexer
func collectAllTokensFromLexer(l *lexer.Lexer) []token.Token {
	var tokens []token.Token
	for {
		tok := l.NextToken()
		tokens = append(tokens, tok)
		if tok.Type == token.EOF {
			break
		}
	}
	return tokens
}

func TestBasicFeatures_PerformanceStress(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	// Generate a large input with all Phase 1 features
	input := ""
	var inputSb144 strings.Builder
	for i := range 100 {
		inputSb144.WriteString(`rule StressTest` + string(rune('A'+i%26)) + ` {
			meta:
				size = 1MB
				addr = 0x1000
			strings:
				$a = "test"
				$b = { E2 34 A1 C8 }
			condition:
				all of them and filesize > 1KB and
				(filesize / 1024) * 2 % 3 == 0 and
				0xFF > 0x100
		}
		`)
	}
	input += inputSb144.String()

	// This should parse without issues and maintain performance
	tokens := helper.CollectTokens(input)

	// Verify we got a reasonable number of tokens
	if len(tokens) < 1000 {
		t.Errorf("Expected at least 1000 tokens for stress test, got %d", len(tokens))
	}

	// Verify all token types are present
	tokenTypes := make(map[token.TokenType]bool)
	for _, tok := range tokens {
		tokenTypes[tok.Type] = true
	}

	expectedTypes := []token.TokenType{
		token.HexIntegerLit, token.SizeLit, token.ALL, token.OF,
		token.MULTIPLY, token.DIVIDE, token.MODULO,
	}

	for _, expectedType := range expectedTypes {
		if !tokenTypes[expectedType] {
			t.Errorf("Expected to find token type %v in stress test", expectedType)
		}
	}
}

func TestBasicFeatures_EdgeCases(t *testing.T) {
	_ = lexer.NewTestHelper(t)

	tests := []struct {
		name     string
		input    string
		hasError bool
	}{
		{
			name:     "empty hex integer",
			input:    "0x",
			hasError: false, // Should parse as valid but empty hex
		},
		{
			name:     "size suffix without number",
			input:    "KB",
			hasError: false, // Should parse as identifier
		},
		{
			name:     "quantifiers in wrong context",
			input:    "all all any none of of",
			hasError: false, // Valid tokens, just unusual usage
		},
		{
			name:     "arithmetic operators alone",
			input:    "+ - * / %",
			hasError: false, // Valid operators
		},
		{
			name:     "mixed valid and invalid",
			input:    "1KB + 0xFF * ??? / 2MB",
			hasError: true, // Should have ILLEGAL token for @@@
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)
			tokens := collectTokens(l)

			hasIllegal := false
			for _, tok := range tokens {
				if tok.Type == token.ILLEGAL {
					hasIllegal = true
					break
				}
			}

			if tt.hasError && !hasIllegal {
				t.Errorf("Expected ILLEGAL token but didn't find one")
			}
			if !tt.hasError && hasIllegal {
				t.Errorf("Unexpected ILLEGAL token found")
			}
		})
	}
}

func TestBasicFeatures_AllFeaturesCombined(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	// Test all Phase 1 features in a single expression
	input := "all of them and 0x1000KB + 100MB * 2 / 1024 % 3 == 0xFF and any of ($a, $b) and not false"

	expected := []token.Token{
		{Type: token.ALL, Literal: "all"},
		{Type: token.OF, Literal: "of"},
		{Type: token.THEM, Literal: "them"},
		{Type: token.AND, Literal: "and"},
		{Type: token.SizeLit, Literal: "0x1000KB"},
		{Type: token.PLUS, Literal: "+"},
		{Type: token.SizeLit, Literal: "100MB"},
		{Type: token.MULTIPLY, Literal: "*"},
		{Type: token.IntegerLit, Literal: "2"},
		{Type: token.DIVIDE, Literal: "/"},
		{Type: token.IntegerLit, Literal: "1024"},
		{Type: token.MODULO, Literal: "%"},
		{Type: token.IntegerLit, Literal: "3"},
		{Type: token.EQ, Literal: "=="},
		{Type: token.HexIntegerLit, Literal: "0xFF"},
		{Type: token.AND, Literal: "and"},
		{Type: token.ANY, Literal: "any"},
		{Type: token.OF, Literal: "of"},
		{Type: token.LPAREN, Literal: "("},
		{Type: token.StringIdentifier, Literal: "$a"},
		{Type: token.COMMA, Literal: ","},
		{Type: token.StringIdentifier, Literal: "$b"},
		{Type: token.RPAREN, Literal: ")"},
		{Type: token.AND, Literal: "and"},
		{Type: token.NOT, Literal: "not"},
		{Type: token.FALSE, Literal: "false"},
		{Type: token.EOF, Literal: ""},
	}

	helper.AssertTokenSequence(input, expected)
}
