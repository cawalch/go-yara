package lexer_test

import (
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func TestAdvancedFeatures_CompleteYARARule(t *testing.T) {
	input := `rule Phase3TestRule {
		meta:
			author = "go-yara"
			version = "3.0"
			enabled = true
		strings:
			$text1 = "malware" nocase wide
			$text2 = "virus" ascii fullword
			$hex1 = { E2 34 A1 C8 } private
			$regex1 = /[a-z]{32}/i ascii
		condition:
			any of them and
			filesize > 1MB and
			filesize < 100KB and
			uint32(0) == 0x5A4D and
			uint32(entrypoint) & 0xFF00 == 0x4D00 and
			int16be(entrypoint + 4) > 0 and
			(uint16(2) & 0xFF00) == 0x4D00 and
			uint8(filesize - 1) != 0x00 and
			(filesize >> 10) < 1024 and
			~uint16(2) == 0xFFFF and
			(flags | 0x01) != 0
	}`

	l := lexer.New(input)
	tokens := collectTokens(l)

	// Verify no illegal tokens
	for _, tok := range tokens {
		if tok.Type == token.ILLEGAL {
			t.Errorf("unexpected ILLEGAL token: %v", tok)
		}
	}

	// Count Phase 3 features
	bitwiseCount := 0
	dataTypeCount := 0
	fileOpCount := 0

	for _, tok := range tokens {
		switch tok.Type {
		// Bitwise operators
		case token.BITWISE_AND, token.BITWISE_OR, token.BITWISE_XOR,
			token.BITWISE_NOT, token.LEFT_SHIFT, token.RIGHT_SHIFT:
			bitwiseCount++
		// Data type functions
		case token.INT8, token.INT16, token.INT32, token.UINT8, token.UINT16, token.UINT32,
			token.INT8BE, token.INT16BE, token.INT32BE, token.UINT8BE, token.UINT16BE, token.UINT32BE:
			dataTypeCount++
		// File operations
		case token.FILESIZE, token.ENTRYPOINT:
			fileOpCount++
		}
	}

	// Verify we have the expected Phase 3 features
	if bitwiseCount < 5 {
		t.Errorf("Expected at least 5 bitwise operators, got %d", bitwiseCount)
	}
	if dataTypeCount < 4 {
		t.Errorf("Expected at least 4 data type functions, got %d", dataTypeCount)
	}
	if fileOpCount < 3 {
		t.Errorf("Expected at least 3 file operations, got %d", fileOpCount)
	}
}

func TestAdvancedFeatures_AllFeatureTypes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []token.TokenType
	}{
		{
			"bitwise operators sequence",
			"value & 0xFF | 0x01 ^ 0xAA ~ data << 2 >> 1",
			[]token.TokenType{
				token.IDENTIFIER, token.BITWISE_AND, token.HEX_INTEGER_LIT,
				token.BITWISE_OR, token.HEX_INTEGER_LIT,
				token.BITWISE_XOR, token.HEX_INTEGER_LIT,
				token.BITWISE_NOT, token.IDENTIFIER,
				token.LEFT_SHIFT, token.INTEGER_LIT,
				token.RIGHT_SHIFT, token.INTEGER_LIT,
				token.EOF,
			},
		},
		{
			"data type functions sequence",
			"uint32(0) int16be(4) uint8(offset) int32(addr)",
			[]token.TokenType{
				token.UINT32, token.LPAREN, token.INTEGER_LIT, token.RPAREN,
				token.INT16BE, token.LPAREN, token.INTEGER_LIT, token.RPAREN,
				token.UINT8, token.LPAREN, token.IDENTIFIER, token.RPAREN,
				token.INT32, token.LPAREN, token.IDENTIFIER, token.RPAREN,
				token.EOF,
			},
		},
		{
			"file operations with expressions",
			"filesize > 1MB and uint32(entrypoint) == 0x5A4D",
			[]token.TokenType{
				token.FILESIZE, token.GT, token.SIZE_LIT,
				token.AND,
				token.UINT32, token.LPAREN, token.ENTRYPOINT, token.RPAREN,
				token.EQ, token.HEX_INTEGER_LIT,
				token.EOF,
			},
		},
		{
			"combined Phase 3 features",
			"(uint32(entrypoint) & 0xFF00) >> 8 == filesize",
			[]token.TokenType{
				token.LPAREN,
				token.UINT32, token.LPAREN, token.ENTRYPOINT, token.RPAREN,
				token.BITWISE_AND, token.HEX_INTEGER_LIT,
				token.RPAREN,
				token.RIGHT_SHIFT, token.INTEGER_LIT,
				token.EQ, token.FILESIZE,
				token.EOF,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)

			for i, expectedType := range tt.expected {
				tok := l.NextToken()
				if tok.Type != expectedType {
					t.Errorf("token %d: expected type %v, got %v (literal: %q)",
						i, expectedType, tok.Type, tok.Literal)
				}
			}
		})
	}
}

func TestAdvancedFeatures_ErrorRecovery(t *testing.T) {
	input := `rule ErrorTest {
		strings:
			$valid = "text" nocase wide
		condition:
			filesize > 1MB and
			uint32(0) & 0xFF00 == 0x4D00 and
			invalid_operator ?? and
			uint16(entrypoint) >> 8 < 256
	}`

	l := lexer.New(input)
	tokens := collectTokens(l)

	// Count valid Phase 3 tokens (should still be parsed correctly)
	validPhase3Count := 0
	illegalCount := 0

	for _, tok := range tokens {
		switch tok.Type {
		case token.FILESIZE, token.ENTRYPOINT, token.UINT32, token.UINT16,
			token.BITWISE_AND, token.RIGHT_SHIFT:
			validPhase3Count++
		case token.ILLEGAL:
			illegalCount++
		}
	}

	// Should have valid Phase 3 tokens despite errors
	if validPhase3Count < 5 {
		t.Errorf("Expected at least 5 valid Phase 3 tokens, got %d", validPhase3Count)
	}

	// Should have some illegal tokens from the invalid syntax
	if illegalCount == 0 {
		t.Error("Expected some ILLEGAL tokens from invalid syntax")
	}
}

func TestAdvancedFeatures_Performance(t *testing.T) {
	// Test performance with many Phase 3 features
	input := `rule PerformanceTest {
		strings:
			$s1 = "test1" nocase wide ascii fullword
			$s2 = { E2 34 A1 } private
		condition:
			any of them and
			filesize > 1MB and filesize < 100KB and
			uint32(0) == 0x5A4D and uint32(entrypoint) & 0xFF00 == 0x4D00 and
			int16be(entrypoint + 4) > 0 and uint16(2) & 0xFF00 == 0x4D00 and
			uint8(filesize - 1) != 0x00 and (filesize >> 10) < 1024 and
			~uint16(2) == 0xFFFF and (flags | 0x01) != 0 and
			int8(offset) ^ 0xAA == 0x55 and uint32be(addr) << 2 > 1000
	}`

	// Run multiple iterations to test performance consistency
	for i := 0; i < 100; i++ {
		l := lexer.New(input)
		tokens := collectTokens(l)

		// Verify we get a reasonable number of tokens
		if len(tokens) < 80 {
			t.Errorf("iteration %d: expected at least 80 tokens, got %d", i, len(tokens))
			break
		}

		// Verify no illegal tokens in valid syntax
		for _, tok := range tokens {
			if tok.Type == token.ILLEGAL {
				t.Errorf("iteration %d: unexpected ILLEGAL token: %v", i, tok)
				break
			}
		}
	}
}

func TestAdvancedFeatures_BackwardsCompatibility(t *testing.T) {
	// Test that Phase 3 features don't break existing functionality
	beforePhase3 := `rule BeforePhase3 {
		meta:
			author = "test"
			enabled = true
		strings:
			$a = "malware" nocase wide
			$b = { E2 34 A1 } private
			$c = /[a-z]{32}/i ascii
		condition:
			any of them and (1 + 2 * 3) == 7
	}`

	afterPhase3 := `rule AfterPhase3 {
		meta:
			author = "test"
			enabled = true
		strings:
			$a = "malware" nocase wide
			$b = { E2 34 A1 } private
			$c = /[a-z]{32}/i ascii
		condition:
			any of them and (1 + 2 * 3) == 7 and
			filesize > 1MB and uint32(0) & 0xFF00 == 0x4D00
	}`

	// Both should parse successfully
	for _, input := range []string{beforePhase3, afterPhase3} {
		l := lexer.New(input)
		tokens := collectTokens(l)

		// Verify no illegal tokens
		for _, tok := range tokens {
			if tok.Type == token.ILLEGAL {
				t.Errorf("unexpected ILLEGAL token: %v", tok)
			}
		}
	}

	// The "after" rule should have Phase 3 tokens
	l := lexer.New(afterPhase3)
	tokens := collectTokens(l)

	hasPhase3Features := false
	for _, tok := range tokens {
		switch tok.Type {
		case token.FILESIZE, token.UINT32, token.BITWISE_AND:
			hasPhase3Features = true
			goto found
		}
	}
found:

	if !hasPhase3Features {
		t.Error("Phase 3 rule should contain Phase 3 feature tokens")
	}
}
