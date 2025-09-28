package lexer_test

import (
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func TestFileOperations_Basic(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	tests := []struct {
		name     string
		input    string
		expected token.TokenType
	}{
		{"filesize", "filesize", token.FILESIZE},
		{"entrypoint", "entrypoint", token.ENTRYPOINT},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			helper.AssertSingleToken(tt.input, tt.expected, tt.input)
		})
	}
}

func TestFileOperations_CaseSensitive(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	// Test that file operation keywords are case-sensitive (only lowercase recognized)
	tests := []struct {
		name     string
		input    string
		expected token.TokenType
	}{
		{"filesize_lowercase", "filesize", token.FILESIZE},
		{"FILESIZE_uppercase", "FILESIZE", token.IDENTIFIER}, // Should be identifier, not keyword
		{"FileSize_mixed", "FileSize", token.IDENTIFIER},     // Should be identifier, not keyword
		{"entrypoint_lowercase", "entrypoint", token.ENTRYPOINT},
		{"ENTRYPOINT_uppercase", "ENTRYPOINT", token.IDENTIFIER}, // Should be identifier, not keyword
		{"EntryPoint_mixed", "EntryPoint", token.IDENTIFIER},     // Should be identifier, not keyword
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			helper.AssertSingleToken(tt.input, tt.expected, tt.input)
		})
	}
}

func TestFileOperations_InComparisons(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	tests := []struct {
		name     string
		input    string
		expected []token.Token
	}{
		{
			name:  "filesize greater than",
			input: "filesize > 1024",
			expected: []token.Token{
				{Type: token.FILESIZE, Literal: "filesize"},
				{Type: token.GT, Literal: ">"},
				{Type: token.INTEGER_LIT, Literal: "1024"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "filesize with size literal",
			input: "filesize > 1MB",
			expected: []token.Token{
				{Type: token.FILESIZE, Literal: "filesize"},
				{Type: token.GT, Literal: ">"},
				{Type: token.SIZE_LIT, Literal: "1MB"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "filesize less than hex",
			input: "filesize < 0x1000",
			expected: []token.Token{
				{Type: token.FILESIZE, Literal: "filesize"},
				{Type: token.LT, Literal: "<"},
				{Type: token.HEX_INTEGER_LIT, Literal: "0x1000"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "entrypoint equality",
			input: "entrypoint == 0x401000",
			expected: []token.Token{
				{Type: token.ENTRYPOINT, Literal: "entrypoint"},
				{Type: token.EQ, Literal: "=="},
				{Type: token.HEX_INTEGER_LIT, Literal: "0x401000"},
				{Type: token.EOF, Literal: ""},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			helper.AssertTokenSequence(tt.input, tt.expected)
		})
	}
}

func TestFileOperations_WithDataTypes(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	tests := []struct {
		name     string
		input    string
		expected []token.Token
	}{
		{
			name:  "uint32 at entrypoint",
			input: "uint32(entrypoint)",
			expected: []token.Token{
				{Type: token.UINT32, Literal: "uint32"},
				{Type: token.LPAREN, Literal: "("},
				{Type: token.ENTRYPOINT, Literal: "entrypoint"},
				{Type: token.RPAREN, Literal: ")"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "uint32 at entrypoint with offset",
			input: "uint32(entrypoint + 4)",
			expected: []token.Token{
				{Type: token.UINT32, Literal: "uint32"},
				{Type: token.LPAREN, Literal: "("},
				{Type: token.ENTRYPOINT, Literal: "entrypoint"},
				{Type: token.PLUS, Literal: "+"},
				{Type: token.INTEGER_LIT, Literal: "4"},
				{Type: token.RPAREN, Literal: ")"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "uint8 at filesize minus one",
			input: "uint8(filesize - 1)",
			expected: []token.Token{
				{Type: token.UINT8, Literal: "uint8"},
				{Type: token.LPAREN, Literal: "("},
				{Type: token.FILESIZE, Literal: "filesize"},
				{Type: token.MINUS, Literal: "-"},
				{Type: token.INTEGER_LIT, Literal: "1"},
				{Type: token.RPAREN, Literal: ")"},
				{Type: token.EOF, Literal: ""},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			helper.AssertTokenSequence(tt.input, tt.expected)
		})
	}
}

func TestFileOperations_WithBitwiseOperations(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	tests := []struct {
		name     string
		input    string
		expected []token.Token
	}{
		{
			name:  "filesize shift operation",
			input: "filesize >> 10",
			expected: []token.Token{
				{Type: token.FILESIZE, Literal: "filesize"},
				{Type: token.RIGHT_SHIFT, Literal: ">>"},
				{Type: token.INTEGER_LIT, Literal: "10"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "entrypoint bitwise and",
			input: "entrypoint & 0xFFF",
			expected: []token.Token{
				{Type: token.ENTRYPOINT, Literal: "entrypoint"},
				{Type: token.BITWISE_AND, Literal: "&"},
				{Type: token.HEX_INTEGER_LIT, Literal: "0xFFF"},
				{Type: token.EOF, Literal: ""},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			helper.AssertTokenSequence(tt.input, tt.expected)
		})
	}
}

func TestFileOperations_InComplexExpressions(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	tests := []struct {
		name     string
		input    string
		expected []token.Token
	}{
		{
			name:  "complex filesize expression",
			input: "(filesize / 1024) * 2 == 0x1000",
			expected: []token.Token{
				{Type: token.LPAREN, Literal: "("},
				{Type: token.FILESIZE, Literal: "filesize"},
				{Type: token.DIVIDE, Literal: "/"},
				{Type: token.INTEGER_LIT, Literal: "1024"},
				{Type: token.RPAREN, Literal: ")"},
				{Type: token.MULTIPLY, Literal: "*"},
				{Type: token.INTEGER_LIT, Literal: "2"},
				{Type: token.EQ, Literal: "=="},
				{Type: token.HEX_INTEGER_LIT, Literal: "0x1000"},
				{Type: token.EOF, Literal: ""},
			},
		},
		{
			name:  "entrypoint with data type and bitwise",
			input: "uint32(entrypoint) & 0xFF00 == 0x4D00",
			expected: []token.Token{
				{Type: token.UINT32, Literal: "uint32"},
				{Type: token.LPAREN, Literal: "("},
				{Type: token.ENTRYPOINT, Literal: "entrypoint"},
				{Type: token.RPAREN, Literal: ")"},
				{Type: token.BITWISE_AND, Literal: "&"},
				{Type: token.HEX_INTEGER_LIT, Literal: "0xFF00"},
				{Type: token.EQ, Literal: "=="},
				{Type: token.HEX_INTEGER_LIT, Literal: "0x4D00"},
				{Type: token.EOF, Literal: ""},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			helper.AssertTokenSequence(tt.input, tt.expected)
		})
	}
}

func TestFileOperations_InYARARule(t *testing.T) {
	helper := lexer.NewTestHelper(t)
	input := `rule FileOperationTest {
		meta:
			description = "Test file operations"
		strings:
			$a = "test"
		condition:
			$a and
			filesize > 1MB and
			filesize < 100KB and
			uint32(entrypoint) == 0x5A4D and
			uint8(filesize - 1) != 0x00 and
			(filesize >> 10) < 1024
	}`

	tokens := helper.CollectTokens(input)
	fileOpCount := 0
	fileOps := []string{}

	for _, tok := range tokens {
		if tok.Type == token.FILESIZE || tok.Type == token.ENTRYPOINT {
			fileOpCount++
			fileOps = append(fileOps, tok.Literal)
		}
	}

	expectedOps := []string{"filesize", "filesize", "entrypoint", "filesize", "filesize"}
	if fileOpCount != len(expectedOps) {
		t.Errorf("Expected %d file operations, got %d", len(expectedOps), fileOpCount)
	}

	for i, expectedOp := range expectedOps {
		if i < len(fileOps) && fileOps[i] != expectedOp {
			t.Errorf("Expected file operation %q at position %d, got %q", expectedOp, i, fileOps[i])
		}
	}
}

func TestFileOperations_WithAllPhase3Features(t *testing.T) {
	helper := lexer.NewTestHelper(t)

	// Test that file operations work with all other Phase 3 features
	input := `filesize > 1MB and uint32(entrypoint) & 0xFF00 == 0x4D00`

	expected := []token.Token{
		{Type: token.FILESIZE, Literal: "filesize"},
		{Type: token.GT, Literal: ">"},
		{Type: token.SIZE_LIT, Literal: "1MB"},
		{Type: token.AND, Literal: "and"},
		{Type: token.UINT32, Literal: "uint32"},
		{Type: token.LPAREN, Literal: "("},
		{Type: token.ENTRYPOINT, Literal: "entrypoint"},
		{Type: token.RPAREN, Literal: ")"},
		{Type: token.BITWISE_AND, Literal: "&"},
		{Type: token.HEX_INTEGER_LIT, Literal: "0xFF00"},
		{Type: token.EQ, Literal: "=="},
		{Type: token.HEX_INTEGER_LIT, Literal: "0x4D00"},
		{Type: token.EOF, Literal: ""},
	}

	helper.AssertTokenSequence(input, expected)
}
