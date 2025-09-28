package lexer_test

import (
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func TestHexString_InYARARule(t *testing.T) {
	helper := lexer.NewTestHelper(t)
	input := `rule TestRule {
		strings:
			$hex1 = { E2 34 A1 C8 23 FB }
			$hex2 = { ?? A? ?B ?? }
			$hex3 = { F4 23 [4-6] 62 B4 }
		condition:
			any of them
	}`

	tokens := helper.CollectTokens(input)
	hexStringCount := 0
	for _, tok := range tokens {
		if tok.Type == token.HEX_STRING_LIT {
			hexStringCount++
		}
	}
	if hexStringCount != 3 {
		t.Errorf("Expected 3 hex string tokens, got %d", hexStringCount)
	}
}

func TestHexString_Variants(t *testing.T) {
	helper := lexer.NewTestHelper(t)
	cases := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple", "{ E2 34 A1 C8 23 FB }", "{ E2 34 A1 C8 23 FB }"},
		{"no spaces", "{E234A1C823FB}", "{E234A1C823FB}"},
		{"mixed case", "{ e2 34 A1 c8 23 Fb }", "{ e2 34 A1 c8 23 Fb }"},
		{"empty", "{ }", "{ }"},
		{"extra whitespace", "{  E2   34  A1  }", "{  E2   34  A1  }"},
		{"wildcards full", "{ E2 34 ?? C8 23 FB }", "{ E2 34 ?? C8 23 FB }"},
		{"wildcards nibble", "{ E2 34 A? C8 ?3 FB }", "{ E2 34 A? C8 ?3 FB }"},
		{"wildcards mixed", "{ ?? A? ?B ?? }", "{ ?? A? ?B ?? }"},
		{"jump fixed", "{ F4 23 [6] 89 00 }", "{ F4 23 [6] 89 00 }"},
		{"jump range", "{ F4 23 [4-6] 62 B4 }", "{ F4 23 [4-6] 62 B4 }"},
		{"jump unbounded", "{ FE 39 45 [10-] 89 00 }", "{ FE 39 45 [10-] 89 00 }"},
		{"jump infinite", "{ FE 39 45 [-] 89 00 }", "{ FE 39 45 [-] 89 00 }"},
		{"NOT byte", "{ F4 23 ~00 62 B4 }", "{ F4 23 ~00 62 B4 }"},
		{"NOT nibble", "{ F4 23 ~?0 62 B4 }", "{ F4 23 ~?0 62 B4 }"},
		{"NOT multi", "{ ~FF ~00 ~A? }", "{ ~FF ~00 ~A? }"},
		{"alts simple", "{ F4 23 ( 62 B4 | 56 ) 45 }", "{ F4 23 ( 62 B4 | 56 ) 45 }"},
		{"alts multi", "{ F4 23 ( 62 B4 | 56 | 45 ?? 67 ) 45 }", "{ F4 23 ( 62 B4 | 56 | 45 ?? 67 ) 45 }"},
		{"alts nested", "{ A1 ( B2 | C3 ( D4 | E5 ) ) F6 }", "{ A1 ( B2 | C3 ( D4 | E5 ) ) F6 }"},
		{"complex", "{ E2 34 ?? C8 A? FB [1-3] ~00 ( 12 | 34 ) }", "{ E2 34 ?? C8 A? FB [1-3] ~00 ( 12 | 34 ) }"},
		{"real-world", "{ 4D 5A [0-100] 50 45 00 00 [200-] ?? ?? ?? ?? }", "{ 4D 5A [0-100] 50 45 00 00 [200-] ?? ?? ?? ?? }"},
		{"unterminated", "{ E2 34 A1", "{ E2 34 A1"},
		{"with newlines", "{\n  E2 34\n  A1 C8\n}", "{\n  E2 34\n  A1 C8\n}"},
		{"with comments", "{ E2 /* comment */ 34 A1 }", "{ E2 /* comment */ 34 A1 }"},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(_ *testing.T) {
			helper.AssertSingleToken(tt.input, token.HEX_STRING_LIT, tt.expected)
		})
	}
}

func TestHexString_VsRegularBraces(t *testing.T) {
	helper := lexer.NewTestHelper(t)
	input := "rule test { condition: true }"
	tokens := helper.CollectTokens(input)
	var lbraceFound, rbraceFound bool
	for _, tok := range tokens {
		if tok.Type == token.LBRACE && tok.Literal == "{" {
			lbraceFound = true
		}
		if tok.Type == token.RBRACE && tok.Literal == "}" {
			rbraceFound = true
		}
		if tok.Type == token.HEX_STRING_LIT {
			t.Fatalf("unexpected HEX_STRING_LIT token: %+v", tok)
		}
	}
	if !lbraceFound || !rbraceFound {
		t.Fatalf("expected to find LBRACE and RBRACE tokens, got: %+v", tokens)
	}
}
