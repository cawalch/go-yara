package compiler

import (
	"slices"
	"testing"

	"github.com/cawalch/go-yara/ast"
)

// Residual gremlins survivors for hex_pattern.go are classified at the bottom
// of this file per the #311 acceptance criteria.

func TestCloneHexTokensDeepCopiesAlternatives(t *testing.T) {
	original := []HexPatternToken{{
		Kind:         HexTokenAlt,
		Alternatives: [][]HexPatternToken{{{Kind: HexTokenByte, Value: 0xAA}}},
	}}
	cloned := cloneHexTokens(original)
	cloned[0].Alternatives[0][0].Value = 0xBB
	if original[0].Alternatives[0][0].Value != 0xAA {
		t.Fatal("cloneHexTokens aliased nested alternatives")
	}
}

func TestParseHexTokens(t *testing.T) {
	tokens, err := parseHexTokens("DE AD")
	if err != nil || len(tokens) != 2 {
		t.Fatalf("parseHexTokens = %v, %v, want 2 tokens", tokens, err)
	}
	if _, err := parseHexTokens("ZZ"); err == nil {
		t.Fatal("parseHexTokens(invalid) = nil error, want error")
	}
}

func TestHasUnboundedJump(t *testing.T) {
	if !hasUnboundedJump([]HexPatternToken{{Kind: HexTokenJump, Max: -1}}) {
		t.Fatal("unbounded jump not detected")
	}
	if hasUnboundedJump([]HexPatternToken{{Kind: HexTokenJump, Max: 0}}) {
		t.Fatal("bounded jump detected as unbounded")
	}
	nested := []HexPatternToken{{Kind: HexTokenAlt, Alternatives: [][]HexPatternToken{{{Kind: HexTokenJump, Max: -1}}}}}
	if !hasUnboundedJump(nested) {
		t.Fatal("nested unbounded jump not detected")
	}
	if hasUnboundedJump([]HexPatternToken{{Kind: HexTokenByte, Value: 1}}) {
		t.Fatal("plain byte detected as unbounded jump")
	}
}

func TestSplitHexAlternatives(t *testing.T) {
	parts := splitHexAlternatives("(a|b)|c")
	if !slices.Equal(parts, []string{"(a|b)", "c"}) {
		t.Fatalf("splitHexAlternatives = %q, want [\"(a|b)\" \"c\"]", parts)
	}
	parts = splitHexAlternatives("a|b|c")
	if !slices.Equal(parts, []string{"a", "b", "c"}) {
		t.Fatalf("splitHexAlternatives(flat) = %q, want [a b c]", parts)
	}
}

func TestParseHexJumpRange(t *testing.T) {
	tests := []struct {
		in       string
		min, max int
	}{
		{in: "", min: 0, max: -1},
		{in: "-", min: 0, max: -1},
		{in: "5", min: 5, max: 5},
		{in: "2-4", min: 2, max: 4},
		{in: "3-", min: 3, max: -1},
	}
	for _, tt := range tests {
		minVal, maxVal, err := parseHexJumpRange(tt.in)
		if err != nil || minVal != tt.min || maxVal != tt.max {
			t.Fatalf("parseHexJumpRange(%q) = (%d,%d,%v), want (%d,%d,nil)", tt.in, minVal, maxVal, err, tt.min, tt.max)
		}
	}
}

func TestExtractHexGroup(t *testing.T) {
	start, end, err := extractHexGroup("(ab)", 0, '(', ')')
	if err != nil || start != 1 || end != 3 {
		t.Fatalf("extractHexGroup = (%d,%d,%v), want (1,3,nil)", start, end, err)
	}
	if _, _, err := extractHexGroup("(ab", 0, '(', ')'); err == nil {
		t.Fatal("extractHexGroup(unterminated) = nil error")
	}
	if _, _, err := extractHexGroup("", 0, '(', ')'); err == nil {
		t.Fatal("extractHexGroup(empty) = nil error")
	}
	if _, _, err := extractHexGroup("x", 0, '(', ')'); err == nil {
		t.Fatal("extractHexGroup(wrong open) = nil error")
	}
}

func TestSkipHexWhitespaceAndComments(t *testing.T) {
	tests := []struct {
		in   string
		pos  int
		want int
	}{
		{in: "  DE", pos: 0, want: 2},
		{in: "/*x*/DE", pos: 0, want: 5},
		{in: "/*ab", pos: 0, want: 3},
		{in: "//x\nDE", pos: 0, want: 4},
		{in: "DE", pos: 0, want: 0},
	}
	for _, tt := range tests {
		if got := skipHexWhitespaceAndComments(tt.in, tt.pos); got != tt.want {
			t.Fatalf("skipHexWhitespaceAndComments(%q,%d) = %d, want %d", tt.in, tt.pos, got, tt.want)
		}
	}
}

func TestHexNibbleAndHexByte(t *testing.T) {
	if got := hexNibble('0'); got != 0 {
		t.Fatalf("hexNibble('0') = %d, want 0", got)
	}
	if got := hexNibble('a'); got != 10 {
		t.Fatalf("hexNibble('a') = %d, want 10", got)
	}
	if got := hexNibble('F'); got != 15 {
		t.Fatalf("hexNibble('F') = %d, want 15", got)
	}
	if got := hexNibble('z'); got != 0 {
		t.Fatalf("hexNibble('z') = %d, want 0", got)
	}
	if got := hexByte('D', 'E'); got != 0xDE {
		t.Fatalf("hexByte('D','E') = %#x, want 0xDE", got)
	}
}

func TestExpandXorKeys(t *testing.T) {
	keys := expandXorKeys([]ast.XorRange{{Min: 0, Max: 2}, {Min: 1, Max: 1}})
	if !slices.Equal(keys, []byte{0, 1, 2}) {
		t.Fatalf("expandXorKeys = %v, want [0 1 2]", keys)
	}
	if got := expandXorKeys(nil); len(got) != 0 {
		t.Fatalf("expandXorKeys(nil) = %v, want empty", got)
	}
	keys = expandXorKeys([]ast.XorRange{{Min: 300, Max: 300}})
	if !slices.Equal(keys, []byte{255}) {
		t.Fatalf("expandXorKeys(300,300) = %v, want [255]", keys)
	}
	keys = expandXorKeys([]ast.XorRange{{Min: -2, Max: -1}})
	if !slices.Equal(keys, []byte{0}) {
		t.Fatalf("expandXorKeys(-2,-1) = %v, want [0]", keys)
	}
	keys = expandXorKeys([]ast.XorRange{{Min: 5, Max: 2}})
	if !slices.Equal(keys, []byte{2, 3, 4, 5}) {
		t.Fatalf("expandXorKeys(swapped) = %v, want [2 3 4 5]", keys)
	}
}

func TestIsLinearHexPattern(t *testing.T) {
	if !isLinearHexPattern([]HexPatternToken{{Kind: HexTokenByte, Value: 1}}) {
		t.Fatal("plain byte pattern reported non-linear")
	}
	if isLinearHexPattern([]HexPatternToken{{Kind: HexTokenJump}}) {
		t.Fatal("jump pattern reported linear")
	}
	if isLinearHexPattern([]HexPatternToken{{Kind: HexTokenAlt}}) {
		t.Fatal("alt pattern reported linear")
	}
}

func TestMatchLinearHexPattern(t *testing.T) {
	tokens := []HexPatternToken{{Kind: HexTokenByte, Value: 0xDE}, {Kind: HexTokenByte, Value: 0xAD}}
	if end, ok := matchLinearHexPattern(tokens, []byte{0xDE, 0xAD}, 0, nil); !ok || end != 2 {
		t.Fatalf("match = (%d,%v), want (2,true)", end, ok)
	}
	if _, ok := matchLinearHexPattern(tokens, []byte{0xDE}, 0, nil); ok {
		t.Fatal("short data matched")
	}
	if _, ok := matchLinearHexPattern(tokens, []byte{0xDE, 0xAD}, -1, nil); ok {
		t.Fatal("negative pos matched")
	}
	if _, ok := matchLinearHexPattern(tokens, []byte{1, 2, 3}, 3, nil); ok {
		t.Fatal("match past the tail matched")
	}
	if _, ok := matchLinearHexPattern([]HexPatternToken{{Kind: HexTokenWildcard}}, []byte{0x00}, 0, nil); !ok {
		t.Fatal("wildcard did not match")
	}
	negated := []HexPatternToken{{Kind: HexTokenByte, Value: 0xDE, Negated: true}}
	if _, ok := matchLinearHexPattern(negated, []byte{0xAD}, 0, nil); !ok {
		t.Fatal("negated byte did not match a different value")
	}
	if _, ok := matchLinearHexPattern(negated, []byte{0xDE}, 0, nil); ok {
		t.Fatal("negated byte matched its own value")
	}
	masked := []HexPatternToken{{Kind: HexTokenMasked, Value: 0xA0, Mask: 0xF0}}
	if _, ok := matchLinearHexPattern(masked, []byte{0xAB}, 0, nil); !ok {
		t.Fatal("masked byte did not match")
	}
	key := byte(0x11)
	if _, ok := matchLinearHexPattern(tokens, []byte{0xCF, 0xBC}, 0, &key); !ok {
		t.Fatal("xor match failed")
	}
}

func TestFindHexMatchesLinear(t *testing.T) {
	pattern := &HexPattern{Tokens: []HexPatternToken{
		{Kind: HexTokenByte, Value: 0xDE},
		{Kind: HexTokenByte, Value: 0xAD},
	}}
	matches := FindHexMatches(pattern, []byte{0x00, 0xDE, 0xAD, 0x00})
	if len(matches) != 1 || matches[0].Offset != 1 || matches[0].Length != 2 {
		t.Fatalf("FindHexMatches = %+v, want one 2-byte match at offset 1", matches)
	}
}

func TestFindHexMatchesBruteForce(t *testing.T) {
	// No definite anchor byte, so the brute-force scan is used.
	pattern := &HexPattern{Tokens: []HexPatternToken{
		{Kind: HexTokenByte, Value: 0xDE, Negated: true},
		{Kind: HexTokenWildcard},
	}}
	matches := FindHexMatches(pattern, []byte{0xDE, 0x00, 0x00})
	if len(matches) != 1 || matches[0].Offset != 1 || matches[0].Length != 2 {
		t.Fatalf("FindHexMatches(brute force) = %+v, want one 2-byte match at offset 1", matches)
	}
}

func TestFindHexMatchesXorRange(t *testing.T) {
	pattern := &HexPattern{
		Tokens:   []HexPatternToken{{Kind: HexTokenByte, Value: 0xDE}},
		XorRange: []ast.XorRange{{Min: 0x11, Max: 0x11}},
	}
	matches := FindHexMatches(pattern, []byte{0xDE ^ 0x11})
	if len(matches) != 1 {
		t.Fatalf("FindHexMatches(xor range) = %+v, want one match", matches)
	}
}

func TestFindHexMatchesEachNilScratch(t *testing.T) {
	pattern := &HexPattern{Tokens: []HexPatternToken{{
		Kind: HexTokenAlt,
		Alternatives: [][]HexPatternToken{
			{{Kind: HexTokenByte, Value: 0xAA}},
			{{Kind: HexTokenByte, Value: 0xBB}},
		},
	}}}
	count := 0
	findHexMatchesEach(pattern, []byte{0xAA}, nil, nil, func(Match) bool {
		count++
		return true
	})
	if count != 1 {
		t.Fatalf("findHexMatchesEach(nil scratch) = %d matches, want 1", count)
	}
}

// Residual gremlins survivors for hex_pattern.go (gremlins v0.6.0, workers=1,
// timeout-coefficient=30), classified per #311:
//
// LIVED / equivalent-mode:
//
//	106:8,302:31   loop bounds whose extra iteration exits immediately.
//	131:11,185:9,  err != nil guards on the parser success path.
//	192:10,258:9,263:9
//	239:13         depth > 0 boundary: depth is either 0 or >= 1.
//	420:45         len(XorRange) > 0 at 0 expands an empty key list.
//	485:11,513:11, end <= start boundaries describe zero-length matches that
//	570:12,601:12  matchEach never produces.
//	518:17,562:19, Length arithmetic on paths the brute-force/anchored tests do
//	575:18         not select; the selected-path variants are killed.
//	666:10,669:10, XOR clamp boundaries are no-ops at the boundary value.
//	672:10,675:10,678:10
//	704:22         scratch.worklist == nil is only true on the first reset.
//	740:10,750:11, dp >= len(data) boundaries are also guarded per-token.
//	769:11,789:27
//	742:19,742:48, matchEach head dispatch guards, shadowed by the per-token
//	742:70,742:96, checks that follow.
//	742:124,797:13,804:13,817:19
//
// NOT COVERED / unfixable-by-tests:
//
//	321:*,323:*,331:*,345:*,347:*,349:*  switch-case conditions in the
//	               whitespace/comment/nibble scanners.
//	640:14,643:30,755:20,775:34  XOR branches of matchEach.
//
// TIMED OUT / non-terminating:
//
//	114:5,163:80,464:*,468:19,549:*,553:20,681:28,809:41  index/jump cursor
//	arithmetic that walks backwards forever.
