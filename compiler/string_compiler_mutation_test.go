package compiler

// Residual gremlins survivors for string_compiler.go, classified per the #311
// acceptance criteria. Re-run with:
//
//	gremlins unleash ./compiler --workers 1 --timeout-coefficient 30 -E "<all-but-string_compiler.go>"
//
// LIVED / equivalent-mode (mutant cannot change observable behaviour):
//
//	262:10,262:19  k<0 / k>0xff clamp guard is unreachable: normalizeXorRange
//	               already clamps every key to [0,255].
//	308:9,311:9    min<0 / max<0 -> <= is a no-op at the boundary (min=max=0
//	314:9,317:9    clamp to the same value). 314/317 min>255 / max>255 -> >=
//	320:9          likewise no-op; max<min -> <= swaps equal values.
//	330:45,364:45, slice-capacity arithmetic in make(); capacity is not
//	465:43,754:39  observable.
//	429:19         len(patterns)<=1 fast path; falling through rebuilds an
//	               identical (non-nil vs nil) slice that no caller distinguishes.
//	468:8,470:8    loop bound i<len vs i<=len and i>=len vs i>len are
//	               behaviourally identical because the body re-checks the bound.
//	492:7          same trailing-bound argument after the whitespace loop.
//	834:16         wide nocase loop bound i<len-1 vs <=len-1 only visits the
//	               trailing UTF-16 high byte (0x00), never an ASCII letter.
//	67:11          negating i+3<dataLen makes the unrolled loop never run; the
//	               byte-wise tail then scans every byte and returns the same
//	               answer, so the panic path is unreachable.
//
// NOT COVERED / unfixable-by-tests:
//
//	614:21,618:28, 636:55,642:44,642:48,780:17,785:17 are conditions inside
//	`switch { case ... }` arms. Go's coverage instrumentation emits no block
//	for a case expression, so gremlins can never mark these covered even
//	though tests do execute them (e.g. "??", "?a", "41", "4?", "?4").
//
// TIMED OUT / non-terminating:
//
//	261:33,490:4   k++ -> k-- / i++ -> i-- spin forever.
//	537:9          pos>=len -> pos<len makes parsehexToken return advance 0
//	               for non-empty input; tokenizeHexString then never advances.
import (
	"bytes"
	"testing"

	"github.com/cawalch/go-yara/ast"
)

func xorModifier(value any) ast.StringModifier {
	return ast.StringModifier{Type: ast.StringModifierXor, Value: value}
}

// TestFastNeedsConversionTailBlock pins the 4-byte unrolled loop bound: a length
// that is not a multiple of four must fall through to the byte-wise tail.
func TestFastNeedsConversionTailBlock(t *testing.T) {
	if fastNeedsConversion([]byte("0000000")) {
		t.Fatal("fastNeedsConversion(7 digits) = true, want false")
	}
	if !fastNeedsConversion([]byte("0000000A")) {
		t.Fatal("fastNeedsConversion(trailing uppercase) = false, want true")
	}
}

func TestSingleXorKeyNegation(t *testing.T) {
	sc := newStringCompiler()
	key, ok := sc.singleXorKey([]ast.StringModifier{xorModifier(int64(0x42))})
	if !ok || key != 0x42 {
		t.Fatalf("singleXorKey(single) = (%#x, %v), want (0x42, true)", key, ok)
	}
}

func TestNormalizeXorModifierNilPointer(t *testing.T) {
	sc := newStringCompiler()
	if got := sc.normalizeXorModifier((*ast.XorRange)(nil)); len(got) != 1 || got[0] != (xorRange{min: 0, max: 255}) {
		t.Fatalf("normalizeXorModifier(nil *XorRange) = %+v, want full range", got)
	}
	if got := sc.normalizeXorModifier(nil); len(got) != 1 || got[0] != (xorRange{min: 0, max: 255}) {
		t.Fatalf("normalizeXorModifier(nil) = %+v, want full range", got)
	}
}

func TestNormalizeXorRangeClamp(t *testing.T) {
	sc := newStringCompiler()
	if got := sc.normalizeXorRange(0, 300); got != (xorRange{min: 0, max: 255}) {
		t.Fatalf("normalizeXorRange(0,300) = %+v, want {0,255}", got)
	}
	if got := sc.normalizeXorRange(300, 0); got != (xorRange{min: 0, max: 255}) {
		t.Fatalf("normalizeXorRange(300,0) = %+v, want {0,255}", got)
	}
}

func TestValidateXorModifierNilPointer(t *testing.T) {
	if err := validateXorModifier((*ast.XorRange)(nil)); err != nil {
		t.Fatalf("validateXorModifier(nil *XorRange) = %v, want nil", err)
	}
}

func TestBase64AlphabetNonEmpty(t *testing.T) {
	sc := newStringCompiler()
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	got, err := sc.base64Alphabet(ast.StringModifier{Type: ast.StringModifierBase64, Value: alphabet})
	if err != nil || got != alphabet {
		t.Fatalf("base64Alphabet(custom) = (%q, %v), want the custom alphabet", got, err)
	}
	if got, err := sc.base64Alphabet(ast.StringModifier{Type: ast.StringModifierBase64}); err != nil || got != "" {
		t.Fatalf("base64Alphabet(no value) = (%q, %v), want (\"\", nil)", got, err)
	}
}

func TestBase64AlignedPatternsSingleByte(t *testing.T) {
	sc := newStringCompiler()
	variants, err := sc.base64AlignedPatterns([]byte("a"), "", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(variants) != 2 {
		t.Fatalf("base64AlignedPatterns(1 byte) = %d variants, want 2", len(variants))
	}
}

func TestBase64AlignedPatternsEmptyData(t *testing.T) {
	sc := newStringCompiler()
	variants, err := sc.base64AlignedPatterns(nil, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(variants) == 0 {
		t.Fatal("base64AlignedPatterns(empty) returned no variants")
	}
}

func TestSkipWhitespaceAndCommentsBounds(t *testing.T) {
	sc := newStringCompiler()
	if got := sc.skipWhitespaceAndComments("  ", 2); got != 2 {
		t.Fatalf("skipWhitespaceAndComments at end = %d, want 2", got)
	}
	if got := sc.skipWhitespaceAndComments(" a", 0); got != 1 {
		t.Fatalf("skipWhitespaceAndComments(\" a\") = %d, want 1", got)
	}
}

func TestSkipCommentHelpers(t *testing.T) {
	sc := newStringCompiler()
	if got := sc.skipMultiLineComment("/*x*/", 0); got != 5 {
		t.Fatalf("skipMultiLineComment(terminated) = %d, want 5", got)
	}
	if got := sc.skipMultiLineComment("/*ab", 0); got != 3 {
		t.Fatalf("skipMultiLineComment(unterminated) = %d, want 3", got)
	}
	if got := sc.skipSingleLineComment("//x", 0); got != 3 {
		t.Fatalf("skipSingleLineComment = %d, want 3", got)
	}
}

func TestParseHexTokenGuards(t *testing.T) {
	sc := newStringCompiler()
	if tok, adv := sc.parsehexToken("", 0); tok.Type != "" || adv != 0 {
		t.Fatalf("parsehexToken(empty) = (%+v,%d), want zero value", tok, adv)
	}
	tok, _ := sc.parsehexToken("41", 0)
	if tok.Type != "byte" {
		t.Fatalf("parsehexToken(41) = %+v, want byte", tok)
	}
	if v, ok := tok.Value.(byte); !ok || v != 0x41 {
		t.Fatalf("parsehexToken(41).Value = %v, want byte 0x41", tok.Value)
	}
}

func TestParseWildcardAndByteTokenGuards(t *testing.T) {
	sc := newStringCompiler()
	if tok, _ := sc.parseWildcardToken("?", 0); tok.Type != "" {
		t.Fatalf("parseWildcardToken(?) = %+v, want empty", tok)
	}
	if tok, _ := sc.parseWildcardToken("??", 0); tok.Type != "wildcard" {
		t.Fatalf("parseWildcardToken(??) = %+v, want wildcard", tok)
	}
	if tok, _ := sc.parseWildcardToken("?a", 0); tok.Type != "masked" {
		t.Fatalf("parseWildcardToken(?a) = %+v, want masked", tok)
	}
	if tok, _ := sc.parsehexByteToken("4", 0); tok.Type != "" {
		t.Fatalf("parsehexByteToken(4) = %+v, want empty", tok)
	}
	if tok, _ := sc.parsehexByteToken("41", 0); tok.Type != "byte" {
		t.Fatalf("parsehexByteToken(41) = %+v, want byte", tok)
	}
	if tok, _ := sc.parsehexByteToken("4?", 0); tok.Type != "masked" {
		t.Fatalf("parsehexByteToken(4?) = %+v, want masked", tok)
	}
}

func TestParseJumpTokenGuards(t *testing.T) {
	sc := newStringCompiler()
	if _, adv := sc.parseJumpToken("[10", 0); adv != 3 {
		t.Fatalf("parseJumpToken(unterminated) advance = %d, want 3", adv)
	}
	tok, adv := sc.parseJumpToken("[10]", 0)
	if tok.Type != "jump" || adv != 4 {
		t.Fatalf("parseJumpToken([10]) = (%+v,%d), want jump/4", tok, adv)
	}
	jump, ok := tok.Value.(map[string]int)
	if !ok || jump["min"] != 10 || jump["max"] != 10 {
		t.Fatalf("parseJumpToken([10]).Value = %v, want min/max 10", tok.Value)
	}
}

func TestParseAlternativesTokenGuards(t *testing.T) {
	sc := newStringCompiler()
	if tok, _ := sc.parseAlternativesToken("(ab", 0); tok.Type != "" {
		t.Fatalf("parseAlternativesToken(unterminated) = %+v, want empty", tok)
	}
	tok, adv := sc.parseAlternativesToken("(ab)", 0)
	if tok.Type != "alternative" || adv != 4 {
		t.Fatalf("parseAlternativesToken((ab)) = (%+v,%d), want alternative/4", tok, adv)
	}
}

func TestParseAlternativesTokenNested(t *testing.T) {
	sc := newStringCompiler()
	tok, adv := sc.parseAlternativesToken("((a))", 0)
	if tok.Type != "alternative" || adv != 5 {
		t.Fatalf("parseAlternativesToken(((a))) = (%+v,%d), want alternative/5", tok, adv)
	}
}

// TestParseAlternativesTokenOffset pins the advance arithmetic on the
// unterminated-group path, which is only observable when pos != 0.
func TestParseAlternativesTokenOffset(t *testing.T) {
	sc := newStringCompiler()
	if _, adv := sc.parseAlternativesToken("xx(ab", 2); adv != 3 {
		t.Fatalf("parseAlternativesToken(offset) advance = %d, want 3", adv)
	}
}

func TestProcessAlternativeTokenEmpty(t *testing.T) {
	sc := newStringCompiler()
	var result []byte
	sc.processAlternativeToken(&result, hexToken{Type: "alternative", Value: [][]byte{}})
	if len(result) != 0 {
		t.Fatalf("processAlternativeToken(empty) appended %v", result)
	}
	sc.processAlternativeToken(&result, hexToken{Type: "alternative", Value: [][]byte{{0x41, 0x42}}})
	if string(result) != "AB" {
		t.Fatalf("processAlternativeToken = %q, want AB", result)
	}
}

func TestParseHexByteMasked(t *testing.T) {
	sc := newStringCompiler()
	tests := []struct {
		in   string
		want byte
	}{
		{in: "4?", want: 0x40},
		{in: "?4", want: 0x04},
		{in: "4a", want: 0x4A},
	}
	for _, tt := range tests {
		if got := sc.parsehexByte(tt.in); got != tt.want {
			t.Fatalf("parsehexByte(%q) = %#x, want %#x", tt.in, got, tt.want)
		}
	}
}

func TestApplyNocaseToWideCaseEdges(t *testing.T) {
	sc := newStringCompiler()
	tests := []struct {
		in   []byte
		want []byte
	}{
		{in: []byte{'A', 0}, want: []byte{'a', 0}},
		{in: []byte{'Z', 0}, want: []byte{'z', 0}},
		{in: []byte{'A', 0, 'B', 0}, want: []byte{'a', 0, 'b', 0}},
	}
	for _, tt := range tests {
		if got := sc.applyNocaseToWide(tt.in); !bytes.Equal(got, tt.want) {
			t.Fatalf("applyNocaseToWide(%v) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestValidateXorRangeBounds(t *testing.T) {
	if err := validateXorRange(0, 0); err != nil {
		t.Fatalf("validateXorRange(0,0) = %v, want nil", err)
	}
	if err := validateXorRange(255, 255); err != nil {
		t.Fatalf("validateXorRange(255,255) = %v, want nil", err)
	}
	if err := validateXorRange(-1, 0); err == nil {
		t.Fatal("validateXorRange(-1,0) = nil, want error")
	}
	if err := validateXorRange(0, 256); err == nil {
		t.Fatal("validateXorRange(0,256) = nil, want error")
	}
}

func TestCalculateByteQualityEdges(t *testing.T) {
	sc := newStringCompiler()
	for _, b := range []byte{'a', 'z', 'A', 'Z'} {
		if got := sc.calculateByteQuality(b); got != 18 {
			t.Fatalf("calculateByteQuality(%q) = %d, want 18", b, got)
		}
	}
	for _, b := range []byte{0x00, 0x20, 0xCC, 0xFF} {
		if got := sc.calculateByteQuality(b); got != 12 {
			t.Fatalf("calculateByteQuality(%#x) = %d, want 12", b, got)
		}
	}
	if got := sc.calculateByteQuality(0x01); got != 20 {
		t.Fatalf("calculateByteQuality(0x01) = %d, want 20", got)
	}
}

func TestIsCommonByteSet(t *testing.T) {
	sc := newStringCompiler()
	for _, b := range []byte{0x00, 0x20, 0x90, 0xCC, 0xFF} {
		if !sc.isCommonByte(b) {
			t.Fatalf("isCommonByte(%#x) = false, want true", b)
		}
	}
	if sc.isCommonByte(0x01) {
		t.Fatal("isCommonByte(0x01) = true, want false")
	}
}

func TestEstimatePatternComplexityPenalty(t *testing.T) {
	sc := newStringCompiler()
	if got := sc.EstimatePatternComplexity([]byte{0x00, 0x00}, nil); got != 6 {
		t.Fatalf("EstimatePatternComplexity(0x00 x2) = %d, want 6", got)
	}
	if got := sc.EstimatePatternComplexity([]byte("abc"), nil); got != 60 {
		t.Fatalf("EstimatePatternComplexity(abc) = %d, want 60", got)
	}
}
