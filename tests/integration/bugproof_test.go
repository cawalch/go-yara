//go:build bugproof

// Package integration contains the libyara-differential proof suite.
//
// Run it with:
//
//	go test -tags bugproof ./tests/integration/ -run TestBug -v
//
// Every test asserts the behaviour libyara 4.5.8 exhibits and that go-yara must
// match. A failing test is a demonstrated divergence, not a stylistic opinion:
// the failure output prints both engines' results side by side.
package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/compiler"
)

type occ struct {
	Off int64
	Len int
}

func requireLibyara(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("yara")
	if err != nil {
		t.Skip("libyara `yara` binary not found")
	}
	v, _ := exec.Command(bin, "--version").Output()
	t.Logf("oracle: %s", strings.TrimSpace(string(v)))
	return bin
}

//nolint:revive // test helper requires multiple testing arguments
func libyaraSpans(t *testing.T, bin, src string, data []byte) ([]occ, error) {
	t.Helper()
	dir := t.TempDir()
	rp, dp := filepath.Join(dir, "r.yar"), filepath.Join(dir, "d.bin")
	if err := os.WriteFile(rp, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "-s", "-L", "--no-warnings", rp, dp).Output()
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			return nil, fmt.Errorf("libyara invocation failed: %w", err)
		}
		combined := string(out) + string(ee.Stderr)
		if strings.Contains(combined, "error:") {
			return nil, fmt.Errorf("libyara rejects: %s", strings.TrimSpace(combined))
		}
		return []occ{}, nil
	}
	var res []occ
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "0x") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 3 {
			continue
		}
		off, e1 := strconv.ParseInt(strings.TrimPrefix(f[0], "0x"), 16, 64)
		ln, e2 := strconv.Atoi(f[1])
		if e1 != nil || e2 != nil {
			continue
		}
		res = append(res, occ{Off: off, Len: ln})
	}
	return res, nil
}

func goYaraSpans(t *testing.T, src string, data []byte) ([]occ, error) {
	t.Helper()
	c := compiler.NewCompiler()
	prog, err := c.CompileSourceWithContext(context.Background(), src)
	if err != nil {
		return nil, fmt.Errorf("go-yara rejects: %w", err)
	}
	res, err := prog.Scan(data)
	if err != nil {
		return nil, fmt.Errorf("go-yara scan error: %w", err)
	}
	var out []occ
	for _, rm := range res.MatchedRules {
		for _, ms := range rm.Matches {
			for _, m := range ms {
				out = append(out, occ{Off: m.Offset, Len: m.Length})
			}
		}
	}
	return out, nil
}

func fmtOcc(o []occ, err error) string {
	if err != nil {
		return err.Error()
	}
	parts := make([]string, len(o))
	for i, v := range o {
		parts[i] = fmt.Sprintf("@%d/%d", v.Off, v.Len)
	}
	return "[" + strings.Join(parts, " ") + "]"
}

// assertSameOccurrenceSet is the core proof primitive: go-yara must report
// exactly the occurrences libyara reports.
//
//nolint:revive // test helper requires multiple testing arguments
func assertSameOccurrenceSet(t *testing.T, bin, src string, data []byte) {
	t.Helper()
	want, yerr := libyaraSpans(t, bin, src, data)
	if yerr != nil {
		t.Fatalf("test premise invalid: %v", yerr)
	}
	got, gerr := goYaraSpans(t, src, data)
	if gerr != nil {
		t.Errorf("DIVERGENCE\n  rule : %s\n  input: %q\n  libyara: %s\n  go-yara: %s",
			src, data, fmtOcc(want, yerr), fmtOcc(got, gerr))
		return
	}
	if fmtOcc(want, nil) != fmtOcc(got, nil) {
		t.Errorf("DIVERGENCE\n  rule : %s\n  input: %q\n  libyara: %s\n  go-yara: %s",
			src, data, fmtOcc(want, nil), fmtOcc(got, nil))
	}
}

// assertGoAccepts proves go-yara compiles a rule libyara compiles.
func assertGoAccepts(t *testing.T, bin, src string) {
	t.Helper()
	if _, err := libyaraSpans(t, bin, src, []byte("abc")); err != nil && strings.HasPrefix(err.Error(), "libyara rejects") {
		t.Fatalf("test premise invalid: %v", err)
	}
	c := compiler.NewCompiler()
	if _, err := c.CompileSourceWithContext(context.Background(), src); err != nil {
		t.Errorf("DIVERGENCE: libyara compiles this rule, go-yara does not\n  rule: %s\n  go-yara: %v", src, err)
	}
}

// assertGoScanSucceeds proves go-yara evaluates (not aborts) a rule libyara evaluates.
//
//nolint:revive // test helper requires multiple testing arguments
func assertGoScanSucceeds(t *testing.T, bin, src string, data []byte) {
	t.Helper()
	if _, err := libyaraSpans(t, bin, src, data); err != nil && strings.HasPrefix(err.Error(), "libyara rejects") {
		t.Fatalf("test premise invalid: %v", err)
	}
	c := compiler.NewCompiler()
	prog, err := c.CompileSourceWithContext(context.Background(), src)
	if err != nil {
		t.Errorf("DIVERGENCE: go-yara cannot compile a rule libyara compiles\n  rule: %s\n  go-yara: %v", src, err)
		return
	}
	if _, err := prog.Scan(data); err != nil {
		t.Errorf("DIVERGENCE: go-yara aborts the scan where libyara evaluates normally\n  rule : %s\n  input: %q\n  go-yara: %v", src, data, err)
	}
}

// assertAgreementOnValues is the oracle-driven primitive used for value
// semantics: substitute each candidate value into the template and require both
// engines to reach the same verdict. No expected value is hardcoded here; the
// divergence is demonstrated by the two engines disagreeing on the same probe.
//
//nolint:revive // test helper requires multiple testing arguments
func assertAgreementOnValues(t *testing.T, bin, tmpl string, data []byte, values []int) {
	t.Helper()
	for _, v := range values {
		src := fmt.Sprintf(tmpl, v)
		want, yerr := libyaraSpans(t, bin, src, data)
		if yerr != nil {
			t.Fatalf("premise invalid for %q: %v", src, yerr)
		}
		c := compiler.NewCompiler()
		prog, err := c.CompileSourceWithContext(context.Background(), src)
		if err != nil {
			t.Errorf("DIVERGENCE: go-yara rejects a rule libyara accepts\n  rule: %s\n  %v", src, err)
			continue
		}
		res, err := prog.Scan(data)
		if err != nil {
			t.Errorf("DIVERGENCE: go-yara aborts the scan\n  rule : %s\n  input: %q\n  go-yara: %v", src, data, err)
			continue
		}
		libyaraMatched := len(want) > 0
		goMatched := len(res.MatchedRules) > 0
		if libyaraMatched != goMatched {
			t.Errorf("DIVERGENCE: different verdict for the same probe\n  rule : %s\n  input: %q\n  libyara matched=%v\n  go-yara matched=%v",
				src, data, libyaraMatched, goMatched)
		}
	}
}

// ---------------------------------------------------------------------------
// BUG-01: additive and multiplicative operators share one precedence level.
// parser/expression_parser.go operatorPrecedence() gives +,-,*,/,% prec 5.
// libyara computes 1+(2*3)=7; go-yara computes (1+2)*3=9.
// ---------------------------------------------------------------------------

func TestBug01_OperatorPrecedence(t *testing.T) {
	bin := requireLibyara(t)
	cases := []struct {
		tmpl string
		vals []int
	}{
		{`rule t { strings: $s = "abc" condition: 1 + 2 * 3 == %d and $s }`, []int{7, 9, 11}},
		{`rule t { strings: $s = "abc" condition: 10 - 2 * 3 == %d and $s }`, []int{4, 24}},
		{`rule t { strings: $s = "abc" condition: 2 + 3 * 4 == %d and $s }`, []int{14, 20}},
		{`rule t { strings: $s = "abc" condition: 1 + 2 * 3 - 4 == %d and $s }`, []int{3, 5}},
		{`rule t { strings: $s = "abc" condition: 1 - 2 * 2 == %d and $s }`, []int{-3, 1}},
		{`rule t { strings: $s = "abc" condition: 2 * 3 - 1 * 4 == %d and $s }`, []int{2, 4}},
	}
	for _, tc := range cases {
		assertAgreementOnValues(t, bin, tc.tmpl, []byte("abcabcxx"), tc.vals)
	}
}

// ---------------------------------------------------------------------------
// BUG-02: `and` must bind tighter than `or`.
// operatorPrecedence() gives AND and OR the same precedence (1).
// ---------------------------------------------------------------------------

func TestBug02_AndBindsTighterThanOr(t *testing.T) {
	bin := requireLibyara(t)
	assertAgreementOnValues(t, bin, `rule t { strings: $s = "abc" condition: 1 or 0 and 0 == %d and $s }`, []byte("abcabcxx"), []int{0, 1})
	assertAgreementOnValues(t, bin, `rule t { strings: $s = "abc" condition: 1 or 1 and 0 == %d and $s }`, []byte("abcabcxx"), []int{0, 1})
	assertAgreementOnValues(t, bin, `rule t { strings: $s = "abc" condition: 0 and 1 or 1 == %d and $s }`, []byte("abcabcxx"), []int{0, 1})
}

// ---------------------------------------------------------------------------
// BUG-03: an out-of-range string occurrence index aborts the whole scan.
// executeOffsetOperation pushes ValueTypeUndefined; compareValues then errors.
// ---------------------------------------------------------------------------

func TestBug03_OutOfRangeOffsetAbortsScan(t *testing.T) {
	bin := requireLibyara(t)
	assertGoScanSucceeds(t, bin, `rule t { strings: $a = "abc" condition: @a[3] == 0 }`, []byte("abcabc"))
	assertGoScanSucceeds(t, bin, `rule t { strings: $a = "abc" condition: @a[99] != 0 }`, []byte("abcabc"))
	// The canonical YARA idiom: iterate a fixed range over occurrences.
	assertGoScanSucceeds(t, bin, `rule t { strings: $a = "abc" condition: for any i in (1..5) : ( @a[i] == 3 ) }`, []byte("abcabc"))
	// Blast radius: one such rule must not destroy the results of other rules.
	src := `rule good { strings: $a = "abc" condition: $a } rule bad { strings: $b = "abc" condition: @b[9] == 0 }`
	c := compiler.NewCompiler()
	prog, err := c.CompileSourceWithContext(context.Background(), src)
	if err != nil {
		t.Fatalf("premise: %v", err)
	}
	res, err := prog.Scan([]byte("abcabc"))
	if err != nil {
		t.Errorf("DIVERGENCE: one bad rule aborts the entire scan, so `good` is lost: %v", err)
	} else if len(res.MatchedRules) == 0 {
		t.Errorf("DIVERGENCE: rule `good` should still match")
	}
}

// ---------------------------------------------------------------------------
// BUG-04: modulo by zero aborts the scan instead of evaluating like libyara.
// ---------------------------------------------------------------------------

func TestBug04_ModuloByZeroAbortsScan(t *testing.T) {
	bin := requireLibyara(t)
	assertGoScanSucceeds(t, bin, `rule t { strings: $a = "abc" condition: (2 % @a[1]) == 0 and $a }`, []byte("abcabc"))
	assertGoScanSucceeds(t, bin, `rule t { strings: $a = "abc" condition: (for any i in (0..3) : ( 10 % i == 0 )) and $a }`, []byte("abcabc"))
}

// ---------------------------------------------------------------------------
// BUG-05: `fullword` treats '_' as a word character; libyara uses isalnum().
// compiler/match_modifiers.go isWordChar includes b == '_'.
// Proven exhaustively over all 256 boundary bytes: 0x5F is the only divergence.
// ---------------------------------------------------------------------------

func TestBug05_FullwordUnderscoreBoundary(t *testing.T) {
	bin := requireLibyara(t)
	assertSameOccurrenceSet(t, bin, `rule t { strings: $a = "abc" fullword condition: $a }`, []byte("abc_"))
	assertSameOccurrenceSet(t, bin, `rule t { strings: $a = "abc" fullword condition: $a }`, []byte("_abc"))
	assertSameOccurrenceSet(t, bin, `rule t { strings: $a = "a" fullword condition: $a }`, []byte("a_a_a"))
	assertSameOccurrenceSet(t, bin, `rule t { strings: $a = "abc" nocase fullword condition: $a }`, []byte("ABC_ABC_abc"))
	assertSameOccurrenceSet(t, bin, `rule t { strings: $a = /.{1,3}/ fullword condition: $a }`, []byte(". c1ca__.a 0"))
}

func TestBug05_FullwordAllBoundaryBytes(t *testing.T) {
	bin := requireLibyara(t)
	for c := 0; c < 256; c++ {
		for _, mode := range []string{"lead", "trail"} {
			var data []byte
			if mode == "lead" {
				data = []byte{byte(c), 'a', 'b', 'c', 0x01}
			} else {
				data = []byte{0x01, 'a', 'b', 'c', byte(c)}
			}
			src := `rule t { strings: $a = "abc" fullword condition: $a }`
			want, err := libyaraSpans(t, bin, src, data)
			if err != nil {
				t.Fatalf("premise: %v", err)
			}
			got, gerr := goYaraSpans(t, src, data)
			if fmtOcc(want, nil) != fmtOcc(got, gerr) {
				t.Errorf("DIVERGENCE byte=0x%02X mode=%s libyara=%s go-yara=%s", c, mode, fmtOcc(want, nil), fmtOcc(got, gerr))
			}
		}
	}
}

// ---------------------------------------------------------------------------
// BUG-06: a spurious zero-length match is reported at offset == len(data).
// compiler/regex_match.go addRegexMatchesLinear iterates pos <= len(data).
// ---------------------------------------------------------------------------

func TestBug06_SpuriousZeroLengthMatchAtEndOfBuffer(t *testing.T) {
	bin := requireLibyara(t)
	assertSameOccurrenceSet(t, bin, `rule t { strings: $a = /0*/ condition: $a }`, []byte("0"))
	assertSameOccurrenceSet(t, bin, `rule t { strings: $a = /0*/ condition: $a }`, []byte("00"))
	assertSameOccurrenceSet(t, bin, `rule t { strings: $a = /a{0,2}/ condition: $a }`, []byte("aaaa"))
	assertSameOccurrenceSet(t, bin, `rule t { strings: $a = /(0|)/ condition: $a }`, []byte("1"))
	// In libyara < 4.5.8, a{0} was dropped due to an upstream atom extraction bug.
	// Only probe a{0} if the libyara oracle itself supports it.
	if spans, _ := libyaraSpans(t, bin, `rule t { strings: $a = /a{0}/ condition: $a }`, []byte("bbb")); len(spans) > 0 {
		assertSameOccurrenceSet(t, bin, `rule t { strings: $a = /a{0}/ condition: $a }`, []byte("bbb"))
		assertAgreementOnValues(t, bin, `rule t { strings: $a = /a{0}/ condition: #a == %d and $a }`, []byte("bbb"), []int{0, 1, 2, 3, 4, 5})
	}
	assertAgreementOnValues(t, bin, `rule t { strings: $a = /0*/ condition: #a == %d and $a }`, []byte("00"), []int{0, 1, 2, 3, 4})
}

// ---------------------------------------------------------------------------
// BUG-07: hex jumps report every accepting path, duplicating one occurrence
// with several lengths. compiler/hex_pattern.go worklist DFS.
// ---------------------------------------------------------------------------

func TestBug07_HexJumpDuplicateOccurrences(t *testing.T) {
	bin := requireLibyara(t)
	assertSameOccurrenceSet(t, bin, `rule t { strings: $a = { 41 [-] 43 } condition: $a }`, []byte("ACC"))
	assertSameOccurrenceSet(t, bin, `rule t { strings: $a = { 41 [-] 43 } condition: $a }`, []byte("ABCAXXC"))
	assertSameOccurrenceSet(t, bin, `rule t { strings: $a = { 41 [-] 43 } condition: $a }`, []byte("ACAC"))
	assertSameOccurrenceSet(t, bin, `rule t { strings: $a = { 41 [1-3] 43 } condition: $a }`, []byte("ACCC"))
	assertAgreementOnValues(t, bin, `rule t { strings: $a = { 41 [-] 43 } condition: #a == %d and $a }`, []byte("ABCAXXC"), []int{0, 1, 2, 3, 4, 5, 6})
}

// ---------------------------------------------------------------------------
// BUG-08: `wide ascii` reports the same offset twice (ascii form + wide form).
// libyara stores one match per (string, offset).
// ---------------------------------------------------------------------------

func TestBug08_WideAsciiDuplicateOccurrences(t *testing.T) {
	bin := requireLibyara(t)
	assertSameOccurrenceSet(t, bin, `rule t { strings: $a = "a" wide ascii condition: $a }`, []byte("a\x00a\x00a"))
	assertSameOccurrenceSet(t, bin, `rule t { strings: $a = "abc" wide ascii condition: $a }`, []byte("abc\x00a\x00b\x00c\x00"))
	assertAgreementOnValues(t, bin, `rule t { strings: $a = "a" wide ascii condition: #a == %d and $a }`, []byte("a\x00a\x00a"), []int{0, 1, 2, 3, 4, 5})
	assertAgreementOnValues(t, bin, `rule t { strings: $a = "_" wide ascii condition: #a == %d and $a }`, []byte("_\x00_"), []int{0, 1, 2, 3, 4})
}

// ---------------------------------------------------------------------------
// BUG-09: regex occurrence length. libyara's PERE stops at the first accepting
// position (leftmost-shortest); regex/vm.go tracks "leftmost-longest".
// ---------------------------------------------------------------------------

func TestBug09_RegexMatchLengthSemantics(t *testing.T) {
	bin := requireLibyara(t)
	assertSameOccurrenceSet(t, bin, `rule t { strings: $a = /(ab|a)/ condition: $a }`, []byte("ab"))
	assertSameOccurrenceSet(t, bin, `rule t { strings: $a = /(a0|a)/ condition: $a }`, []byte("aa0"))
	assertSameOccurrenceSet(t, bin, `rule t { strings: $a = /(abc|ab)/ condition: $a }`, []byte("abcd"))
	assertSameOccurrenceSet(t, bin, `rule t { strings: $a = /.{2}(c+|..)/ condition: $a }`, []byte("0ca ._c0c.ac00ab.0c"))
}

// ---------------------------------------------------------------------------
// BUG-10: `not` cannot be applied to an integer expression.
// semantic/validator.go: "logical not requires boolean operand".
// ---------------------------------------------------------------------------

func TestBug10_NotOnIntegerRejected(t *testing.T) {
	bin := requireLibyara(t)
	for _, src := range []string{
		`rule t { strings: $a = "abc" condition: not 0 and $a }`,
		`rule t { strings: $a = "abc" condition: not #a and $a }`,
		`rule t { strings: $a = "abc" condition: not 1 + 1 and $a }`,
	} {
		assertGoAccepts(t, bin, src)
	}
}

// ---------------------------------------------------------------------------
// BUG-11: libyara's integer division operator is `\`, not `/`.
// ---------------------------------------------------------------------------

func TestBug11_IntegerDivisionOperator(t *testing.T) {
	bin := requireLibyara(t)
	assertGoAccepts(t, bin, `rule t { strings: $a = "abc" condition: 10 \ 2 == 5 and $a }`)
	assertGoAccepts(t, bin, `rule t { strings: $a = "abc" condition: 100 \ 5 \ 2 == 10 and $a }`)
}

// ---------------------------------------------------------------------------
// BUG-12: unknown regex escapes such as `\_` are rejected. libyara treats an
// unknown escape as the literal byte (unless --strict-escape is used).
// ---------------------------------------------------------------------------

func TestBug12_UnknownRegexEscapeRejected(t *testing.T) {
	bin := requireLibyara(t)
	for _, src := range []string{
		`rule t { strings: $a = /\_/ condition: $a }`,
		`rule t { strings: $a = /(a\_b)/ condition: $a }`,
		`rule t { strings: $a = /\!/ condition: $a }`,
		`rule t { strings: $a = /\~/ condition: $a }`,
	} {
		assertGoAccepts(t, bin, src)
	}
	assertSameOccurrenceSet(t, bin, `rule t { strings: $a = /\_/ condition: $a }`, []byte("a_b"))
}

// ---------------------------------------------------------------------------
// BUG-13: regexes containing a literal `,`, `]` or `{` are rejected.
// ---------------------------------------------------------------------------

func TestBug13_LiteralRegexMetacharactersRejected(t *testing.T) {
	bin := requireLibyara(t)
	for _, src := range []string{
		`rule t { strings: $a = /,/ condition: $a }`,
		`rule t { strings: $a = /]/ condition: $a }`,
		`rule t { strings: $a = /{s/ condition: $a }`,
		`rule t { strings: $a = /(0){0/ condition: $a }`,
	} {
		assertGoAccepts(t, bin, src)
	}
}

// ---------------------------------------------------------------------------
// BUG-14: an empty alternation branch is unsupported.
// ---------------------------------------------------------------------------

func TestBug14_EmptyAlternationBranch(t *testing.T) {
	bin := requireLibyara(t)
	assertGoAccepts(t, bin, `rule t { strings: $a = /(o|)/ condition: $a }`)
	assertGoAccepts(t, bin, `rule t { strings: $a = /^(b|)c$/ condition: $a }`)
	assertSameOccurrenceSet(t, bin, `rule t { strings: $a = /^(b|)c$/ condition: $a }`, []byte("dbc"))
}

// ---------------------------------------------------------------------------
// BUG-15: `for any i in (0)` (single-value range) is rejected.
// ---------------------------------------------------------------------------

func TestBug15_SingleValueForRange(t *testing.T) {
	bin := requireLibyara(t)
	assertGoAccepts(t, bin, `rule t { strings: $a = "0" condition: for any i in (0) : ( $a ) and $a }`)
}

// ---------------------------------------------------------------------------
// BUG-16 (#289): bitwise and shift operators precedence.
// ---------------------------------------------------------------------------

func TestBug16_BitwiseAndShiftPrecedence(t *testing.T) {
	bin := requireLibyara(t)
	assertAgreementOnValues(t, bin, `rule t { strings: $s = "abc" condition: 3 | 1 & 2 == %d and $s }`, []byte("abcabcxx"), []int{2, 3})
	assertAgreementOnValues(t, bin, `rule t { strings: $s = "abc" condition: 3 ^ 1 & 2 == %d and $s }`, []byte("abcabcxx"), []int{2, 3})
	assertAgreementOnValues(t, bin, `rule t { strings: $s = "abc" condition: 1 | 3 & 2 == %d and $s }`, []byte("abcabcxx"), []int{2, 3})
	assertAgreementOnValues(t, bin, `rule t { strings: $s = "abc" condition: 2 ^ 3 & 1 == %d and $s }`, []byte("abcabcxx"), []int{1, 3})
	assertAgreementOnValues(t, bin, `rule t { strings: $s = "abc" condition: 3 & 1 << 2 == %d and $s }`, []byte("abcabcxx"), []int{0, 4})
	assertAgreementOnValues(t, bin, `rule t { strings: $s = "abc" condition: 3 | 1 << 2 == %d and $s }`, []byte("abcabcxx"), []int{7, 12})
}

// assertBothReject proves both libyara and go-yara reject an invalid rule at compile time.
func assertBothReject(t *testing.T, bin, src string) {
	t.Helper()
	_, yerr := libyaraSpans(t, bin, src, []byte("dummy"))
	if yerr == nil {
		t.Fatalf("test premise invalid: libyara unexpectedly accepted %q", src)
	}
	c := compiler.NewCompiler()
	if _, err := c.CompileSourceWithContext(context.Background(), src); err == nil {
		t.Errorf("DIVERGENCE: libyara rejects this invalid rule, but go-yara accepts it\n  rule: %s", src)
	}
}

// ---------------------------------------------------------------------------
// BUG-17: `defined` unary operator in condition.
// ---------------------------------------------------------------------------

func TestBug17_DefinedOperator(t *testing.T) {
	bin := requireLibyara(t)
	assertSameOccurrenceSet(t, bin, `rule t { strings: $a = "foo" condition: defined @a[1] and $a }`, []byte("foobar"))
	assertSameOccurrenceSet(t, bin, `rule t { strings: $a = "foo" condition: not defined @a[2] and $a }`, []byte("foobar"))
	assertSameOccurrenceSet(t, bin, `rule t { strings: $a = "foo" condition: defined !a[1] and $a }`, []byte("foobar"))
	assertSameOccurrenceSet(t, bin, `rule t { strings: $a = "foo" condition: defined #a and $a }`, []byte("foobar"))
	assertSameOccurrenceSet(t, bin, `rule t { strings: $a = "foo" condition: defined filesize and $a }`, []byte("foobar"))
}

// ---------------------------------------------------------------------------
// BUG-18: Hex alternations reject unbounded jumps.
// ---------------------------------------------------------------------------

func TestBug18_HexAlternationUnboundedJumps(t *testing.T) {
	bin := requireLibyara(t)
	assertBothReject(t, bin, `rule t { strings: $a = { 01 ( 02 | 03 [-] 04 ) 05 } condition: $a }`)
	assertBothReject(t, bin, `rule t { strings: $a = { 01 ( 02 | 03 [1-] 04 ) 05 } condition: $a }`)
	assertBothReject(t, bin, `rule t { strings: $a = { 01 ( 02 | ( 03 | 04 [-] 05 ) ) 06 } condition: $a }`)
	// Bounded jumps inside alternation are valid:
	assertGoAccepts(t, bin, `rule t { strings: $a = { 01 ( 02 | 03 [1-2] 04 ) 05 } condition: $a }`)
	assertSameOccurrenceSet(t, bin, `rule t { strings: $a = { 01 ( 02 | 03 [1-2] 04 ) 05 } condition: $a }`, []byte("\x01\x03\xaa\x04\x05"))
}

// ---------------------------------------------------------------------------
// BUG-19: Division and modulo by constant zero are rejected at compile time.
// ---------------------------------------------------------------------------

func TestBug19_ConstantDivisionByZeroRejected(t *testing.T) {
	bin := requireLibyara(t)
	assertBothReject(t, bin, `rule t { condition: 1 \ 0 == 0 }`)
	assertBothReject(t, bin, `rule t { condition: 1 % 0 == 0 }`)
	assertBothReject(t, bin, `rule t { condition: filesize \ 0 == 0 }`)
	assertBothReject(t, bin, `rule t { condition: filesize % 0 == 0 }`)
	assertBothReject(t, bin, `rule t { condition: true or (1 \ 0 == 0) }`)
}
