package integration

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/compiler"
)

func TestLibyaraCompatibilityMatrixDifferential(t *testing.T) {
	bin := libyaraOracle(t)

	for _, tc := range []struct {
		name           string
		source         string
		data           []byte
		wantLibyaraErr string
		wantDefaultErr string
		wantStrictErr  string
		wantDefaultHit bool
		wantWarning    string
	}{
		{
			name:           "negative-range-lower-bound",
			source:         `rule c { strings: $a = "ab" condition: $a in (-5..5) }`,
			data:           []byte("ab"),
			wantLibyaraErr: "range lower bound can not be negative",
			wantDefaultErr: "range lower bound can not be negative",
			wantStrictErr:  "range lower bound can not be negative",
		},
		{
			name:           "negative-range-lower-bound-in-of",
			source:         `rule c { strings: $a = "ab" condition: any of ($a) in (-5..5) }`,
			data:           []byte("ab"),
			wantLibyaraErr: "range lower bound can not be negative",
			wantDefaultErr: "range lower bound can not be negative",
			wantStrictErr:  "range lower bound can not be negative",
		},
		{
			name:           "reversed-constant-range-for-loop",
			source:         `rule c { condition: for all i in (5..1) : (i == 0) }`,
			data:           []byte("ab"),
			wantLibyaraErr: "range lower bound must be less than upper bound",
			wantDefaultErr: "range lower bound must be less than upper bound",
			wantStrictErr:  "range lower bound must be less than upper bound",
		},
		{
			name:           "reversed-constant-range-string-in",
			source:         `rule c { strings: $a = "ab" condition: $a in (5..1) }`,
			data:           []byte("ab"),
			wantLibyaraErr: "range lower bound must be less than upper bound",
			wantDefaultErr: "range lower bound must be less than upper bound",
			wantStrictErr:  "range lower bound must be less than upper bound",
		},
		{
			name:           "dynamic-negative-range-lower-bound-allowed",
			source:         `rule c { strings: $a = "ab" condition: $a in (-1..filesize) }`,
			data:           []byte("ab"),
			wantDefaultHit: true,
		},
		{
			name:           "indexed-string-count-rejected",
			source:         `rule c { strings: $a = "ab" condition: #a[0] == 0 }`,
			data:           []byte("ab"),
			wantLibyaraErr: "unexpected '['",
			wantDefaultErr: "unexpected '['",
			wantStrictErr:  "unexpected '['",
		},
		{
			name:           "indexed-placeholder-count-rejected",
			source:         `rule c { strings: $a = "ab" condition: for any of ($a) : (#[1] == 1) }`,
			data:           []byte("ab"),
			wantLibyaraErr: "unexpected '['",
			wantDefaultErr: "unexpected '['",
			wantStrictErr:  "unexpected '['",
		},
		{
			name:           "wildcard-string-declaration-rejected",
			source:         `rule c { strings: $nomatch* = "zzz" condition: for any of ($nomatch*) : (true) }`,
			data:           []byte("ab"),
			wantLibyaraErr: "unexpected string identifier with wildcard",
			wantDefaultErr: "unexpected string identifier with wildcard",
			wantStrictErr:  "unexpected string identifier with wildcard",
		},
		{
			name:           "empty-wildcard-set-for-loop",
			source:         `rule c { strings: $a = "ab" condition: $a and for any of ($nomatch*) : (true) }`,
			data:           []byte("ab"),
			wantLibyaraErr: `undefined string "$nomatch*"`,
			wantStrictErr:  `undefined string "$nomatch*"`,
			wantDefaultHit: false,
		},
		{
			name:           "empty-wildcard-set-of",
			source:         `rule c { strings: $a = "ab" condition: $a and any of ($z*) }`,
			data:           []byte("ab"),
			wantLibyaraErr: `undefined string "$z*"`,
			wantStrictErr:  `undefined string "$z*"`,
			wantDefaultHit: false,
		},
		{
			name:           "empty-them-set",
			source:         `rule c { condition: any of them }`,
			data:           []byte("ab"),
			wantLibyaraErr: `undefined string "$*"`,
			wantStrictErr:  `undefined string "$*"`,
			wantDefaultHit: false,
		},
		{
			name:           "unreferenced-string-strict-error-default-warning",
			source:         `rule c { strings: $a = "abc" condition: true }`,
			data:           []byte("ab"),
			wantLibyaraErr: `unreferenced string "$a"`,
			wantStrictErr:  `unreferenced string "$a"`,
			wantDefaultHit: true,
			wantWarning:    compiler.WarningUnusedString,
		},
		{
			name:           "unreferenced-anonymous-string-strict-error",
			source:         `rule c { strings: $ = "abc" condition: true }`,
			data:           []byte("ab"),
			wantLibyaraErr: `unreferenced string "$"`,
			wantStrictErr:  `unreferenced string "$"`,
			wantDefaultHit: true,
			wantWarning:    compiler.WarningUnusedString,
		},
		{
			name:           "underscore-prefix-suppresses-unreferenced-error",
			source:         `rule c { strings: $_a = "abc" condition: true }`,
			data:           []byte("ab"),
			wantDefaultHit: true,
		},
		{
			name:           "percent-out-of-bounds-rejected",
			source:         `rule c { strings: $a = "ab" condition: 0% of them }`,
			data:           []byte("ab"),
			wantLibyaraErr: "percentage must be between 1 and 100 (inclusive)",
			wantDefaultErr: "percentage must be between 1 and 100 (inclusive)",
			wantStrictErr:  "percentage must be between 1 and 100 (inclusive)",
		},
		{
			name:           "mixed-regex-greediness-rejected",
			source:         `rule c { strings: $a = /a+b??/ condition: $a }`,
			data:           []byte("ab"),
			wantLibyaraErr: "greedy and ungreedy quantifiers can't be mixed",
			wantDefaultErr: "greedy and ungreedy quantifiers can't be mixed",
			wantStrictErr:  "greedy and ungreedy quantifiers can't be mixed",
		},
		{
			name:           "expression-quantifier-accepted",
			source:         `rule c { strings: $a = "a" $b = "b" condition: (1+1) of them }`,
			data:           []byte("ab"),
			wantDefaultHit: true,
		},
		{
			name:           "duplicate-meta-keys-accepted",
			source:         `rule c { meta: hash = "1" hash = "2" condition: true }`,
			data:           []byte("ab"),
			wantDefaultHit: true,
		},
		{
			name:           "hex-leading-jump",
			source:         `rule c { strings: $a = { [1-2] 61 62 } condition: $a }`,
			data:           []byte("xabc"),
			wantLibyaraErr: "syntax error",
			wantDefaultHit: true,
			wantStrictErr:  "leading or trailing jump",
		},
		{
			name:           "hex-trailing-jump",
			source:         `rule c { strings: $a = { 61 62 [1-2] } condition: $a }`,
			data:           []byte("xabc"),
			wantLibyaraErr: "syntax error",
			wantDefaultHit: true,
			wantStrictErr:  "leading or trailing jump",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oracle, oracleErr := scanWithLibyara(t, bin, tc.source, tc.data)
			assertCompileOutcome(t, compileOutcomeCheck{label: "libyara", err: oracleErr, wantSubstr: tc.wantLibyaraErr})

			// 1. Default go-yara compiler behavior.
			defaultComp := compiler.NewCompiler()
			defaultProg, defaultErr := defaultComp.CompileSourceWithContext(context.Background(), tc.source)
			if tc.wantDefaultErr != "" || defaultErr != nil {
				assertCompileOutcome(t, compileOutcomeCheck{label: "default", err: defaultErr, wantSubstr: tc.wantDefaultErr})
			} else {
				assertWarningCode(t, defaultComp.GetWarnings(), tc.wantWarning)
				verifyScanAndRoundTrip(t, defaultProg, compatibilityExpectation{data: tc.data, wantHit: tc.wantDefaultHit})
			}

			// 2. Strict libyara compatibility mode.
			strictComp := compiler.NewCompiler(compiler.WithStrictLibyaraCompatibility(true))
			strictProg, strictErr := strictComp.CompileSourceWithContext(context.Background(), tc.source)
			if tc.wantStrictErr != "" || strictErr != nil {
				assertCompileOutcome(t, compileOutcomeCheck{label: "strict", err: strictErr, wantSubstr: tc.wantStrictErr})
				return
			}
			_, oracleMatch := oracle["c"]
			verifyScanAndRoundTrip(t, strictProg, compatibilityExpectation{data: tc.data, wantHit: oracleMatch})
		})
	}
}

type compatibilityExpectation struct {
	data    []byte
	wantHit bool
}

type compileOutcomeCheck struct {
	label      string
	err        error
	wantSubstr string
}

func assertCompileOutcome(t *testing.T, check compileOutcomeCheck) {
	t.Helper()
	if check.wantSubstr == "" {
		if check.err != nil {
			t.Fatalf("%s unexpected err=%v", check.label, check.err)
		}
		return
	}
	if check.err == nil {
		t.Fatalf("%s expected error containing %q, got nil", check.label, check.wantSubstr)
	}
	if !strings.Contains(check.err.Error(), check.wantSubstr) {
		t.Fatalf("%s err = %q, want substring %q", check.label, check.err.Error(), check.wantSubstr)
	}
}

func assertWarningCode(t *testing.T, warnings []compiler.CompilationWarning, wantCode string) {
	t.Helper()
	if wantCode == "" {
		return
	}
	for _, w := range warnings {
		if w.Code == wantCode {
			return
		}
	}
	t.Fatalf("expected warning %q, got %+v", wantCode, warnings)
}

func verifyScanAndRoundTrip(t *testing.T, prog *compiler.CompiledProgram, want compatibilityExpectation) {
	t.Helper()
	s := prog.NewScanner()
	defer s.Close()
	res, err := s.Scan(want.data)
	if err != nil {
		t.Fatalf("Scan err=%v", err)
	}
	got := len(res.MatchedRules) == 1 && res.MatchedRules[0].Rule == "c"
	if got != want.wantHit {
		t.Fatalf("Scan match = %v, want %v", got, want.wantHit)
	}

	blob, err := prog.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary err=%v", err)
	}
	rt, err := compiler.UnmarshalCompiledProgram(blob)
	if err != nil {
		t.Fatalf("UnmarshalCompiledProgram err=%v", err)
	}
	rs := rt.NewScanner()
	defer rs.Close()
	rres, err := rs.ScanReader(bytes.NewReader(want.data))
	if err != nil {
		t.Fatalf("ScanReader err=%v", err)
	}
	gotRT := len(rres.MatchedRules) == 1 && rres.MatchedRules[0].Rule == "c"
	if gotRT != want.wantHit {
		t.Fatalf("ScanReader round-trip match = %v, want %v", gotRT, want.wantHit)
	}
}

func TestLibyaraStrictWithIgnoreInvalidRules(t *testing.T) {
	src := `
rule invalid_unused {
	strings:
		$a = "unused"
	condition:
		true
}

rule valid_rule {
	strings:
		$b = "ok"
	condition:
		$b
}
`
	c := compiler.NewCompiler(
		compiler.WithStrictLibyaraCompatibility(true),
		compiler.WithIgnoreInvalidRules(true),
	)
	prog, err := c.CompileSourceWithContext(context.Background(), src)
	if err != nil {
		t.Fatalf("CompileSourceWithContext() error = %v", err)
	}
	ignored := c.GetIgnoredRules()
	if len(ignored) != 1 || ignored[0].Rule != "invalid_unused" {
		t.Fatalf("GetIgnoredRules() = %+v, want [invalid_unused]", ignored)
	}
	s := prog.NewScanner()
	defer s.Close()
	res, err := s.Scan([]byte("ok"))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(res.MatchedRules) != 1 || res.MatchedRules[0].Rule != "valid_rule" {
		t.Fatalf("MatchedRules = %+v, want [valid_rule]", res.MatchedRules)
	}
}
