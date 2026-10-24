package compiler

import (
	"bytes"
	"testing"
)

func TestRegexReversePrefixPruning(t *testing.T) {
	ruleSource := `
rule test_pruning {
    strings:
        $re1 = /[0-9]{2,10}_needle/
        $re2 = /foo_bar_target/
        $re3 = /[a-z]{3,6}_suffix/ wide
        $re4 = /header[0-9]{2,4}_token/ nocase
    condition:
        any of them
}`
	compiler := NewCompiler()
	prog, err := compiler.CompileSource(ruleSource)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}

	p1 := prog.Rules[0].RegexPatterns["$re1"]
	if !p1.hasPrecedingByteSet || !p1.hasPrefixRepeat {
		t.Fatalf("$re1 reverse prefix not populated: %+v", p1)
	}
	if p1.prefixRepeatMin != 2 || p1.prefixRepeatMax != 10 {
		t.Fatalf("$re1 prefix repeat bounds = [%d, %d], want [2, 10]", p1.prefixRepeatMin, p1.prefixRepeatMax)
	}
	if !p1.prefixRepeatClass.Contains('5') || p1.prefixRepeatClass.Contains('x') {
		t.Fatalf("$re1 prefixRepeatClass mismatch")
	}

	p2 := prog.Rules[0].RegexPatterns["$re2"]
	if !p2.hasPrecedingByteSet || len(p2.exactPrefixSuffix) == 0 {
		t.Fatalf("$re2 exactPrefixSuffix = %q, want non-empty", string(p2.exactPrefixSuffix))
	}
	if !p2.hasFirstByteSet || !p2.firstByteSet.Contains('f') || p2.firstByteSet.Contains('x') {
		t.Fatalf("$re2 firstByteSet mismatch")
	}

	p3 := prog.Rules[0].RegexPatterns["$re3"]
	if !p3.hasPrecedingByteSet || !p3.hasPrefixRepeat {
		t.Fatalf("$re3 wide reverse prefix not populated: %+v", p3)
	}
	if len(p3.wideExactPrefix) != 0 && string(p3.exactPrefixSuffix) != "_" {
		t.Fatalf("$re3 exactPrefixSuffix mismatch")
	}

	p4 := prog.Rules[0].RegexPatterns["$re4"]
	if !p4.hasPrecedingByteSet || !p4.hasFirstByteSet {
		t.Fatalf("$re4 nocase reverse prefix not populated: %+v", p4)
	}
	if !p4.firstByteSet.Contains('h') || !p4.firstByteSet.Contains('H') {
		t.Fatalf("$re4 firstByteSet nocase mismatch")
	}
}

func TestRegexReversePrefixPruningEndToEnd(t *testing.T) {
	ruleSource := `
rule test_scan {
    strings:
        $re1 = /[0-9]{2,10}_needle/
        $re2 = /foo_bar_target/
        $re3 = /[a-z]{3,5}_token/ wide
    condition:
        all of them
}`
	compiler := NewCompiler()
	prog, err := compiler.CompileSource(ruleSource)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}

	scanner := NewScanner(prog)
	defer scanner.Close()

	// Construct test data containing both false positives and valid matches.
	var buf bytes.Buffer
	// False positives for $re1: "xx_needle" (not digits), "1_needle" (only 1 digit, requires >=2)
	buf.WriteString("benign_filler xx_needle 1_needle ")
	// Valid match for $re1: "12345_needle"
	buf.WriteString("98765_needle ")
	// False positives for $re2: "baz_bar_target", "zzz_target"
	buf.WriteString("baz_bar_target zzz_target ")
	// Valid match for $re2: "foo_bar_target"
	buf.WriteString("foo_bar_target ")
	// False positive for $re3 (wide): "12_token" in wide
	for _, b := range []byte("12_token") {
		buf.WriteByte(b)
		buf.WriteByte(0)
	}
	buf.WriteString(" ")
	// Valid match for $re3 (wide): "abc_token" in wide
	for _, b := range []byte("abc_token") {
		buf.WriteByte(b)
		buf.WriteByte(0)
	}

	res, err := scanner.Scan(buf.Bytes())
	if err != nil {
		t.Fatalf("scanner.Scan() error = %v", err)
	}

	if !res.RuleResults["test_scan"] {
		t.Fatalf("rule test_scan did not match: %+v", res.Matches)
	}

	m1 := res.Matches["test_scan"]["$re1"]
	// $re1 matches "98765_needle" at lengths 12, 11, 10, 9; "xx_needle" and "1_needle" are discarded.
	if len(m1) != 4 {
		t.Fatalf("$re1 matches = %d, want 4; matches: %+v", len(m1), m1)
	}
	matchedStr1 := string(buf.Bytes()[m1[0].Offset : m1[0].Offset+int64(m1[0].Length)])
	if matchedStr1 != "98765_needle" {
		t.Fatalf("$re1 matched text = %q, want '98765_needle'", matchedStr1)
	}

	m2 := res.Matches["test_scan"]["$re2"]
	if len(m2) != 1 {
		t.Fatalf("$re2 matches = %d, want 1; matches: %+v", len(m2), m2)
	}
	matchedStr2 := string(buf.Bytes()[m2[0].Offset : m2[0].Offset+int64(m2[0].Length)])
	if matchedStr2 != "foo_bar_target" {
		t.Fatalf("$re2 matched text = %q, want 'foo_bar_target'", matchedStr2)
	}

	m3 := res.Matches["test_scan"]["$re3"]
	if len(m3) != 1 {
		t.Fatalf("$re3 matches = %d, want 1; matches: %+v", len(m3), m3)
	}
}
