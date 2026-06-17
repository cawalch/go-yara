package compiler

import (
	"bytes"
	"testing"
)

// TestNocaseTextModifier is an end-to-end regression test for the `nocase`
// string modifier. nocase was previously completely broken: the pattern bytes
// were lowercased but FlagsNoCase was never propagated to the Aho-Corasick
// automaton, so the lowercased pattern could only ever match lowercase data.
// "foobar" nocase failed to match "FOOBAR", "FoObAr", wide variants, etc.
// These cases assert actual runtime match results, not just compile success.
func TestNocaseTextModifier(t *testing.T) {
	source := `
rule NocaseText {
	strings:
		$a = "foobar" nocase
	condition:
		$a
}`

	compiler := NewCompiler()
	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{name: "lowercase", data: []byte("foobar"), want: true},
		{name: "uppercase", data: []byte("FOOBAR"), want: true},
		{name: "mixed_case", data: []byte("FoObAr"), want: true},
		{name: "first_cap", data: []byte("Foobar"), want: true},
		{name: "substring_uppercase", data: []byte("xxFOOxxbar"), want: false}, // "foobar" not contiguous
		{name: "substring_uppercase_contiguous", data: []byte("xxFOOBARxx"), want: true},
		{name: "no_match", data: []byte("totally different"), want: false},
		{name: "empty_data", data: []byte{}, want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := evaluateRule(program.Rules[0], program, tc.data)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if ok != tc.want {
				t.Fatalf("matched=%v, want %v (data=%q)", ok, tc.want, tc.data)
			}
		})
	}
}

// TestNocaseWideModifier covers nocase combined with wide. The XOR of nocase
// must apply to the interleaved zero bytes too (both are byte-wise).
func TestNocaseWideModifier(t *testing.T) {
	source := `
rule NocaseWide {
	strings:
		$a = "foobar" nocase wide
	condition:
		$a
}`
	compiler := NewCompiler()
	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	wide := func(s string) []byte {
		b := make([]byte, len(s)*2)
		for i, c := range []byte(s) {
			b[i*2] = c
			b[i*2+1] = 0
		}
		return b
	}

	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{name: "wide_lowercase", data: wide("foobar"), want: true},
		{name: "wide_uppercase", data: wide("FOOBAR"), want: true},
		{name: "wide_mixed", data: wide("FoObAr"), want: true},
		{name: "ascii_uppercase_not_wide", data: []byte("FOOBAR"), want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := evaluateRule(program.Rules[0], program, tc.data)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if ok != tc.want {
				t.Fatalf("matched=%v, want %v", ok, tc.want)
			}
		})
	}
}

// TestNocaseDoesNotCorruptCaseSensitive is the critical guard for the shared
// Aho-Corasick fix. To make nocase work in the shared automaton, nocase
// strings register both ASCII cases of each letter in the trie. That means a
// case-sensitive string whose output state lies on a nocase string's path
// (e.g. a prefix: case-sensitive "foo" on the path of nocase "foobar") could
// fire on the wrong case. The matcher re-verifies candidates against the
// stored pattern so a case-sensitive string never matches the wrong case.
func TestNocaseDoesNotCorruptCaseSensitive(t *testing.T) {
	// Case-sensitive "foo" is a prefix of nocase "foobar", so "foo"'s output
	// state sits on the nocase dual-transition path. Scanning "FOO" must NOT
	// match the case-sensitive string; scanning "foobar" must match both.
	source := `
rule Mix {
	strings:
		$cs = "foo"
		$nc = "foobar" nocase
	condition:
		any of them
}`
	compiler := NewCompiler()
	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	scanner := NewScanner(program)

	// On "FOO": case-sensitive must NOT match (corruption guard), and nocase
	// "foobar" must not match either (wrong length).
	r, err := scanner.Scan([]byte("FOO"))
	if err != nil {
		t.Fatalf("scan FOO: %v", err)
	}
	if matches, ok := r.Matches["Mix"]["$cs"]; ok {
		t.Errorf("case-sensitive $cs matched uppercase \"FOO\" (corruption from nocase dual transitions): %v", matches)
	}

	// On "foobar": case-sensitive "foo" matches (prefix), nocase "foobar" matches.
	r2, err := scanner.Scan([]byte("foobar"))
	if err != nil {
		t.Fatalf("scan foobar: %v", err)
	}
	if _, ok := r2.Matches["Mix"]["$cs"]; !ok {
		t.Errorf("case-sensitive $cs did not match exact lowercase \"foobar\"")
	}
	if _, ok := r2.Matches["Mix"]["$nc"]; !ok {
		t.Errorf("nocase $nc did not match lowercase \"foobar\"")
	}

	// On "FOOBAR": only nocase matches.
	r3, err := scanner.Scan([]byte("FOOBAR"))
	if err != nil {
		t.Fatalf("scan FOOBAR: %v", err)
	}
	if _, ok := r3.Matches["Mix"]["$cs"]; ok {
		t.Errorf("case-sensitive $cs matched uppercase data")
	}
	if _, ok := r3.Matches["Mix"]["$nc"]; !ok {
		t.Errorf("nocase $nc did not match uppercase \"FOOBAR\"")
	}
}

// TestNocaseXorModifier covers nocase combined with xor. Per the YARA spec,
// xor is applied after every other modifier, so nocase lowercase + xor must
// match any case of the xored bytes.
func TestNocaseXorModifier(t *testing.T) {
	source := `
rule NocaseXor {
	strings:
		$a = "Test" xor nocase
	condition:
		$a
}`
	compiler := NewCompiler()
	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	xorBytes := func(in []byte, key byte) []byte {
		out := make([]byte, len(in))
		for i, b := range in {
			out[i] = b ^ key
		}
		return out
	}

	plain := []byte("Test")
	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{name: "plaintext_lowercase", data: plain, want: true},
		{name: "plaintext_uppercase", data: bytes.ToUpper(plain), want: true},
		{name: "xor0x01_lower", data: xorBytes(plain, 0x01), want: true},
		{name: "xor0x01_upper", data: bytes.ToUpper(xorBytes(plain, 0x01)), want: true},
		{name: "no_match", data: []byte("xxxxxxxx"), want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := evaluateRule(program.Rules[0], program, tc.data)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if ok != tc.want {
				t.Fatalf("matched=%v, want %v (data=%q)", ok, tc.want, tc.data)
			}
		})
	}
}
