package integration

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/compiler"
)

func TestLibyaraOfExpressionQuantifierDifferential(t *testing.T) {
	bin := libyaraOracle(t)

	for _, tc := range []struct {
		name      string
		source    string
		data      []byte
		wantErr   string
		wantMatch bool
	}{
		{
			name:      "parenthesized-literal-of-them",
			source:    `rule q { strings: $a = "abc" condition: (1) of them }`,
			data:      []byte("abc"),
			wantMatch: true,
		},
		{
			name:      "parenthesized-arithmetic-of-them",
			source:    `rule q { strings: $a = "abc" $b = "def" condition: (1+1) of them }`,
			data:      []byte("abcdef"),
			wantMatch: true,
		},
		{
			name:      "unparenthesized-arithmetic-of-them",
			source:    `rule q { strings: $a = "abc" $b = "def" condition: 1+1 of them }`,
			data:      []byte("abcdef"),
			wantMatch: true,
		},
		{
			name:      "string-count-of-them",
			source:    `rule q { strings: $a = "aa" $b = "xx" $c = "yy" condition: #a of ($b, $c) }`,
			data:      []byte("aaxx"),
			wantMatch: true,
		},
		{
			name:      "string-count-of-them-shortfall",
			source:    `rule q { strings: $a = "aa" $b = "xx" $c = "yy" condition: #a of ($b, $c) }`,
			data:      []byte("aaaaaxx"),
			wantMatch: false,
		},
		{
			name:      "filesize-of-them-match",
			source:    `rule q { strings: $a = "a" $b = "b" condition: filesize of them }`,
			data:      []byte("ab"),
			wantMatch: true,
		},
		{
			name:      "filesize-of-them-nomatch",
			source:    `rule q { strings: $a = "a" $b = "b" condition: filesize of them }`,
			data:      []byte("abc"),
			wantMatch: false,
		},
		{
			name:      "uint8-zero-of-them-match",
			source:    `rule q { strings: $a = "abc" condition: uint8(0) of them }`,
			data:      []byte("\x00zzz"),
			wantMatch: true,
		},
		{
			name:      "uint8-zero-of-them-nomatch",
			source:    `rule q { strings: $a = "abc" condition: uint8(0) of them }`,
			data:      []byte("\x00abc"),
			wantMatch: false,
		},
		{
			name:      "uint8-undefined-of-them-all-match",
			source:    `rule q { strings: $a = "abc" $b = "def" condition: uint8(255) of them }`,
			data:      []byte("abcdef"),
			wantMatch: true,
		},
		{
			name:      "uint8-undefined-of-them-partial-nomatch",
			source:    `rule q { strings: $a = "abc" $b = "def" condition: uint8(255) of them }`,
			data:      []byte("abczzz"),
			wantMatch: false,
		},
		{
			name:      "uint8-undefined-of-them-zero-nomatch",
			source:    `rule q { strings: $a = "abc" $b = "def" condition: uint8(255) of them }`,
			data:      []byte("zzz"),
			wantMatch: false,
		},
		{
			name:      "uint8-undefined-of-them-in-range-match",
			source:    `rule q { strings: $a = "abc" $b = "def" condition: uint8(255) of them in (0..6) }`,
			data:      []byte("abcdef"),
			wantMatch: true,
		},
		{
			name:      "uint8-undefined-of-them-in-range-partial-nomatch",
			source:    `rule q { strings: $a = "abc" $b = "def" condition: uint8(255) of them in (0..5) }`,
			data:      []byte("abczzzdef"),
			wantMatch: false,
		},
		{
			name:      "defined-uint8-undefined-of-them",
			source:    `rule q { strings: $a = "abc" condition: defined(uint8(255) of them) }`,
			data:      []byte("zzz"),
			wantMatch: true,
		},
		{
			name:      "runtime-negative-of-them-match",
			source:    `rule q { strings: $a = "abc" condition: (uint8(0) - 5) of them }`,
			data:      []byte("\x00zzz"),
			wantMatch: true,
		},
		{
			name:    "negative-literal-of-them",
			source:  `rule q { strings: $a = "abc" condition: -1 of them }`,
			data:    []byte("abc"),
			wantErr: `invalid value in condition: "-1"`,
		},
		{
			name:    "negative-folded-of-them",
			source:  `rule q { strings: $a = "abc" condition: (1-2) of them }`,
			data:    []byte("abc"),
			wantErr: `invalid value in condition: "-1"`,
		},
		{
			name:    "negative-for-literal-quantifier",
			source:  `rule q { condition: for -1 i in (1..3) : (i == 2) }`,
			data:    []byte("abc"),
			wantErr: `invalid value in condition: "-1"`,
		},
		{
			name:    "negative-for-folded-of-quantifier",
			source:  `rule q { strings: $a = "abc" condition: for (1-2) of them : ($) }`,
			data:    []byte("abc"),
			wantErr: `invalid value in condition: "-1"`,
		},
		{
			name:      "for-parenthesized-expr-of-them",
			source:    `rule q { strings: $a = "abc" $b = "def" condition: for (1+1) of them : ($) }`,
			data:      []byte("abcdef"),
			wantMatch: true,
		},
		{
			name:      "for-unparenthesized-expr-of-them",
			source:    `rule q { strings: $a = "abc" $b = "def" condition: for 1+1 of them : ($) }`,
			data:      []byte("abcdef"),
			wantMatch: true,
		},
		{
			name:      "for-string-count-of-them",
			source:    `rule q { strings: $a = "x" $b = "bb" $c = "cc" condition: for #a of ($b, $c) : ($) }`,
			data:      []byte("xxbbcc"),
			wantMatch: true,
		},
		{
			name:      "for-string-count-of-them-shortfall",
			source:    `rule q { strings: $a = "x" $b = "bb" $c = "cc" condition: for #a of ($b, $c) : ($) }`,
			data:      []byte("xxxbbcc"),
			wantMatch: false,
		},
		{
			name:      "for-parenthesized-int-range",
			source:    `rule q { condition: for (1) i in (1..3) : (i == 2) }`,
			data:      []byte("x"),
			wantMatch: true,
		},
		{
			name:      "for-undefined-quantifier-of-them-all-match",
			source:    `rule q { strings: $a = "abc" $b = "def" condition: for uint8(255) of them : ($) }`,
			data:      []byte("abcdef"),
			wantMatch: true,
		},
		{
			name:      "for-undefined-quantifier-of-them-partial-nomatch",
			source:    `rule q { strings: $a = "abc" $b = "def" condition: for uint8(255) of them : ($) }`,
			data:      []byte("abczzz"),
			wantMatch: false,
		},
		{
			name:      "for-undefined-quantifier-int-range-all-match",
			source:    `rule q { condition: for uint8(255) i in (1..3) : (i >= 1) }`,
			data:      []byte("x"),
			wantMatch: true,
		},
		{
			name:      "for-undefined-quantifier-int-range-partial-nomatch",
			source:    `rule q { condition: for uint8(255) i in (1..3) : (i == 2) }`,
			data:      []byte("x"),
			wantMatch: false,
		},
		{
			name:      "for-uint8-zero-int-range-empty-nomatch",
			source:    `rule q { condition: for uint8(0) i in (uint8(0)+5..1) : (true) }`,
			data:      []byte("\x00"),
			wantMatch: false,
		},
		{
			name:      "for-runtime-negative-int-range-empty-nomatch",
			source:    `rule q { condition: for (uint8(0) - 5) i in (uint8(0)+5..1) : (true) }`,
			data:      []byte("\x00"),
			wantMatch: false,
		},
		{
			name:      "for-uint8-zero-int-range-zero-matches-true",
			source:    `rule q { condition: for uint8(0) i in (1..3) : (i > 10) }`,
			data:      []byte("\x00"),
			wantMatch: true,
		},
		{
			name:      "for-uint8-zero-int-range-one-match-false",
			source:    `rule q { condition: for uint8(0) i in (1..3) : (i == 2) }`,
			data:      []byte("\x00"),
			wantMatch: false,
		},
		{
			name:      "not-uint8-zero-of-them",
			source:    `rule q { strings: $a = "abc" condition: not uint8(0) of them }`,
			data:      []byte("\x00abc"),
			wantMatch: true,
		},
		{
			name:    "undefined-identifier-of-them",
			source:  `rule q { strings: $a = "abc" condition: abc of them }`,
			data:    []byte("abc"),
			wantErr: "undefined identifier",
		},
		{
			name:    "boolean-literal-of-them",
			source:  `rule q { strings: $a = "abc" condition: true of them }`,
			data:    []byte("abc"),
			wantErr: "unexpected",
		},
		{
			name:    "comparison-of-them",
			source:  `rule q { strings: $a = "abc" condition: (1 == 1) of them }`,
			data:    []byte("abc"),
			wantErr: "unexpected",
		},
		{
			name:    "in-range-before-of-them",
			source:  `rule q { strings: $a = "abc" condition: 1 in (1..3) of them }`,
			data:    []byte("abc"),
			wantErr: "unexpected",
		},
		{
			name:    "string-literal-of-them",
			source:  `rule q { strings: $a = "abc" condition: "foo" of them }`,
			data:    []byte("abc"),
			wantErr: "quantifier expression must evaluate to an integer",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oracle, oracleErr := scanWithLibyara(t, bin, tc.source, tc.data)
			prog, goErr := compiler.NewCompiler().CompileSourceWithContext(context.Background(), tc.source)

			if tc.wantErr != "" {
				if oracleErr == nil {
					t.Fatalf("expected libyara compile error, got matched=%v", oracle)
				}
				if goErr == nil {
					t.Fatalf("expected go-yara compile error matching %q, got nil", tc.wantErr)
				}
				if !strings.Contains(goErr.Error(), tc.wantErr) {
					t.Fatalf("go-yara compile err = %q, want substring %q", goErr.Error(), tc.wantErr)
				}
				return
			}

			if oracleErr != nil {
				t.Fatalf("libyara compile err=%v", oracleErr)
			}
			if goErr != nil {
				t.Fatalf("go-yara compile err=%v", goErr)
			}

			s := prog.NewScanner()
			defer s.Close()
			res, err := s.Scan(tc.data)
			if err != nil {
				t.Fatalf("go-yara scan err=%v", err)
			}
			gotMatch := len(res.MatchedRules) == 1 && res.MatchedRules[0].Rule == "q"
			_, oracleMatch := oracle["q"]
			if oracleMatch != tc.wantMatch || gotMatch != oracleMatch {
				t.Fatalf("match mismatch: got=%v libyara=%v want=%v", gotMatch, oracleMatch, tc.wantMatch)
			}

			// Verify serialization round-trip and ScanReader fidelity.
			blob, err := prog.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary err=%v", err)
			}
			roundTrip, err := compiler.UnmarshalCompiledProgram(blob)
			if err != nil {
				t.Fatalf("UnmarshalCompiledProgram err=%v", err)
			}
			rs := roundTrip.NewScanner()
			defer rs.Close()
			rres, err := rs.ScanReader(bytes.NewReader(tc.data))
			if err != nil {
				t.Fatalf("ScanReader err=%v", err)
			}
			gotRoundTrip := len(rres.MatchedRules) == 1 && rres.MatchedRules[0].Rule == "q"
			if gotRoundTrip != oracleMatch {
				t.Fatalf("round-trip ScanReader mismatch: got=%v libyara=%v", gotRoundTrip, oracleMatch)
			}
		})
	}
}
