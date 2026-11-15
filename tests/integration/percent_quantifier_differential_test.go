package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/compiler"
)

func TestLibyaraPercentQuantifierDifferential(t *testing.T) {
	bin := libyaraOracle(t)

	for _, tc := range []struct {
		name      string
		source    string
		data      []byte
		wantErr   string
		wantMatch bool
	}{
		{
			name:    "zero-percent-literal",
			source:  `rule q { strings: $a = "abc" condition: 0% of them }`,
			data:    []byte("abc"),
			wantErr: "percentage must be between 1 and 100 (inclusive)",
		},
		{
			name:    "over-hundred-percent-literal",
			source:  `rule q { strings: $a = "abc" condition: 101% of them }`,
			data:    []byte("abc"),
			wantErr: "percentage must be between 1 and 100 (inclusive)",
		},
		{
			name:    "negative-percent-literal",
			source:  `rule q { strings: $a = "abc" condition: -1% of them }`,
			data:    []byte("abc"),
			wantErr: "percentage must be between 1 and 100 (inclusive)",
		},
		{
			name:    "zero-percent-folded",
			source:  `rule q { strings: $a = "abc" condition: (1-1)% of them }`,
			data:    []byte("abc"),
			wantErr: "percentage must be between 1 and 100 (inclusive)",
		},
		{
			name:    "over-hundred-percent-folded",
			source:  `rule q { strings: $a = "abc" condition: (100+1)% of them }`,
			data:    []byte("abc"),
			wantErr: "percentage must be between 1 and 100 (inclusive)",
		},
		{
			name:    "zero-percent-in-range",
			source:  `rule q { strings: $a = "abc" condition: 0% of ($a) in (0..3) }`,
			data:    []byte("abc"),
			wantErr: "percentage must be between 1 and 100 (inclusive)",
		},
		{
			name:    "zero-percent-at-offset",
			source:  `rule q { strings: $a = "abc" condition: 0% of them at 0 }`,
			data:    []byte("abc"),
			wantErr: "percentage must be between 1 and 100 (inclusive)",
		},
		{
			name:    "for-zero-percent-rejected",
			source:  `rule q { strings: $a = "abc" condition: for 0% of them : ($) }`,
			data:    []byte("abc"),
			wantErr: "expected 'of'",
		},
		{
			name:      "one-percent-match",
			source:    `rule q { strings: $a = "abc" $b = "xyz" condition: 1% of them }`,
			data:      []byte("abc"),
			wantMatch: true,
		},
		{
			name:      "hundred-percent-match",
			source:    `rule q { strings: $a = "abc" condition: 100% of them }`,
			data:      []byte("abc"),
			wantMatch: true,
		},
		{
			name:      "computed-folded-fifty-percent",
			source:    `rule q { strings: $a = "abc" $b = "xyz" condition: (25+25)% of them }`,
			data:      []byte("abc"),
			wantMatch: true,
		},
		{
			name:      "runtime-uint8-zero-percent-with-match",
			source:    `rule q { strings: $a = "abc" condition: uint8(0)% of them }`,
			data:      []byte("\x00abc"),
			wantMatch: true,
		},
		{
			name:      "runtime-uint8-zero-percent-without-match",
			source:    `rule q { strings: $a = "abc" condition: uint8(0)% of them }`,
			data:      []byte("\x00zzz"),
			wantMatch: true,
		},
		{
			name:      "runtime-uint8-200-percent-nomatch",
			source:    `rule q { strings: $a = "abc" condition: uint8(0)% of them }`,
			data:      []byte("\xc8abc"),
			wantMatch: false,
		},
		{
			name:      "runtime-uint8-oob-undefined-nomatch",
			source:    `rule q { strings: $a = "abc" condition: uint8(99)% of them }`,
			data:      []byte("abc"),
			wantMatch: false,
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
		})
	}
}
