package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/compiler"
)

func TestLibyaraRegexMixedGreedinessDifferential(t *testing.T) {
	bin := libyaraOracle(t)

	for _, tc := range []struct {
		name       string
		source     string
		data       []byte
		wantReject bool
	}{
		// Rejected mixed patterns
		{name: "plus-then-qmark-lazy", source: `rule r { strings: $a = /a+b??/ condition: $a }`, data: []byte("ab"), wantReject: true},
		{name: "star-then-qmark-lazy", source: `rule r { strings: $a = /a*b??/ condition: $a }`, data: []byte("ab"), wantReject: true},
		{name: "qmark-lazy-then-plus", source: `rule r { strings: $a = /a??b+/ condition: $a }`, data: []byte("ab"), wantReject: true},
		{name: "plus-lazy-then-plus", source: `rule r { strings: $a = /a+?b+/ condition: $a }`, data: []byte("ab"), wantReject: true},
		{name: "star-then-mid-qmark-lazy", source: `rule r { strings: $a = /ab*c??d/ condition: $a }`, data: []byte("abd"), wantReject: true},
		{name: "lazy-plus-then-exact-range", source: `rule r { strings: $a = /a+?b{2}/ condition: $a }`, data: []byte("abb"), wantReject: true},
		{name: "lazy-plus-then-bounded-range", source: `rule r { strings: $a = /a+?b{2,3}/ condition: $a }`, data: []byte("abb"), wantReject: true},
		{name: "greedy-plus-then-lazy-range", source: `rule r { strings: $a = /a+b{2,3}?/ condition: $a }`, data: []byte("abb"), wantReject: true},
		{name: "bounded-range-then-lazy-plus", source: `rule r { strings: $a = /a{1,2}b+?/ condition: $a }`, data: []byte("aab"), wantReject: true},
		{name: "greedy-inside-lazy-group", source: `rule r { strings: $a = /(a+b)??/ condition: $a }`, data: []byte("ab"), wantReject: true},
		{name: "lazy-inside-greedy-group", source: `rule r { strings: $a = /(a|b+?)+/ condition: $a }`, data: []byte("ab"), wantReject: true},
		{name: "escaped-qmark-greedy-then-lazy", source: `rule r { strings: $a = /\??a+?/ condition: $a }`, data: []byte("?a"), wantReject: true},
		{name: "mixed-with-inline-flags", source: `rule r { strings: $a = /a+b??/i wide nocase condition: $a }`, data: []byte("AB"), wantReject: true},
		{name: "unbounded-mixed-ranges", source: `rule r { strings: $a = /a{1,}?b{1,2}/ condition: $a }`, data: []byte("ab"), wantReject: true},

		// Accepted homogeneous patterns and condition `matches`
		{name: "all-lazy-plus", source: `rule r { strings: $a = /a+?/ condition: $a }`, data: []byte("ab")},
		{name: "all-lazy-star", source: `rule r { strings: $a = /a*?/ condition: $a }`, data: []byte("ab")},
		{name: "all-lazy-qmark", source: `rule r { strings: $a = /ab??/ condition: $a }`, data: []byte("ab")},
		{name: "all-lazy-range", source: `rule r { strings: $a = /a{1,2}?/ condition: $a }`, data: []byte("ab")},
		{name: "all-lazy-multi", source: `rule r { strings: $a = /a+?b*?c??d{1,2}?/ condition: $a }`, data: []byte("ad")},
		{name: "all-lazy-exact-range", source: `rule r { strings: $a = /a+?b{2}?/ condition: $a }`, data: []byte("abb")},
		{name: "all-greedy", source: `rule r { strings: $a = /[a-c]*d?/ condition: $a }`, data: []byte("ab")},
		{name: "all-lazy-group", source: `rule r { strings: $a = /(a|b)+?/ condition: $a }`, data: []byte("ab")},
		{name: "literal-curly-braces-with-lazy", source: `rule r { strings: $a = /a+?x\{foo\}/ condition: $a }`, data: []byte("ax{foo}")},
		{name: "condition-matches-operator", source: `rule r { condition: "ab" matches /a+b??/ }`, data: []byte("ab")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oracle, oracleErr := scanWithLibyara(t, bin, tc.source, tc.data)
			prog, goErr := compiler.NewCompiler().CompileSourceWithContext(context.Background(), tc.source)

			if tc.wantReject {
				if oracleErr == nil {
					t.Fatalf("libyara unexpectedly accepted %q", tc.source)
				}
				if goErr == nil {
					t.Fatalf("go-yara unexpectedly accepted %q", tc.source)
				}
				if !strings.Contains(goErr.Error(), "greedy and ungreedy quantifiers can't be mixed in a regular expression") {
					t.Fatalf("go-yara error = %q, want libyara message", goErr.Error())
				}
				return
			}

			if oracleErr != nil {
				t.Fatalf("libyara rejected %q: %v", tc.source, oracleErr)
			}
			if goErr != nil {
				t.Fatalf("go-yara rejected %q: %v", tc.source, goErr)
			}
			s := prog.NewScanner()
			defer s.Close()
			res, err := s.Scan(tc.data)
			if err != nil {
				t.Fatalf("scan err=%v", err)
			}
			gotMatch := len(res.MatchedRules) == 1 && res.MatchedRules[0].Rule == "r"
			_, oracleMatch := oracle["r"]
			if gotMatch != oracleMatch {
				t.Fatalf("match mismatch for %s: go=%v libyara=%v", tc.name, gotMatch, oracleMatch)
			}
		})
	}
}
