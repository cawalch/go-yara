package compiler

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestHexJumpRangeValidation(t *testing.T) {
	invalid := []struct {
		name    string
		pattern string
		wantErr string
	}{
		{name: "max_above_int32", pattern: `{ 61 [0-2147483648] 62 }`, wantErr: "jump length too large"},
		{name: "single_above_int32", pattern: `{ 61 [2147483648] 62 }`, wantErr: "jump length too large"},
		{name: "single_uint32_overflow", pattern: `{ 61 [4294967296] 62 }`, wantErr: "jump length too large"},
		{name: "unbounded_min_above_int32", pattern: `{ 61 [2147483648-] 62 }`, wantErr: "jump length too large"},
		{name: "reversed_range", pattern: `{ 61 [10-9] 62 }`, wantErr: "invalid jump range"},
		{name: "negative_min", pattern: `{ 61 [-1] 62 }`, wantErr: "invalid jump"},
		{name: "negative_max", pattern: `{ 61 [1--5] 62 }`, wantErr: "invalid jump range"},
	}

	sc := newStringCompiler()
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := sc.parseHexPattern(tc.pattern); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("parseHexPattern(%s) error = %v, want substring %q", tc.pattern, err, tc.wantErr)
			}
			src := "rule t { strings: $a = " + tc.pattern + " condition: $a }"
			if _, err := NewCompiler().CompileSource(src); err == nil {
				t.Fatalf("CompileSource(%s) unexpectedly succeeded", src)
			}
		})
	}

	valid := []string{
		`{ 61 [0-0] 62 }`,
		`{ 61 [0-2147483647] 62 }`,
		`{ 61 [2147483647-] 62 }`,
		`{ 61 [-] 62 }`,
	}
	for _, pat := range valid {
		if _, err := sc.parseHexPattern(pat); err != nil {
			t.Fatalf("parseHexPattern(%s) error = %v", pat, err)
		}
	}
}

func TestHexJumpNonMatchingLargeRangePerformance(t *testing.T) {
	noMatchBuf := bytes.Repeat([]byte{'A'}, 16384)
	matchAtEndBuf := append(bytes.Repeat([]byte{'A'}, 16384), 'C')

	cases := []struct {
		name      string
		pattern   string
		data      []byte
		wantCount int
	}{
		{name: "max_int32_no_match", pattern: `{ 41 [0-2147483647] 43 }`, data: noMatchBuf, wantCount: 0},
		{name: "wildcard_then_missing_no_match", pattern: `{ 41 [0-2147483647] ?? 43 }`, data: noMatchBuf, wantCount: 0},
		{name: "repeated_prefix_then_missing_no_match", pattern: `{ 41 [0-2147483647] 41 43 }`, data: noMatchBuf, wantCount: 0},
		{name: "unbounded_no_match", pattern: `{ 41 [-] 43 }`, data: noMatchBuf, wantCount: 0},
		{name: "max_int32_match_at_end", pattern: `{ 41 [0-2147483647] 43 }`, data: matchAtEndBuf, wantCount: 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := "rule h { strings: $a = " + tc.pattern + " condition: any of them }"
			prog, err := NewCompiler().CompileSource(src)
			if err != nil {
				t.Fatalf("CompileSource() error = %v", err)
			}
			start := time.Now()
			res, err := prog.Scan(tc.data)
			elapsed := time.Since(start)
			if err != nil {
				t.Fatalf("Scan() error = %v", err)
			}
			if len(res.MatchedRules) != tc.wantCount {
				t.Fatalf("MatchedRules = %d, want %d", len(res.MatchedRules), tc.wantCount)
			}
			if elapsed > 250*time.Millisecond {
				t.Fatalf("Scan(%s) took %v, expected sub-250ms", tc.pattern, elapsed)
			}
		})
	}
}

func TestHexJumpMultipleOccurrencesCacheCorrectness(t *testing.T) {
	cases := []struct {
		name      string
		pattern   string
		data      string
		wantCount int
	}{
		{name: "abca_xx_c", pattern: `{ 41 [-] 43 }`, data: "ABCAXXC", wantCount: 2},
		{name: "acac", pattern: `{ 41 [-] 43 }`, data: "ACAC", wantCount: 2},
		{name: "accc", pattern: `{ 41 [1-3] 43 }`, data: "ACCC", wantCount: 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := "rule h { strings: $a = " + tc.pattern + " condition: $a }"
			prog, err := NewCompiler().CompileSource(src)
			if err != nil {
				t.Fatalf("CompileSource() error = %v", err)
			}
			res, err := prog.Scan([]byte(tc.data))
			if err != nil {
				t.Fatalf("Scan() error = %v", err)
			}
			if len(res.MatchedRules) != 1 {
				t.Fatalf("MatchedRules = %d, want 1", len(res.MatchedRules))
			}
			if got := len(res.MatchedRules[0].Matches["$a"]); got != tc.wantCount {
				t.Fatalf("match count = %d (%v), want %d", got, res.MatchedRules[0].Matches["$a"], tc.wantCount)
			}
		})
	}
}
