package compiler

import (
	"bytes"
	"testing"
)

// Keep this harness self-contained: perf_gate.sh also installs it in its
// temporary baseline worktree so both revisions measure identical workloads.
func hexJumpLargeRangeCases() []struct {
	name      string
	pattern   string
	data      []byte
	wantCount int
} {
	noMatch := bytes.Repeat([]byte{'A'}, 16384)
	matchAtEnd := append(bytes.Clone(noMatch), 'C')
	return []struct {
		name      string
		pattern   string
		data      []byte
		wantCount int
	}{
		{"max_int32_no_match", `{ 41 [0-2147483647] 43 }`, noMatch, 0},
		{"wildcard_then_missing_no_match", `{ 41 [0-2147483647] ?? 43 }`, noMatch, 0},
		{"repeated_prefix_then_missing_no_match", `{ 41 [0-2147483647] 41 43 }`, noMatch, 0},
		{"unbounded_no_match", `{ 41 [-] 43 }`, noMatch, 0},
		{"max_int32_match_at_end", `{ 41 [0-2147483647] 43 }`, matchAtEnd, 1},
	}
}

func BenchmarkHexJumpLargeRange(b *testing.B) {
	for _, tc := range hexJumpLargeRangeCases() {
		b.Run(tc.name, func(b *testing.B) {
			prog, err := NewCompiler().CompileSource("rule h { strings: $a = " + tc.pattern + " condition: any of them }")
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(tc.data)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				res, err := prog.Scan(tc.data)
				if err != nil {
					b.Fatal(err)
				}
				if len(res.MatchedRules) != tc.wantCount {
					b.Fatalf("MatchedRules = %d, want %d", len(res.MatchedRules), tc.wantCount)
				}
			}
		})
	}
}
