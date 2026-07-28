package compiler

import (
	"fmt"
	"strings"
	"testing"
)

// BenchmarkACScanLargeInput guards the per-byte scan cost, which is the whole
// cost on large inputs: on a 16KB event the scan was 99% of Matches(). Existing
// scanner benchmarks use small inputs, where per-event fixed cost hides this.
//
// Every string starts with a different byte on purpose. A credential ruleset has
// a wide root — ghp_, gho_, AKIA, password, github_pat_ and so on — which puts
// the scan on the general Aho-Corasick path. Give all the strings a common first
// byte instead and the root collapses to <= maxSparseRootTransitions, the sparse
// root SIMD skip takes over, findNextState is barely reached, and this benchmark
// stops measuring the per-byte transition cost at all.
func BenchmarkACScanLargeInput(b *testing.B) {
	const leadBytes = "abcdefghijklmnopqrstuvwx"
	var sb strings.Builder
	for r := range 12 {
		fmt.Fprintf(&sb, "rule scan_rule_%d {\n    strings:\n", r)
		for s := range 6 {
			lead := leadBytes[(r*6+s)%len(leadBytes)]
			if s%2 == 0 {
				fmt.Fprintf(&sb, "        $t%d = \"%ctok_%d_%d_\"\n", s, lead, r, s)
			} else {
				fmt.Fprintf(&sb, "        $r%d = /%ctok_%d_%d_[A-Za-z0-9]{12}/\n", s, lead, r, s)
			}
		}
		sb.WriteString("    condition:\n        any of them\n}\n\n")
	}
	program, err := NewCompiler().CompileSource(sb.String())
	if err != nil {
		b.Fatalf("CompileSource() error = %v", err)
	}

	base := `{"ts":"2026-07-28T10:00:00Z","level":"info","svc":"checkout","msg":"request completed","status":200}`
	for _, size := range []int{1024, 8192, 16384, 51200} {
		filler := strings.Repeat("abcdefghij0123456789 msg=payload ", size/33+2)
		data := []byte(base[:len(base)-1] + fmt.Sprintf(`,"detail":"%s"}`, filler[:max(0, size-len(base))]))
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			benchmarkScannerMatches(b, program, data)
		})
	}
}

// BenchmarkACCompileClose covers the compile-time cost of closing the goto
// table, which is O(states x 256). It runs once per program, off the scan path,
// but should stay small as the ruleset grows.
func BenchmarkACCompileClose(b *testing.B) {
	for _, rules := range []int{12, 64} {
		var sb strings.Builder
		for r := range rules {
			fmt.Fprintf(&sb, "rule c_rule_%d {\n    strings:\n", r)
			for s := range 12 {
				fmt.Fprintf(&sb, "        $t%d = \"literal_token_%d_%d_\"\n", s, r, s)
			}
			sb.WriteString("    condition:\n        any of them\n}\n\n")
		}
		source := sb.String()
		b.Run(fmt.Sprintf("rules=%d", rules), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := NewCompiler().CompileSource(source); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
