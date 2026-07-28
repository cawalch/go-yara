package compiler

import (
	"fmt"
	"strings"
	"testing"
)

// buildRejectScaleProgram builds a program with ruleCount rules of stringsPerRule
// strings each, mixing text and regex strings the way a real credential ruleset
// does. Every string is anchored on a distinct literal so the shared automaton
// rejects the benchmark input outright.
func buildRejectScaleProgram(tb testing.TB, ruleCount, stringsPerRule int) *CompiledProgram {
	tb.Helper()
	var sb strings.Builder
	for r := range ruleCount {
		fmt.Fprintf(&sb, "rule scale_rule_%d {\n    strings:\n", r)
		for s := range stringsPerRule {
			if s%2 == 0 {
				fmt.Fprintf(&sb, "        $t%d = \"tok_%d_%d_\"\n", s, r, s)
			} else {
				fmt.Fprintf(&sb, "        $r%d = /tok_%d_%d_[A-Za-z0-9]{12}/\n", s, r, s)
			}
		}
		sb.WriteString("    condition:\n        any of them\n}\n\n")
	}
	program, err := NewCompiler().CompileSource(sb.String())
	if err != nil {
		tb.Fatalf("CompileSource() error = %v", err)
	}
	if len(program.Rules) != ruleCount {
		tb.Fatalf("compiled %d rules, want %d", len(program.Rules), ruleCount)
	}
	return program
}

// BenchmarkPrefilterRejectScale measures the reject path as the ruleset grows.
//
// The reject path walks every evaluated rule and every string in it. The
// per-string kind and cache index are compile-time constants, so this should
// scale with a cheap slice walk; if it ever resolves them per scan through the
// string-keyed StringKinds/RegexPatterns/HexPatterns maps again, the string
// hashing dominates and ns/op climbs far faster than the automaton scan does.
// Single-rule benchmarks cannot see that — the cost is in rules × strings.
func BenchmarkPrefilterRejectScale(b *testing.B) {
	reject := []byte(`{"ts":"2026-07-28T10:00:00Z","level":"info","svc":"checkout","msg":"request completed","route":"/v2/items/1234","status":200,"latency_ms":37}`)

	for _, dims := range []struct {
		rules, strings int
	}{
		{1, 6},
		{8, 6},
		{23, 6},
		{23, 12},
		{64, 12},
	} {
		name := fmt.Sprintf("rules=%d/strings=%d", dims.rules, dims.strings)
		b.Run(name, func(b *testing.B) {
			program := buildRejectScaleProgram(b, dims.rules, dims.strings)
			benchmarkScannerMatches(b, program, reject)
		})
	}
}

// BenchmarkPrefilterRejectScaleParallel guards the same path under concurrency,
// where each scanner walks the shared immutable program.
func BenchmarkPrefilterRejectScaleParallel(b *testing.B) {
	reject := []byte(`{"ts":"2026-07-28T10:00:00Z","level":"info","svc":"checkout","msg":"request completed","status":200}`)
	program := buildRejectScaleProgram(b, 23, 12)

	b.ReportAllocs()
	b.SetBytes(int64(len(reject)))
	b.RunParallel(func(pb *testing.PB) {
		scanner := NewScanner(program)
		defer scanner.Close()
		for pb.Next() {
			if _, err := scanner.Matches(reject); err != nil {
				b.Error(err)
				return
			}
		}
	})
}
