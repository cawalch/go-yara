package compiler

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// BenchmarkTeddyMultiPatternScaling evaluates multi-pattern search throughput
// across 4, 8, 16, and 32 distinct patterns on clean (absent) 64KB input.
func BenchmarkTeddyMultiPatternScaling(b *testing.B) {
	for _, numPatterns := range []int{4, 8, 16, 32} {
		var sb strings.Builder
		sb.WriteString("rule teddy_scale {\n    strings:\n")
		for i := range numPatterns {
			fmt.Fprintf(&sb, "        $s%d = \"token_prefix_%02d_unique\"\n", i, i)
		}
		sb.WriteString("    condition:\n        any of them\n}")

		program, err := NewCompiler().CompileSource(sb.String())
		if err != nil {
			b.Fatal(err)
		}

		cleanData := bytes.Repeat([]byte("The quick brown fox jumps over the lazy dog. 1234567890 "), 1200)[:65536]

		b.Run(fmt.Sprintf("patterns=%d/clean_64KB", numPatterns), func(b *testing.B) {
			b.SetBytes(int64(len(cleanData)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				matches, err := program.Matches(cleanData)
				if err != nil || matches {
					b.Fatalf("Matches() error=%v, matches=%v", err, matches)
				}
			}
		})
	}
}

// BenchmarkTeddyMultiRuleScanner benchmarks a multi-rule workload (10 rules with 3 patterns each = 30 patterns)
// comparing clean scanning vs tail hit scanning.
func BenchmarkTeddyMultiRuleScanner(b *testing.B) {
	const numRules = 10
	var sb strings.Builder
	for r := range numRules {
		fmt.Fprintf(&sb, `rule detection_rule_%d {
			strings:
				$a = "cmd_exec_%d_marker" nocase
				$b = "powershell_proc_%d_token" nocase
				$c = "service_install_%d_target" nocase
			condition:
				any of them
		}
		`, r, r, r, r)
	}

	program, err := NewCompiler().CompileSource(sb.String())
	if err != nil {
		b.Fatal(err)
	}

	scanner := NewScanner(program)
	defer scanner.Close()

	cleanData := bytes.Repeat([]byte("benign security audit log entry filler payload 0123456789 "), 1200)[:65536]
	hitData := bytes.Clone(cleanData)
	copy(hitData[len(hitData)-35:], "powershell_proc_5_token")

	b.Run("10_rules_30_patterns/clean_64KB", func(b *testing.B) {
		b.SetBytes(int64(len(cleanData)))
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			res, err := scanner.Scan(cleanData)
			if err != nil || len(res.MatchedRules) != 0 {
				b.Fatalf("Scan() err=%v, matches=%v", err, len(res.MatchedRules))
			}
		}
	})

	b.Run("10_rules_30_patterns/hit_tail_64KB", func(b *testing.B) {
		b.SetBytes(int64(len(hitData)))
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			res, err := scanner.Scan(hitData)
			if err != nil || len(res.MatchedRules) != 1 {
				b.Fatalf("Scan() err=%v, matches=%v", err, len(res.MatchedRules))
			}
		}
	})
}
