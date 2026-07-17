package goyara

import (
	"context"
	"fmt"
	"testing"

	"github.com/cawalch/go-yara/compiler"
	"github.com/cawalch/go-yara/performance/tournament/matrix"
)

var goYaraResultSink *compiler.ScanResult

func BenchmarkTournament(b *testing.B) {
	for _, ruleCase := range matrix.Rules() {
		program, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), ruleCase.Source)
		if err != nil {
			b.Fatalf("compile %s: %v", ruleCase.Name, err)
		}
		scanner := compiler.NewScanner(program)
		b.Run(ruleCase.Name, func(b *testing.B) {
			benchmarkRule(b, scanner)
		})
		scanner.Close()
	}
}

func benchmarkRule(b *testing.B, scanner *compiler.Scanner) {
	for _, content := range matrix.Contents {
		b.Run(content.Name, func(b *testing.B) {
			for _, size := range matrix.Sizes {
				b.Run(fmt.Sprintf("%dKiB", size>>10), func(b *testing.B) {
					data := matrix.Data(content, size)
					result, err := scanner.Scan(data)
					if err != nil {
						b.Fatal(err)
					}
					matchedRules := len(result.MatchedRules)
					matchedNames := make([]string, len(result.MatchedRules))
					for index, matched := range result.MatchedRules {
						matchedNames[index] = matched.Rule
					}
					matchFingerprint := matrix.MatchFingerprint(matchedNames)

					b.SetBytes(int64(len(data)))
					b.ReportAllocs()
					b.ResetTimer()
					for b.Loop() {
						goYaraResultSink, err = scanner.Scan(data)
						if err != nil {
							b.Fatal(err)
						}
					}
					b.ReportMetric(float64(matchedRules), "matched_rules/op")
					b.ReportMetric(float64(matchFingerprint), "match_fingerprint/op")
				})
			}
		})
	}
}
