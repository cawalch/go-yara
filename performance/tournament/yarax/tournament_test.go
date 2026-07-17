package yarax

import (
	"fmt"
	"testing"

	yara_x "github.com/VirusTotal/yara-x/go"
	"github.com/cawalch/go-yara/performance/tournament/matrix"
)

var yaraXResultSink *yara_x.ScanResults

func BenchmarkTournament(b *testing.B) {
	for _, ruleCase := range matrix.Rules() {
		rules, err := yara_x.Compile(ruleCase.Source)
		if err != nil {
			b.Fatalf("compile %s: %v", ruleCase.Name, err)
		}
		scanner := yara_x.NewScanner(rules)
		b.Run(ruleCase.Name, func(b *testing.B) {
			benchmarkRule(b, scanner)
		})
		scanner.Destroy()
		rules.Destroy()
	}
}

func benchmarkRule(b *testing.B, scanner *yara_x.Scanner) {
	for _, content := range matrix.Contents {
		b.Run(content.Name, func(b *testing.B) {
			for _, size := range matrix.Sizes {
				b.Run(fmt.Sprintf("%dKiB", size>>10), func(b *testing.B) {
					data := matrix.Data(content, size)
					result, err := scanner.Scan(data)
					if err != nil {
						b.Fatal(err)
					}
					matchedRules := len(result.MatchingRules())
					matchedNames := make([]string, len(result.MatchingRules()))
					for index, matched := range result.MatchingRules() {
						matchedNames[index] = matched.Identifier()
					}
					matchFingerprint := matrix.MatchFingerprint(matchedNames)

					b.SetBytes(int64(len(data)))
					b.ReportAllocs()
					b.ResetTimer()
					for b.Loop() {
						yaraXResultSink, err = scanner.Scan(data)
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
