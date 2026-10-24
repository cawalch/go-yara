package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/cawalch/go-yara/compiler"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	program, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), `
rule marker { strings: $a = "marker" condition: $a }
rule other { strings: $a = "other" condition: $a }`)
	if err != nil {
		return err
	}
	var metrics compiler.ScanTelemetry
	starts, completions, matches, profiles := 0, 0, 0, 0
	completionSeesFinal := false
	scanner := compiler.NewScanner(program,
		compiler.WithTelemetryLatency(&metrics),
		compiler.WithHooks(compiler.ScanHooks{
			OnScanStart: func(context.Context, int64) { starts++ },
			OnScanComplete: func(context.Context, *compiler.ScanResult, time.Duration) {
				completions++
				completionSeesFinal = metrics.TotalScans == 2 && metrics.TotalMatches == 1 && metrics.TotalScanDurationNs > 0
			},
			OnPatternProfile: func(p compiler.PatternProfile) {
				if p.RuleName == "marker" {
					fmt.Printf("%s/%s: candidates=%d known=%t occurrences=%d\n",
						p.RuleName, p.StringID, p.CandidateHits, p.CandidateHitsKnown, p.VerifiedMatches)
				}
			},
			OnRuleEvaluated: func(compiler.RuleProfile) { profiles++ },
			OnMatch: func(*compiler.CompiledRule, compiler.RuleMatch) compiler.MatchAction {
				matches++
				return compiler.MatchActionContinue
			},
		}),
	)
	defer scanner.Close()
	for _, input := range []string{"clean", "marker marker"} {
		if _, err := scanner.Scan([]byte(input)); err != nil {
			return err
		}
	}
	// Read or export the sink after Scan returns. Keep one sink per scanner.
	fmt.Printf("scans=%d bytes=%d matched rules=%d\n", metrics.TotalScans, metrics.BytesScanned, metrics.TotalMatches)
	fmt.Printf("starts=%d completions=%d match callbacks=%d\n", starts, completions, matches)
	fmt.Printf("rule profiles received: %t\n", profiles > 0)
	fmt.Printf("completion sees final metrics: %t\n", completionSeesFinal)
	// Export TotalScanDurationNs, PrefilterDurationNs, PatternSearchNs, and
	// ConditionEvalNs here. Exact timings vary by workload and machine.
	metrics.Reset()
	fmt.Printf("after reset: scans=%d bytes=%d matched rules=%d\n", metrics.TotalScans, metrics.BytesScanned, metrics.TotalMatches)
	return nil
}
