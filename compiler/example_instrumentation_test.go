package compiler_test

import (
	"fmt"

	"github.com/cawalch/go-yara/compiler"
)

func ExampleScanHooks_OnPatternProfile() {
	program, err := compiler.NewCompiler().CompileSource(`
rule token { strings: $a="marker" fullword condition:$a }`)
	if err != nil {
		panic(err)
	}
	var metrics compiler.ScanTelemetry
	scanner := compiler.NewScanner(program,
		compiler.WithTelemetryLatency(&metrics),
		compiler.WithHooks(compiler.ScanHooks{
			OnPatternProfile: func(profile compiler.PatternProfile) {
				fmt.Printf("%s/%s: candidates=%d known=%t occurrences=%d\n",
					profile.RuleName, profile.StringID, profile.CandidateHits,
					profile.CandidateHitsKnown, profile.VerifiedMatches)
			},
		}),
	)
	defer scanner.Close()
	if _, err := scanner.Scan([]byte("xmarker marker")); err != nil {
		panic(err)
	}
	fmt.Printf("scans=%d matched rules=%d\n", metrics.TotalScans, metrics.TotalMatches)
	// Export timing fields here. Durations vary by workload and machine.
	// Output:
	// token/$a: candidates=2 known=true occurrences=1
	// scans=1 matched rules=1
}
