package report_test

import (
	"strings"
	"testing"

	"github.com/cawalch/go-yara/performance/tournament/report"
)

const goYaraOutput = `goos: darwin
goarch: arm64
cpu: Test CPU
BenchmarkTournament/literal/punct_sparse/match_sparse/16KiB-8 10 100 ns/op 200.00 MB/s 0.000 match_fingerprint/op 0.000 matched_rules/op 300 B/op 4 allocs/op
BenchmarkTournament/literal/punct_sparse/match_sparse/16KiB-8 10 100 ns/op 220.00 MB/s 0.000 match_fingerprint/op 0.000 matched_rules/op 320 B/op 5 allocs/op
BenchmarkTournament/literal/punct_sparse/match_sparse/16KiB-8 10 100 ns/op 210.00 MB/s 0.000 match_fingerprint/op 0.000 matched_rules/op 310 B/op 4 allocs/op
`

const yaraXOutput = `goos: darwin
goarch: arm64
cpu: Test CPU
BenchmarkTournament/literal/punct_sparse/match_sparse/16KiB-8 10 100 ns/op 400.00 MB/s 0.000 match_fingerprint/op 0.000 matched_rules/op 30 B/op 1 allocs/op
BenchmarkTournament/literal/punct_sparse/match_sparse/16KiB-8 10 100 ns/op 420.00 MB/s 0.000 match_fingerprint/op 0.000 matched_rules/op 32 B/op 1 allocs/op
BenchmarkTournament/literal/punct_sparse/match_sparse/16KiB-8 10 100 ns/op 410.00 MB/s 0.000 match_fingerprint/op 0.000 matched_rules/op 31 B/op 1 allocs/op
`

func TestParseAndCompareUsesMedianRatios(t *testing.T) {
	goYara, err := report.Parse(strings.NewReader(goYaraOutput))
	if err != nil {
		t.Fatal(err)
	}
	yaraX, err := report.Parse(strings.NewReader(yaraXOutput))
	if err != nil {
		t.Fatal(err)
	}
	comparison, err := report.Compare(goYara, yaraX, report.Policy{
		Baseline: &report.Baseline{
			GOOS:   "darwin",
			GOARCH: "arm64",
			CPU:    "Test CPU",
			Ratios: map[string]float64{
				"literal/punct_sparse/match_sparse/16KiB": 0.75,
			},
		},
		MinRatio:      0.5,
		MaxRegression: 0.2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(comparison.Rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(comparison.Rows))
	}
	row := comparison.Rows[0]
	if row.GoYaraMBPerSec != 210 || row.YaraXMBPerSec != 410 {
		t.Fatalf("medians = %.2f/%.2f, want 210/410", row.GoYaraMBPerSec, row.YaraXMBPerSec)
	}
	if row.Ratio < 0.512 || row.Ratio > 0.513 {
		t.Fatalf("ratio = %.6f, want about 0.512", row.Ratio)
	}
	if len(comparison.Failures) != 1 {
		t.Fatalf("failures = %v, want one baseline regression", comparison.Failures)
	}
}

func TestCompareRejectsSemanticMismatch(t *testing.T) {
	goYara, err := report.Parse(strings.NewReader(strings.ReplaceAll(goYaraOutput,
		"0.000 matched_rules/op", "1.000 matched_rules/op")))
	if err != nil {
		t.Fatal(err)
	}
	yaraX, err := report.Parse(strings.NewReader(yaraXOutput))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := report.Compare(goYara, yaraX, report.Policy{MinRatio: 0.5, MaxRegression: 0.2}); err == nil {
		t.Fatal("Compare accepted mismatched rule results")
	}
}

func TestCompareRejectsMatchingRuleIdentityMismatch(t *testing.T) {
	goYara, err := report.Parse(strings.NewReader(strings.ReplaceAll(goYaraOutput,
		"0.000 match_fingerprint/op", "123.000 match_fingerprint/op")))
	if err != nil {
		t.Fatal(err)
	}
	yaraX, err := report.Parse(strings.NewReader(yaraXOutput))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := report.Compare(goYara, yaraX, report.Policy{MinRatio: 0.5, MaxRegression: 0.2}); err == nil {
		t.Fatal("Compare accepted different matching rule identities")
	}
}

func TestCSVIsReusableAsBaseline(t *testing.T) {
	goYara, _ := report.Parse(strings.NewReader(goYaraOutput))
	yaraX, _ := report.Parse(strings.NewReader(yaraXOutput))
	comparison, err := report.Compare(goYara, yaraX, report.Policy{MinRatio: 0.5, MaxRegression: 0.2})
	if err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	if err := report.WriteCSV(&output, comparison); err != nil {
		t.Fatal(err)
	}
	baseline, err := report.ReadBaseline(strings.NewReader(output.String()))
	if err != nil {
		t.Fatal(err)
	}
	if difference := baseline.Ratios[comparison.Rows[0].Cell] - comparison.Rows[0].Ratio; difference < -0.000001 || difference > 0.000001 {
		t.Fatalf("baseline ratio = %.6f, want %.6f", baseline.Ratios[comparison.Rows[0].Cell], comparison.Rows[0].Ratio)
	}
}

func TestCompareRejectsBaselineFromDifferentCPU(t *testing.T) {
	goYara, _ := report.Parse(strings.NewReader(goYaraOutput))
	yaraX, _ := report.Parse(strings.NewReader(yaraXOutput))
	_, err := report.Compare(goYara, yaraX, report.Policy{
		Baseline: &report.Baseline{
			GOOS:   "darwin",
			GOARCH: "arm64",
			CPU:    "Another CPU",
			Ratios: map[string]float64{},
		},
		MinRatio:      0.5,
		MaxRegression: 0.2,
	})
	if err == nil || !strings.Contains(err.Error(), "baseline platform differs") {
		t.Fatalf("Compare error = %v, want baseline platform mismatch", err)
	}
}

func TestReadBaselineRejectsMixedPlatforms(t *testing.T) {
	input := "goos,goarch,cpu,cell,ratio\n" +
		"darwin,arm64,CPU A,cell-a,0.5\n" +
		"darwin,arm64,CPU B,cell-b,0.6\n"
	if _, err := report.ReadBaseline(strings.NewReader(input)); err == nil {
		t.Fatal("ReadBaseline accepted mixed CPU metadata")
	}
}
