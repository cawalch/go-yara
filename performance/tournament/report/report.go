// Package report parses Go benchmark output and compares go-yara with yara-x.
package report

import (
	"bufio"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
)

const benchmarkPrefix = "BenchmarkTournament/"

// Sample contains the metrics from one benchmark repetition.
type Sample struct {
	MBPerSec    float64
	BytesPerOp  float64
	AllocsPerOp float64
	Matched     float64
	MatchHash   float64
}

// Run contains all samples emitted by one engine.
type Run struct {
	GOOS    string
	GOARCH  string
	CPU     string
	Samples map[string][]Sample
}

// Row is the median comparison for one matrix cell.
type Row struct {
	Cell            string
	GoYaraMBPerSec  float64
	YaraXMBPerSec   float64
	Ratio           float64
	GoYaraBytesOp   float64
	YaraXBytesOp    float64
	GoYaraAllocsOp  float64
	YaraXAllocsOp   float64
	MatchedRules    float64
	MatchHash       float64
	BaselineRatio   float64
	Regression      float64
	BaselinePresent bool
}

// Comparison is one paired tournament result.
type Comparison struct {
	GOOS     string
	GOARCH   string
	CPU      string
	Rows     []Row
	Geomean  float64
	Warnings []string
	Failures []string
}

// Baseline maps matrix cells to their prior go-yara/yara-x ratio.
type Baseline map[string]float64

// Policy configures warning and regression thresholds.
type Policy struct {
	Baseline      Baseline
	MinRatio      float64
	MaxRegression float64
}

// Parse reads standard Go benchmark output.
func Parse(reader io.Reader) (Run, error) {
	run := Run{Samples: make(map[string][]Sample)}
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "goos:"):
			run.GOOS = strings.TrimSpace(strings.TrimPrefix(line, "goos:"))
		case strings.HasPrefix(line, "goarch:"):
			run.GOARCH = strings.TrimSpace(strings.TrimPrefix(line, "goarch:"))
		case strings.HasPrefix(line, "cpu:"):
			run.CPU = strings.TrimSpace(strings.TrimPrefix(line, "cpu:"))
		case strings.HasPrefix(line, benchmarkPrefix):
			cell, sample, err := parseBenchmarkLine(line)
			if err != nil {
				return Run{}, err
			}
			run.Samples[cell] = append(run.Samples[cell], sample)
		}
	}
	if err := scanner.Err(); err != nil {
		return Run{}, err
	}
	if len(run.Samples) == 0 {
		return Run{}, errors.New("no BenchmarkTournament samples found")
	}
	return run, nil
}

func parseBenchmarkLine(line string) (string, Sample, error) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return "", Sample{}, fmt.Errorf("malformed benchmark line %q", line)
	}
	cell := trimCPUCount(strings.TrimPrefix(fields[0], benchmarkPrefix))
	metrics := make(map[string]float64, (len(fields)-2)/2)
	for index := 2; index+1 < len(fields); index += 2 {
		value, err := strconv.ParseFloat(fields[index], 64)
		if err != nil {
			return "", Sample{}, fmt.Errorf("parse %s for %s: %w", fields[index+1], cell, err)
		}
		metrics[fields[index+1]] = value
	}
	if metrics["MB/s"] <= 0 {
		return "", Sample{}, fmt.Errorf("benchmark %s has no positive MB/s metric", cell)
	}
	return cell, Sample{
		MBPerSec:    metrics["MB/s"],
		BytesPerOp:  metrics["B/op"],
		AllocsPerOp: metrics["allocs/op"],
		Matched:     metrics["matched_rules/op"],
		MatchHash:   metrics["match_fingerprint/op"],
	}, nil
}

func trimCPUCount(name string) string {
	separator := strings.LastIndexByte(name, '-')
	if separator < 0 || separator == len(name)-1 {
		return name
	}
	for _, char := range name[separator+1:] {
		if char < '0' || char > '9' {
			return name
		}
	}
	return name[:separator]
}

// Compare pairs engine runs, validates semantic parity, and computes medians.
func Compare(goYara, yaraX Run, policy Policy) (Comparison, error) {
	if goYara.GOOS == "" || goYara.GOARCH == "" || yaraX.GOOS == "" || yaraX.GOARCH == "" {
		return Comparison{}, errors.New("benchmark output is missing goos/goarch metadata")
	}
	if goYara.GOOS != yaraX.GOOS || goYara.GOARCH != yaraX.GOARCH {
		return Comparison{}, fmt.Errorf("engine platforms differ: go-yara=%s/%s yara-x=%s/%s",
			goYara.GOOS, goYara.GOARCH, yaraX.GOOS, yaraX.GOARCH)
	}
	if policy.MinRatio <= 0 {
		return Comparison{}, errors.New("minimum ratio must be positive")
	}
	if policy.MaxRegression <= 0 || policy.MaxRegression >= 1 {
		return Comparison{}, errors.New("maximum regression must be between 0 and 1")
	}

	comparison := Comparison{GOOS: goYara.GOOS, GOARCH: goYara.GOARCH, CPU: goYara.CPU}
	cellNames := make([]string, 0, len(goYara.Samples))
	for cell := range goYara.Samples {
		cellNames = append(cellNames, cell)
	}
	slices.Sort(cellNames)
	if len(cellNames) != len(yaraX.Samples) {
		return Comparison{}, fmt.Errorf("cell count differs: go-yara=%d yara-x=%d", len(cellNames), len(yaraX.Samples))
	}

	logRatioSum := 0.0
	for _, cell := range cellNames {
		goSamples := goYara.Samples[cell]
		xSamples, exists := yaraX.Samples[cell]
		if !exists {
			return Comparison{}, fmt.Errorf("yara-x output is missing cell %s", cell)
		}
		goMedian := medianSample(goSamples)
		xMedian := medianSample(xSamples)
		if math.Abs(goMedian.Matched-xMedian.Matched) > 0.001 {
			return Comparison{}, fmt.Errorf("matched-rule mismatch for %s: go-yara=%.0f yara-x=%.0f",
				cell, goMedian.Matched, xMedian.Matched)
		}
		if math.Abs(goMedian.MatchHash-xMedian.MatchHash) > 0.001 {
			return Comparison{}, fmt.Errorf("matching-rule fingerprint mismatch for %s: go-yara=%.0f yara-x=%.0f",
				cell, goMedian.MatchHash, xMedian.MatchHash)
		}
		ratio := goMedian.MBPerSec / xMedian.MBPerSec
		row := Row{
			Cell:           cell,
			GoYaraMBPerSec: goMedian.MBPerSec,
			YaraXMBPerSec:  xMedian.MBPerSec,
			Ratio:          ratio,
			GoYaraBytesOp:  goMedian.BytesPerOp,
			YaraXBytesOp:   xMedian.BytesPerOp,
			GoYaraAllocsOp: goMedian.AllocsPerOp,
			YaraXAllocsOp:  xMedian.AllocsPerOp,
			MatchedRules:   goMedian.Matched,
			MatchHash:      goMedian.MatchHash,
		}
		if ratio < policy.MinRatio {
			comparison.Warnings = append(comparison.Warnings,
				fmt.Sprintf("%s ratio %.3fx is below %.3fx", cell, ratio, policy.MinRatio))
		}
		if baselineRatio, ok := policy.Baseline[cell]; ok {
			row.BaselinePresent = true
			row.BaselineRatio = baselineRatio
			row.Regression = (baselineRatio - ratio) / baselineRatio
			if row.Regression > policy.MaxRegression {
				comparison.Failures = append(comparison.Failures,
					fmt.Sprintf("%s ratio regressed %.1f%% (%.3fx -> %.3fx)",
						cell, row.Regression*100, baselineRatio, ratio))
			}
		}
		comparison.Rows = append(comparison.Rows, row)
		logRatioSum += math.Log(ratio)
	}
	comparison.Geomean = math.Exp(logRatioSum / float64(len(comparison.Rows)))
	return comparison, nil
}

func medianSample(samples []Sample) Sample {
	return Sample{
		MBPerSec:    medianMetric(samples, func(sample Sample) float64 { return sample.MBPerSec }),
		BytesPerOp:  medianMetric(samples, func(sample Sample) float64 { return sample.BytesPerOp }),
		AllocsPerOp: medianMetric(samples, func(sample Sample) float64 { return sample.AllocsPerOp }),
		Matched:     medianMetric(samples, func(sample Sample) float64 { return sample.Matched }),
		MatchHash:   medianMetric(samples, func(sample Sample) float64 { return sample.MatchHash }),
	}
}

func medianMetric(samples []Sample, metric func(Sample) float64) float64 {
	values := make([]float64, len(samples))
	for index, sample := range samples {
		values[index] = metric(sample)
	}
	slices.Sort(values)
	middle := len(values) / 2
	if len(values)%2 == 1 {
		return values[middle]
	}
	return (values[middle-1] + values[middle]) / 2
}

// ReadBaseline reads a CSV previously emitted by WriteCSV.
func ReadBaseline(reader io.Reader) (Baseline, error) {
	records, err := csv.NewReader(reader).ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) < 2 {
		return nil, errors.New("baseline has no data rows")
	}
	headings := make(map[string]int, len(records[0]))
	for index, heading := range records[0] {
		headings[heading] = index
	}
	cellIndex, cellOK := headings["cell"]
	ratioIndex, ratioOK := headings["ratio"]
	if !cellOK || !ratioOK {
		return nil, errors.New("baseline must contain cell and ratio columns")
	}
	baseline := make(Baseline, len(records)-1)
	for _, record := range records[1:] {
		if len(record) <= cellIndex || len(record) <= ratioIndex {
			return nil, errors.New("baseline row has too few columns")
		}
		ratio, parseErr := strconv.ParseFloat(record[ratioIndex], 64)
		if parseErr != nil {
			return nil, fmt.Errorf("parse baseline ratio for %s: %w", record[cellIndex], parseErr)
		}
		baseline[record[cellIndex]] = ratio
	}
	return baseline, nil
}

// WriteCSV writes the complete per-cell result. Its output is also the
// versioned baseline format.
func WriteCSV(writer io.Writer, comparison Comparison) error {
	csvWriter := csv.NewWriter(writer)
	if err := csvWriter.Write([]string{
		"goos", "goarch", "cpu", "cell", "goyara_mb_s", "yarax_mb_s", "ratio",
		"goyara_b_op", "yarax_b_op", "goyara_allocs_op", "yarax_allocs_op", "matched_rules", "match_fingerprint",
	}); err != nil {
		return err
	}
	for _, row := range comparison.Rows {
		if err := csvWriter.Write([]string{
			comparison.GOOS,
			comparison.GOARCH,
			comparison.CPU,
			row.Cell,
			fmt.Sprintf("%.3f", row.GoYaraMBPerSec),
			fmt.Sprintf("%.3f", row.YaraXMBPerSec),
			fmt.Sprintf("%.6f", row.Ratio),
			fmt.Sprintf("%.3f", row.GoYaraBytesOp),
			fmt.Sprintf("%.3f", row.YaraXBytesOp),
			fmt.Sprintf("%.3f", row.GoYaraAllocsOp),
			fmt.Sprintf("%.3f", row.YaraXAllocsOp),
			fmt.Sprintf("%.0f", row.MatchedRules),
			fmt.Sprintf("%.0f", row.MatchHash),
		}); err != nil {
			return err
		}
	}
	csvWriter.Flush()
	return csvWriter.Error()
}

// WriteMarkdown writes a human-readable full tournament report.
func WriteMarkdown(writer io.Writer, comparison Comparison, minRatio float64) error {
	if _, err := fmt.Fprintf(writer, "# go-yara vs yara-x benchmark tournament\n\n"+
		"Platform: `%s/%s`  \nCPU: `%s`  \nGeomean ratio: **%.3fx**\n\n",
		comparison.GOOS, comparison.GOARCH, comparison.CPU, comparison.Geomean); err != nil {
		return err
	}
	if _, err := io.WriteString(writer,
		"| Cell | go-yara MB/s | yara-x MB/s | Ratio | go-yara B/op | yara-x B/op | Matches | Status |\n"+
			"|---|---:|---:|---:|---:|---:|---:|---|\n"); err != nil {
		return err
	}
	for _, row := range comparison.Rows {
		status := "ok"
		if row.Ratio < minRatio {
			status = "below target"
		}
		if row.BaselinePresent && row.Regression > 0 {
			status = fmt.Sprintf("%.1f%% below baseline", row.Regression*100)
		}
		if _, err := fmt.Fprintf(writer, "| `%s` | %.2f | %.2f | %.3fx | %.0f | %.0f | %.0f | %s |\n",
			row.Cell, row.GoYaraMBPerSec, row.YaraXMBPerSec, row.Ratio,
			row.GoYaraBytesOp, row.YaraXBytesOp, row.MatchedRules, status); err != nil {
			return err
		}
	}
	return nil
}
