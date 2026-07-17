package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/cawalch/go-yara/performance/tournament/report"
)

func main() {
	goYaraPath := flag.String("goyara", "", "go-yara benchmark output")
	yaraXPath := flag.String("yarax", "", "yara-x benchmark output")
	baselinePath := flag.String("baseline", "", "prior tournament CSV")
	csvPath := flag.String("csv", "", "write current CSV")
	markdownPath := flag.String("markdown", "", "write current Markdown report")
	failureCellsPath := flag.String("failure-cells", "", "write cells that exceed the regression limit")
	checkCellsPath := flag.String("check-cells", "", "only enforce regressions for cells listed in this file")
	minRatio := flag.Float64("min-ratio", 0.5, "warn below this go-yara/yara-x ratio")
	maxRegression := flag.Float64("max-regression", 0.25, "fail above this relative ratio regression")
	check := flag.Bool("check", false, "exit non-zero when a baseline regression exceeds the limit")
	flag.Parse()

	if *goYaraPath == "" || *yaraXPath == "" {
		log.Fatal("-goyara and -yarax are required")
	}
	goYara := readRun(*goYaraPath)
	yaraX := readRun(*yaraXPath)
	baseline := readBaseline(*baselinePath)
	comparison, err := report.Compare(goYara, yaraX, report.Policy{
		Baseline:      baseline,
		CheckCells:    readCellSet(*checkCellsPath),
		MinRatio:      *minRatio,
		MaxRegression: *maxRegression,
	})
	if err != nil {
		log.Fatal(err)
	}
	writeOutput(*csvPath, func(writer io.Writer) error { return report.WriteCSV(writer, comparison) })
	writeOutput(*markdownPath, func(writer io.Writer) error {
		return report.WriteMarkdown(writer, comparison, *minRatio)
	})
	writeOutput(*failureCellsPath, func(writer io.Writer) error {
		buffered := bufio.NewWriter(writer)
		for _, cell := range report.FailedCells(comparison) {
			if _, writeErr := fmt.Fprintln(buffered, cell); writeErr != nil {
				return writeErr
			}
		}
		return buffered.Flush()
	})

	fmt.Printf("Tournament: %d cells on %s/%s (%s)\n", len(comparison.Rows), comparison.GOOS, comparison.GOARCH, comparison.CPU)
	fmt.Printf("Geomean go-yara/yara-x ratio: %.3fx\n", comparison.Geomean)
	fmt.Printf("Cells below %.3fx: %d\n", *minRatio, len(comparison.Warnings))
	for _, warning := range comparison.Warnings {
		fmt.Printf("WARN: %s\n", warning)
	}
	failureLabel := "REGRESSION"
	if *check {
		failureLabel = "FAIL"
	}
	for _, failure := range comparison.Failures {
		fmt.Printf("%s: %s\n", failureLabel, failure)
	}
	if *check && len(comparison.Failures) > 0 {
		os.Exit(1)
	}
}

func readCellSet(path string) map[string]struct{} {
	if path == "" {
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	cells := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if scanner.Text() != "" {
			cells[scanner.Text()] = struct{}{}
		}
	}
	scanErr := scanner.Err()
	closeErr := file.Close()
	if scanErr != nil {
		log.Fatal(scanErr)
	}
	if closeErr != nil {
		log.Fatal(closeErr)
	}
	return cells
}

func readRun(path string) report.Run {
	file, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	run, err := report.Parse(file)
	closeErr := file.Close()
	if err != nil {
		log.Fatal(err)
	}
	if closeErr != nil {
		log.Fatal(closeErr)
	}
	return run
}

func readBaseline(path string) *report.Baseline {
	if path == "" {
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	baseline, err := report.ReadBaseline(file)
	closeErr := file.Close()
	if err != nil {
		log.Fatal(err)
	}
	if closeErr != nil {
		log.Fatal(closeErr)
	}
	return baseline
}

func writeOutput(path string, write func(io.Writer) error) {
	if path == "" {
		return
	}
	file, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
	}
	writeErr := write(file)
	closeErr := file.Close()
	if writeErr != nil {
		log.Fatal(writeErr)
	}
	if closeErr != nil {
		log.Fatal(closeErr)
	}
}
