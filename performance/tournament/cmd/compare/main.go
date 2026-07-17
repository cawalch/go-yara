package main

import (
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

	fmt.Printf("Tournament: %d cells on %s/%s (%s)\n", len(comparison.Rows), comparison.GOOS, comparison.GOARCH, comparison.CPU)
	fmt.Printf("Geomean go-yara/yara-x ratio: %.3fx\n", comparison.Geomean)
	fmt.Printf("Cells below %.3fx: %d\n", *minRatio, len(comparison.Warnings))
	for _, warning := range comparison.Warnings {
		fmt.Printf("WARN: %s\n", warning)
	}
	for _, failure := range comparison.Failures {
		fmt.Printf("FAIL: %s\n", failure)
	}
	if *check && len(comparison.Failures) > 0 {
		os.Exit(1)
	}
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

func readBaseline(path string) report.Baseline {
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
