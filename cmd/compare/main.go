// Command-line tool for comprehensive performance comparison between go-yara and reference YARA
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cawalch/go-yara/internal/profiling/comparison"
)

func main() {
	flags := parseFlags()
	config := buildConfig(flags)
	printConfiguration(flags)

	comparator := createComparator(config)
	results := runComparison(comparator)
	saveResults(flags, comparator, results)

	if flags.verbose {
		printDetailedResults(comparator)
	}
}

type cliFlags struct {
	ruleDirs        string
	dataDirs        string
	rulePattern     string
	maxRuleFiles    int
	maxDataFiles    int
	maxRulesPerFile int
	maxDataSize     int64
	compTimeout     time.Duration
	execTimeout     time.Duration
	parallelism     int
	profileCPU      bool
	profileMem      bool
	profileAllocs   bool
	verbose         bool
	outputFile      string
	reportFile      string
	quickMode       bool
	deepMode        bool
}

func parseFlags() *cliFlags {
	ruleDirs := flag.String("rules", "examples,testdata,rules", "Comma-separated directories containing YARA files")
	dataDirs := flag.String("data", "testdata,examples/data", "Comma-separated directories containing test data")
	rulePattern := flag.String("pattern", "*.yar", "Pattern for rule files")
	maxRuleFiles := flag.Int("max-rules", 50, "Maximum number of rule files to test")
	maxDataFiles := flag.Int("max-data", 100, "Maximum number of data files to test")
	maxRulesPerFile := flag.Int("max-rules-per-file", 20, "Maximum rules per file")
	maxDataSize := flag.Int64("max-data-size", 10485760, "Maximum data file size in bytes (default: 10MB)")
	compTimeout := flag.Duration("comp-timeout", 30*time.Second, "Compilation timeout")
	execTimeout := flag.Duration("exec-timeout", 60*time.Second, "Execution timeout")
	parallelism := flag.Int("parallel", 0, "Number of parallel workers (0 = auto)")
	profileCPU := flag.Bool("profile-cpu", true, "Enable CPU profiling")
	profileMem := flag.Bool("profile-mem", true, "Enable memory profiling")
	profileAllocs := flag.Bool("profile-allocs", true, "Enable allocation profiling")
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	outputFile := flag.String("output", "", "Output file for results (JSON format)")
	reportFile := flag.String("report", "", "Output file for human-readable report")
	quickMode := flag.Bool("quick", false, "Quick mode: reduced test set for faster results")
	deepMode := flag.Bool("deep", false, "Deep mode: comprehensive testing with larger datasets")
	flag.Parse()

	flags := &cliFlags{
		ruleDirs:        *ruleDirs,
		dataDirs:        *dataDirs,
		rulePattern:     *rulePattern,
		maxRuleFiles:    *maxRuleFiles,
		maxDataFiles:    *maxDataFiles,
		maxRulesPerFile: *maxRulesPerFile,
		maxDataSize:     *maxDataSize,
		compTimeout:     *compTimeout,
		execTimeout:     *execTimeout,
		parallelism:     *parallelism,
		profileCPU:      *profileCPU,
		profileMem:      *profileMem,
		profileAllocs:   *profileAllocs,
		verbose:         *verbose,
		outputFile:      *outputFile,
		reportFile:      *reportFile,
		quickMode:       *quickMode,
		deepMode:        *deepMode,
	}

	adjustParametersForMode(flags)
	return flags
}

func adjustParametersForMode(flags *cliFlags) {
	if flags.quickMode {
		flags.maxRuleFiles = 10
		flags.maxDataFiles = 20
		flags.maxRulesPerFile = 10
		flags.maxDataSize = 1024 * 1024 // 1MB
		flags.parallelism = 2
		flags.profileCPU = false
		flags.profileMem = false
		flags.profileAllocs = false
		fmt.Println("Running in quick mode...")
	}

	if flags.deepMode {
		flags.maxRuleFiles = 200
		flags.maxDataFiles = 500
		flags.maxRulesPerFile = 50
		flags.maxDataSize = 50 * 1024 * 1024 // 50MB
		if flags.parallelism == 0 {
			flags.parallelism = 8
		}
		fmt.Println("Running in deep mode...")
	}
}

func buildConfig(flags *cliFlags) *comparison.ComparisonConfig {
	ruleDirectories := cleanDirectories(strings.Split(flags.ruleDirs, ","))
	dataDirectories := cleanDirectories(strings.Split(flags.dataDirs, ","))

	return &comparison.ComparisonConfig{
		RuleDirectories:    ruleDirectories,
		DataDirectories:    dataDirectories,
		TestFilePattern:    flags.rulePattern,
		MaxRuleFiles:       flags.maxRuleFiles,
		MaxDataFiles:       flags.maxDataFiles,
		MaxRulesPerFile:    flags.maxRulesPerFile,
		MaxDataSize:        flags.maxDataSize,
		TimeoutCompilation: flags.compTimeout,
		TimeoutExecution:   flags.execTimeout,
		ProfileCPU:         flags.profileCPU,
		ProfileMemory:      flags.profileMem,
		ProfileAllocs:      flags.profileAllocs,
		Verbose:            flags.verbose,
		Parallelism:        flags.parallelism,
	}
}

func cleanDirectories(dirs []string) []string {
	for i, dir := range dirs {
		dirs[i] = strings.TrimSpace(dir)
	}
	return dirs
}

func printConfiguration(flags *cliFlags) {
	fmt.Printf("=== Go-YARA vs Reference YARA Performance Comparison ===\n")
	fmt.Printf("Configuration:\n")
	fmt.Printf("  Rule directories: %v\n", cleanDirectories(strings.Split(flags.ruleDirs, ",")))
	fmt.Printf("  Data directories: %v\n", cleanDirectories(strings.Split(flags.dataDirs, ",")))
	fmt.Printf("  Max rule files: %d\n", flags.maxRuleFiles)
	fmt.Printf("  Max data files: %d\n", flags.maxDataFiles)
	fmt.Printf("  Max rules per file: %d\n", flags.maxRulesPerFile)
	fmt.Printf("  Max data size: %d MB\n", flags.maxDataSize/1024/1024)
	fmt.Printf("  Parallelism: %d\n", flags.parallelism)
	fmt.Printf("  Profiling: CPU=%v, Memory=%v, Allocations=%v\n", flags.profileCPU, flags.profileMem, flags.profileAllocs)
	fmt.Printf("\n")
}

func createComparator(config *comparison.ComparisonConfig) *comparison.Comparator {
	comparator, err := comparison.NewComparator(config)
	if err != nil {
		log.Fatalf("Failed to create comparator: %v", err)
	}
	return comparator
}

func runComparison(comparator *comparison.Comparator) time.Duration {
	fmt.Printf("Running comparison...\n")
	startTime := time.Now()

	if err := comparator.RunComparison(); err != nil {
		log.Fatalf("Comparison failed: %v", err)
	}

	duration := time.Since(startTime)
	fmt.Printf("Comparison completed in %s\n\n", duration)

	comparator.UpdateAggregatedMetrics()
	comparator.PrintSummary()
	return duration
}

func saveResults(flags *cliFlags, comparator *comparison.Comparator, _ time.Duration) {
	if flags.outputFile != "" {
		if err := comparator.SaveResults(flags.outputFile); err != nil {
			log.Printf("Failed to save results: %v", err)
		} else {
			fmt.Printf("Detailed results saved to: %s\n", flags.outputFile)
		}
	}

	if flags.reportFile != "" {
		report := comparator.GenerateReport()
		if err := os.WriteFile(flags.reportFile, []byte(report), 0600); err != nil {
			log.Printf("Failed to save report: %v", err)
		} else {
			fmt.Printf("Human-readable report saved to: %s\n", flags.reportFile)
		}
	}
}

// printDetailedResults prints detailed breakdown of comparison results
func printDetailedResults(comparator *comparison.Comparator) {
	results := comparator.GetResults()

	printEnvironmentInfo(results.Environment)
	printGoYaraMetrics(results.GoYaraResults)
	printReferenceYaraMetrics(results.ReferenceYaraResults)
	printPerformanceGaps(results.PerformanceGaps)
	printCorrectnessAnalysis(results.CorrectnessResults)

	fmt.Printf("\nPerformance Outliers:\n")
	printOutliers(results.TestCases)
}

func printEnvironmentInfo(env *comparison.EnvironmentInfo) {
	fmt.Printf("\nEnvironment:\n")
	fmt.Printf("  Go Version: %s\n", env.GoVersion)
	fmt.Printf("  OS/Arch: %s/%s\n", env.OS, env.Arch)
	fmt.Printf("  CPU Cores: %d\n", env.NumCPU)
	fmt.Printf("  YARA Version: %s\n", env.YaraVersion)
}

func printGoYaraMetrics(results *comparison.GoYaraResults) {
	if results == nil {
		return
	}

	fmt.Printf("\nGo-YARA Performance:\n")
	printCompilationMetrics(results.CompilationMetrics)
	printExecutionMetrics(results.ExecutionMetrics)
	printMemoryMetrics(results.MemoryMetrics)
}

func printReferenceYaraMetrics(results *comparison.ReferenceYaraResults) {
	if results == nil {
		return
	}

	fmt.Printf("\nReference YARA Performance:\n")
	printCompilationMetrics(results.CompilationMetrics)
	printExecutionMetrics(results.ExecutionMetrics)
}

func printCompilationMetrics(metrics any) {
	if metrics == nil {
		return
	}

	switch m := metrics.(type) {
	case *comparison.CompilationMetrics:
		fmt.Printf("  Compilation: %d files, %d rules, avg %s, %.1f rules/sec\n",
			m.SuccessCount, m.TotalRules, m.AvgTime, m.RulesPerSec)
	}
}

func printExecutionMetrics(metrics any) {
	if metrics == nil {
		return
	}

	switch m := metrics.(type) {
	case *comparison.ExecutionMetrics:
		fmt.Printf("  Execution: %d runs, %d matches, avg %s, %.2f MB/sec\n",
			m.SuccessCount, m.TotalMatches, m.AvgTime, m.MBPerSec)
	}
}

func printMemoryMetrics(metrics any) {
	if metrics == nil {
		return
	}

	switch m := metrics.(type) {
	case *comparison.MemoryMetrics:
		fmt.Printf("  Memory: %d total allocs, %d total bytes, %.1f allocs/sec\n",
			m.TotalAllocs, m.TotalBytes, m.AllocsPerSec)
	}
}

func printPerformanceGaps(gaps *comparison.PerformanceGaps) {
	if gaps == nil {
		return
	}

	fmt.Printf("\nPerformance Gaps:\n")
	fmt.Printf("  Compilation Speedup: %.2fx\n", gaps.CompilationSpeedup)
	fmt.Printf("  Execution Speedup: %.2fx\n", gaps.ExecutionSpeedup)
	if gaps.MemoryReduction != 0 {
		fmt.Printf("  Memory Reduction: %.2f%%\n", gaps.MemoryReduction*100)
	}
	if gaps.AllocationReduction > 0 {
		fmt.Printf("  Allocation Reduction: %.2f%%\n", gaps.AllocationReduction*100)
	}
	fmt.Printf("  Overall Score: %.2f\n", gaps.OverallScore)
}

func printCorrectnessAnalysis(results *comparison.CorrectnessResults) {
	if results == nil {
		return
	}

	fmt.Printf("\nCorrectness Analysis:\n")
	fmt.Printf("  Total Test Cases: %d\n", results.TotalTestCases)
	fmt.Printf("  Matching Results: %d\n", results.MatchingResults)
	fmt.Printf("  Different Results: %d\n", results.DifferentResults)
	fmt.Printf("  Match Accuracy: %.2f%%\n", results.MatchAccuracy*100)
	fmt.Printf("  False Positives: %d\n", results.FalsePositives)
	fmt.Printf("  False Negatives: %d\n", results.FalseNegatives)

	if len(results.Discrepancies) > 0 {
		printTopDiscrepancies(results.Discrepancies)
	}
}

func printTopDiscrepancies(discrepancies []*comparison.Discrepancy) {
	fmt.Printf("\nTop 5 Discrepancies:\n")
	maxDiscrepancies := min(len(discrepancies), 5)

	for i := range maxDiscrepancies {
		disp := discrepancies[i]
		fmt.Printf("  %d. %s vs %s (%s)\n", i+1,
			filepath.Base(disp.RuleFile), filepath.Base(disp.DataFile), disp.MatchType)
		fmt.Printf("     Go-YARA only: %v\n", disp.GoYaraMatches)
		fmt.Printf("     Ref-YARA only: %v\n", disp.RefYaraMatches)
	}
}

// printOutliers prints test cases with unusual performance characteristics
func printOutliers(testCases []*comparison.TestCaseResult) {
	outliers := findOutliers(testCases)
	printOutlierResults(outliers)
}

type outliers struct {
	fastestCompile *comparison.TestCaseResult
	slowestCompile *comparison.TestCaseResult
	fastestExec    *comparison.TestCaseResult
	slowestExec    *comparison.TestCaseResult
	mostMatches    *comparison.TestCaseResult
	fewestMatches  *comparison.TestCaseResult
}

func findOutliers(testCases []*comparison.TestCaseResult) outliers {
	var result outliers

	for _, tc := range testCases {
		if !isValidTestCase(tc) {
			continue
		}

		result = updateOutliers(result, tc)
	}

	return result
}

func isValidTestCase(tc *comparison.TestCaseResult) bool {
	return tc.GoYaraResult != nil && tc.ReferenceYaraResult != nil
}

func updateOutliers(current outliers, tc *comparison.TestCaseResult) outliers {
	// Fastest compilation
	if current.fastestCompile == nil || tc.GoYaraResult.CompilationTime < current.fastestCompile.GoYaraResult.CompilationTime {
		current.fastestCompile = tc
	}

	// Slowest compilation
	if current.slowestCompile == nil || tc.GoYaraResult.CompilationTime > current.slowestCompile.GoYaraResult.CompilationTime {
		current.slowestCompile = tc
	}

	// Fastest execution
	if current.fastestExec == nil || tc.GoYaraResult.ExecutionTime < current.fastestExec.GoYaraResult.ExecutionTime {
		current.fastestExec = tc
	}

	// Slowest execution
	if current.slowestExec == nil || tc.GoYaraResult.ExecutionTime > current.slowestExec.GoYaraResult.ExecutionTime {
		current.slowestExec = tc
	}

	// Most matches
	if current.mostMatches == nil || tc.GoYaraResult.MatchCount > current.mostMatches.GoYaraResult.MatchCount {
		current.mostMatches = tc
	}

	// Fewest matches (but not zero if possible)
	if tc.GoYaraResult.MatchCount > 0 {
		if current.fewestMatches == nil || tc.GoYaraResult.MatchCount < current.fewestMatches.GoYaraResult.MatchCount {
			current.fewestMatches = tc
		}
	}

	return current
}

func printOutlierResults(outliers outliers) {
	if outliers.fastestCompile != nil {
		fmt.Printf("  Fastest Compilation: %s (%s)\n",
			outliers.fastestCompile.Name, outliers.fastestCompile.GoYaraResult.CompilationTime)
	}

	if outliers.slowestCompile != nil && outliers.slowestCompile != outliers.fastestCompile {
		fmt.Printf("  Slowest Compilation: %s (%s)\n",
			outliers.slowestCompile.Name, outliers.slowestCompile.GoYaraResult.CompilationTime)
	}

	if outliers.fastestExec != nil {
		fmt.Printf("  Fastest Execution: %s (%s, %d matches)\n",
			outliers.fastestExec.Name, outliers.fastestExec.GoYaraResult.ExecutionTime, outliers.fastestExec.GoYaraResult.MatchCount)
	}

	if outliers.slowestExec != nil && outliers.slowestExec != outliers.fastestExec {
		fmt.Printf("  Slowest Execution: %s (%s, %d matches)\n",
			outliers.slowestExec.Name, outliers.slowestExec.GoYaraResult.ExecutionTime, outliers.slowestExec.GoYaraResult.MatchCount)
	}

	if outliers.mostMatches != nil {
		fmt.Printf("  Most Matches: %s (%d matches)\n",
			outliers.mostMatches.Name, outliers.mostMatches.GoYaraResult.MatchCount)
	}

	if outliers.fewestMatches != nil && outliers.fewestMatches != outliers.mostMatches {
		fmt.Printf("  Fewest Matches: %s (%d matches)\n",
			outliers.fewestMatches.Name, outliers.fewestMatches.GoYaraResult.MatchCount)
	}
}
