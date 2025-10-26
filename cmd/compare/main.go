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
	// Command-line flags
	var (
		ruleDirs        = flag.String("rules", "examples,testdata,rules", "Comma-separated directories containing YARA files")
		dataDirs        = flag.String("data", "testdata,examples/data", "Comma-separated directories containing test data")
		rulePattern     = flag.String("pattern", "*.yar", "Pattern for rule files")
		maxRuleFiles    = flag.Int("max-rules", 50, "Maximum number of rule files to test")
		maxDataFiles    = flag.Int("max-data", 100, "Maximum number of data files to test")
		maxRulesPerFile = flag.Int("max-rules-per-file", 20, "Maximum rules per file")
		maxDataSize     = flag.Int64("max-data-size", 10485760, "Maximum data file size in bytes (default: 10MB)")
		compTimeout     = flag.Duration("comp-timeout", 30*time.Second, "Compilation timeout")
		execTimeout     = flag.Duration("exec-timeout", 60*time.Second, "Execution timeout")
		parallelism     = flag.Int("parallel", 0, "Number of parallel workers (0 = auto)")
		profileCPU      = flag.Bool("profile-cpu", true, "Enable CPU profiling")
		profileMem      = flag.Bool("profile-mem", true, "Enable memory profiling")
		profileAllocs   = flag.Bool("profile-allocs", true, "Enable allocation profiling")
		verbose         = flag.Bool("verbose", false, "Enable verbose output")
		outputFile      = flag.String("output", "", "Output file for results (JSON format)")
		reportFile      = flag.String("report", "", "Output file for human-readable report")
		quickMode       = flag.Bool("quick", false, "Quick mode: reduced test set for faster results")
		deepMode        = flag.Bool("deep", false, "Deep mode: comprehensive testing with larger datasets")
	)
	flag.Parse()

	// Adjust parameters based on mode
	if *quickMode {
		*maxRuleFiles = 10
		*maxDataFiles = 20
		*maxRulesPerFile = 10
		*maxDataSize = 1024 * 1024 // 1MB
		*parallelism = 2
		*profileCPU = false
		*profileMem = false
		*profileAllocs = false
		fmt.Println("Running in quick mode...")
	}

	if *deepMode {
		*maxRuleFiles = 200
		*maxDataFiles = 500
		*maxRulesPerFile = 50
		*maxDataSize = 50 * 1024 * 1024 // 50MB
		if *parallelism == 0 {
			*parallelism = 8
		}
		fmt.Println("Running in deep mode...")
	}

	// Parse directories
	ruleDirectories := strings.Split(*ruleDirs, ",")
	dataDirectories := strings.Split(*dataDirs, ",")

	// Clean up directory paths
	for i, dir := range ruleDirectories {
		ruleDirectories[i] = strings.TrimSpace(dir)
	}
	for i, dir := range dataDirectories {
		dataDirectories[i] = strings.TrimSpace(dir)
	}

	// Create comparison configuration
	config := &comparison.ComparisonConfig{
		RuleDirectories:    ruleDirectories,
		DataDirectories:    dataDirectories,
		TestFilePattern:    *rulePattern,
		MaxRuleFiles:       *maxRuleFiles,
		MaxDataFiles:       *maxDataFiles,
		MaxRulesPerFile:    *maxRulesPerFile,
		MaxDataSize:        *maxDataSize,
		TimeoutCompilation: *compTimeout,
		TimeoutExecution:   *execTimeout,
		ProfileCPU:         *profileCPU,
		ProfileMemory:      *profileMem,
		ProfileAllocs:      *profileAllocs,
		Verbose:            *verbose,
		Parallelism:        *parallelism,
	}

	// Print configuration
	fmt.Printf("=== Go-YARA vs Reference YARA Performance Comparison ===\n")
	fmt.Printf("Configuration:\n")
	fmt.Printf("  Rule directories: %v\n", ruleDirectories)
	fmt.Printf("  Data directories: %v\n", dataDirectories)
	fmt.Printf("  Max rule files: %d\n", *maxRuleFiles)
	fmt.Printf("  Max data files: %d\n", *maxDataFiles)
	fmt.Printf("  Max rules per file: %d\n", *maxRulesPerFile)
	fmt.Printf("  Max data size: %d MB\n", *maxDataSize/1024/1024)
	fmt.Printf("  Parallelism: %d\n", *parallelism)
	fmt.Printf("  Profiling: CPU=%v, Memory=%v, Allocations=%v\n", *profileCPU, *profileMem, *profileAllocs)
	fmt.Printf("\n")

	// Create comparator
	comparator, err := comparison.NewComparator(config)
	if err != nil {
		log.Fatalf("Failed to create comparator: %v", err)
	}

	// Run comparison
	fmt.Printf("Running comparison...\n")
	startTime := time.Now()

	if runErr := comparator.RunComparison(); runErr != nil {
		log.Fatalf("Comparison failed: %v", runErr)
	}

	duration := time.Since(startTime)
	fmt.Printf("Comparison completed in %s\n\n", duration)

	// Update aggregated metrics
	comparator.UpdateAggregatedMetrics()

	// Print summary
	comparator.PrintSummary()

	// Save results if requested
	if *outputFile != "" {
		if saveErr := comparator.SaveResults(*outputFile); saveErr != nil {
			log.Printf("Failed to save results: %v", saveErr)
		} else {
			fmt.Printf("Detailed results saved to: %s\n", *outputFile)
		}
	}

	// Generate report if requested
	if *reportFile != "" {
		report := comparator.GenerateReport()
		if writeErr := os.WriteFile(*reportFile, []byte(report), 0600); writeErr != nil {
			log.Printf("Failed to save report: %v", writeErr)
		} else {
			fmt.Printf("Human-readable report saved to: %s\n", *reportFile)
		}
	}

	// Print detailed breakdown
	if *verbose {
		fmt.Printf("\n=== Detailed Results ===\n")
		printDetailedResults(comparator)
	}
}

// printDetailedResults prints detailed breakdown of comparison results
func printDetailedResults(comparator *comparison.Comparator) {
	results := comparator.GetResults()

	// Environment info
	fmt.Printf("\nEnvironment:\n")
	fmt.Printf("  Go Version: %s\n", results.Environment.GoVersion)
	fmt.Printf("  OS/Arch: %s/%s\n", results.Environment.OS, results.Environment.Arch)
	fmt.Printf("  CPU Cores: %d\n", results.Environment.NumCPU)
	fmt.Printf("  YARA Version: %s\n", results.Environment.YaraVersion)

	// Go-YARA metrics
	if results.GoYaraResults != nil {
		fmt.Printf("\nGo-YARA Performance:\n")
		if results.GoYaraResults.CompilationMetrics != nil {
			comp := results.GoYaraResults.CompilationMetrics
			fmt.Printf("  Compilation: %d files, %d rules, avg %s, %.1f rules/sec\n",
				comp.SuccessCount, comp.TotalRules, comp.AvgTime, comp.RulesPerSec)
		}
		if results.GoYaraResults.ExecutionMetrics != nil {
			exec := results.GoYaraResults.ExecutionMetrics
			fmt.Printf("  Execution: %d runs, %d matches, avg %s, %.2f MB/sec\n",
				exec.SuccessCount, exec.TotalMatches, exec.AvgTime, exec.MBPerSec)
		}
		if results.GoYaraResults.MemoryMetrics != nil {
			mem := results.GoYaraResults.MemoryMetrics
			fmt.Printf("  Memory: %d total allocs, %d total bytes, %.1f allocs/sec\n",
				mem.TotalAllocs, mem.TotalBytes, mem.AllocsPerSec)
		}
	}

	// Reference YARA metrics
	if results.ReferenceYaraResults != nil {
		fmt.Printf("\nReference YARA Performance:\n")
		if results.ReferenceYaraResults.CompilationMetrics != nil {
			comp := results.ReferenceYaraResults.CompilationMetrics
			fmt.Printf("  Compilation: %d files, %d rules, avg %s, %.1f rules/sec\n",
				comp.SuccessCount, comp.TotalRules, comp.AvgTime, comp.RulesPerSec)
		}
		if results.ReferenceYaraResults.ExecutionMetrics != nil {
			exec := results.ReferenceYaraResults.ExecutionMetrics
			fmt.Printf("  Execution: %d runs, %d matches, avg %s, %.2f MB/sec\n",
				exec.SuccessCount, exec.TotalMatches, exec.AvgTime, exec.MBPerSec)
		}
	}

	// Performance gaps
	if results.PerformanceGaps != nil {
		fmt.Printf("\nPerformance Gaps:\n")
		fmt.Printf("  Compilation Speedup: %.2fx\n", results.PerformanceGaps.CompilationSpeedup)
		fmt.Printf("  Execution Speedup: %.2fx\n", results.PerformanceGaps.ExecutionSpeedup)
		if results.PerformanceGaps.MemoryReduction != 0 {
			fmt.Printf("  Memory Reduction: %.2f%%\n", results.PerformanceGaps.MemoryReduction*100)
		}
		if results.PerformanceGaps.AllocationReduction > 0 {
			fmt.Printf("  Allocation Reduction: %.2f%%\n", results.PerformanceGaps.AllocationReduction*100)
		}
		fmt.Printf("  Overall Score: %.2f\n", results.PerformanceGaps.OverallScore)
	}

	// Correctness
	if results.CorrectnessResults != nil {
		fmt.Printf("\nCorrectness Analysis:\n")
		fmt.Printf("  Total Test Cases: %d\n", results.CorrectnessResults.TotalTestCases)
		fmt.Printf("  Matching Results: %d\n", results.CorrectnessResults.MatchingResults)
		fmt.Printf("  Different Results: %d\n", results.CorrectnessResults.DifferentResults)
		fmt.Printf("  Match Accuracy: %.2f%%\n", results.CorrectnessResults.MatchAccuracy*100)
		fmt.Printf("  False Positives: %d\n", results.CorrectnessResults.FalsePositives)
		fmt.Printf("  False Negatives: %d\n", results.CorrectnessResults.FalseNegatives)

		if len(results.CorrectnessResults.Discrepancies) > 0 {
			fmt.Printf("\nTop 5 Discrepancies:\n")
			maxDiscrepancies := 5
			if len(results.CorrectnessResults.Discrepancies) < maxDiscrepancies {
				maxDiscrepancies = len(results.CorrectnessResults.Discrepancies)
			}

			for i := 0; i < maxDiscrepancies; i++ {
				disp := results.CorrectnessResults.Discrepancies[i]
				fmt.Printf("  %d. %s vs %s (%s)\n", i+1,
					filepath.Base(disp.RuleFile), filepath.Base(disp.DataFile), disp.MatchType)
				fmt.Printf("     Go-YARA only: %v\n", disp.GoYaraMatches)
				fmt.Printf("     Ref-YARA only: %v\n", disp.RefYaraMatches)
			}
		}
	}

	// Performance outliers
	fmt.Printf("\nPerformance Outliers:\n")
	printOutliers(results.TestCases)
}

// printOutliers prints test cases with unusual performance characteristics
func printOutliers(testCases []*comparison.TestCaseResult) {
	var fastestCompile, slowestCompile *comparison.TestCaseResult
	var fastestExec, slowestExec *comparison.TestCaseResult
	var mostMatches, fewestMatches *comparison.TestCaseResult

	for _, tc := range testCases {
		if tc.GoYaraResult == nil || tc.ReferenceYaraResult == nil {
			continue
		}

		// Fastest compilation
		if fastestCompile == nil || tc.GoYaraResult.CompilationTime < fastestCompile.GoYaraResult.CompilationTime {
			fastestCompile = tc
		}

		// Slowest compilation
		if slowestCompile == nil || tc.GoYaraResult.CompilationTime > slowestCompile.GoYaraResult.CompilationTime {
			slowestCompile = tc
		}

		// Fastest execution
		if fastestExec == nil || tc.GoYaraResult.ExecutionTime < fastestExec.GoYaraResult.ExecutionTime {
			fastestExec = tc
		}

		// Slowest execution
		if slowestExec == nil || tc.GoYaraResult.ExecutionTime > slowestExec.GoYaraResult.ExecutionTime {
			slowestExec = tc
		}

		// Most matches
		if mostMatches == nil || tc.GoYaraResult.MatchCount > mostMatches.GoYaraResult.MatchCount {
			mostMatches = tc
		}

		// Fewest matches (but not zero if possible)
		if tc.GoYaraResult.MatchCount > 0 {
			if fewestMatches == nil || tc.GoYaraResult.MatchCount < fewestMatches.GoYaraResult.MatchCount {
				fewestMatches = tc
			}
		}
	}

	if fastestCompile != nil {
		fmt.Printf("  Fastest Compilation: %s (%s)\n",
			fastestCompile.Name, fastestCompile.GoYaraResult.CompilationTime)
	}

	if slowestCompile != nil && slowestCompile != fastestCompile {
		fmt.Printf("  Slowest Compilation: %s (%s)\n",
			slowestCompile.Name, slowestCompile.GoYaraResult.CompilationTime)
	}

	if fastestExec != nil {
		fmt.Printf("  Fastest Execution: %s (%s, %d matches)\n",
			fastestExec.Name, fastestExec.GoYaraResult.ExecutionTime, fastestExec.GoYaraResult.MatchCount)
	}

	if slowestExec != nil && slowestExec != fastestExec {
		fmt.Printf("  Slowest Execution: %s (%s, %d matches)\n",
			slowestExec.Name, slowestExec.GoYaraResult.ExecutionTime, slowestExec.GoYaraResult.MatchCount)
	}

	if mostMatches != nil {
		fmt.Printf("  Most Matches: %s (%d matches)\n",
			mostMatches.Name, mostMatches.GoYaraResult.MatchCount)
	}

	if fewestMatches != nil && fewestMatches != mostMatches {
		fmt.Printf("  Fewest Matches: %s (%d matches)\n",
			fewestMatches.Name, fewestMatches.GoYaraResult.MatchCount)
	}
}
