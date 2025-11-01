// Command profile-execution provides comprehensive execution profiling for go-yara
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/cawalch/go-yara/internal/profiling/comparison"
	"github.com/cawalch/go-yara/internal/profiling/execution"
)

func main() {
	config := execution.DefaultProfilingConfig()

	// Parse command line flags
	addFlags(config)

	if len(os.Args) == 1 {
		printUsage()
		return
	}

	// Execute based on command
	cmd := flag.Arg(0)
	if cmd == "" {
		printUsage()
		return
	}

	switch cmd {
	case "profile":
		runProfiling(config)
	case "benchmark":
		runBenchmarking(config)
	case "compare":
		runComparison(config)
	case "analyze":
		runAnalysis(config)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

// addFlags adds profiling configuration flags
func addFlags(config *execution.ProfilingConfig) {
	flag.StringVar(&config.TestDataDir, "test-data", config.TestDataDir, "Directory containing test data files")
	flag.StringVar(&config.RulesDir, "rules-dir", config.RulesDir, "Directory containing rule files")
	flag.StringVar(&config.OutputDir, "output-dir", config.OutputDir, "Directory to write profiling results")
	flag.DurationVar(&config.BenchTime, "bench-time", config.BenchTime, "Benchmark duration")
	flag.IntVar(&config.BenchCount, "bench-count", config.BenchCount, "Number of benchmark runs")
	flag.DurationVar(&config.Timeout, "timeout", config.Timeout, "Per-test timeout")
	flag.IntVar(&config.MaxRules, "max-rules", config.MaxRules, "Maximum number of rules to test")
	flag.Int64Var(&config.MaxDataSize, "max-data-size", config.MaxDataSize, "Maximum data size to test (bytes)")
	flag.BoolVar(&config.CPUProfile, "cpu-profile", config.CPUProfile, "Enable CPU profiling")
	flag.BoolVar(&config.MemoryProfile, "mem-profile", config.MemoryProfile, "Enable memory profiling")
	flag.BoolVar(&config.AllocProfile, "alloc-profile", config.AllocProfile, "Enable allocation profiling")
	flag.BoolVar(&config.TraceProfile, "trace-profile", config.TraceProfile, "Enable execution tracing")
	flag.BoolVar(&config.Verbose, "verbose", config.Verbose, "Verbose output")
	flag.BoolVar(&config.JSONOutput, "json", config.JSONOutput, "JSON output format")
	flag.StringVar(&config.YaraBinary, "yara-binary", config.YaraBinary, "Path to reference YARA binary")
	flag.BoolVar(&config.CompareWithYara, "compare-yara", config.CompareWithYara, "Compare with reference YARA")

	// Pattern filters
	patterns := flag.String("patterns", "", "Comma-separated list of rule file patterns to include")
	flag.Func("data-sizes", "Comma-separated list of data sizes to test (e.g., 1024,10240,102400)", func(s string) error {
		if s != "" {
			sizes := strings.Split(s, ",")
			config.DataSizes = make([]int64, 0, len(sizes))
			for _, sizeStr := range sizes {
				var size int64
				_, err := fmt.Sscanf(strings.TrimSpace(sizeStr), "%d", &size)
				if err != nil {
					return fmt.Errorf("invalid data size: %s", sizeStr)
				}
				config.DataSizes = append(config.DataSizes, size)
			}
		}
		return nil
	})

	flag.Parse()

	if *patterns != "" {
		config.RulePatterns = strings.Split(*patterns, ",")
		for i := range config.RulePatterns {
			config.RulePatterns[i] = strings.TrimSpace(config.RulePatterns[i])
		}
	}
}

// printUsage prints usage information
func printUsage() {
	fmt.Printf(`Usage: %s <command> [flags]

Commands:
  profile    - Run comprehensive execution profiling
  benchmark  - Run performance benchmarks
  compare    - Compare go-yara performance with reference YARA
  analyze    - Analyze existing profiling results

Flags:
`, os.Args[0])
	flag.PrintDefaults()

	fmt.Printf(`
Examples:
  # Run basic profiling
  %s profile -test-data=testdata -rules-dir=rules -verbose

  # Run benchmarks with specific data sizes
  %s benchmark -data-sizes=1024,10240,102400 -cpu-profile -mem-profile

  # Compare with reference YARA
  %s compare -yara-binary=/usr/local/bin/yara -compare-yara -verbose

  # Profile specific rule patterns
  %s profile -patterns="simple,hex,regex" -max-data-size=1048576

`, os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}

// runProfiling executes comprehensive execution profiling
func runProfiling(config *execution.ProfilingConfig) {
	fmt.Printf("Starting execution profiling...\n")
	printConfig(config)

	profiler := execution.NewProfiler(config)

	start := time.Now()
	if err := profiler.RunProfiling(); err != nil {
		log.Fatalf("Profiling failed: %v", err)
	}

	duration := time.Since(start)
	fmt.Printf("Profiling completed in %v\n", duration)

	if config.Verbose {
		printEnvironmentInfo()
	}
}

// runBenchmarking executes performance benchmarks
func runBenchmarking(config *execution.ProfilingConfig) {
	fmt.Printf("Starting execution benchmarking...\n")
	printConfig(config)

	// Create test file structure
	if err := ensureTestData(config); err != nil {
		log.Fatalf("Failed to setup test data: %v", err)
	}

	suite := execution.NewBenchmarkSuite(config)
	opts := execution.DefaultBenchmarkOptions()
	opts.ProfileCPU = config.CPUProfile
	opts.ProfileMem = config.MemoryProfile

	fmt.Printf("Running benchmarks (this may take a while)...\n")

	// Run benchmarks
	suite.RunAllBenchmarks(nil, opts)

	fmt.Printf("Benchmarks completed\n")
}

// runComparison executes comparison with reference YARA
func runComparison(config *execution.ProfilingConfig) {
	fmt.Printf("Starting YARA comparison...\n")
	printConfig(config)

	// Convert execution config to comparison config
	compConfig := &comparison.ComparisonConfig{
		RuleDirectories:    []string{config.RulesDir},
		DataDirectories:    []string{config.TestDataDir},
		TestFilePattern:    "*.yar",
		MaxRuleFiles:       50,
		MaxDataFiles:       50,
		MaxRulesPerFile:    config.MaxRules,
		MaxDataSize:        config.MaxDataSize,
		TimeoutCompilation: config.Timeout,
		TimeoutExecution:   config.Timeout,
		ProfileCPU:         config.CPUProfile,
		ProfileMemory:      config.MemoryProfile,
		ProfileAllocs:      config.AllocProfile,
		Verbose:            config.Verbose,
		Parallelism:        1, // Use single thread for comparison
	}

	comparator, err := comparison.NewComparator(compConfig)
	if err != nil {
		log.Fatalf("Failed to create comparator: %v", err)
	}

	start := time.Now()
	if runErr := comparator.RunComparison(); runErr != nil {
		log.Fatalf("Comparison failed: %v", runErr)
	}

	duration := time.Since(start)
	fmt.Printf("Comparison completed in %v\n", duration)
}

// runAnalysis analyzes existing profiling results
func runAnalysis(config *execution.ProfilingConfig) {
	fmt.Printf("Analyzing profiling results...\n")

	// Look for existing profiling results
	resultsDir := config.OutputDir
	if resultsDir == "" {
		resultsDir = "profiles/execution"
	}

	files, err := filepath.Glob(filepath.Join(resultsDir, "*.json"))
	if err != nil {
		log.Fatalf("Failed to find profiling results: %v", err)
	}

	if len(files) == 0 {
		fmt.Printf("No profiling results found in %s\n", resultsDir)
		fmt.Printf("Run profiling first: %s profile\n", os.Args[0])
		return
	}

	fmt.Printf("Found %d profiling result files\n", len(files))

	// Analyze each file
	for _, file := range files {
		fmt.Printf("Analyzing %s...\n", filepath.Base(file))
		analyzeProfileFile(file)
	}
}

// printConfig prints current configuration
func printConfig(config *execution.ProfilingConfig) {
	fmt.Printf("Configuration:\n")
	fmt.Printf("  Test Data Dir: %s\n", config.TestDataDir)
	fmt.Printf("  Rules Dir: %s\n", config.RulesDir)
	fmt.Printf("  Output Dir: %s\n", config.OutputDir)
	fmt.Printf("  Benchmark Time: %v\n", config.BenchTime)
	fmt.Printf("  Benchmark Count: %d\n", config.BenchCount)
	fmt.Printf("  Timeout: %v\n", config.Timeout)
	fmt.Printf("  Max Rules: %d\n", config.MaxRules)
	fmt.Printf("  Max Data Size: %s\n", formatBytes(config.MaxDataSize))
	fmt.Printf("  CPU Profile: %t\n", config.CPUProfile)
	fmt.Printf("  Memory Profile: %t\n", config.MemoryProfile)
	fmt.Printf("  Compare with YARA: %t\n", config.CompareWithYara)
	if config.CompareWithYara {
		fmt.Printf("  YARA Binary: %s\n", config.YaraBinary)
	}
	if len(config.RulePatterns) > 0 {
		fmt.Printf("  Rule Patterns: %s\n", strings.Join(config.RulePatterns, ", "))
	}
	if len(config.DataSizes) > 0 {
		sizes := make([]string, len(config.DataSizes))
		for i, size := range config.DataSizes {
			sizes[i] = formatBytes(size)
		}
		fmt.Printf("  Data Sizes: %s\n", strings.Join(sizes, ", "))
	}
	fmt.Printf("\n")
}

// printEnvironmentInfo prints environment information
func printEnvironmentInfo() {
	fmt.Printf("Environment:\n")
	fmt.Printf("  Go Version: %s\n", runtime.Version())
	fmt.Printf("  OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("  CPU Cores: %d\n", runtime.NumCPU())
	fmt.Printf("  Goroutines: %d\n", runtime.NumGoroutine())

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("  Memory Usage: %s\n", formatBytes(int64(m.Alloc)))
	fmt.Printf("  Total Allocations: %s\n", formatBytes(int64(m.TotalAlloc)))
	fmt.Printf("\n")
}

// ensureTestData ensures test data directories and files exist
func ensureTestData(config *execution.ProfilingConfig) error {
	// Create test data directory if it doesn't exist
	if err := os.MkdirAll(config.TestDataDir, 0750); err != nil {
		return fmt.Errorf("creating test data directory: %w", err)
	}

	// Create rules directory if it doesn't exist
	if err := os.MkdirAll(config.RulesDir, 0750); err != nil {
		return fmt.Errorf("creating rules directory: %w", err)
	}

	// Generate sample test data if needed
	if err := generateSampleTestData(config); err != nil {
		return fmt.Errorf("generating sample test data: %w", err)
	}

	// Generate sample rules if needed
	if err := generateSampleRules(config); err != nil {
		return fmt.Errorf("generating sample rules: %w", err)
	}

	return nil
}

// generateSampleTestData generates sample test data files
func generateSampleTestData(config *execution.ProfilingConfig) error {
	// Check if test data files already exist
	files, err := os.ReadDir(config.TestDataDir)
	if err == nil && len(files) > 0 {
		return nil // Files already exist
	}

	fmt.Printf("Generating sample test data...\n")

	// Generate test files of different sizes
	testSizes := []int64{1024, 10240, 102400, 1048576} // 1KB, 10KB, 100KB, 1MB

	for _, size := range testSizes {
		filename := filepath.Join(config.TestDataDir, fmt.Sprintf("test_data_%dKB.dat", size/1024))

		// Generate some patterned data
		data := make([]byte, size)
		for j := range data {
			data[j] = byte(j % 256)
		}

		// Insert some patterns that might match rules
		patterns := []string{"MALWARE", "SUSPICIOUS", "TEST", "PATTERN"}
		for j, pattern := range patterns {
			patternBytes := []byte(pattern)
			pos := int(size) * (j + 1) / (len(patterns) + 1)
			if pos+len(patternBytes) < len(data) {
				copy(data[pos:], patternBytes)
			}
		}

		if writeErr := os.WriteFile(filename, data, 0600); writeErr != nil {
			return fmt.Errorf("writing test file %s: %w", filename, writeErr)
		}
	}

	return nil
}

// generateSampleRules generates sample YARA rule files
func generateSampleRules(config *execution.ProfilingConfig) error {
	// Check if rule files already exist
	files, err := os.ReadDir(config.RulesDir)
	if err == nil && len(files) > 0 {
		return nil // Files already exist
	}

	fmt.Printf("Generating sample YARA rules...\n")

	// Simple rule with text strings
	simpleRule := `rule SimpleText {
	meta:
		description = "Simple text matching rule"
		author = "profiler"
	strings:
		$a = "MALWARE"
		$b = "SUSPICIOUS"
	condition:
		$a or $b
}`

	if writeErr := os.WriteFile(filepath.Join(config.RulesDir, "simple_text.yar"), []byte(simpleRule), 0600); writeErr != nil {
		return writeErr
	}

	// Rule with hex patterns
	hexRule := `rule HexPattern {
	meta:
		description = "Hex pattern matching rule"
		author = "profiler"
	strings:
		$a = { 4D 41 4C 57 41 52 45 } // "MALWARE" in hex
		$b = { 54 45 53 54 }          // "TEST" in hex
	condition:
		$a or $b
}`

	if writeErr := os.WriteFile(filepath.Join(config.RulesDir, "hex_pattern.yar"), []byte(hexRule), 0600); writeErr != nil {
		return writeErr
	}

	// Rule with regex patterns
	regexRule := `rule RegexPattern {
	meta:
		description = "Regex pattern matching rule"
		author = "profiler"
	strings:
		$a = /M[AL]*WARE/
		$b = /SUS.*IOUS/
	condition:
		$a or $b
}`

	if writeErr := os.WriteFile(filepath.Join(config.RulesDir, "regex_pattern.yar"), []byte(regexRule), 0600); writeErr != nil {
		return writeErr
	}

	// Complex rule with multiple patterns
	complexRule := `rule ComplexRule {
	meta:
		description = "Complex rule with multiple patterns"
		author = "profiler"
	strings:
		$text1 = "MALWARE"
		$text2 = "SUSPICIOUS"
		$text3 = "PATTERN"
		$hex1 = { 4D 41 4C 57 41 52 45 }
		$hex2 = { 54 45 53 54 }
		$regex1 = /PATTERN.*TEST/
	condition:
		($text1 and $text2) or $hex1 or ($regex1 within 100)
}`

	return os.WriteFile(filepath.Join(config.RulesDir, "complex_rule.yar"), []byte(complexRule), 0600)
}

// analyzeProfileFile analyzes a single profiling result file
func analyzeProfileFile(filename string) {
	// This would load and analyze the JSON profiling results
	// For now, just print the filename
	fmt.Printf("  - Found profile file: %s\n", filepath.Base(filename))

	// TODO: Implement actual analysis logic
	// - Load JSON file
	// - Extract key metrics
	// - Identify hotspots
	// - Generate recommendations
}

// formatBytes formats a byte count as human-readable
func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
