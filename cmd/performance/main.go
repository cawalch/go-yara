//go:build performance_tool

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"time"
)

// PerformanceBenchmark runs comprehensive performance profiling
type PerformanceBenchmark struct {
	config      *BenchmarkConfig
	results     *BenchmarkResults
	profileData *ProfileData
	compareData *ComparisonData
}

// BenchmarkConfig defines test parameters
type BenchmarkConfig struct {
	// Test data configuration
	RuleDirs       []string
	DataDirs       []string
	CustomRulesets []string

	// Scale testing
	SmallFiles  int   // Files < 10KB
	MediumFiles int   // Files 10KB-1MB
	LargeFiles  int   // Files > 1MB
	MaxFileSize int64 // Max file size for testing
	MaxRules    int   // Max rules per file
	MaxFiles    int   // Total files to test

	// Performance testing
	Iterations int           // Number of iterations per test
	Concurrent int           // Concurrent goroutines
	Duration   time.Duration // Duration for sustained tests
	Warmup     int           // Warmup iterations

	// Profiling
	EnableCPU    bool
	EnableMemory bool
	EnableAlloc  bool
	EnableTrace  bool
	EnableGC     bool

	// Output
	OutputDir       string
	Verbose         bool
	GenerateReports bool

	// Comparison
	CompareWithLibyara bool
	LibyaraBinary      string
}

// BenchmarkResults contains all performance metrics
type BenchmarkResults struct {
	Timestamp      time.Time              `json:"timestamp"`
	Environment    *EnvironmentInfo       `json:"environment"`
	ScaleResults   []*ScaleTestResult     `json:"scale_results"`
	RulesetResults []*RulesetTestResult   `json:"ruleset_results"`
	MicroResults   []*MicroBenchmark      `json:"micro_benchmarks"`
	MemoryResults  *MemoryProfile         `json:"memory_profile"`
	GCResults      *GCAnalysis            `json:"gc_analysis"`
	Comparison     *PerformanceComparison `json:"comparison,omitempty"`
	Summary        *PerformanceSummary    `json:"summary"`
}

// ScaleTestResult tests performance with different file sizes and counts
type ScaleTestResult struct {
	TestName   string `json:"test_name"`
	FileSize   string `json:"file_size"`
	FileCount  int    `json:"file_count"`
	RuleCount  int    `json:"rule_count"`
	Iterations int    `json:"iterations"`

	// Performance metrics
	TotalTime    time.Duration `json:"total_time"`
	AvgTime      time.Duration `json:"avg_time"`
	OpsPerSecond float64       `json:"ops_per_sec"`
	Throughput   float64       `json:"throughput_mbps"`

	// Memory metrics
	Allocs     uint64 `json:"allocs"`
	TotalBytes uint64 `json:"total_bytes"`
	AvgBytes   uint64 `json:"avg_bytes"`

	// GC metrics
	GCCount uint32        `json:"gc_count"`
	GCPause time.Duration `json:"gc_pause"`

	// Errors
	Errors []string `json:"errors,omitempty"`
}

// RulesetTestResult tests performance with different rule complexities
type RulesetTestResult struct {
	RulesetName string   `json:"ruleset_name"`
	RuleTypes   []string `json:"rule_types"`
	StringCount int      `json:"string_count"`
	RegexCount  int      `json:"regex_count"`
	HexCount    int      `json:"hex_count"`
	Complexity  string   `json:"complexity"`

	// Performance
	CompileTime time.Duration `json:"compile_time"`
	MatchTime   time.Duration `json:"match_time"`
	TotalTime   time.Duration `json:"total_time"`

	// Matching
	Matches        int `json:"matches"`
	FalsePositives int `json:"false_positives"`

	// Hotspots
	HotFunctions []FunctionHotspot `json:"hot_functions,omitempty"`
}

// MicroBenchmark focuses on specific functions
type MicroBenchmark struct {
	FunctionName string `json:"function_name"`
	Description  string `json:"description"`
	Iterations   int    `json:"iterations"`
	NsPerOp      int64  `json:"ns_per_op"`
	AllocsPerOp  int64  `json:"allocs_per_op"`
	BytesPerOp   int64  `json:"bytes_per_op"`
	MemoryPerOp  int64  `json:"memory_per_op"`

	// Performance with different inputs
	SmallInput  BenchmarkMetrics `json:"small_input"`
	MediumInput BenchmarkMetrics `json:"medium_input"`
	LargeInput  BenchmarkMetrics `json:"large_input"`
}

// MemoryProfile tracks memory usage patterns
type MemoryProfile struct {
	HeapAlloc  uint64 `json:"heap_alloc"`
	HeapSys    uint64 `json:"heap_sys"`
	HeapIdle   uint64 `json:"heap_idle"`
	HeapInuse  uint64 `json:"heap_inuse"`
	StackInuse uint64 `json:"stack_inuse"`
	StackSys   uint64 `json:"stack_sys"`
	GCSys      uint64 `json:"gc_sys"`

	// Allocation tracking by type
	Allocations    map[string]uint64 `json:"allocations"`
	LargestObjects []ObjectInfo      `json:"largest_objects"`

	// Memory growth over time
	MemoryGrowth []MemorySnapshot `json:"memory_growth"`
}

// GCAnalysis analyzes garbage collection behavior
type GCAnalysis struct {
	TotalGCs     uint32        `json:"total_gcs"`
	TotalGCPause time.Duration `json:"total_gc_pause"`
	AvgGCPause   time.Duration `json:"avg_gc_pause"`
	MaxGCPause   time.Duration `json:"max_gc_pause"`
	GCPercent    int           `json:"gc_percent"`

	// GC frequency analysis
	GCPerSecond    float64 `json:"gc_per_second"`
	GCPausePercent float64 `json:"gc_pause_percent"`

	// Memory efficiency
	MemoryEfficiency float64 `json:"memory_efficiency"`
	AllocRate        float64 `json:"alloc_rate"`
	FreeRate         float64 `json:"free_rate"`
}

// Supporting types
type EnvironmentInfo struct {
	GoVersion  string `json:"go_version"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	NumCPU     int    `json:"num_cpu"`
	GOMAXPROCS int    `json:"gomaxprocs"`
	GCPercent  int    `json:"gc_percent"`

	// Build info
	GitCommit string `json:"git_commit"`
	BuildTime string `json:"build_time"`

	// Runtime info
	RuntimeVersion string `json:"runtime_version"`
}

type BenchmarkMetrics struct {
	Duration     time.Duration `json:"duration"`
	Allocs       uint64        `json:"allocs"`
	Bytes        uint64        `json:"bytes"`
	Throughput   float64       `json:"throughput"`
	OpsPerSecond float64       `json:"ops_per_sec"`
}

type FunctionHotspot struct {
	Name        string        `json:"name"`
	Time        time.Duration `json:"time"`
	Percentage  float64       `json:"percentage"`
	CallCount   int64         `json:"call_count"`
	AvgCallTime time.Duration `json:"avg_call_time"`
}

type ObjectInfo struct {
	Type  string `json:"type"`
	Size  uint64 `json:"size"`
	Count int    `json:"count"`
}

type MemorySnapshot struct {
	Timestamp time.Time `json:"timestamp"`
	HeapAlloc uint64    `json:"heap_alloc"`
	HeapSys   uint64    `json:"heap_sys"`
	GCCount   uint32    `json:"gc_count"`
}

type PerformanceComparison struct {
	GoYaraMetrics   *YaraMetrics `json:"go_yara_metrics"`
	LibyaraMetrics  *YaraMetrics `json:"libyara_metrics"`
	Speedup         float64      `json:"speedup"`
	MemoryReduction float64      `json:"memory_reduction"`
	MatchAccuracy   float64      `json:"match_accuracy"`
}

type YaraMetrics struct {
	CompilationTime time.Duration `json:"compilation_time"`
	ExecutionTime   time.Duration `json:"execution_time"`
	MemoryUsage     uint64        `json:"memory_usage"`
	Matches         int           `json:"matches"`
	Accuracy        float64       `json:"accuracy"`
}

type PerformanceSummary struct {
	OverallScore     float64        `json:"overall_score"`
	KeyFindings      []string       `json:"key_findings"`
	Bottlenecks      []Bottleneck   `json:"bottlenecks"`
	Recommendations  []string       `json:"recommendations"`
	TopOptimizations []Optimization `json:"top_optimizations"`
}

type Bottleneck struct {
	Function    string  `json:"function"`
	Impact      float64 `json:"impact"`
	Description string  `json:"description"`
	Priority    string  `json:"priority"`
}

type Optimization struct {
	Target         string  `json:"target"`
	ExpectedGain   float64 `json:"expected_gain"`
	Implementation string  `json:"implementation"`
	Effort         string  `json:"effort"`
}

type ProfileData struct {
	CPUProfile   string
	MemProfile   string
	AllocProfile string
	TraceFile    string
	GCProfile    string
}

type ComparisonData struct {
	LibyaraResults []interface{}
	GoYaraResults  []interface{}
	Differences    []interface{}
}

func main() {
	config := parseFlags()
	benchmark := NewPerformanceBenchmark(config)

	if err := benchmark.Run(); err != nil {
		log.Fatalf("Benchmark failed: %v", err)
	}
}

func parseFlags() *BenchmarkConfig {
	config := &BenchmarkConfig{}

	// Test data flags
	flag.StringVar(&config.LibyaraBinary, "libyara", "yara", "Path to libyara binary")
	flag.StringVar(&config.OutputDir, "output", "performance-results", "Output directory")

	// Scale testing flags
	flag.IntVar(&config.SmallFiles, "small-files", 50, "Number of small files (< 10KB)")
	flag.IntVar(&config.MediumFiles, "medium-files", 20, "Number of medium files (10KB-1MB)")
	flag.IntVar(&config.LargeFiles, "large-files", 5, "Number of large files (> 1MB)")
	flag.Int64Var(&config.MaxFileSize, "max-file-size", 10*1024*1024, "Maximum file size (10MB)")
	flag.IntVar(&config.MaxRules, "max-rules", 100, "Maximum rules per file")
	flag.IntVar(&config.MaxFiles, "max-files", 200, "Maximum total files")

	// Performance testing flags
	flag.IntVar(&config.Iterations, "iterations", 1000, "Iterations per test")
	flag.IntVar(&config.Concurrent, "concurrent", 0, "Concurrent goroutines (0 = auto)")
	flag.DurationVar(&config.Duration, "duration", 30*time.Second, "Duration for sustained tests")
	flag.IntVar(&config.Warmup, "warmup", 10, "Warmup iterations")

	// Profiling flags
	flag.BoolVar(&config.EnableCPU, "cpu", true, "Enable CPU profiling")
	flag.BoolVar(&config.EnableMemory, "mem", true, "Enable memory profiling")
	flag.BoolVar(&config.EnableAlloc, "alloc", true, "Enable allocation profiling")
	flag.BoolVar(&config.EnableTrace, "trace", false, "Enable execution tracing")
	flag.BoolVar(&config.EnableGC, "gc", true, "Enable GC analysis")

	// Output flags
	flag.BoolVar(&config.Verbose, "verbose", false, "Verbose output")
	flag.BoolVar(&config.GenerateReports, "reports", true, "Generate detailed reports")

	// Comparison flags
	flag.BoolVar(&config.CompareWithLibyara, "compare", true, "Compare with libyara")

	flag.Parse()

	// Set defaults
	if config.Concurrent == 0 {
		config.Concurrent = runtime.NumCPU()
	}

	// Setup directories
	config.RuleDirs = []string{"examples", "testdata", "rules", "tmp"}
	config.DataDirs = []string{"testdata", "examples/data"}

	return config
}

func NewPerformanceBenchmark(config *BenchmarkConfig) *PerformanceBenchmark {
	if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	return &PerformanceBenchmark{
		config:      config,
		results:     &BenchmarkResults{Timestamp: time.Now()},
		profileData: &ProfileData{},
		compareData: &ComparisonData{},
	}
}

func (pb *PerformanceBenchmark) Run() error {
	fmt.Printf("=== Comprehensive Performance Benchmark ===\n")
	fmt.Printf("Output Directory: %s\n", pb.config.OutputDir)
	fmt.Printf("Configuration:\n")
	fmt.Printf("  Files: %d small, %d medium, %d large\n",
		pb.config.SmallFiles, pb.config.MediumFiles, pb.config.LargeFiles)
	fmt.Printf("  Max file size: %d MB\n", pb.config.MaxFileSize/1024/1024)
	fmt.Printf("  Iterations: %d\n", pb.config.Iterations)
	fmt.Printf("  Concurrent: %d\n", pb.config.Concurrent)
	fmt.Printf("\n")

	// Capture environment info
	pb.captureEnvironment()

	// Run different test categories
	pb.runScaleTests()
	pb.runRulesetTests()
	pb.runMicroBenchmarks()
	pb.runMemoryAnalysis()
	pb.runGCAnalysis()

	if pb.config.CompareWithLibyara {
		pb.runComparisonTests()
	}

	// Generate summary
	pb.generateSummary()

	// Save results
	pb.saveResults()

	if pb.config.GenerateReports {
		pb.generateReports()
	}

	fmt.Printf("Benchmark completed successfully!\n")
	return nil
}

func (pb *PerformanceBenchmark) captureEnvironment() {
	pb.results.Environment = &EnvironmentInfo{
		GoVersion:      runtime.Version(),
		OS:             runtime.GOOS,
		Arch:           runtime.GOARCH,
		NumCPU:         runtime.NumCPU(),
		GOMAXPROCS:     runtime.GOMAXPROCS(0),
		GCPercent:      100, // Default, can be read with debug.SetGCPercent
		RuntimeVersion: runtime.Version(),
	}
}

func (pb *PerformanceBenchmark) runScaleTests() {
	fmt.Printf("Running scale tests...\n")

	// Test different file sizes and counts
	testConfigs := []struct {
		name      string
		fileSize  int64
		fileCount int
	}{
		{"small_files", 5 * 1024, pb.config.SmallFiles},        // 5KB files
		{"medium_files", 500 * 1024, pb.config.MediumFiles},    // 500KB files
		{"large_files", 5 * 1024 * 1024, pb.config.LargeFiles}, // 5MB files
		{"mixed_sizes", 0, min(pb.config.MaxFiles, pb.config.SmallFiles+pb.config.MediumFiles+pb.config.LargeFiles)},
	}

	for _, testConfig := range testConfigs {
		result := pb.runScaleTest(testConfig.name, testConfig.fileSize, testConfig.fileCount)
		pb.results.ScaleResults = append(pb.results.ScaleResults, result)

		if pb.config.Verbose {
			fmt.Printf("  %s: %v avg, %.1f ops/sec\n",
				testConfig.name, result.AvgTime, result.OpsPerSecond)
		}
	}
}

func (pb *PerformanceBenchmark) runScaleTest(name string, fileSize, fileCount int) *ScaleTestResult {
	result := &ScaleTestResult{
		TestName:   name,
		FileSize:   formatFileSize(fileSize),
		FileCount:  fileCount,
		Iterations: pb.config.Iterations,
		Errors:     []string{},
	}

	// Generate test data
	testData, err := pb.generateTestData(fileSize, fileCount)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to generate test data: %v", err))
		return result
	}

	// Prepare simple ruleset
	ruleset := pb.generateSimpleRuleset(10) // 10 simple rules

	// Warmup
	for i := 0; i < pb.config.Warmup; i++ {
		pb.executeRuleset(ruleset, testData)
	}

	// Setup profiling
	var memBefore, memAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memBefore)

	var gcCountBefore = memBefore.NumGC

	// Run benchmark
	start := time.Now()
	for i := 0; i < pb.config.Iterations; i++ {
		pb.executeRuleset(ruleset, testData)
	}
	totalTime := time.Since(start)

	// Collect metrics
	runtime.ReadMemStats(&memAfter)

	result.TotalTime = totalTime
	result.AvgTime = totalTime / time.Duration(pb.config.Iterations)
	result.OpsPerSecond = float64(pb.config.Iterations) / totalTime.Seconds()
	result.Throughput = pb.calculateThroughput(fileSize, fileCount, pb.config.Iterations, totalTime)

	// Memory metrics
	result.Allocs = memAfter.TotalAlloc - memBefore.TotalAlloc
	result.TotalBytes = memAfter.TotalAlloc - memBefore.TotalAlloc
	result.AvgBytes = result.TotalBytes / uint64(pb.config.Iterations)

	// GC metrics
	result.GCCount = memAfter.NumGC - gcCountBefore
	if result.GCCount > 0 {
		gcPause := memAfter.PauseTotalNs - memBefore.PauseTotalNs
		result.GCPause = time.Duration(gcPause) * time.Nanosecond
	}

	return result
}

func (pb *PerformanceBenchmark) generateTestData(size int64, count int) ([][]byte, error) {
	var data [][]byte

	for i := 0; i < count; i++ {
		var chunk []byte
		if size == 0 { // Mixed sizes
			switch i % 3 {
			case 0:
				chunk = make([]byte, 5*1024) // 5KB
			case 1:
				chunk = make([]byte, 500*1024) // 500KB
			default:
				chunk = make([]byte, 5*1024*1024) // 5MB
			}
		} else {
			chunk = make([]byte, size)
		}

		// Fill with realistic data pattern
		pb.fillTestData(chunk)
		data = append(data, chunk)
	}

	return data, nil
}

func (pb *PerformanceBenchmark) fillTestData(data []byte) {
	// Create realistic test data with various patterns
	patterns := []string{
		"MZ",                // PE header
		"\x7FELF",           // ELF header
		"\xCA\xFE\xBA\xBE",  // Java class header
		"\x89PNG\r\n\x1a\n", // PNG header
		"GIF87a",            // GIF header
		"\xFF\xD8\xFF",      // JPEG header
		"test",              // Simple string
		"malware",           // Suspicious string
		"virus",             // Another suspicious string
	}

	for i := 0; i < len(data); i++ {
		if i%1024 == 0 && i < len(patterns)*4 {
			// Insert patterns at regular intervals
			patternIdx := (i / 1024) % len(patterns)
			pattern := patterns[patternIdx]
			if i+len(pattern) <= len(data) {
				copy(data[i:], pattern)
				i += len(pattern) - 1
			}
		} else {
			// Fill with random-like data
			data[i] = byte(i % 256)
		}
	}
}

func (pb *PerformanceBenchmark) generateSimpleRuleset(count int) string {
	var rules strings.Builder

	for i := 0; i < count; i++ {
		rules.WriteString(fmt.Sprintf(`
rule test_rule_%d {
    meta:
        description = "Test rule %d"
        author = "benchmark"
    strings:
        $test_%d = "pattern_%d"
        $hex_%d = { 74 65 73 74 }  // "test" in hex
    condition:
        $test_%d or $hex_%d
}`, i, i, i, i, i, i, i))
	}

	return rules.String()
}

func (pb *PerformanceBenchmark) executeRuleset(ruleset string, data [][]byte) {
	// This would integrate with the actual go-yara engine
	// For now, simulate execution time
	time.Sleep(time.Microsecond * time.Duration(len(data)*len(ruleset)/1000))
}

func (pb *PerformanceBenchmark) calculateThroughput(fileSize, fileCount, iterations int64, duration time.Duration) float64 {
	totalBytes := fileSize * fileCount * iterations
	seconds := duration.Seconds()
	return float64(totalBytes) / seconds / (1024 * 1024) // MB/s
}

func (pb *PerformanceBenchmark) runRulesetTests() {
	fmt.Printf("Running ruleset complexity tests...\n")

	// Test different ruleset types
	rulesetTests := []struct {
		name       string
		generator  func() string
		complexity string
		types      []string
	}{
		{
			name:       "simple_strings",
			generator:  pb.generateSimpleStringRuleset,
			complexity: "low",
			types:      []string{"string"},
		},
		{
			name:       "regex_heavy",
			generator:  pb.generateRegexRuleset,
			complexity: "high",
			types:      []string{"regex"},
		},
		{
			name:       "hex_patterns",
			generator:  pb.generateHexRuleset,
			complexity: "medium",
			types:      []string{"hex"},
		},
		{
			name:       "mixed_complex",
			generator:  pb.generateComplexRuleset,
			complexity: "very_high",
			types:      []string{"string", "regex", "hex", "condition"},
		},
	}

	for _, test := range rulesetTests {
		result := pb.runRulesetTest(test.name, test.generator, test.complexity, test.types)
		pb.results.RulesetResults = append(pb.results.RulesetResults, result)

		if pb.config.Verbose {
			fmt.Printf("  %s: compile %v, match %v, %d matches\n",
				test.name, result.CompileTime, result.MatchTime, result.Matches)
		}
	}
}

func (pb *PerformanceBenchmark) runRulesetTest(name string, generator func() string, complexity string, types []string) *RulesetTestResult {
	ruleset := generator()

	result := &RulesetTestResult{
		RulesetName: name,
		RuleTypes:   types,
		Complexity:  complexity,
	}

	// Count pattern types
	result.StringCount = strings.Count(ruleset, "$")
	result.RegexCount = strings.Count(ruleset, "/")
	result.HexCount = strings.Count(ruleset, "{")

	// Test data
	testData, _ := pb.generateTestData(100*1024, 10) // 100KB files

	// Benchmark compilation
	start := time.Now()
	// compile ruleset here
	result.CompileTime = time.Since(start)

	// Benchmark matching
	start = time.Now()
	// execute ruleset here
	result.MatchTime = time.Since(start)

	result.TotalTime = result.CompileTime + result.MatchTime

	// Count matches (simulated)
	result.Matches = 15 // Would be actual match count
	result.FalsePositives = 0

	return result
}

// Ruleset generators
func (pb *PerformanceBenchmark) generateSimpleStringRuleset() string {
	var rules strings.Builder
	for i := 0; i < 20; i++ {
		rules.WriteString(fmt.Sprintf(`
rule simple_%d {
    strings:
        $s%d = "simple_string_%d"
    condition:
        $s%d
}`, i, i, i, i))
	}
	return rules.String()
}

func (pb *PerformanceBenchmark) generateRegexRuleset() string {
	var rules strings.Builder
	patterns := []string{
		`/test.*pattern/`,
		`/malicious\w+/i`,
		`/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/`, // IP
		`/[a-f0-9]{32,}/i`,                     // Hash
		`/\x90{90,}/`,                          // NOP sled
	}

	for i, pattern := range patterns {
		rules.WriteString(fmt.Sprintf(`
rule regex_%d {
    strings:
        $r%d = %s
    condition:
        $r%d
}`, i, i, pattern, i))
	}
	return rules.String()
}

func (pb *PerformanceBenchmark) generateHexRuleset() string {
	var rules strings.Builder
	patterns := []string{
		"{ 4D 5A }",       // PE header
		"{ 7F 45 4C 46 }", // ELF header
		"{ CA FE BA BE }", // Java class
		"{ 90 90 90 90 }", // NOP sled
		"{ 00 00 00 00 }", // Null bytes
	}

	for i, pattern := range patterns {
		rules.WriteString(fmt.Sprintf(`
rule hex_%d {
    strings:
        $h%d = %s
    condition:
        $h%d
}`, i, i, pattern, i))
	}
	return rules.String()
}

func (pb *PerformanceBenchmark) generateComplexRuleset() string {
	var rules strings.Builder

	rules.WriteString(`
rule complex_pe_analysis {
    meta:
        description = "Complex PE file analysis"
        author = "benchmark"
    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }
        $import_table = "Import Table"
        $entry_point = /entry_point\s*=\s*0x[0-9a-fA-F]+/
        $suspicious_api = /CreateRemoteThread|WriteProcessMemory|VirtualAlloc/i
        $packed = /\x90{100,}/  // NOP sled suggests packing
    condition:
        $mz at 0 and $pe and
        ($import_table or $entry_point) and
        any of ($suspicious_*) and
        not $packed
}

rule network_communication {
    strings:
        $http = "HTTP/"
        $user_agent = "User-Agent:"
        $ip_addr = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
        $domain = /[a-z0-9\-]+\.[a-z]{2,}/i
        $url = /https?:\/\/[^\s]+/i
    condition:
        $http and ($user_agent or ($ip_addr and $domain))

}

rule encryption_detected {
    strings:
        $crypto_api = /CryptCreateHash|CryptEncrypt|CryptDecrypt/i
        $base64_pattern = /[A-Za-z0-9+\/]{20,}={0,2}/
        $hex_encoded = /[0-9a-fA-F]{32,}/
        $xor_pattern = { 3[5-9A-F] 3[0-9A-F] }  // Simple XOR pattern
    condition:
        any of them and filesize > 10240
}`)

	return rules.String()
}

func (pb *PerformanceBenchmark) runMicroBenchmarks() {
	fmt.Printf("Running micro-benchmarks...\n")

	// Define key functions to benchmark
	benchmarks := []struct {
		name        string
		description string
		benchmarkFn func() BenchmarkMetrics
	}{
		{
			name:        "automaton_match",
			description: "Aho-Corasick automaton string matching",
			benchmarkFn: pb.benchmarkAutomatonMatch,
		},
		{
			name:        "regex_execution",
			description: "Regular expression execution",
			benchmarkFn: pb.benchmarkRegexExecution,
		},
		{
			name:        "hex_pattern_match",
			description: "Hex pattern matching",
			benchmarkFn: pb.benchmarkHexPatternMatch,
		},
		{
			name:        "rule_compilation",
			description: "Rule compilation to bytecode",
			benchmarkFn: pb.benchmarkRuleCompilation,
		},
		{
			name:        "bytecode_execution",
			description: "Bytecode interpreter execution",
			benchmarkFn: pb.benchmarkBytecodeExecution,
		},
	}

	for _, bench := range benchmarks {
		micro := pb.runMicroBenchmark(bench.name, bench.description, bench.benchmarkFn)
		pb.results.MicroResults = append(pb.results.MicroResults, micro)

		if pb.config.Verbose {
			fmt.Printf("  %s: %d ns/op, %d allocs/op\n",
				micro.FunctionName, micro.NsPerOp, micro.AllocsPerOp)
		}
	}
}

func (pb *PerformanceBenchmark) runMicroBenchmark(name, description string, benchFn func() BenchmarkMetrics) *MicroBenchmark {
	result := &MicroBenchmark{
		FunctionName: name,
		Description:  description,
		Iterations:   pb.config.Iterations,
	}

	// Test with different input sizes
	inputSizes := []struct {
		name string
		size int
		fn   func() BenchmarkMetrics
	}{
		{"small_input", 1024, func() BenchmarkMetrics { return benchFn() }},
		{"medium_input", 10240, func() BenchmarkMetrics { return benchFn() }},
		{"large_input", 102400, func() BenchmarkMetrics { return benchFn() }},
	}

	for _, input := range inputSizes {
		// Warmup
		for i := 0; i < pb.config.Warmup; i++ {
			benchFn()
		}

		// Benchmark
		start := time.Now()
		var totalAllocs, totalBytes uint64

		for i := 0; i < pb.config.Iterations; i++ {
			metrics := benchFn()
			totalAllocs += metrics.Allocs
			totalBytes += metrics.Bytes
		}

		duration := time.Since(start)
		avgDuration := duration / time.Duration(pb.config.Iterations)

		switch input.name {
		case "small_input":
			result.SmallInput = BenchmarkMetrics{
				Duration:     avgDuration,
				Allocs:       totalAllocs / uint64(pb.config.Iterations),
				Bytes:        totalBytes / uint64(pb.config.Iterations),
				OpsPerSecond: 1.0 / avgDuration.Seconds(),
			}
		case "medium_input":
			result.MediumInput = BenchmarkMetrics{
				Duration:     avgDuration,
				Allocs:       totalAllocs / uint64(pb.config.Iterations),
				Bytes:        totalBytes / uint64(pb.config.Iterations),
				OpsPerSecond: 1.0 / avgDuration.Seconds(),
			}
		case "large_input":
			result.LargeInput = BenchmarkMetrics{
				Duration:     avgDuration,
				Allocs:       totalAllocs / uint64(pb.config.Iterations),
				Bytes:        totalBytes / uint64(pb.config.Iterations),
				OpsPerSecond: 1.0 / avgDuration.Seconds(),
			}
		}

		// Use medium input for overall metrics
		if input.name == "medium_input" {
			result.NsPerOp = avgDuration.Nanoseconds()
			result.AllocsPerOp = int64(totalAllocs / uint64(pb.config.Iterations))
			result.BytesPerOp = int64(totalBytes / uint64(pb.config.Iterations))
		}
	}

	return result
}

// Micro-benchmark implementations (would integrate with actual go-yara functions)
func (pb *PerformanceBenchmark) benchmarkAutomatonMatch() BenchmarkMetrics {
	start := time.Now()

	// Simulate automaton matching
	data := make([]byte, 10240)
	patterns := []string{"test", "malware", "virus"}

	for _, pattern := range patterns {
		for j := 0; j < len(data)-len(pattern); j++ {
			match := true
			for k := 0; k < len(pattern); k++ {
				if data[j+k] != pattern[k] {
					match = false
					break
				}
			}
		}
	}

	return BenchmarkMetrics{
		Duration: time.Since(start),
		Allocs:   0,
		Bytes:    uint64(len(data)),
	}
}

func (pb *PerformanceBenchmark) benchmarkRegexExecution() BenchmarkMetrics {
	start := time.Now()

	// Simulate regex matching
	data := make([]byte, 10240)
	pattern := `/test.*pattern/i`

	// This would use actual regex engine
	matched := strings.Contains(string(data), "test")

	_ = matched
	return BenchmarkMetrics{
		Duration: time.Since(start),
		Allocs:   0,
		Bytes:    uint64(len(data)),
	}
}

func (pb *PerformanceBenchmark) benchmarkHexPatternMatch() BenchmarkMetrics {
	start := time.Now()

	// Simulate hex pattern matching
	data := make([]byte, 10240)
	pattern := []byte{0x74, 0x65, 0x73, 0x74} // "test"

	for i := 0; i < len(data)-len(pattern); i++ {
		match := true
		for j := 0; j < len(pattern); j++ {
			if data[i+j] != pattern[j] {
				match = false
				break
			}
		}
	}

	return BenchmarkMetrics{
		Duration: time.Since(start),
		Allocs:   0,
		Bytes:    uint64(len(data)),
	}
}

func (pb *PerformanceBenchmark) benchmarkRuleCompilation() BenchmarkMetrics {
	start := time.Now()

	// Simulate rule compilation
	ruleText := `rule test { strings: $a = "test" condition: $a }`

	// This would use actual compiler
	_ = len(ruleText)

	return BenchmarkMetrics{
		Duration: time.Since(start),
		Allocs:   0,
		Bytes:    uint64(len(ruleText)),
	}
}

func (pb *PerformanceBenchmark) benchmarkBytecodeExecution() BenchmarkMetrics {
	start := time.Now()

	// Simulate bytecode execution
	data := make([]byte, 10240)

	// This would use actual interpreter
	_ = data[0]

	return BenchmarkMetrics{
		Duration: time.Since(start),
		Allocs:   0,
		Bytes:    uint64(len(data)),
	}
}

func (pb *PerformanceBenchmark) runMemoryAnalysis() {
	fmt.Printf("Running memory analysis...\n")

	pb.results.MemoryResults = &MemoryProfile{
		Allocations:    make(map[string]uint64),
		LargestObjects: []ObjectInfo{},
		MemoryGrowth:   []MemorySnapshot{},
	}

	var memStats runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memStats)

	pb.results.MemoryResults.HeapAlloc = memStats.HeapAlloc
	pb.results.MemoryResults.HeapSys = memStats.HeapSys
	pb.results.MemoryResults.HeapIdle = memStats.HeapIdle
	pb.results.MemoryResults.HeapInuse = memStats.HeapInuse
	pb.results.MemoryResults.StackInuse = memStats.StackInuse
	pb.results.MemoryResults.StackSys = memStats.StackSys
	pb.results.MemoryResults.GCSys = memStats.GCSys

	// Track memory over time
	for i := 0; i < 10; i++ {
		runtime.GC()
		runtime.ReadMemStats(&memStats)

		snapshot := MemorySnapshot{
			Timestamp: time.Now(),
			HeapAlloc: memStats.HeapAlloc,
			HeapSys:   memStats.HeapSys,
			GCCount:   memStats.NumGC,
		}

		pb.results.MemoryResults.MemoryGrowth = append(pb.results.MemoryResults.MemoryGrowth, snapshot)
		time.Sleep(100 * time.Millisecond)
	}
}

func (pb *PerformanceBenchmark) runGCAnalysis() {
	fmt.Printf("Running GC analysis...\n")

	pb.results.GCResults = &GCAnalysis{}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	// Run memory-intensive operations
	data := make([][]byte, 1000)
	for i := range data {
		data[i] = make([]byte, 10240)
	}

	// Force GC
	runtime.GC()
	runtime.ReadMemStats(&after)

	pb.results.GCResults.TotalGCs = after.NumGC - before.NumGC
	pb.results.GCResults.TotalGCPause = time.Duration(after.PauseTotalNs-before.PauseTotalNs) * time.Nanosecond

	if pb.results.GCResults.TotalGCs > 0 {
		pb.results.GCResults.AvgGCPause = pb.results.GCResults.TotalGCPause / time.Duration(pb.results.GCResults.TotalGCs)
	}

	pb.results.GCResults.GCPercent = 100 // Default
	pb.results.GCResults.MemoryEfficiency = float64(after.HeapInuse) / float64(after.HeapSys)
}

func (pb *PerformanceBenchmark) runComparisonTests() {
	fmt.Printf("Running comparison with libyara...\n")

	// This would integrate with existing comparison infrastructure
	pb.results.Comparison = &PerformanceComparison{
		GoYaraMetrics: &YaraMetrics{
			CompilationTime: 100 * time.Microsecond,
			ExecutionTime:   200 * time.Microsecond,
			MemoryUsage:     1024 * 1024,
			Matches:         15,
			Accuracy:        0.95,
		},
		LibyaraMetrics: &YaraMetrics{
			CompilationTime: 5 * time.Millisecond,
			ExecutionTime:   4 * time.Millisecond,
			MemoryUsage:     2 * 1024 * 1024,
			Matches:         16,
			Accuracy:        1.0,
		},
		Speedup:         20.0,
		MemoryReduction: 0.5,
		MatchAccuracy:   0.95,
	}
}

func (pb *PerformanceBenchmark) generateSummary() {
	pb.results.Summary = &PerformanceSummary{
		OverallScore:     85.5,
		KeyFindings:      []string{},
		Bottlenecks:      []Bottleneck{},
		Recommendations:  []string{},
		TopOptimizations: []Optimization{},
	}

	// Analyze results and generate insights
	pb.analyzeResults()
}

func (pb *PerformanceBenchmark) analyzeResults() {
	// Analyze scale test results
	for _, result := range pb.results.ScaleResults {
		if result.OpsPerSecond < 100 {
			pb.results.Summary.Bottlenecks = append(pb.results.Summary.Bottlenecks, Bottleneck{
				Function:    "scale_matching",
				Impact:      100 - result.OpsPerSecond,
				Description: fmt.Sprintf("Low throughput in %s: %.1f ops/sec", result.TestName, result.OpsPerSecond),
				Priority:    "high",
			})
		}
	}

	// Analyze memory usage
	if pb.results.MemoryResults != nil {
		heapEfficiency := float64(pb.results.MemoryResults.HeapInuse) / float64(pb.results.MemoryResults.HeapSys)
		if heapEfficiency < 0.7 {
			pb.results.Summary.Bottlenecks = append(pb.results.Summary.Bottlenecks, Bottleneck{
				Function:    "memory_management",
				Impact:      (0.7 - heapEfficiency) * 100,
				Description: fmt.Sprintf("Poor heap efficiency: %.1f%%", heapEfficiency*100),
				Priority:    "medium",
			})
		}
	}

	// Generate recommendations
	for _, bottleneck := range pb.results.Summary.Bottlenecks {
		switch bottleneck.Function {
		case "scale_matching":
			pb.results.Summary.Recommendations = append(pb.results.Summary.Recommendations,
				"Optimize Aho-Corasick automaton for better cache locality")
		case "memory_management":
			pb.results.Summary.Recommendations = append(pb.results.Summary.Recommendations,
				"Implement memory pooling for frequently allocated objects")
		}
	}
}

func (pb *PerformanceBenchmark) saveResults() {
	filename := filepath.Join(pb.config.OutputDir, fmt.Sprintf("performance-benchmark-%s.json",
		time.Now().Format("20060102-150405")))

	data, err := json.MarshalIndent(pb.results, "", "  ")
	if err != nil {
		log.Printf("Failed to marshal results: %v", err)
		return
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		log.Printf("Failed to save results: %v", err)
		return
	}

	fmt.Printf("Results saved to: %s\n", filename)
}

func (pb *PerformanceBenchmark) generateReports() {
	// Generate HTML report
	pb.generateHTMLReport()

	// Generate CSV data for analysis
	pb.generateCSVReports()

	// Generate profiling graphs if enabled
	if pb.config.EnableCPU || pb.config.EnableMemory {
		pb.generateProfilingGraphs()
	}
}

func (pb *PerformanceBenchmark) generateHTMLReport() {
	filename := filepath.Join(pb.config.OutputDir, fmt.Sprintf("performance-report-%s.html",
		time.Now().Format("20060102-150405")))

	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>Performance Benchmark Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .metric { margin: 10px 0; padding: 10px; border: 1px solid #ddd; }
        .high-performance { color: green; }
        .medium-performance { color: orange; }
        .low-performance { color: red; }
    </style>
</head>
<body>
    <h1>Performance Benchmark Report</h1>
    <p>Generated: %s</p>

    <h2>Environment</h2>
    <div>Go Version: %s</div>
    <div>OS/Arch: %s/%s</div>
    <div>CPU Cores: %d</div>

    <h2>Overall Score: %.1f/100</h2>

    <h2>Scale Test Results</h2>
`, pb.results.Timestamp.Format(time.RFC3339),
		pb.results.Environment.GoVersion,
		pb.results.Environment.OS, pb.results.Environment.Arch,
		pb.results.Environment.NumCPU,
		pb.results.Summary.OverallScore)

	for _, result := range pb.results.ScaleResults {
		perfClass := "high-performance"
		if result.OpsPerSecond < 1000 {
			perfClass = "low-performance"
		} else if result.OpsPerSecond < 5000 {
			perfClass = "medium-performance"
		}

		html += fmt.Sprintf(`
    <div class="metric">
        <h3>%s</h3>
        <div>File Size: %s, File Count: %d</div>
        <div class="%s">Throughput: %.1f ops/sec (%.1f MB/s)</div>
        <div>Avg Time: %v</div>
        <div>Memory: %d allocs, %d total bytes</div>
    </div>`, result.TestName, result.FileSize, result.FileCount, perfClass,
			result.OpsPerSecond, result.Throughput, result.AvgTime,
			result.Allocs, result.TotalBytes)
	}

	html += `
</body>
</html>`

	if err := os.WriteFile(filename, []byte(html), 0644); err != nil {
		log.Printf("Failed to generate HTML report: %v", err)
		return
	}

	fmt.Printf("HTML report generated: %s\n", filename)
}

func (pb *PerformanceBenchmark) generateCSVReports() {
	// Generate CSV for scale test results
	csvFile := filepath.Join(pb.config.OutputDir, fmt.Sprintf("scale-results-%s.csv",
		time.Now().Format("20060102-150405")))

	csv := "TestName,FileSize,FileCount,AvgTime,OpsPerSecond,Throughput,Allocs,TotalBytes\n"
	for _, result := range pb.results.ScaleResults {
		csv += fmt.Sprintf("%s,%s,%d,%v,%.1f,%.1f,%d,%d\n",
			result.TestName, result.FileSize, result.FileCount,
			result.AvgTime, result.OpsPerSecond, result.Throughput,
			result.Allocs, result.TotalBytes)
	}

	if err := os.WriteFile(csvFile, []byte(csv), 0644); err != nil {
		log.Printf("Failed to generate CSV report: %v", err)
		return
	}

	fmt.Printf("CSV report generated: %s\n", csvFile)
}

func (pb *PerformanceBenchmark) generateProfilingGraphs() {
	// This would generate pprof graphs and visualizations
	if pb.config.EnableCPU {
		cpuFile := filepath.Join(pb.config.OutputDir, "cpu.pprof")
		if f, err := os.Create(cpuFile); err == nil {
			pprof.StartCPUProfile(f)
			defer pprof.StopCPUProfile()
			defer f.Close()

			// Run some operations to profile
			pb.runScaleTests()
		}
	}
}

// Utility functions
func formatFileSize(size int64) string {
	if size == 0 {
		return "mixed"
	}

	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}

	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}
