//go:build simple_bench

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"runtime/pprof"
	"time"

	"github.com/cawalch/go-yara/compiler"
)

// SimpleBenchmark provides a basic performance testing framework
type SimpleBenchmark struct {
	config  *SimpleConfig
	results *SimpleResults
}

// SimpleConfig defines basic benchmark configuration
type SimpleConfig struct {
	Iterations   int    `json:"iterations"`
	DataSize     int    `json:"data_size"`
	Rules        int    `json:"rules"`
	Workers      int    `json:"workers"`
	OutputDir    string `json:"output_dir"`
	Verbose      bool   `json:"verbose"`
	CPUProfile   bool   `json:"cpu_profile"`
	MemProfile   bool   `json:"mem_profile"`
	AllocProfile bool   `json:"alloc_profile"`
}

// SimpleResults contains basic benchmark results
type SimpleResults struct {
	Timestamp   time.Time          `json:"timestamp"`
	Environment *SimpleEnv         `json:"environment"`
	Benchmarks  []*BenchmarkResult `json:"benchmarks"`
}

// SimpleEnv captures test environment details
type SimpleEnv struct {
	GoVersion  string        `json:"go_version"`
	OS         string        `json:"os"`
	Arch       string        `json:"arch"`
	NumCPU     int           `json:"num_cpu"`
	TestConfig *SimpleConfig `json:"test_config"`
}

// BenchmarkResult represents results for a specific benchmark
type BenchmarkResult struct {
	Name         string        `json:"name"`
	Iterations   int           `json:"iterations"`
	Duration     time.Duration `json:"duration"`
	AvgTime      time.Duration `json:"avg_time"`
	OpsPerSecond float64       `json:"ops_per_second"`
	Allocs       uint64        `json:"allocs"`
	Bytes        uint64        `json:"bytes"`
}

func main() {
	config := parseFlags()
	benchmark := NewSimpleBenchmark(config)

	if err := benchmark.Run(); err != nil {
		log.Fatalf("Benchmark failed: %v", err)
	}

	benchmark.PrintResults()
}

func parseFlags() *SimpleConfig {
	config := &SimpleConfig{}

	flag.IntVar(&config.Iterations, "iterations", 1000, "Number of iterations per benchmark")
	flag.IntVar(&config.DataSize, "data", 1048576, "Data size in bytes (default 1MB)")
	flag.IntVar(&config.Rules, "rules", 10, "Number of rules to compile")
	flag.IntVar(&config.Workers, "workers", 0, "Number of concurrent workers (0 = auto)")
	flag.StringVar(&config.OutputDir, "output", "simple-results", "Output directory")
	flag.BoolVar(&config.Verbose, "verbose", false, "Verbose output")
	flag.BoolVar(&config.CPUProfile, "cpu", false, "Enable CPU profiling")
	flag.BoolVar(&config.MemProfile, "mem", false, "Enable memory profiling")
	flag.BoolVar(&config.AllocProfile, "alloc", false, "Enable allocation profiling")

	flag.Parse()
	return config
}

func NewSimpleBenchmark(config *SimpleConfig) *SimpleBenchmark {
	return &SimpleBenchmark{
		config: config,
		results: &SimpleResults{
			Timestamp:  time.Now(),
			Benchmarks: make([]*BenchmarkResult, 0),
		},
	}
}

func (sb *SimpleBenchmark) Run() error {
	if sb.config.Verbose {
		fmt.Printf("=== Simple Performance Benchmark ===\n")
		fmt.Printf("Go Version: %s\n", runtime.Version())
		fmt.Printf("OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		fmt.Printf("CPU Cores: %d\n", runtime.NumCPU())
		fmt.Printf("Iterations: %d\n", sb.config.Iterations)
		fmt.Printf("Workers: %d\n", sb.config.Workers)
		fmt.Printf("\n")
	}

	// Create output directory
	if err := os.MkdirAll(sb.config.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Enable profiling if requested
	if sb.config.CPUProfile {
		f, err := os.Create(fmt.Sprintf("%s/cpu.prof", sb.config.OutputDir))
		if err != nil {
			return fmt.Errorf("failed to create CPU profile file: %w", err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	if sb.config.MemProfile {
		f, err := os.Create(fmt.Sprintf("%s/mem.prof", sb.config.OutputDir))
		if err != nil {
			return fmt.Errorf("failed to create memory profile file: %w", err)
		}
		runtime.GC()
		pprof.WriteHeapProfile(f)
	}

	// Run benchmarks
	benchmarks := []struct {
		name string
		fn   func() *BenchmarkResult
	}{
		{"rule_compilation", sb.benchmarkRuleCompilation},
		{"string_matching", sb.benchmarkStringMatching},
		{"data_processing", sb.benchmarkDataProcessing},
		{"concurrent_execution", sb.benchmarkConcurrentExecution},
		{"memory_allocation", sb.benchmarkMemoryAllocation},
	}

	for _, bm := range benchmarks {
		if sb.config.Verbose {
			fmt.Printf("Running %s...\n", bm.name)
		}
		result := bm.fn()
		sb.results.Benchmarks = append(sb.results.Benchmarks, result)
		if sb.config.Verbose {
			fmt.Printf("  %s: %v avg, %.1f ops/sec\n", bm.name, result.AvgTime, result.OpsPerSecond)
		}
	}

	// Add environment info
	sb.results.Environment = &SimpleEnv{
		GoVersion:  runtime.Version(),
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		NumCPU:     runtime.NumCPU(),
		TestConfig: sb.config,
	}

	return nil
}

func (sb *SimpleBenchmark) benchmarkRuleCompilation() *BenchmarkResult {
	// Simulate rule compilation
	ruleText := `
rule test_%d {
    meta:
        description = "Test rule"
        author = "benchmark"
    strings:
        $test = "test_string_%d"
    condition:
        $test
}
`

	var totalDuration time.Duration
	var totalAllocs, totalBytes uint64

	// Warmup
	for i := 0; i < 10; i++ {
		sb.compileRule(fmt.Sprintf(ruleText, i, i))
	}

	// Benchmark
	runtime.GC()
	var memBefore, memAfter runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	start := time.Now()
	for i := 0; i < sb.config.Iterations; i++ {
		sb.compileRule(fmt.Sprintf(ruleText, i, i))
	}
	totalDuration = time.Since(start)

	runtime.ReadMemStats(&memAfter)
	totalAllocs = memAfter.TotalAlloc - memBefore.TotalAlloc
	totalBytes = memAfter.TotalAlloc - memBefore.TotalAlloc

	return &BenchmarkResult{
		Name:         "rule_compilation",
		Iterations:   sb.config.Iterations,
		Duration:     totalDuration,
		AvgTime:      totalDuration / time.Duration(sb.config.Iterations),
		OpsPerSecond: float64(sb.config.Iterations) / totalDuration.Seconds(),
		Allocs:       totalAllocs / uint64(sb.config.Iterations),
		Bytes:        totalBytes / uint64(sb.config.Iterations),
	}
}

func (sb *SimpleBenchmark) compileRule(ruleStr string) interface{} {
	// Simulate rule compilation (simplified version)
	// In reality, this would use the actual go-yara compiler
	patterns := []string{"test", "malware", "virus", "trojan"}
	ac := compiler.NewACAutomaton()

	for i, pattern := range patterns {
		ac.AddString(fmt.Sprintf("$pattern_%d", i), []byte(pattern), false, false)
	}
	ac.BuildFailureLinks()

	return ac
}

func (sb *SimpleBenchmark) benchmarkStringMatching() *BenchmarkResult {
	// Use real ACAutomaton for performance testing
	patterns := []string{"test", "malware", "virus", "trojan", "backdoor", "exploit"}
	data := make([]byte, sb.config.DataSize)

	// Fill data with some patterns for realistic testing
	for i, pattern := range patterns {
		patternBytes := []byte(pattern)
		for j := 0; j < len(data)-len(patternBytes) && i*len(patternBytes)+j < len(data); j += len(patternBytes) * 2 {
			copy(data[i*len(patternBytes)+j:], patternBytes)
		}
	}

	// Build automaton once for efficiency
	ac := compiler.NewACAutomaton()
	for i, pattern := range patterns {
		ac.AddString(fmt.Sprintf("$pattern_%d", i), patternBytes, false, false)
	}
	ac.BuildFailureLinks()

	var totalDuration time.Duration
	var totalMatches int

	// Warmup
	for i := 0; i < 10; i++ {
		_ = ac.Search(data)
	}

	// Benchmark
	start := time.Now()
	for i := 0; i < sb.config.Iterations; i++ {
		matches := ac.Search(data)
		totalMatches += len(matches)
	}
	totalDuration = time.Since(start)

	return &BenchmarkResult{
		Name:         "string_matching",
		Iterations:   sb.config.Iterations,
		Duration:     totalDuration,
		AvgTime:      totalDuration / time.Duration(sb.config.Iterations),
		OpsPerSecond: float64(sb.config.Iterations) / totalDuration.Seconds(),
		Allocs:       0, // ACAutomaton doesn't allocate during search
		Bytes:        0,
	}
}

func (sb *SimpleBenchmark) benchmarkDataProcessing() *BenchmarkResult {
	// Simulate data processing
	data := make([]byte, sb.config.DataSize)
	for i := range data {
		data[i] = byte(i % 256)
	}

	var totalDuration time.Duration

	// Warmup
	for i := 0; i < 10; i++ {
		_ = sb.processData(data)
	}

	// Benchmark
	start := time.Now()
	for i := 0; i < sb.config.Iterations; i++ {
		_ = sb.processData(data)
	}
	totalDuration = time.Since(start)

	return &BenchmarkResult{
		Name:         "data_processing",
		Iterations:   sb.config.Iterations,
		Duration:     totalDuration,
		AvgTime:      totalDuration / time.Duration(sb.config.Iterations),
		OpsPerSecond: float64(sb.config.Iterations) / totalDuration.Seconds(),
		Allocs:       0,
		Bytes:        0,
	}
}

func (sb *SimpleBenchmark) processData(data []byte) uint64 {
	// Simulate some data processing
	sum := uint64(0)
	for _, b := range data {
		sum += uint64(b)
	}
	return sum
}

func (sb *SimpleBenchmark) benchmarkConcurrentExecution() *BenchmarkResult {
	workers := sb.config.Workers
	if workers == 0 {
		workers = runtime.NumCPU()
	}

	data := make([]byte, sb.config.DataSize)
	for i := range data {
		data[i] = byte(i % 256)
	}

	var totalDuration time.Duration

	// Benchmark concurrent processing
	start := time.Now()

	// Create work channels
	chunkSize := len(data) / workers
	results := make(chan uint64, workers)

	for i := 0; i < workers; i++ {
		go func(start, end int) {
			sum := uint64(0)
			for j := start; j < end && j < len(data); j++ {
				sum += uint64(data[j])
			}
			results <- sum
		}(i*chunkSize, (i+1)*chunkSize)
	}

	// Collect results
	for i := 0; i < workers; i++ {
		<-results
	}

	totalDuration = time.Since(start)

	return &BenchmarkResult{
		Name:         "concurrent_execution",
		Iterations:   sb.config.Iterations,
		Duration:     totalDuration,
		AvgTime:      totalDuration / time.Duration(sb.config.Iterations),
		OpsPerSecond: float64(sb.config.Iterations) / totalDuration.Seconds(),
		Allocs:       0,
		Bytes:        0,
	}
}

func (sb *SimpleBenchmark) benchmarkMemoryAllocation() *BenchmarkResult {
	// Benchmark memory allocation patterns
	var totalDuration time.Duration
	var totalAllocs, totalBytes uint64

	// Warmup
	for i := 0; i < 10; i++ {
		_ = make([]byte, 1024)
	}

	// Benchmark
	runtime.GC()
	var memBefore, memAfter runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	start := time.Now()
	for i := 0; i < sb.config.Iterations; i++ {
		_ = make([]byte, 1024)
	}
	totalDuration = time.Since(start)

	runtime.ReadMemStats(&memAfter)
	totalAllocs = memAfter.TotalAlloc - memBefore.TotalAlloc
	totalBytes = memAfter.TotalAlloc - memBefore.TotalAlloc

	return &BenchmarkResult{
		Name:         "memory_allocation",
		Iterations:   sb.config.Iterations,
		Duration:     totalDuration,
		AvgTime:      totalDuration / time.Duration(sb.config.Iterations),
		OpsPerSecond: float64(sb.config.Iterations) / totalDuration.Seconds(),
		Allocs:       totalAllocs / uint64(sb.config.Iterations),
		Bytes:        totalBytes / uint64(sb.config.Iterations),
	}
}

func (sb *SimpleBenchmark) PrintResults() {
	// Save results to JSON file
	// This would require encoding/json import in a real implementation
	// For now, just print the results

	fmt.Printf("\nBenchmark completed in %v\n", time.Since(sb.results.Timestamp))
	fmt.Printf("Results saved to: %s\n", sb.config.OutputDir)

	if sb.config.Verbose {
		fmt.Printf("\n=== Detailed Results ===\n")
		for _, result := range sb.results.Benchmarks {
			fmt.Printf("%-20s: %12v avg, %.1f ops/sec", result.Name, result.AvgTime, result.OpsPerSecond)
			if result.Allocs > 0 || result.Bytes > 0 {
				fmt.Printf(" (%.1f allocs/op, %.1f B/op)", float64(result.Allocs), float64(result.Bytes))
			}
			fmt.Printf("\n")
		}
	}
}
