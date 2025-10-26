// Package execution provides benchmarking for YARA rule execution
package execution

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/cawalch/go-yara/compiler"
)

// BenchmarkSuite provides comprehensive execution benchmarking
type BenchmarkSuite struct {
	testCases   []TestCase
	results     map[string]*BenchmarkResult
	cachedRules []*compiler.CompiledRule // Cache for compiled rules
}

// BenchmarkResult represents results from a single benchmark
type BenchmarkResult struct {
	Name           string
	Operations     int64
	NsPerOp        int64
	AllocedBytes   int64
	AllocsPerOp    int64
	MemoryPeak     int64
	BytesPerSecond float64
	RulesPerSecond float64
	Success        bool
	Error          string
	ProfileData    map[string]interface{}
}

// BenchmarkOptions provides options for running benchmarks
type BenchmarkOptions struct {
	Patterns    []string // Rule file patterns to include
	DataSizes   []int64  // Specific data sizes to test
	MinDataSize int64    // Minimum data size
	MaxDataSize int64    // Maximum data size
	MaxRules    int      // Maximum number of rules
	Timeout     time.Duration
	Parallel    bool
	ProfileCPU  bool
	ProfileMem  bool
}

// DefaultBenchmarkOptions returns sensible default benchmark options
func DefaultBenchmarkOptions() *BenchmarkOptions {
	return &BenchmarkOptions{
		MinDataSize: 1024,                                            // 1KB
		MaxDataSize: 10 * 1024 * 1024,                                // 10MB
		DataSizes:   []int64{1024, 10240, 102400, 1048576, 10485760}, // 1KB, 10KB, 100KB, 1MB, 10MB
		MaxRules:    50,
		Timeout:     60 * time.Second,
		Parallel:    true,
		ProfileCPU:  true,
		ProfileMem:  true,
	}
}

// NewBenchmarkSuite creates a new benchmark suite
func NewBenchmarkSuite(config *ProfilingConfig) *BenchmarkSuite {
	// config parameter reserved for future use
	_ = config // nolint:revive

	return &BenchmarkSuite{
		results: make(map[string]*BenchmarkResult),
	}
}

// RunAllBenchmarks runs a comprehensive benchmark suite
func (bs *BenchmarkSuite) RunAllBenchmarks(b *testing.B, opts *BenchmarkOptions) {
	if opts == nil {
		opts = DefaultBenchmarkOptions()
	}

	// Discover test cases
	if err := bs.discoverTestCases(opts); err != nil {
		b.Fatalf("Failed to discover test cases: %v", err)
	}

	if len(bs.testCases) == 0 {
		b.Skip("No test cases found for benchmarking")
	}

	b.Logf("Running benchmarks on %d test cases", len(bs.testCases))

	// Run different benchmark categories
	bs.runCompilationBenchmarks(b)
	bs.runExecutionBenchmarks(b)
	bs.runPatternMatchingBenchmarks(b)
	bs.runMemoryBenchmarks(b)

	if opts.ProfileCPU {
		bs.runCPUProfileBenchmarks(b)
	}

	// Generate benchmark report
	bs.generateBenchmarkReport(b)
}

// runCompilationBenchmarks benchmarks rule compilation performance
func (bs *BenchmarkSuite) runCompilationBenchmarks(b *testing.B) {
	b.Run("Compilation", func(b *testing.B) {
		// Group test cases by rule file to avoid re-compilation
		ruleGroups := bs.groupTestCasesByRule()

		for ruleFile, cases := range ruleGroups {
			if len(cases) == 0 {
				continue
			}

			b.Run(filepath.Base(ruleFile), func(b *testing.B) {
				bs.benchmarkRuleCompilation(b, ruleFile, cases[0])
			})
		}
	})
}

// runExecutionBenchmarks benchmarks rule execution performance
func (bs *BenchmarkSuite) runExecutionBenchmarks(b *testing.B) {
	b.Run("Execution", func(b *testing.B) {
		for _, testCase := range bs.testCases {
			b.Run(testCase.Name, func(b *testing.B) {
				bs.benchmarkRuleExecution(b, testCase)
			})
		}
	})
}

// runPatternMatchingBenchmarks benchmarks specific pattern matching components
func (bs *BenchmarkSuite) runPatternMatchingBenchmarks(b *testing.B) {
	b.Run("PatternMatching", func(b *testing.B) {
		bs.benchmarkAhoCorasick(b)
		bs.benchmarkRegexMatching(b)
		bs.benchmarkStringMatching(b)
	})
}

// runMemoryBenchmarks benchmarks memory usage patterns
func (bs *BenchmarkSuite) runMemoryBenchmarks(b *testing.B) {
	b.Run("Memory", func(b *testing.B) {
		bs.benchmarkInterpreterMemory(b)
		bs.benchmarkAutomatonMemory(b)
		bs.benchmarkRuleMemory(b)
	})
}

// runCPUProfileBenchmarks runs benchmarks with CPU profiling enabled
func (bs *BenchmarkSuite) runCPUProfileBenchmarks(b *testing.B) {
	b.Run("CPUProfile", func(b *testing.B) {
		// Focus on the most resource-intensive test cases
		sort.Slice(bs.testCases, func(i, j int) bool {
			return bs.testCases[i].DataSize > bs.testCases[j].DataSize
		})

		// Run top 5 largest test cases with profiling
		maxCases := 5
		if len(bs.testCases) < maxCases {
			maxCases = len(bs.testCases)
		}

		for i := 0; i < maxCases; i++ {
			testCase := bs.testCases[i]
			b.Run(testCase.Name, func(b *testing.B) {
				bs.benchmarkWithCPUProfile(b, testCase)
			})
		}
	})
}

// benchmarkRuleCompilation benchmarks compilation of a specific rule file
func (bs *BenchmarkSuite) benchmarkRuleCompilation(b *testing.B, ruleFile string, testCase TestCase) {
	_ = testCase // nolint: revive // Parameter reserved for future use
	// Read rule file content
	ruleContent, err := os.ReadFile(ruleFile)
	if err != nil {
		b.Fatalf("Failed to read rule file %s: %v", ruleFile, err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(int64(len(ruleContent)))

	var compiledRules []*compiler.CompiledRule

	for i := 0; i < b.N; i++ {
		runtime.GC() // Force GC before each iteration for cleaner measurement

		start := time.Now()
		compiledRules, err = bs.compileRules(ruleContent)
		if err != nil {
			b.Fatalf("Compilation failed: %v", err)
		}
		duration := time.Since(start)

		// Store first successful compilation for use in other benchmarks
		if i == 0 && len(compiledRules) > 0 {
			// Cache compiled rules for reuse in other benchmarks
			bs.cachedRules = make([]*compiler.CompiledRule, len(compiledRules))
			copy(bs.cachedRules, compiledRules)
		}

		// Report timing
		b.ReportMetric(float64(duration.Nanoseconds())/float64(len(compiledRules)), "ns/rule")
	}

	b.StopTimer()

	// Report compilation statistics
	b.ReportMetric(float64(len(compiledRules)), "rules/compile")
	if len(compiledRules) > 0 {
		totalStrings := 0
		for _, rule := range compiledRules {
			if rule.Automaton != nil {
				totalStrings += rule.Automaton.StringCount
			}
		}
		b.ReportMetric(float64(totalStrings), "strings/compile")
	}
}

// benchmarkRuleExecution benchmarks execution of compiled rules
func (bs *BenchmarkSuite) benchmarkRuleExecution(b *testing.B, testCase TestCase) {
	// Pre-compile rules
	compiledRules, err := bs.compileRulesFromFile(testCase.RuleFile)
	if err != nil {
		b.Fatalf("Failed to compile rules: %v", err)
	}

	if len(compiledRules) == 0 {
		b.Skip("No rules to execute")
	}

	// Read test data
	data, err := os.ReadFile(testCase.DataFile)
	if err != nil {
		b.Fatalf("Failed to read test data: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(testCase.DataSize)

	var totalMatches int
	var executionTime time.Duration

	for i := 0; i < b.N; i++ {
		runtime.GC()

		start := time.Now()
		matches, execErr := bs.executeRules(compiledRules, data)
		if execErr != nil {
			b.Fatalf("Execution failed: %v", execErr)
		}
		executionTime += time.Since(start)
		totalMatches += len(matches)
	}

	b.StopTimer()

	// Report execution metrics
	avgExecutionTime := executionTime / time.Duration(b.N)
	b.ReportMetric(float64(avgExecutionTime.Nanoseconds())/float64(testCase.DataSize), "ns/byte")
	b.ReportMetric(float64(avgExecutionTime.Nanoseconds())/float64(len(compiledRules)), "ns/rule_exec")
	b.ReportMetric(float64(totalMatches)/float64(b.N), "matches/exec")

	if avgExecutionTime > 0 {
		throughput := float64(testCase.DataSize) / avgExecutionTime.Seconds()
		b.ReportMetric(throughput/1024/1024, "MB/sec")
	}
}

// benchmarkAhoCorasick benchmarks Aho-Corasick automaton performance
func (bs *BenchmarkSuite) benchmarkAhoCorasick(b *testing.B) {
	b.Run("AutomatonSearch", func(b *testing.B) {
		// Create test patterns
		patterns := []struct {
			name string
			data []byte
		}{
			{"short_text", []byte("example")},
			{"medium_text", []byte("intermediate_pattern")},
			{"long_hex", make([]byte, 32)}, // 32-byte hex pattern
		}

		// Generate test data
		testData := make([]byte, 64*1024) // 64KB
		for i := range testData {
			testData[i] = byte(i % 256)
		}

		for _, pattern := range patterns {
			b.Run(pattern.name, func(b *testing.B) {
				// Create automaton
				ac := compiler.NewACAutomaton()
				err := ac.AddString("test_pattern", pattern.data, false, false)
				if err != nil {
					b.Fatalf("Failed to add pattern: %v", err)
				}
				err = ac.Compile()
				if err != nil {
					b.Fatalf("Failed to compile automaton: %v", err)
				}

				b.ResetTimer()
				b.ReportAllocs()
				b.SetBytes(int64(len(testData)))

				var matches []compiler.ACMatch
				for i := 0; i < b.N; i++ {
					matches = ac.Search(testData)
				}

				b.StopTimer()
				b.ReportMetric(float64(len(matches)), "matches/search")
			})
		}
	})
}

// benchmarkRegexMatching benchmarks regex engine performance
func (bs *BenchmarkSuite) benchmarkRegexMatching(b *testing.B) {
	regexPatterns := []struct {
		name    string
		pattern string
		flags   int
	}{
		{"simple_literal", "abc", 0},
		{"simple_wildcard", "a.c", 0},
		{"character_class", "[a-z]+", 0},
		{"repetition", "a+", 0},
		{"alternation", "a|b|c", 0},
	}

	// Generate test data containing matches
	testData := make([]byte, 32*1024)
	for i := range testData {
		testData[i] = byte('a' + (i % 26))
	}

	for _, rp := range regexPatterns {
		b.Run(rp.name, func(b *testing.B) {
			// Compile regex
			regex := bs.compileRegex(rp.pattern, rp.flags)
			if regex == nil {
				b.Skip("Regex compilation failed")
			}

			b.ResetTimer()
			b.ReportAllocs()
			b.SetBytes(int64(len(testData)))

			var matches int
			for i := 0; i < b.N; i++ {
				matches = bs.matchRegex(regex, testData)
			}

			b.StopTimer()
			b.ReportMetric(float64(matches), "matches")
		})
	}
}

// benchmarkStringMatching benchmarks string matching performance
func (bs *BenchmarkSuite) benchmarkStringMatching(b *testing.B) {
	testCases := []struct {
		name     string
		pattern  string
		dataSize int
	}{
		{"short_pattern", "test", 1024},
		{"medium_pattern", "intermediate_string", 10240},
		{"long_pattern", "very_long_search_pattern_string", 102400},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			// Create test data
			data := make([]byte, tc.dataSize)
			for i := range data {
				data[i] = byte('a' + (i % 26))
			}

			// Insert pattern at random positions
			patternBytes := []byte(tc.pattern)
			for i := 0; i < 10; i++ {
				pos := (i * tc.dataSize / 10) % (tc.dataSize - len(patternBytes))
				copy(data[pos:], patternBytes)
			}

			b.ResetTimer()
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))

			var matches int
			for i := 0; i < b.N; i++ {
				matches = bs.countStringOccurrences(data, patternBytes)
			}

			b.StopTimer()
			b.ReportMetric(float64(matches), "matches")
		})
	}
}

// benchmarkInterpreterMemory benchmarks interpreter memory usage
func (bs *BenchmarkSuite) benchmarkInterpreterMemory(b *testing.B) {
	// Test different interpreter configurations
	configs := []struct {
		name        string
		stackSize   int
		memorySlots int
		ruleCount   int
	}{
		{"small", 64, 64, 1},
		{"medium", 256, 256, 10},
		{"large", 1024, 512, 50},
	}

	for _, config := range configs {
		b.Run(config.name, func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				runtime.GC()

				// Create interpreter with specific configuration
				interpreter := bs.createInterpreter(config.stackSize, config.memorySlots)

				// Simulate rule execution
				bs.simulateExecution(interpreter, config.ruleCount)
			}
		})
	}
}

// benchmarkAutomatonMemory benchmarks Aho-Corasick automaton memory usage
func (bs *BenchmarkSuite) benchmarkAutomatonMemory(b *testing.B) {
	stringCounts := []int{10, 50, 100, 500, 1000}

	for _, count := range stringCounts {
		b.Run(fmt.Sprintf("strings_%d", count), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				runtime.GC()

				// Create automaton with many strings
				ac := compiler.NewACAutomaton()

				for j := 0; j < count; j++ {
					pattern := fmt.Sprintf("pattern_%d", j)
					data := []byte(pattern)
					if err := ac.AddString(pattern, data, false, false); err != nil {
						b.Logf("Failed to add pattern %s to automaton: %v", pattern, err)
						continue
					}
				}

				if err := ac.Compile(); err != nil {
					b.Logf("Failed to compile automaton: %v", err)
					continue
				}
			}

			b.ReportMetric(float64(count), "strings/automaton")
		})
	}
}

// benchmarkRuleMemory benchmarks rule memory usage
func (bs *BenchmarkSuite) benchmarkRuleMemory(b *testing.B) {
	// Test memory usage for different types of rules
	ruleTypes := []struct {
		name string
		rule string
	}{
		{"simple_string", `rule test { strings: $a = "test" condition: $a }`},
		{"multiple_strings", `rule test { strings: $a = "test" $b = "example" condition: $a or $b }`},
		{"hex_pattern", `rule test { strings: $a = { 48 65 6C 6C 6F } condition: $a }`},
		{"regex_pattern", `rule test { strings: $a = /test.*example/ condition: $a }`},
	}

	for _, rt := range ruleTypes {
		b.Run(rt.name, func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				runtime.GC()

				// Compile rule
				compiledRules, err := bs.compileRules([]byte(rt.rule))
				if err != nil {
					b.Fatalf("Failed to compile rule: %v", err)
				}

				// Simulate execution
				data := []byte("test example data")
				if _, execErr := bs.executeRules(compiledRules, data); execErr != nil {
					b.Logf("Failed to execute rules: %v", execErr)
					continue
				}
			}
		})
	}
}

// benchmarkWithCPUProfile runs a benchmark with CPU profiling enabled
func (bs *BenchmarkSuite) benchmarkWithCPUProfile(b *testing.B, testCase TestCase) {
	// This would integrate with runtime/pprof for CPU profiling
	// For now, just run the standard benchmark
	bs.benchmarkRuleExecution(b, testCase)
}

// Helper methods (these would integrate with actual compiler/interpreter)

func (bs *BenchmarkSuite) compileRules(ruleContent []byte) ([]*compiler.CompiledRule, error) {
	// Placeholder implementation
	return []*compiler.CompiledRule{}, nil
}

func (bs *BenchmarkSuite) compileRulesFromFile(filename string) ([]*compiler.CompiledRule, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return bs.compileRules(content)
}

func (bs *BenchmarkSuite) executeRules(rules []*compiler.CompiledRule, data []byte) ([]compiler.Match, error) {
	// Placeholder implementation
	return []compiler.Match{}, nil
}

func (bs *BenchmarkSuite) compileRegex(pattern string, flags int) interface{} {
	// Placeholder implementation
	return nil
}

func (bs *BenchmarkSuite) matchRegex(regex interface{}, data []byte) int {
	// Placeholder implementation
	return 0
}

func (bs *BenchmarkSuite) countStringOccurrences(data, pattern []byte) int {
	// Simple string search implementation
	count := 0
	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j := range pattern {
			if data[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			count++
		}
	}
	return count
}

func (bs *BenchmarkSuite) createInterpreter(stackSize, memorySlots int) *compiler.Interpreter {
	// Parameters reserved for future use
	_ = stackSize   // nolint: revive
	_ = memorySlots // nolint: revive
	// Placeholder implementation
	return compiler.NewInterpreter(nil)
}

func (bs *BenchmarkSuite) simulateExecution(interpreter *compiler.Interpreter, ruleCount int) {
	// Placeholder implementation
}

func (bs *BenchmarkSuite) discoverTestCases(opts *BenchmarkOptions) error {
	// Implementation similar to profiler.DiscoverTestCases
	return nil
}

func (bs *BenchmarkSuite) groupTestCasesByRule() map[string][]TestCase {
	groups := make(map[string][]TestCase)
	for _, tc := range bs.testCases {
		groups[tc.RuleFile] = append(groups[tc.RuleFile], tc)
	}
	return groups
}

func (bs *BenchmarkSuite) generateBenchmarkReport(b *testing.B) {
	// Generate comprehensive benchmark report
	b.Logf("Benchmark Summary:")
	b.Logf("  Total test cases: %d", len(bs.results))

	if len(bs.results) > 0 {
		var avgNsPerOp, avgAllocedBytes, avgAllocsPerOp float64
		count := 0

		for _, result := range bs.results {
			if result.Success {
				avgNsPerOp += float64(result.NsPerOp)
				avgAllocedBytes += float64(result.AllocedBytes)
				avgAllocsPerOp += float64(result.AllocsPerOp)
				count++
			}
		}

		if count > 0 {
			avgNsPerOp /= float64(count)
			avgAllocedBytes /= float64(count)
			avgAllocsPerOp /= float64(count)

			b.Logf("  Average ns/op: %.0f", avgNsPerOp)
			b.Logf("  Average B/op: %.0f", avgAllocedBytes)
			b.Logf("  Average allocs/op: %.0f", avgAllocsPerOp)
		}
	}
}
