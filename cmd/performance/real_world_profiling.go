//go:build profiling_tool

package main

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"time"

	. "github.com/cawalch/go-yara/compiler"
)

// RealWorldProfiling tests realistic YARA workloads based on comparison data
type RealWorldProfiling struct {
	Scenarios []ProfilingScenario
}

type ProfilingScenario struct {
	Name        string
	Description string
	Rules       []string
	DataSize    int64
	Iterations  int
}

func main() {
	fmt.Printf("=== Real-World YARA Performance Profiling ===\n")
	fmt.Printf("Go Version: %s\n", runtime.Version())
	fmt.Printf("OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("CPU Cores: %d\n", runtime.NumCPU())
	fmt.Printf("\n")

	profiling := &RealWorldProfiling{
		Scenarios: []ProfilingScenario{
			{
				Name:        "Small Files, Many Rules",
				Description: "Realistic malware analysis - 1KB files with 10 rules",
				DataSize:    1024,
				Iterations:  10000,
				Rules: []string{
					`rule SmallString1 { strings: $s1 = "malware"; condition: $s1 }`,
					`rule SmallString2 { strings: $s2 = "trojan"; condition: $s2 }`,
					`rule SmallString3 { strings: $s3 = "virus"; condition: $s3 }`,
					`rule SmallString4 { strings: $s4 = "backdoor"; condition: $s4 }`,
					`rule SmallString5 { strings: $s5 = "rootkit"; condition: $s5 }`,
					`rule SmallHex1 { strings: $h1 = { 4D 5A }; condition: $h1 }`,       // PE header
					`rule SmallHex2 { strings: $h2 = { 7F 45 4C 46 }; condition: $h2 }`, // ELF header
					`rule SmallRegex1 { strings: $r1 = /test.*pattern/i; condition: $r1 }`,
					`rule SmallRegex2 { strings: $r2 = /[a-zA-Z0-9]{32}/; condition: $r2 }`,
					`rule SmallSize { condition: filesize > 512 and filesize < 2048 }`,
				},
			},
			{
				Name:        "Large Files, Few Rules",
				Description: "Large file analysis - 100KB files with 5 rules",
				DataSize:    102400,
				Iterations:  1000,
				Rules: []string{
					`rule LargePE { strings: $pe = "MZ"; condition: $pe and filesize > 50000 }`,
					`rule LargeStrings { strings: $s1 = "suspicious"; $s2 = "malicious"; condition: $s1 or $s2 }`,
					`rule LargeHex { strings: $hex = { 50 4B 03 04 }; condition: $hex }`, // ZIP header
					`rule LargeRegex { strings: $regex = /function\s+\w+\s*\(/; condition: $regex }`,
					`rule LargeConditions { condition: filesize > 80000 and uint32be(0) == 0x89504E47 }`, // PNG
				},
			},
			{
				Name:        "Mixed Pattern Types",
				Description: "Complex rule set with all pattern types - 10KB files with 8 rules",
				DataSize:    10240,
				Iterations:  2000,
				Rules: []string{
					`rule Mixed1 { strings: $a = "test"; $b = { 74 65 73 74 }; $c = /t..t/; condition: $a or $b or $c }`,
					`rule Mixed2 { strings: $wide = "test" wide; condition: $wide }`,
					`rule Mixed3 { strings: $xor = { 55 55 55 55 } xor 0x20; condition: $xor }`,
					`rule Mixed4 { strings: $base64 = "dGVzdA==" base64; condition: $base64 }`,
					`rule Mixed5 { strings: $alt = "test" | "demo" | "sample"; condition: $alt }`,
					`rule Mixed6 { strings: $jump = { 74 65 [5-10] 74 }; condition: $jump }`,
					`rule Mixed7 { strings: $wild = { 74 ?? 73 74 }; condition: $wild }`,
					`rule Mixed8 { condition: uint16(0) == 0x4D5A and uint32be(0) == 0x00004550 }`, // PE with sections
				},
			},
		},
	}

	// Create profiling output files
	cpuFile, err := os.Create("real_world_cpu.prof")
	if err != nil {
		panic(err)
	}
	defer cpuFile.Close()

	memFile, err := os.Create("real_world_mem.prof")
	if err != nil {
		panic(err)
	}
	defer memFile.Close()

	// Start profiling
	pprof.StartCPUProfile(cpuFile)
	defer pprof.StopCPUProfile()

	// Run all scenarios
	for i, scenario := range profiling.Scenarios {
		fmt.Printf("=== Scenario %d: %s ===\n", i+1, scenario.Name)
		fmt.Printf("Description: %s\n", scenario.Description)
		fmt.Printf("Data Size: %d bytes, Iterations: %d\n", scenario.DataSize, scenario.Iterations)

		// Profile each scenario
		result := profiling.runScenario(scenario)
		profiling.printResults(result)

		// Force GC between scenarios
		runtime.GC()
		fmt.Printf("\n")
	}

	// Memory profiling at the end
	runtime.GC()
	pprof.WriteHeapProfile(memFile)

	profiling.printSummary()
}

type ScenarioResult struct {
	ScenarioName        string
	TotalTime           time.Duration
	AvgTime             time.Duration
	OpsPerSecond        float64
	TotalMatches        int
	MemoryAllocs        uint64
	MemoryBytes         uint64
	BottleneckFunctions []FunctionProfile
}

type FunctionProfile struct {
	Name      string
	CPUTime   time.Duration
	CallCount int64
}

func (rp *RealWorldProfiling) runScenario(scenario ProfilingScenario) ScenarioResult {
	// Generate test data
	data := rp.generateTestData(scenario.DataSize)

	var totalTime time.Duration
	var totalMatches int

	// Track memory before
	var memBefore, memAfter runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	// Warmup
	rp.executeRules(scenario.Rules, data, 10)

	// Benchmark
	start := time.Now()
	for i := 0; i < scenario.Iterations; i++ {
		matches := rp.executeRules(scenario.Rules, data, 1)
		totalMatches += matches
	}
	totalTime = time.Since(start)

	runtime.ReadMemStats(&memAfter)

	avgTime := totalTime / time.Duration(scenario.Iterations)
	opsPerSec := float64(scenario.Iterations) / totalTime.Seconds()

	return ScenarioResult{
		ScenarioName: scenario.Name,
		TotalTime:    totalTime,
		AvgTime:      avgTime,
		OpsPerSecond: opsPerSec,
		TotalMatches: totalMatches,
		MemoryAllocs: memAfter.TotalAlloc - memBefore.TotalAlloc,
		MemoryBytes:  memAfter.TotalAlloc - memBefore.TotalAlloc,
	}
}

func (rp *RealWorldProfiling) executeRules(rules []string, data []byte, iterations int) int {
	totalMatches := 0

	for iter := 0; iter < iterations; iter++ {
		for _, ruleText := range rules {
			// Create pattern matcher for this rule
			pm := NewPatternMatcher()

			// Extract patterns from rule (simplified)
			patterns := rp.extractPatternsFromRule(ruleText)

			// Add patterns to matcher
			for i, pattern := range patterns {
				identifier := fmt.Sprintf("$pattern_%d", i)
				err := pm.AddPattern(identifier, []byte(pattern), false, false)
				if err != nil {
					continue
				}
			}

			// Compile and match
			err := pm.Compile()
			if err != nil {
				continue
			}

			matches := pm.MatchPatternsOptimized(data)
			for _, patternMatches := range matches {
				totalMatches += len(patternMatches)
			}
		}
	}

	return totalMatches
}

func (rp *RealWorldProfiling) extractPatternsFromRule(ruleText string) []string {
	// Simplified pattern extraction - real implementation would parse YARA syntax
	patterns := []string{}

	// Look for common patterns
	if contains(ruleText, "malware") {
		patterns = append(patterns, "malware")
	}
	if contains(ruleText, "trojan") {
		patterns = append(patterns, "trojan")
	}
	if contains(ruleText, "virus") {
		patterns = append(patterns, "virus")
	}
	if contains(ruleText, "MZ") {
		patterns = append(patterns, "MZ")
	}
	if contains(ruleText, "test") {
		patterns = append(patterns, "test")
	}

	// Add hex patterns
	if contains(ruleText, "{ 4D 5A }") {
		patterns = append(patterns, "MZ")
	}

	return patterns
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if s[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func (rp *RealWorldProfiling) generateTestData(size int64) []byte {
	data := make([]byte, size)

	// Add realistic content patterns
	patterns := [][]byte{
		[]byte("MZ"), // PE header
		[]byte("This program cannot be run"),
		[]byte("malware"),
		[]byte("trojan"),
		[]byte("virus"),
		[]byte("suspicious"),
		[]byte("test"),
		{0x4D, 0x5A},             // PE header in hex
		{0x50, 0x4B, 0x03, 0x04}, // ZIP header
	}

	// Distribute patterns throughout the data
	for i := int64(0); i < size-100; i += 200 {
		patternIndex := int(i/200) % len(patterns)
		pattern := patterns[patternIndex]
		patternLen := int64(len(pattern))
		if i+patternLen < size {
			copy(data[i:i+patternLen], pattern)
		}
	}

	// Fill remaining with random-like data
	for i := range data {
		if data[i] == 0 {
			data[i] = byte(i % 256)
		}
	}

	return data
}

func (rp *RealWorldProfiling) printResults(result ScenarioResult) {
	fmt.Printf("Results:\n")
	fmt.Printf("  Total Time:     %v\n", result.TotalTime)
	fmt.Printf("  Average Time:   %v\n", result.AvgTime)
	fmt.Printf("  Operations/sec: %.1f\n", result.OpsPerSecond)
	fmt.Printf("  Total Matches:  %d\n", result.TotalMatches)
	fmt.Printf("  Memory Allocs:  %d\n", result.MemoryAllocs)
	fmt.Printf("  Memory Bytes:   %d KB\n", result.MemoryBytes/1024)

	// Performance analysis
	if result.OpsPerSecond < 100 {
		fmt.Printf("  ⚠ Performance: Very slow (< 100 ops/sec)\n")
	} else if result.OpsPerSecond < 1000 {
		fmt.Printf("  ⚠ Performance: Slow (< 1000 ops/sec)\n")
	} else if result.OpsPerSecond < 10000 {
		fmt.Printf("  ✓ Performance: Moderate (1000-10000 ops/sec)\n")
	} else {
		fmt.Printf("  ✓ Performance: Fast (> 10000 ops/sec)\n")
	}
}

func (rp *RealWorldProfiling) printSummary() {
	fmt.Printf("=== Profiling Summary ===\n")
	fmt.Printf("Generated profiling files:\n")
	fmt.Printf("  - real_world_cpu.prof (use: go tool pprof real_world_cpu.prof)\n")
	fmt.Printf("  - real_world_mem.prof (use: go tool pprof real_world_mem.prof)\n")
	fmt.Printf("\nAnalysis completed successfully.\n")
}
