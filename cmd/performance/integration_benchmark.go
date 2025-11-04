//go:build integration_bench

package main

import (
	"fmt"
	"runtime"
	"time"

	"github.com/cawalch/go-yara/compiler"
	. "github.com/cawalch/go-yara/compiler"
)

// IntegrationBenchmark tests the complete pipeline performance
type IntegrationBenchmark struct {
	Patterns []string
	Data     []byte
}

func main() {
	fmt.Printf("=== End-to-End Integration Benchmark ===\n")
	fmt.Printf("Go Version: %s\n", runtime.Version())
	fmt.Printf("OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("CPU Cores: %d\n", runtime.NumCPU())
	fmt.Printf("\n")

	// Realistic test data
	patterns := []string{
		"MZ",                         // PE header
		"This program cannot be run", // Windows error message
		"ELF",                        // ELF header
		"#!/bin/sh",                  // Shell script
		"<html>",                     // HTML marker
		"PK\x03\x04",                 // ZIP header
		"\xFF\xD8\xFF",               // JPEG header
		"\x89PNG\r\n\x1A\n",          // PNG header
		"GIF89a",                     // GIF header
		"malware",                    // General malware strings
		"trojan",                     // Trojan indicators
		"backdoor",                   // Backdoor strings
		"rootkit",                    // Rootkit indicators
		"suspicious",                 // Suspicious patterns
		"virus",                      // Virus signatures
	}

	// Create realistic test data (1MB)
	data := make([]byte, 1024*1024)

	// Add some PE-like headers
	copy(data[0:2], []byte("MZ"))
	copy(data[1000:1017], []byte("This program cannot be run"))

	// Add various file signatures throughout
	fileSignatures := [][]byte{
		[]byte("ELF"),
		[]byte("#!/bin/bash"),
		[]byte("<html>"),
		[]byte("PK\x03\x04"),
		[]byte("\xFF\xD8\xFF"),
		[]byte("\x89PNG\r\n\x1A\n"),
		[]byte("GIF89a"),
	}

	// Distribute patterns throughout the data
	for i := 0; i < len(data)-200; i += 200 {
		sigIndex := (i / 200) % len(fileSignatures)
		copy(data[i:i+len(fileSignatures[sigIndex])], fileSignatures[sigIndex])
	}

	// Add some malware-like strings
	malwareStrings := []string{"malware", "trojan", "backdoor", "suspicious"}
	for i := 0; i < len(data)-50; i += 500 {
		strIndex := (i / 500) % len(malwareStrings)
		copy(data[i:i+len(malwareStrings[strIndex])], malwareStrings[strIndex])
	}

	benchmark := &IntegrationBenchmark{
		Patterns: patterns,
		Data:     data,
	}

	iterations := 1000

	fmt.Printf("Test data size: %d bytes\n", len(benchmark.Data))
	fmt.Printf("Pattern count: %d\n", len(benchmark.Patterns))
	fmt.Printf("Iterations: %d\n", iterations)
	fmt.Printf("\n")

	// Test 1: Original pipeline (using existing string compiler + interpreter)
	fmt.Printf("1. Testing original pipeline...\n")
	originalResults := benchmarkOriginalPipeline(benchmark, iterations)

	// Test 2: Optimized pipeline (using optimized pattern matcher)
	fmt.Printf("2. Testing optimized pipeline...\n")
	optimizedResults := benchmarkOptimizedPipeline(benchmark, iterations)

	// Test 3: Raw optimized Aho-Corasick (for comparison)
	fmt.Printf("3. Testing raw optimized Aho-Corasick...\n")
	rawResults := benchmarkRawOptimized(benchmark, iterations)

	// Analysis
	fmt.Printf("\n=== Performance Analysis ===\n")
	fmt.Printf("Original pipeline:     %v avg, %.1f ops/sec, %d matches\n",
		originalResults.avgTime, originalResults.opsPerSec, originalResults.totalMatches)
	fmt.Printf("Optimized pipeline:    %v avg, %.1f ops/sec, %d matches\n",
		optimizedResults.avgTime, optimizedResults.opsPerSec, optimizedResults.totalMatches)
	fmt.Printf("Raw optimized AC:      %v avg, %.1f ops/sec, %d matches\n",
		rawResults.avgTime, rawResults.opsPerSec, rawResults.totalMatches)

	// Calculate improvements
	pipelineImprovement := optimizedResults.opsPerSec / originalResults.opsPerSec
	rawImprovement := rawResults.opsPerSec / originalResults.opsPerSec

	fmt.Printf("\nPipeline improvement:  %.1fx faster\n", pipelineImprovement)
	fmt.Printf("Raw AC improvement:     %.1fx faster\n", rawImprovement)

	// Match consistency check
	if originalResults.totalMatches == optimizedResults.totalMatches &&
		optimizedResults.totalMatches == rawResults.totalMatches {
		fmt.Printf("✓ All implementations return consistent match counts\n")
	} else {
		fmt.Printf("WARNING: Match count mismatch!\n")
		fmt.Printf("  Original: %d, Optimized: %d, Raw: %d\n",
			originalResults.totalMatches, optimizedResults.totalMatches, rawResults.totalMatches)
	}

	// Target analysis
	fmt.Printf("\n=== Target Analysis ===\n")
	targetOpsPerSec := 50000.0 // From PLAN.md
	currentBest := optimizedResults.opsPerSec

	fmt.Printf("Target performance: %.1f ops/sec\n", targetOpsPerSec)
	fmt.Printf("Current best:      %.1f ops/sec\n", currentBest)
	progress := (currentBest / targetOpsPerSec) * 100
	fmt.Printf("Progress:          %.1f%% towards target\n", progress)

	if currentBest >= targetOpsPerSec {
		fmt.Printf("✓ Performance target achieved!\n")
	} else {
		needed := targetOpsPerSec / currentBest
		fmt.Printf("⚠ Need %.1fx more improvement\n", needed)

		if needed > 10 {
			fmt.Printf("Recommendations:\n")
			fmt.Printf("  - Implement SIMD optimizations\n")
			fmt.Printf("  - Consider parallel processing\n")
			fmt.Printf("  - Optimize memory access patterns\n")
			fmt.Printf("  - Profile for specific bottlenecks\n")
		}
	}

	// Memory efficiency
	fmt.Printf("\n=== Memory Efficiency ===\n")
	fmt.Printf("Current optimized implementation uses transition tables for O(1) lookup\n")
	fmt.Printf("Trade-off: Higher memory usage for significantly faster search\n")

	if pipelineImprovement > 2 {
		fmt.Printf("✓ Memory trade-off is justified by performance gain\n")
	}
}

type BenchmarkResults struct {
	avgTime      time.Duration
	opsPerSec    float64
	totalMatches int
	error        string
}

func benchmarkOriginalPipeline(benchmark *IntegrationBenchmark, iterations int) BenchmarkResults {
	var totalTime time.Duration
	totalMatches := 0

	for i := 0; i < iterations; i++ {
		start := time.Now()

		// Simulate original pipeline: compile + interpret
		// This is simplified - real pipeline would be more complex
		_ = compiler.NewStringCompiler(nil)

		// Add patterns to string compiler (simplified)
		for j, pattern := range benchmark.Patterns {
			info := compiler.StringInfo{
				Identifier: fmt.Sprintf("$pattern_%d", j),
				Pattern:    []byte(pattern),
			}
			// This would normally go through the full compilation pipeline
			_ = info
		}

		// Simulate matching with naive approach (like the simple benchmark)
		matches := 0
		for _, pattern := range benchmark.Patterns {
			for pos := 0; pos <= len(benchmark.Data)-len(pattern); pos++ {
				match := true
				for k := 0; k < len(pattern); k++ {
					if pos+k >= len(benchmark.Data) || benchmark.Data[pos+k] != pattern[k] {
						match = false
						break
					}
				}
				if match {
					matches++
				}
			}
		}

		totalTime += time.Since(start)
		totalMatches += matches
	}

	avgTime := totalTime / time.Duration(iterations)
	opsPerSec := float64(iterations) / totalTime.Seconds()

	return BenchmarkResults{
		avgTime:      avgTime,
		opsPerSec:    opsPerSec,
		totalMatches: totalMatches,
	}
}

func benchmarkOptimizedPipeline(benchmark *IntegrationBenchmark, iterations int) BenchmarkResults {
	var totalTime time.Duration
	totalMatches := 0

	// Create string pattern compiler once
	spc := NewStringPatternCompiler()

	// Compile patterns once
	stringInfos := make([]StringInfo, len(benchmark.Patterns))
	for i, pattern := range benchmark.Patterns {
		stringInfos[i] = StringInfo{
			Identifier: fmt.Sprintf("$pattern_%d", i),
			Pattern:    []byte(pattern),
		}
	}

	err := spc.CompileStringPatterns(stringInfos)
	if err != nil {
		return BenchmarkResults{error: err.Error()}
	}

	// Benchmark matching
	for i := 0; i < iterations; i++ {
		start := time.Now()
		matches := spc.ExecuteMatching(benchmark.Data)
		totalTime += time.Since(start)

		for _, patternMatches := range matches {
			totalMatches += len(patternMatches)
		}
	}

	avgTime := totalTime / time.Duration(iterations)
	opsPerSec := float64(iterations) / totalTime.Seconds()

	return BenchmarkResults{
		avgTime:      avgTime,
		opsPerSec:    opsPerSec,
		totalMatches: totalMatches,
	}
}

func benchmarkRawOptimized(benchmark *IntegrationBenchmark, iterations int) BenchmarkResults {
	var totalTime time.Duration
	totalMatches := 0

	// Create and compile automaton once
	pm := NewPatternMatcher()
	for i, pattern := range benchmark.Patterns {
		identifier := fmt.Sprintf("p%d", i)
		err := pm.AddPattern(identifier, []byte(pattern), false, false)
		if err != nil {
			return BenchmarkResults{error: err.Error()}
		}
	}

	err := pm.Compile()
	if err != nil {
		return BenchmarkResults{error: err.Error()}
	}

	// Benchmark search
	for i := 0; i < iterations; i++ {
		start := time.Now()
		matches := pm.MatchPatternsOptimized(benchmark.Data)
		totalTime += time.Since(start)

		for _, patternMatches := range matches {
			totalMatches += len(patternMatches)
		}
	}

	avgTime := totalTime / time.Duration(iterations)
	opsPerSec := float64(iterations) / totalTime.Seconds()

	return BenchmarkResults{
		avgTime:      avgTime,
		opsPerSec:    opsPerSec,
		totalMatches: totalMatches,
	}
}
