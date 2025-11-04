//go:build optimization_bench

package main

import (
	"fmt"
	"runtime"
	"time"

	"github.com/cawalch/go-yara/compiler"
	. "github.com/cawalch/go-yara/compiler" // Import for NewOptimizedACAutomaton
)

// BenchmarkOptimization compares original vs optimized Aho-Corasick
type BenchmarkOptimization struct {
	Patterns []string
	Data     []byte
}

func main() {
	fmt.Printf("=== Aho-Corasick Optimization Benchmark ===\n")
	fmt.Printf("Go Version: %s\n", runtime.Version())
	fmt.Printf("OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("CPU Cores: %d\n", runtime.NumCPU())
	fmt.Printf("\n")

	// Test data - more realistic patterns
	patterns := []string{
		"malware", "virus", "trojan", "backdoor", "rootkit",
		"suspicious", "detect", "threat", "attack", "exploit",
		"payload", "shellcode", "injection", "process", "memory",
	}

	data := make([]byte, 1024*1024) // 1MB data

	// Fill data with patterns distributed throughout
	patternLength := len(patterns)
	for i := 0; i < len(data)-100; i += 50 {
		pattern := patterns[(i/50)%patternLength]
		copy(data[i:], pattern)
	}

	benchmark := &BenchmarkOptimization{
		Patterns: patterns,
		Data:     data,
	}

	iterations := 1000

	// Benchmark original implementation
	fmt.Printf("Benchmarking original Aho-Corasick implementation...\n")
	originalResults := benchmarkOriginal(benchmark, iterations)

	// Benchmark optimized implementation
	fmt.Printf("Benchmarking optimized Aho-Corasick implementation...\n")
	optimizedResults := benchmarkOptimized(benchmark, iterations)

	// Compare results
	fmt.Printf("\n=== Performance Comparison ===\n")
	fmt.Printf("Original:  %v avg, %.1f ops/sec, %d matches\n",
		originalResults.avgTime, originalResults.opsPerSec, originalResults.totalMatches)
	fmt.Printf("Optimized: %v avg, %.1f ops/sec, %d matches\n",
		optimizedResults.avgTime, optimizedResults.opsPerSec, optimizedResults.totalMatches)

	improvement := optimizedResults.opsPerSec / originalResults.opsPerSec
	fmt.Printf("Performance improvement: %.1fx faster\n", improvement)

	if originalResults.totalMatches != optimizedResults.totalMatches {
		fmt.Printf("WARNING: Match count mismatch! Original: %d, Optimized: %d\n",
			originalResults.totalMatches, optimizedResults.totalMatches)
	} else {
		fmt.Printf("✓ Match counts are consistent\n")
	}

	// Memory usage comparison
	fmt.Printf("\n=== Memory Usage Comparison ===\n")
	fmt.Printf("Original memory usage:  ~%d KB\n", originalResults.memoryKB)
	fmt.Printf("Optimized memory usage: ~%d KB\n", optimizedResults.memoryKB)

	memoryRatio := float64(originalResults.memoryKB) / float64(optimizedResults.memoryKB)
	fmt.Printf("Memory efficiency: %.1fx better\n", memoryRatio)

	// Target analysis
	fmt.Printf("\n=== Target Analysis ===\n")
	target := 50000.0 // Target ops/sec from PLAN.md
	currentPerformance := optimizedResults.opsPerSec

	fmt.Printf("Target performance: %.1f ops/sec\n", target)
	fmt.Printf("Current performance: %.1f ops/sec\n", currentPerformance)
	fmt.Printf("Progress towards target: %.1f%%\n", (currentPerformance/target)*100)

	if currentPerformance >= target {
		fmt.Printf("✓ Performance target achieved!\n")
	} else {
		remaining := target / currentPerformance
		fmt.Printf("⚠ Need %.1fx more improvement to reach target\n", remaining)
	}

	// Recommendations
	fmt.Printf("\n=== Optimization Recommendations ===\n")
	if improvement < 2 {
		fmt.Printf("⚠ Limited improvement - consider:\n")
		fmt.Printf("  - SIMD optimizations for ARM64\n")
		fmt.Printf("  - Better memory layout for cache locality\n")
		fmt.Printf("  - Lock-free concurrent access\n")
	} else if improvement >= 10 {
		fmt.Printf("✓ Significant improvement achieved!\n")
		fmt.Printf("  Consider further optimizations:\n")
		fmt.Printf("  - Profile-guided optimization\n")
		fmt.Printf("  - Platform-specific tuning\n")
	} else {
		fmt.Printf("✓ Good improvement achieved\n")
		fmt.Printf("  Additional optimizations available:\n")
		fmt.Printf("  - Memory pooling improvements\n")
		fmt.Printf("  - Branch prediction optimization\n")
	}
}

type BenchmarkResults struct {
	avgTime      time.Duration
	opsPerSec    float64
	totalMatches int
	memoryKB     int
}

func benchmarkOriginal(benchmark *BenchmarkOptimization, iterations int) BenchmarkResults {
	// Compile once
	ac := compiler.NewACAutomaton()
	for i, pattern := range benchmark.Patterns {
		err := ac.AddString(fmt.Sprintf("p%d", i), []byte(pattern), false, false)
		if err != nil {
			return BenchmarkResults{}
		}
	}
	err := ac.Compile()
	if err != nil {
		return BenchmarkResults{}
	}

	// Benchmark search
	var totalTime time.Duration
	totalMatches := 0

	for i := 0; i < iterations; i++ {
		start := time.Now()
		matches := ac.Search(benchmark.Data)
		totalTime += time.Since(start)
		totalMatches += len(matches)
	}

	avgTime := totalTime / time.Duration(iterations)
	opsPerSec := float64(iterations) / totalTime.Seconds()
	memoryKB := ac.EstimateMemoryUsage() / 1024

	return BenchmarkResults{
		avgTime:      avgTime,
		opsPerSec:    opsPerSec,
		totalMatches: totalMatches,
		memoryKB:     memoryKB,
	}
}

func benchmarkOptimized(benchmark *BenchmarkOptimization, iterations int) BenchmarkResults {
	// Compile once
	ac := NewOptimizedACAutomaton()
	for i, pattern := range benchmark.Patterns {
		err := ac.AddString(fmt.Sprintf("p%d", i), []byte(pattern), false, false)
		if err != nil {
			return BenchmarkResults{}
		}
	}
	err := ac.Compile()
	if err != nil {
		return BenchmarkResults{}
	}

	// Benchmark search
	var totalTime time.Duration
	totalMatches := 0

	for i := 0; i < iterations; i++ {
		start := time.Now()
		matches := ac.Search(benchmark.Data)
		totalTime += time.Since(start)
		totalMatches += len(matches)
	}

	avgTime := totalTime / time.Duration(iterations)
	opsPerSec := float64(iterations) / totalTime.Seconds()
	memoryKB := ac.EstimateMemoryUsage() / 1024

	return BenchmarkResults{
		avgTime:      avgTime,
		opsPerSec:    opsPerSec,
		totalMatches: totalMatches,
		memoryKB:     memoryKB,
	}
}
