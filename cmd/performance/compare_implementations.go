//go:build compare_tool

package main

import (
	"fmt"
	"runtime"
	"time"

	"github.com/cawalch/go-yara/compiler"
)

// NaivePatternMatching represents the simple O(n*m) pattern matching
func NaivePatternMatching(patterns []string, data []byte) int {
	matches := 0
	for _, pattern := range patterns {
		for i := 0; i <= len(data)-len(pattern); i++ {
			match := true
			for j := 0; j < len(pattern); j++ {
				if i+j >= len(data) || data[i+j] != pattern[j] {
					match = false
					break
				}
			}
			if match {
				matches++
			}
		}
	}
	return matches
}

// RealAhoCorasickMatching uses the actual Aho-Corasick implementation
func RealAhoCorasickMatching(patterns []string, data []byte) int {
	// Import the real implementation
	ac := compiler.NewACAutomaton()

	// Add patterns
	for i, pattern := range patterns {
		err := ac.AddString(fmt.Sprintf("p%d", i), []byte(pattern), false, false)
		if err != nil {
			return 0
		}
	}

	// Compile automaton
	err := ac.Compile()
	if err != nil {
		return 0
	}

	// Search
	matches := ac.Search(data)
	return len(matches)
}

// BenchmarkComparison compares naive vs Aho-Corasick performance
type BenchmarkComparison struct {
	Patterns []string
	Data     []byte
}

func main() {
	fmt.Printf("=== Pattern Matching Performance Comparison ===\n")
	fmt.Printf("Go Version: %s\n", runtime.Version())
	fmt.Printf("OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("CPU Cores: %d\n", runtime.NumCPU())
	fmt.Printf("\n")

	// Test data
	patterns := []string{"test", "malware", "virus", "suspicious", "pattern", "detect", "threat", "attack"}
	data := make([]byte, 1024*1024) // 1MB data

	// Fill data with some patterns
	for i := 0; i < len(data)-100; i += 100 {
		if i < len(patterns)*20 {
			pattern := patterns[(i/100)%len(patterns)]
			copy(data[i:], pattern)
		}
	}

	benchmark := &BenchmarkComparison{
		Patterns: patterns,
		Data:     data,
	}

	iterations := 1000

	// Benchmark naive implementation
	fmt.Printf("Benchmarking naive pattern matching...\n")
	start := time.Now()
	naiveMatches := 0
	for i := 0; i < iterations; i++ {
		naiveMatches += NaivePatternMatching(benchmark.Patterns, benchmark.Data)
	}
	naiveDuration := time.Since(start)
	naiveOpsPerSec := float64(iterations) / naiveDuration.Seconds()
	fmt.Printf("  Naive: %v avg, %.1f ops/sec, %d total matches\n",
		naiveDuration/time.Duration(iterations), naiveOpsPerSec, naiveMatches)

	// Benchmark real Aho-Corasick implementation
	fmt.Printf("Benchmarking real Aho-Corasick implementation...\n")
	start = time.Now()
	acMatches := 0
	for i := 0; i < iterations; i++ {
		acMatches += RealAhoCorasickMatching(benchmark.Patterns, benchmark.Data)
	}
	acDuration := time.Since(start)
	acOpsPerSec := float64(iterations) / acDuration.Seconds()
	fmt.Printf("  Aho-Corasick: %v avg, %.1f ops/sec, %d total matches\n",
		acDuration/time.Duration(iterations), acOpsPerSec, acMatches)

	// Calculate improvement
	improvement := acOpsPerSec / naiveOpsPerSec
	fmt.Printf("\nPerformance Improvement: %.1fx faster\n", improvement)

	if naiveMatches != acMatches {
		fmt.Printf("WARNING: Match counts differ! Naive: %d, AC: %d\n", naiveMatches, acMatches)
	} else {
		fmt.Printf("✓ Match counts are consistent\n")
	}

	// Analysis
	fmt.Printf("\nAnalysis:\n")
	if improvement > 10 {
		fmt.Printf("✓ Aho-Corasick shows significant performance advantage\n")
		fmt.Printf("  The bottleneck is likely using naive implementation instead of real AC\n")
	} else {
		fmt.Printf("⚠ Performance improvement is minimal\n")
		fmt.Printf("  Need to investigate further optimization opportunities\n")
	}
}
