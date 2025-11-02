//go:build analysis_tool

package main

import (
	"fmt"
	"runtime"
	"time"

	"github.com/cawalch/go-yara/compiler"
)

// CompilationAnalysis measures compilation vs search performance
type CompilationAnalysis struct {
	Patterns []string
	Data     []byte
}

func main() {
	fmt.Printf("=== Aho-Corasick Compilation vs Search Analysis ===\n")
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

	analysis := &CompilationAnalysis{
		Patterns: patterns,
		Data:     data,
	}

	iterations := 1000

	// Test 1: Measure compilation overhead
	fmt.Printf("1. Measuring compilation overhead...\n")
	compileTimes := make([]time.Duration, iterations)
	for i := 0; i < iterations; i++ {
		start := time.Now()
		ac := compiler.NewACAutomaton()

		// Add patterns
		for j, pattern := range analysis.Patterns {
			err := ac.AddString(fmt.Sprintf("p%d", j), []byte(pattern), false, false)
			if err != nil {
				fmt.Printf("Error adding pattern: %v\n", err)
				return
			}
		}

		// Compile automaton
		err := ac.Compile()
		if err != nil {
			fmt.Printf("Error compiling automaton: %v\n", err)
			return
		}

		compileTimes[i] = time.Since(start)
	}

	var totalCompileTime time.Duration
	for _, t := range compileTimes {
		totalCompileTime += t
	}
	avgCompileTime := totalCompileTime / time.Duration(iterations)
	fmt.Printf("  Average compilation time: %v\n", avgCompileTime)
	fmt.Printf("  Compilation ops/sec: %.1f\n", float64(iterations)/totalCompileTime.Seconds())

	// Test 2: Measure search performance (reuse compiled automaton)
	fmt.Printf("\n2. Measuring search performance (with pre-compiled automaton)...\n")

	// Pre-compile automaton once
	ac := compiler.NewACAutomaton()
	for j, pattern := range analysis.Patterns {
		err := ac.AddString(fmt.Sprintf("p%d", j), []byte(pattern), false, false)
		if err != nil {
			fmt.Printf("Error adding pattern: %v\n", err)
			return
		}
	}
	err := ac.Compile()
	if err != nil {
		fmt.Printf("Error compiling automaton: %v\n", err)
		return
	}

	// Benchmark search performance
	searchTimes := make([]time.Duration, iterations)
	totalMatches := 0
	for i := 0; i < iterations; i++ {
		start := time.Now()
		matches := ac.Search(analysis.Data)
		searchTimes[i] = time.Since(start)
		totalMatches += len(matches)
	}

	var totalSearchTime time.Duration
	for _, t := range searchTimes {
		totalSearchTime += t
	}
	avgSearchTime := totalSearchTime / time.Duration(iterations)
	fmt.Printf("  Average search time: %v\n", avgSearchTime)
	fmt.Printf("  Search ops/sec: %.1f\n", float64(iterations)/totalSearchTime.Seconds())
	fmt.Printf("  Total matches found: %d\n", totalMatches)

	// Test 3: Measure end-to-end performance (compile + search each time)
	fmt.Printf("\n3. Measuring end-to-end performance (compile + search)...\n")
	endToEndTimes := make([]time.Duration, iterations/10) // Fewer iterations since it's slower
	totalEndToEndMatches := 0

	for i := 0; i < iterations/10; i++ {
		start := time.Now()

		// Compile
		ac := compiler.NewACAutomaton()
		for j, pattern := range analysis.Patterns {
			err := ac.AddString(fmt.Sprintf("p%d", j), []byte(pattern), false, false)
			if err != nil {
				fmt.Printf("Error adding pattern: %v\n", err)
				return
			}
		}
		err := ac.Compile()
		if err != nil {
			fmt.Printf("Error compiling automaton: %v\n", err)
			return
		}

		// Search
		matches := ac.Search(analysis.Data)
		totalEndToEndMatches += len(matches)

		endToEndTimes[i] = time.Since(start)
	}

	// Run full iterations for end-to-end to match search test
	for i := iterations / 10; i < iterations; i++ {
		start := time.Now()

		// Compile
		ac := compiler.NewACAutomaton()
		for j, pattern := range analysis.Patterns {
			err := ac.AddString(fmt.Sprintf("p%d", j), []byte(pattern), false, false)
			if err != nil {
				fmt.Printf("Error adding pattern: %v\n", err)
				return
			}
		}
		err := ac.Compile()
		if err != nil {
			fmt.Printf("Error compiling automaton: %v\n", err)
			return
		}

		// Search
		matches := ac.Search(analysis.Data)
		totalEndToEndMatches += len(matches)

		endToEndTimes = append(endToEndTimes, time.Since(start))
	}

	var totalEndToEndTime time.Duration
	for _, t := range endToEndTimes {
		totalEndToEndTime += t
	}
	avgEndToEndTime := totalEndToEndTime / time.Duration(len(endToEndTimes))
	fmt.Printf("  Average end-to-end time: %v\n", avgEndToEndTime)
	fmt.Printf("  End-to-end ops/sec: %.1f\n", float64(len(endToEndTimes))/totalEndToEndTime.Seconds())
	fmt.Printf("  Total matches found: %d\n", totalEndToEndMatches)

	// Analysis
	fmt.Printf("\n=== Performance Analysis ===\n")
	compileRatio := float64(avgCompileTime.Nanoseconds()) / float64(avgSearchTime.Nanoseconds())
	searchRatio := float64(avgSearchTime.Nanoseconds()) / float64(avgEndToEndTime.Nanoseconds())

	fmt.Printf("Compilation time vs Search time ratio: %.1fx\n", compileRatio)
	fmt.Printf("Search time vs End-to-end time ratio: %.1fx\n", searchRatio)

	if compileRatio > 10 {
		fmt.Printf("⚠ Compilation overhead is significant (%.1fx search time)\n", compileRatio)
		fmt.Printf("  Consider caching compiled automata\n")
	} else {
		fmt.Printf("✓ Compilation overhead is reasonable\n")
	}

	if totalMatches != totalEndToEndMatches {
		fmt.Printf("WARNING: Match count mismatch! Search-only: %d, End-to-end: %d\n",
			totalMatches, totalEndToEndMatches)
	}

	// Memory usage analysis
	fmt.Printf("\n=== Memory Usage Analysis ===\n")
	var memStats runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memStats)

	fmt.Printf("Current memory usage:\n")
	fmt.Printf("  Heap alloc: %d KB\n", memStats.HeapAlloc/1024)
	fmt.Printf("  Heap sys: %d KB\n", memStats.HeapSys/1024)
	fmt.Printf("  Total alloc: %d KB\n", memStats.TotalAlloc/1024)
	fmt.Printf("  GC count: %d\n", memStats.NumGC)
	fmt.Printf("  GC pause total: %v\n", time.Duration(memStats.PauseTotalNs)*time.Nanosecond)
}
