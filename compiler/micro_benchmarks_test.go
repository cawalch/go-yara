package compiler

import (
	"fmt"
	"testing"
	"time"
)

// Micro-benchmarks to isolate string matching performance issues

func BenchmarkMicro_AhoCorasick_Basic(b *testing.B) {
	// Test basic Aho-Corasick pattern matching
	ac := NewACAutomaton()
	patterns := []string{"test", "hello", "world"}

	for _, pattern := range patterns {
		ac.AddString(pattern, []byte(pattern), false, false)
	}
	ac.BuildFailureLinks()

	data := []byte("this is a test string with hello and world")

	for b.Loop() {
		_ = ac.Search(data)
	}
}

func BenchmarkMicro_AhoCorasick_SearchOnly(b *testing.B) {
	// Isolate just the search operation (pre-built automaton)
	ac := NewACAutomaton()
	patterns := []string{"test", "hello", "world", "pattern", "match"}

	for i, pattern := range patterns {
		ac.AddString(fmt.Sprintf("$pattern_%d", i), []byte(pattern), false, false)
	}
	ac.BuildFailureLinks()

	data := []byte("this is a test string with hello and world and pattern matching")

	for b.Loop() {
		_ = ac.Search(data)
	}
}

func BenchmarkMicro_AhoCorasick_LargePatternSet(b *testing.B) {
	// Test with larger pattern set
	ac := NewACAutomaton()
	patterns := make([]string, 100)

	for i := range 100 {
		patterns[i] = fmt.Sprintf("pattern_%d", i)
	}

	for i, pattern := range patterns {
		ac.AddString(fmt.Sprintf("$pattern_%d", i), []byte(pattern), false, false)
	}
	ac.BuildFailureLinks()

	data := []byte("this contains pattern_42 and pattern_7 and pattern_99")

	for b.Loop() {
		_ = ac.Search(data)
	}
}

func BenchmarkMicro_AhoCorasick_ManyMatches(b *testing.B) {
	// Test with data that contains many matches
	ac := NewACAutomaton()
	patterns := []string{"a", "the", "and", "or", "but", "in", "on", "at", "to", "for"}

	for i, pattern := range patterns {
		ac.AddString(fmt.Sprintf("$pattern_%d", i), []byte(pattern), false, false)
	}
	ac.BuildFailureLinks()

	data := []byte("a quick brown fox jumps over the lazy dog and runs to the barn")

	for b.Loop() {
		_ = ac.Search(data)
	}
}

func BenchmarkMicro_AhoCorasick_LargeData(b *testing.B) {
	// Test with large data input
	ac := NewACAutomaton()
	patterns := []string{"malware", "virus", "trojan", "backdoor", "exploit"}

	for i, pattern := range patterns {
		ac.AddString(fmt.Sprintf("$pattern_%d", i), []byte(pattern), false, false)
	}
	ac.BuildFailureLinks()

	// Create 1MB of data
	data := make([]byte, 1024*1024)
	copy(data, "this is some large data with malware signatures and virus patterns")

	for b.Loop() {
		_ = ac.Search(data)
	}
}

// Performance regression test
func BenchmarkMicro_StringMatching_PerformanceRegression(b *testing.B) {
	// This should match the performance from the simple benchmark
	// Target: 50,000 ops/sec (20 microseconds per operation)
	ac := NewACAutomaton()

	// Add realistic patterns
	patterns := []string{
		"MZ",       // PE header
		"PE",       // PE signature
		"\x7fELF",  // ELF header
		"malware",  // Common threat indicator
		"virus",    // Another indicator
		"trojan",   // Trojan signature
		"backdoor", // Backdoor indicator
	}

	for i, pattern := range patterns {
		ac.AddString(fmt.Sprintf("$pattern_%d", i), []byte(pattern), false, false)
	}
	ac.BuildFailureLinks()

	// Realistic data size (10KB)
	data := make([]byte, 10240)
	copy(data, "This is a realistic data buffer with PE headers and malware signatures")

	b.ReportAllocs()
	for b.Loop() {
		_ = ac.Search(data)
	}
}

// Helper function to measure actual performance metrics
func TestMicro_StringMatching_MeasureCurrentPerformance(t *testing.T) {
	ac := NewACAutomaton()
	patterns := []string{"test", "hello", "world", "malware", "virus"}

	for i, pattern := range patterns {
		ac.AddString(fmt.Sprintf("$pattern_%d", i), []byte(pattern), false, false)
	}
	ac.BuildFailureLinks()

	data := []byte("this is a test with malware and virus signatures")

	// Measure actual time per operation
	iterations := 10000
	start := time.Now()

	for range iterations {
		_ = ac.Search(data)
	}

	duration := time.Since(start)
	avgDuration := duration / time.Duration(iterations)
	opsPerSec := float64(time.Second) / float64(avgDuration)

	t.Logf("String Matching Performance:")
	t.Logf("  Total time: %v", duration)
	t.Logf("  Average per operation: %v", avgDuration)
	t.Logf("  Operations per second: %.1f", opsPerSec)
	t.Logf("  Target: 50,000 ops/sec")
	t.Logf("  Gap: %.1fx", 50000.0/opsPerSec)
}

// Benchmark the compilation process
func BenchmarkMicro_AhoCorasick_BuildFailureLinks(b *testing.B) {
	patterns := []string{"test", "hello", "world", "malware", "virus", "trojan"}

	for b.Loop() {
		ac := NewACAutomaton()
		for j, pattern := range patterns {
			ac.AddString(fmt.Sprintf("$pattern_%d", j), []byte(pattern), false, false)
		}
		ac.BuildFailureLinks()
	}
}
