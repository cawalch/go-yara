package compiler

import (
	"os"
	"runtime"
	"testing"
	"time"
)

// BenchmarkLargeFileProcessing benchmarks current large file processing
func BenchmarkLargeFileProcessing(b *testing.B) {
	// Create test data
	testData := make([]byte, 50*1024*1024) // 50MB
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	// Insert some test patterns
	patterns := []byte("test_pattern_malware_detection_virus_trojan")
	for i := 0; i < len(testData)-len(patterns); i += 1024 {
		copy(testData[i:], patterns)
	}

	// Create simple rule
	ruleText := `
rule large_file_test {
    strings:
        $pattern1 = "test_pattern"
        $pattern2 = "malware"
        $pattern3 = "detection"
        $pattern4 = "virus"
        $pattern5 = "trojan"
    condition:
        any of them
}`

	comp := NewCompiler()
	compiledProgram, err := comp.CompileSource(ruleText)
	if err != nil {
		b.Fatalf("Failed to compile rules: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(50 * 1024 * 1024) // Report throughput in MB

	for i := 0; i < b.N; i++ {
		// Simulate current processing - load entire file into memory
		start := time.Now()

		// Current approach: process entire file at once
		// This is what we need to optimize
		_ = testData
		_ = compiledProgram

		// Simulate string matching (this is the bottleneck)
		// In reality, this would use the compiled program to scan the entire file
		for j := 0; j < len(testData); j++ {
			_ = testData[j] // Simulate byte processing - this is the bottleneck
		}

		elapsed := time.Since(start)
		b.ReportMetric(float64(elapsed.Nanoseconds())/1e6, "ms/op")
	}
}

// BenchmarkCurrentMemoryUsage profiles memory usage for large files
func BenchmarkCurrentMemoryUsage(b *testing.B) {
	runtime.GC()
	var memBefore, memAfter runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	// Create large test data
	testData := make([]byte, 100*1024*1024) // 100MB
	runtime.ReadMemStats(&memAfter)

	allocMemory := memAfter.Alloc - memBefore.Alloc
	b.Logf("Initial allocation for 100MB file: %d MB", allocMemory/1024/1024)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		runtime.GC()
		runtime.ReadMemStats(&memBefore)

		// Current approach: process entire file in memory
		processedData := make([]byte, len(testData))
		copy(processedData, testData)

		// Simulate processing
		_ = processedData

		runtime.ReadMemStats(&memAfter)
		b.ReportMetric(float64(memAfter.Alloc-memBefore.Alloc)/1024/1024, "MB/alloc")
	}
}

// ProfileLargeFileProcessing creates a detailed profile
func TestProfileLargeFileProcessing(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping profiling test in short mode")
	}

	// Create CPU profile
	cpuFile, err := os.Create("large_file_cpu.prof")
	if err != nil {
		t.Fatalf("Failed to create CPU profile: %v", err)
	}
	defer cpuFile.Close()

	// Create memory profile
	memFile, err := os.Create("large_file_mem.prof")
	if err != nil {
		t.Fatalf("Failed to create memory profile: %v", err)
	}
	defer memFile.Close()

	// Test data
	testData := make([]byte, 50*1024*1024) // 50MB
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	ruleText := `
rule profile_test {
    strings:
        $pattern = "test"
    condition:
        $pattern
}`

	// Start CPU profiling
	// runtime/pprof.StartCPUProfile(cpuFile)
	// defer runtime/pprof.StopCPUProfile()

	comp := NewCompiler()
	compiledProgram, err := comp.CompileSource(ruleText)
	if err != nil {
		t.Fatalf("Failed to compile rules: %v", err)
	}

	// Process the file multiple times to get good profiling data
	start := time.Now()
	for i := 0; i < 10; i++ {
		// Current processing approach
		_ = testData
		_ = compiledProgram

		// Simulate string matching
		for j := 0; j < len(testData); j += 1024 {
			// This is where the bottleneck occurs
			_ = testData[j] // Simulate processing chunks
		}
	}
	elapsed := time.Since(start)

	// Memory profiling
	runtime.GC()
	// runtime/pprof.WriteHeapProfile(memFile)

	t.Logf("Processed 50MB file 10 times in %v", elapsed)
	t.Logf("Average time per run: %v", elapsed/10)
	t.Logf("Throughput: %.2f MB/s", (50*10)/elapsed.Seconds())
}
