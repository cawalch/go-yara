package lexer

import (
	"sync"
	"testing"
	"time"
)

// TestStringInterner_BasicFunctionality tests the basic string interning functionality
func TestStringInterner_BasicFunctionality(t *testing.T) {
	si := &stringInterner{
		cache:     make(map[string]string, 8),
		maxSize:   8,
		maxLength: 16,
	}

	// Test interning short strings
	short := "hello"
	interned := si.internString(short)
	if interned != short {
		t.Errorf("Expected %s, got %s", short, interned)
	}

	// Test that identical strings return the same interned version
	interned2 := si.internString(short)
	if interned2 != short {
		t.Error("Expected identical content for interned strings")
	}

	// Test that long strings are not interned
	long := "this is a very long string that exceeds the limit"
	longInterned := si.internString(long)
	if longInterned != long {
		t.Error("Long strings should not be interned")
	}
}

// TestStringInterner_Concurrency tests thread safety under concurrent access
func TestStringInterner_Concurrency(t *testing.T) {
	si := &stringInterner{
		cache:     make(map[string]string, 64),
		maxSize:   64,
		maxLength: 16,
	}

	const (
		numGoroutines = 100
		numIterations = 1000
	)

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Use different strings to test cache growth and collision handling
	testStrings := []string{"hello", "world", "test", "golang", "yara", "lex", "parse"}

	for i := range numGoroutines {
		go func(id int) {
			defer wg.Done()
			for j := range numIterations {
				// Rotate through test strings to create cache hits and misses
				str := testStrings[j%len(testStrings)]
				result := si.internString(str)
				if result != str {
					t.Errorf("Goroutine %d, iteration %d: expected %s, got %s", id, j, str, result)
				}
			}
		}(i)
	}

	// Wait for all goroutines to complete
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All goroutines completed successfully
	case <-time.After(30 * time.Second):
		t.Fatal("Test timed out - possible deadlock or excessive contention")
	}

	// Verify cache integrity
	si.mu.RLock()
	cacheSize := len(si.cache)
	si.mu.RUnlock()

	if cacheSize > si.maxSize {
		t.Errorf("Cache size %d exceeds maximum %d", cacheSize, si.maxSize)
	}
}

// TestStringInterner_ConcurrentReadWrite tests concurrent reads and writes
func TestStringInterner_ConcurrentReadWrite(t *testing.T) {
	si := &stringInterner{
		cache:     make(map[string]string, 32),
		maxSize:   32,
		maxLength: 16,
	}

	const (
		numReaders = 50
		numWriters = 10
		numOps     = 1000
	)

	var wg sync.WaitGroup
	wg.Add(numReaders + numWriters)

	// Start reader goroutines
	for i := range numReaders {
		go func(id int) {
			defer wg.Done()
			for range numOps {
				// Try to read strings that might be added by writers
				testStr := "test"
				result := si.internString(testStr)
				if result != testStr {
					t.Errorf("Reader %d: expected %s, got %s", id, testStr, result)
				}
			}
		}(i)
	}

	// Start writer goroutines
	for i := range numWriters {
		go func(id int) {
			defer wg.Done()
			for j := range numOps {
				// Add unique strings to test cache growth
				str := string(rune('a'+(id%26))) + string(rune('a'+(j%26)))
				if len(str) <= si.maxLength {
					result := si.internString(str)
					if result != str {
						t.Errorf("Writer %d: expected %s, got %s", id, str, result)
					}
				}
			}
		}(i)
	}

	// Wait with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(30 * time.Second):
		t.Fatal("Concurrent read/write test timed out")
	}
}

// TestStringInterner_MaxSizeLimit tests that the cache respects size limits
func TestStringInterner_MaxSizeLimit(t *testing.T) {
	si := &stringInterner{
		cache:     make(map[string]string, 4),
		maxSize:   4,
		maxLength: 16,
	}

	// Add more strings than the cache can hold
	strings := []string{"a", "b", "c", "d", "e", "f"}
	for _, str := range strings {
		result := si.internString(str)
		if result != str {
			t.Errorf("Expected %s, got %s", str, result)
		}
	}

	// Verify cache size is limited
	si.mu.RLock()
	cacheSize := len(si.cache)
	si.mu.RUnlock()

	if cacheSize > si.maxSize {
		t.Errorf("Cache size %d exceeds maximum %d", cacheSize, si.maxSize)
	}
}

// TestStringInterner_GlobalInterner tests the global interner instance
func TestStringInterner_GlobalInterner(t *testing.T) {
	// Test that the global interner doesn't panic under concurrent access
	const numGoroutines = 20
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := range numGoroutines {
		go func(id int) {
			defer wg.Done()
			for range 100 {
				str := "test_string"
				result := globalInterner.internString(str)
				if result != str {
					t.Errorf("Global interner failed for goroutine %d", id)
				}
			}
		}(i)
	}

	wg.Wait()
}

// BenchmarkStringInterner_SingleThread benchmarks single-threaded performance
func BenchmarkStringInterner_SingleThread(b *testing.B) {
	si := &stringInterner{
		cache:     make(map[string]string, 1024),
		maxSize:   1024,
		maxLength: 16,
	}

	strings := []string{"hello", "world", "test", "benchmark", "golang"}

	b.ResetTimer()
	for i := range b.N {
		str := strings[i%len(strings)]
		si.internString(str)
	}
}

// BenchmarkStringInterner_Concurrent benchmarks concurrent performance
func BenchmarkStringInterner_Concurrent(b *testing.B) {
	si := &stringInterner{
		cache:     make(map[string]string, 1024),
		maxSize:   1024,
		maxLength: 16,
	}

	strings := []string{"hello", "world", "test", "benchmark", "golang"}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			str := strings[i%len(strings)]
			si.internString(str)
			i++
		}
	})
}
