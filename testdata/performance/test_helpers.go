//go:build testdata

package testutils

import (
	"os"
	"path/filepath"
)

// EnsureLargeTestData generates large test data files if they don't exist.
// This function can be used in benchmarks and tests to ensure the required
// large test files are available before running.
func EnsureLargeTestData() error {
	dir := "testdata/performance"
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Check if large files already exist
	files := map[string]int{
		"large_binary.exe":    10 * 1024 * 1024, // 10MB
		"large_log.txt":       5 * 1024 * 1024,  // 5MB
		"large_test_50mb.bin": 50 * 1024 * 1024, // 50MB
	}

	for filename, size := range files {
		path := filepath.Join(dir, filename)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			// File doesn't exist, generate it
			if err := generateLargeFile(path, size); err != nil {
				return err
			}
		}
	}

	return nil
}

// RemoveLargeTestData removes large test data files to free disk space.
// This can be used in test cleanup functions.
func RemoveLargeTestData() error {
	dir := "testdata/performance"

	files := []string{
		"large_binary.exe",
		"large_log.txt",
		"large_test_50mb.bin",
	}

	for _, filename := range files {
		path := filepath.Join(dir, filename)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}

	return nil
}

// generateLargeFile creates a test file with realistic patterns
func generateLargeFile(filename string, size int) error {
	data := make([]byte, size)

	// Create realistic large file content
	patterns := [][]byte{
		[]byte("MZ"),                 // PE header
		{0x7F, 0x45, 0x4C, 0x46},     // ELF header
		[]byte("malware"),            // Suspicious string
		[]byte("virus"),              // Another suspicious string
		[]byte("trojan"),             // More suspicious content
		[]byte("CreateRemoteThread"), // API call
		[]byte("WriteProcessMemory"), // API call
		[]byte("VirtualAllocEx"),     // API call
	}

	// Fill file with patterns mixed with random data
	patternIndex := 0
	for i := 0; i < size; i++ {
		if i%4096 == 0 && patternIndex < len(patterns) {
			pattern := patterns[patternIndex]
			if i+len(pattern) < size {
				copy(data[i:], pattern)
				i += len(pattern) - 1
			}
			patternIndex++
		} else {
			data[i] = byte(i % 256)
		}
	}

	return os.WriteFile(filename, data, 0644)
}
