# Performance Test Data

This directory contains test data for performance testing and benchmarking of the go-yara library.

## Files

### Sample Files (tracked in git)
- `pe_malware_sample.bin` - PE file with malware patterns
- `elf_backdoor_sample.bin` - ELF file with backdoor patterns
- `webshell_sample.php` - PHP webshell sample
- `ransomware_sample.exe` - Ransomware patterns
- `banker_sample.dll` - Banking trojan patterns
- `ddos_bot_sample.exe` - DDoS bot patterns
- `miner_sample.exe` - Cryptocurrency miner patterns
- `apt_surveillance_sample.exe` - APT surveillance patterns
- `clean_program.exe` - Clean PE file for false positive testing
- `clean_document.pdf` - Clean document for baseline testing
- `clean_script.js` - Clean JavaScript file

### Large Files (generated on demand)
- `large_binary.exe` (10MB) - Large executable with embedded patterns
- `large_log.txt` (5MB) - Large log file for text processing tests
- `large_test_50mb.bin` (50MB) - Large binary file for memory/processing tests

**Note**: Large files are not tracked in git to keep the repository size manageable. They are generated on demand when needed.

## Usage

### Generating Test Data

The `generate_test_data.go` script can generate all or specific types of test data:

```bash
# Generate all test data (samples + large files)
go run generate_test_data.go

# Generate only large performance files
go run generate_test_data.go large

# Generate only sample files (malware samples)
go run generate_test_data.go samples
```

### Using in Tests/Benchmarks

For benchmarks that need large files, you can use the test helper:

```go
//go:build testdata

import "github.com/cawalch/go-yara/testdata/performance"

func BenchmarkLargeFileProcessing(b *testing.B) {
    // Ensure large test files exist before running benchmark
    if err := testdata/performance.EnsureLargeTestData(); err != nil {
        b.Fatalf("Failed to generate test data: %v", err)
    }
    defer testdata/performance.RemoveLargeTestData() // Clean up after benchmark

    // Your benchmark code here
    // ...
}
```

### Build Tags

The test helper uses the `testdata` build tag to ensure it's only included when actually needed:

```bash
go test -tags=testdata ./...
```

## Pattern Distribution

The generated files contain realistic patterns distributed throughout:
- PE headers (MZ)
- ELF headers
- Suspicious strings (malware, virus, trojan)
- Common API calls used by malware
- Mixed with pseudo-random data to simulate realistic file content

## Cleanup

To remove generated large files and free disk space:

```bash
go run generate_test_data.go cleanup
# Or use the test helper in your code
testdata/performance.RemoveLargeTestData()
```