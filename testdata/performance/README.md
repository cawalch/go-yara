# Performance Test Data

This directory contains tracked rule sets and synthetic sample files used by
performance tests. Large inputs are generated locally and ignored by git.

## Files

### Tracked samples

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

The directory also contains YARA rule sets for simple and mixed workloads.

### Generated inputs

- `large_binary.exe` (10MB) - Large executable with embedded patterns
- `large_log.txt` (5MB) - Large log file for text processing tests
- `large_test_50mb.bin` (50MB) - Large binary file for memory/processing tests

Generate fixtures from the repository root:

```bash
go run ./testdata/performance/generate_test_data.go all
go run ./testdata/performance/generate_test_data.go large
go run ./testdata/performance/generate_test_data.go samples
```

## Pattern Distribution

The generated files mix deterministic filler with:

- PE headers (MZ)
- ELF headers
- Suspicious strings (malware, virus, trojan)
- Common API calls used by malware
