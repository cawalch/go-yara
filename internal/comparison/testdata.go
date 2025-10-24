//go:build cgo && yara_clib
// +build cgo,yara_clib

// Package comparison provides test data for performance comparison.
package comparison

import (
	"os"
	"path/filepath"
)

// TestData represents a YARA rule test case.
type TestData struct {
	Name    string
	Content string
	Source  string // Where the test data came from
}

// LoadTestData loads YARA rules from various sources for comparison testing.
func LoadTestData() ([]TestData, error) {
	var testData []TestData

	// Add inline test cases
	testData = append(testData, getInlineTestCases()...)

	// Load from fuzzer corpus
	corpusData, err := loadFuzzerCorpus()
	if err == nil {
		testData = append(testData, corpusData...)
	}

	// Load sample rules
	sampleData := loadSampleRules()
	testData = append(testData, sampleData...)

	return testData, nil
}

// getInlineTestCases returns a set of inline test cases covering various YARA features.
func getInlineTestCases() []TestData {
	return []TestData{
		{
			Name:    "simple_rule",
			Source:  "inline",
			Content: `rule test { condition: false }`,
		},
		{
			Name:   "basic_operators",
			Source: "inline",
			Content: `rule r1 { condition: true or false }
rule r2 { condition: 0x1 and 0x2}
rule r3 { condition: 2 > 1 }`,
		},
		{
			Name:   "strings_and_hex",
			Source: "inline",
			Content: `rule r12 { strings: $a = "abc" wide nocase fullword condition: $a }
rule r15 { strings: $a = { 64 01 00 00 60 01 } condition: $a }
rule r16 { strings: $a = { 64 01 [1-3] (60|61) 01 } condition: $a }`,
		},
		{
			Name:   "regex_patterns",
			Source: "inline",
			Content: `rule r21 { strings: $a = /a.*efg/ condition: $a }
rule r22 { strings: $a = /abc[^D]/ nocase condition: $a }
rule r24 { strings: $a = /[0-9a-f]+/ condition: $a }`,
		},
		{
			Name:   "complex_rule",
			Source: "inline",
			Content: `rule ComplexRule {
	meta:
		author = "test"
	strings:
		$a = "malware" nocase wide
		$b = { E2 34 A1 C8 }
		$c = "trojan" ascii
	condition:
		any of them and
		filesize > 102400 and filesize < 52428800 and
		uint32(0) == 0x5A4D
}`,
		},
		{
			Name:    "arithmetic_only",
			Source:  "inline",
			Content: `rule r8 { condition: (1 + 1) * 2 == (9 - 1) / 2 }`,
		},
		{
			Name:    "simple_arithmetic",
			Source:  "inline",
			Content: `rule simple_arith { condition: 1 + 1 == 2 }`,
		},
		{
			Name:    "bitwise_only",
			Source:  "inline",
			Content: `rule bitwise { condition: ~0xAA ^ 0x5A & 0xFF == (~0xAA) ^ (0x5A & 0xFF) }`,
		},
		{
			Name:    "bitwise_only",
			Source:  "inline",
			Content: `rule bitwise { condition: ~0xAA ^ 0x5A & 0xFF == (~0xAA) ^ (0x5A & 0xFF) }`,
		},
		{
			Name:    "simple_arithmetic",
			Source:  "inline",
			Content: `rule simple_arith { condition: 1 + 1 == 2 }`,
		},
		{
			Name:   "data_type_functions",
			Source: "inline",
			Content: `rule r28 { condition: uint32be(0) == 0xAABBCCDD }
rule r29 { condition: uint16(2) & 0xFF00 == 0x4D00 }
rule r30 { condition: int16be(entrypoint + 4) > 0 }`,
		},
		{
			Name:   "quantifiers",
			Source: "inline",
			Content: `rule r13 {
	strings:
		$a = "abcdef"
		$b = "cdef"
		$c = "ef"
	condition:
		all of them
}`,
		},
	}
}

// loadFuzzerCorpus loads YARA rules from the fuzzer corpus.
func loadFuzzerCorpus() ([]TestData, error) {
	var testData []TestData
	corpusPath := "yara/tests/oss-fuzz/rules_fuzzer_corpus"

	entries, err := os.ReadDir(corpusPath)
	if err != nil {
		return nil, err
	}

	// Load up to 10 corpus files to keep benchmarks reasonable
	count := 0
	for _, entry := range entries {
		if entry.IsDir() || count >= 10 {
			continue
		}

		filePath := filepath.Join(corpusPath, entry.Name())
		content, readErr := os.ReadFile(filePath)
		if readErr != nil {
			continue
		}

		testData = append(testData, TestData{
			Name:    "corpus_" + entry.Name(),
			Source:  "fuzzer_corpus",
			Content: string(content),
		})
		count++
	}

	return testData, nil
}

// loadSampleRules loads sample YARA rules from the repository.
func loadSampleRules() []TestData {
	var testData []TestData

	// Load sample.rules if it exists
	samplePath := "yara/sample.rules"
	content, err := os.ReadFile(samplePath)
	if err == nil {
		testData = append(testData, TestData{
			Name:    "sample_rules",
			Source:  "sample",
			Content: string(content),
		})
	}

	return testData
}

// GetBenchmarkRules returns a set of rules specifically designed for benchmarking.
func GetBenchmarkRules() []TestData {
	return []TestData{
		{
			Name:    "bench_small",
			Source:  "benchmark",
			Content: `rule small { condition: true }`,
		},
		{
			Name:    "bench_medium",
			Source:  "benchmark",
			Content: `rule medium { strings: $a = "test" condition: $a }`,
		},
		{
			Name:    "bench_large",
			Source:  "benchmark",
			Content: `rule large { meta: author = "test" strings: $s1 = "malware" $s2 = "virus" $h1 = { E2 34 A1 C8 } condition: ($s1 or $s2 or $h1) and filesize > 1024 }`,
		},
	}
}
