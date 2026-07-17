package compiler

import (
	"crypto/md5" // #nosec G501 -- compatibility test.
	"fmt"
	"testing"
)

func TestBlockScannerNonContiguousBlocks(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule test {
    strings:
        $a = "ipsum"
    condition:
        $a
}
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}

	scanner := program.NewBlockScanner(WithMatchData(16))
	defer scanner.Close()
	if err := scanner.Scan(0, []byte("Lorem ipsum")); err != nil {
		t.Fatalf("Scan(first block) error = %v", err)
	}
	if err := scanner.Scan(1000, []byte("dolor sit amet")); err != nil {
		t.Fatalf("Scan(second block) error = %v", err)
	}
	result, err := scanner.Finish()
	if err != nil {
		t.Fatalf("Finish() error = %v", err)
	}
	if !result.RuleResults["test"] {
		t.Fatal("test did not match")
	}
	matches := result.Matches["test"]["$a"]
	if len(matches) != 1 || matches[0].Offset != 6 || matches[0].Base != 0 || string(matches[0].MatchedData) != "ipsum" {
		t.Fatalf("matches = %+v, want ipsum at base 0 offset 6", matches)
	}
}

func TestBlockScannerAggregatesCountsAndAbsoluteOffsets(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule aggregate {
    strings:
        $a = "abc"
    condition:
        #a == 2 and @a[2] == 1001
}
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}

	scanner := program.NewBlockScanner()
	defer scanner.Close()
	if err := scanner.Scan(0, []byte("abc")); err != nil {
		t.Fatalf("Scan(first block) error = %v", err)
	}
	if err := scanner.Scan(1000, []byte("xabc")); err != nil {
		t.Fatalf("Scan(second block) error = %v", err)
	}
	result, err := scanner.Finish()
	if err != nil {
		t.Fatalf("Finish() error = %v", err)
	}
	if !result.RuleResults["aggregate"] {
		t.Fatalf("RuleResults = %v", result.RuleResults)
	}
	matches := result.Matches["aggregate"]["$a"]
	if len(matches) != 2 || matches[0].Offset != 0 || matches[1].Offset != 1001 {
		t.Fatalf("matches = %+v, want offsets 0 and 1001", matches)
	}
}

func TestBlockScannerDeduplicatesOverlaps(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule overlap {
    strings:
        $a = "abc"
    condition:
        #a == 1
}
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}

	scanner := program.NewBlockScanner()
	defer scanner.Close()
	if err := scanner.Scan(0, []byte("xabc")); err != nil {
		t.Fatalf("Scan(first block) error = %v", err)
	}
	if err := scanner.Scan(1, []byte("abc")); err != nil {
		t.Fatalf("Scan(overlap block) error = %v", err)
	}
	result, err := scanner.Finish()
	if err != nil {
		t.Fatalf("Finish() error = %v", err)
	}
	if !result.RuleResults["overlap"] {
		t.Fatal("overlap did not match after deduplication")
	}
	if got := len(result.Matches["overlap"]["$a"]); got != 1 {
		t.Fatalf("deduplicated match count = %d, want 1", got)
	}
}

func TestBlockScannerSupportsSparseReadsAndModules(t *testing.T) {
	data := []byte("\x7fELFpayload")
	wantMD5 := fmt.Sprintf("%x", md5.Sum(data[4:])) // #nosec G401 -- compatibility test.
	program, err := NewCompiler().CompileSource(fmt.Sprintf(`
import "hash"
rule sparse {
    strings:
        $payload = "payload"
    condition:
        uint32(1000) == 0x464c457f and
        $payload at 1004 and
        hash.md5(1004, 7) == "%s"
}
`, wantMD5))
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}

	scanner := program.NewBlockScanner()
	defer scanner.Close()
	if err := scanner.Scan(1000, data); err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	result, err := scanner.Finish()
	if err != nil {
		t.Fatalf("Finish() error = %v", err)
	}
	if !result.RuleResults["sparse"] || len(result.PrunedRules) != 0 {
		t.Fatalf("result = %+v", result)
	}
}

func TestBlockScannerFileSizeFastScanAndReset(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule options {
    strings:
        $a = "abc"
    condition:
        filesize == 2000 and $a
}

`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}

	scanner := program.NewBlockScanner(WithFastScan())
	defer scanner.Close()
	if err := scanner.SetFileSize(2000); err != nil {
		t.Fatalf("SetFileSize() error = %v", err)
	}
	if err := scanner.Scan(0, []byte("abcabc")); err != nil {
		t.Fatalf("Scan(first block) error = %v", err)
	}
	if err := scanner.Scan(1000, []byte("abc")); err != nil {
		t.Fatalf("Scan(second block) error = %v", err)
	}
	result, err := scanner.Finish()
	if err != nil {
		t.Fatalf("Finish() error = %v", err)
	}
	if !result.RuleResults["options"] || len(result.Matches["options"]["$a"]) != 1 {
		t.Fatalf("result = %+v", result)
	}

	scanner.Reset()
	if err := scanner.Scan(0, []byte("none")); err != nil {
		t.Fatalf("Scan(after reset) error = %v", err)
	}
	result, err = scanner.Finish()
	if err != nil {
		t.Fatalf("Finish(after reset) error = %v", err)
	}
	if result.RuleResults["options"] {
		t.Fatal("reset retained prior blocks or file size")
	}
}

func TestBlockScannerHeaderConstraintChecksAllOverlappingBlocks(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule overlap_header {
    strings:
        $magic = "MZ"
    condition:
        $magic at 1
}
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}

	scanner := program.NewBlockScanner()
	defer scanner.Close()
	if err := scanner.Scan(0, []byte("x")); err != nil {
		t.Fatalf("Scan(short block) error = %v", err)
	}
	if err := scanner.Scan(0, []byte("xMZ")); err != nil {
		t.Fatalf("Scan(overlapping block) error = %v", err)
	}
	result, err := scanner.Finish()
	if err != nil {
		t.Fatalf("Finish() error = %v", err)
	}
	if !result.RuleResults["overlap_header"] || len(result.PrunedRules) != 0 {
		t.Fatalf("result = %+v, want overlap_header match", result)
	}
}
