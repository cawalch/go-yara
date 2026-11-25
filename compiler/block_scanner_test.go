package compiler

import (
	"context"
	"crypto/md5" // #nosec G501 -- compatibility test.
	"fmt"
	"testing"
)

func TestBlockScannerMatchMetadataIsOwnedByResult(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule owned : stable {
    meta:
        author = "test"
    condition:
        true
}
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}

	scanner := program.NewBlockScanner()
	defer scanner.Close()
	if err := scanner.Scan(0, []byte("data")); err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	result, err := scanner.Finish()
	if err != nil {
		t.Fatalf("Finish() error = %v", err)
	}
	match := result.MatchedRules[0]
	match.Tags[0] = "changed"
	match.Meta["author"] = "changed"
	match.Meta["extra"] = true

	scanner.Reset()
	if err := scanner.Scan(0, []byte("data")); err != nil {
		t.Fatalf("second Scan() error = %v", err)
	}
	result, err = scanner.Finish()
	if err != nil {
		t.Fatalf("second Finish() error = %v", err)
	}
	match = result.MatchedRules[0]
	if len(match.Tags) != 1 || match.Tags[0] != "stable" {
		t.Fatalf("second match tags = %v, want [stable]", match.Tags)
	}
	if match.Meta["author"] != "test" || match.Meta["extra"] != nil {
		t.Fatalf("second match metadata = %v, want unchanged compiled metadata", match.Meta)
	}
}

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
	matches[1].Offset = 42
	again, err := scanner.Finish()
	if err != nil {
		t.Fatalf("second Finish() error = %v", err)
	}
	matches = again.Matches["aggregate"]["$a"]
	if len(matches) != 2 || matches[0].Offset != 0 || matches[1].Offset != 1001 {
		t.Fatalf("second Finish() matches = %+v, want offsets 0 and 1001", matches)
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

func TestBlockScannerFastScanRetainsConditionRequiredMatches(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule counted {
    strings:
        $c = /beta[0-9]/
    condition:
        #c >= 2
}
rule presence {
    strings:
        $p = "present"
    condition:
        $p
}
`)
	if err != nil {
		t.Fatal(err)
	}

	scanner := program.NewBlockScanner(WithFastScan())
	defer scanner.Close()
	if err := scanner.Scan(1000, []byte("beta1 beta2 present")); err != nil {
		t.Fatal(err)
	}
	result, err := scanner.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if !result.RuleResults["counted"] || len(result.Matches["counted"]["$c"]) != 2 {
		t.Fatalf("counted result = %+v, want two retained matches", result)
	}
}

func TestBlockScannerStringMatchesReadsAbsoluteBlockOffset(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule content_regex {
    strings:
        $a = "needle"
    condition:
        $a and $a matches /^need/
}
`)
	if err != nil {
		t.Fatal(err)
	}

	scanner := program.NewBlockScanner()
	defer scanner.Close()
	if err := scanner.Scan(4096, []byte("xxneedlexx")); err != nil {
		t.Fatal(err)
	}
	result, err := scanner.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if !result.RuleResults["content_regex"] {
		t.Fatalf("content_regex result = %+v, want match", result)
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

func TestBlockScannerIndexedMatchDataAcrossOverlaps(t *testing.T) {
	program := mustCompileStreamingProgram(t, `rule words {
    strings:
        $word = /w(or)d/ capture(token = 1)
    condition:
        $word
}`)
	scanner := program.NewBlockScanner(WithMatchData(8), WithMatchContext(2, 8), WithEvidence(8))
	defer scanner.Close()

	for _, block := range []MemoryBlock{
		{Base: 100, Data: []byte("word a")},
		{Base: 5, Data: []byte("word t")},
		{Base: 100, Data: []byte("word and")},
	} {
		if err := scanner.Scan(block.Base, block.Data); err != nil {
			t.Fatal(err)
		}
	}

	type outcome struct {
		base, offset int64
		after        string
	}
	check := func(want []outcome) {
		t.Helper()
		result, err := scanner.Finish()
		if err != nil {
			t.Fatal(err)
		}
		matches := result.Matches["words"]["$word"]
		if len(matches) != len(want) {
			t.Fatalf("got %d matches, want %d", len(matches), len(want))
		}
		for i, match := range matches {
			got := outcome{base: match.Base, offset: match.Offset, after: string(match.ContextAfter)}
			if got != want[i] || string(match.MatchedData) != "word" || captureDataByName(match.Captures)["token"] != "or" {
				t.Fatalf("match %d = %+v with context %q, want %+v with match data and capture", i, match, got.after, want[i])
			}
		}
	}

	first := []outcome{{5, 5, " t"}, {100, 100, " a"}}
	check(first)
	check(first)
	if err := scanner.Scan(100, []byte("word and word b")); err != nil {
		t.Fatal(err)
	}
	check(append(first, outcome{100, 109, " b"}))

	scanner.Reset()
	if err := scanner.Scan(0, []byte("word c")); err != nil {
		t.Fatal(err)
	}
	check([]outcome{{0, 0, " c"}})
}

func TestBlockScannerBorrowedInputOwnership(t *testing.T) {
	program := mustCompileStreamingProgram(t, `rule words {
    strings:
        $word = "word"
    condition:
        #word == 2 and uint8(100) == 119
}`)
	scanner := program.NewBlockScanner(WithMatchData(8))
	defer scanner.Close()

	borrowed := []byte("word")
	copied := []byte("word")
	if err := scanner.ScanBorrowedWithContext(context.Background(), 100, borrowed); err != nil {
		t.Fatal(err)
	}
	if err := scanner.Scan(0, copied); err != nil {
		t.Fatal(err)
	}
	if &scanner.blocks[0].Data[0] != &borrowed[0] || &scanner.blocks[1].Data[0] == &copied[0] {
		t.Fatal("block borrowing and copying did not honor input ownership")
	}
	copied[0] = 'x'
	result, err := scanner.Finish()
	if err != nil {
		t.Fatal(err)
	}
	matches := result.Matches["words"]["$word"]
	if !result.RuleResults["words"] || len(matches) != 2 ||
		string(matches[0].MatchedData) != "word" || string(matches[1].MatchedData) != "word" {
		t.Fatalf("unexpected result: %+v", result)
	}
	scanner.Reset()
	borrowed[0] = 'x'
	if got := string(matches[1].MatchedData); got != "word" {
		t.Fatalf("result data after Reset = %q, want word", got)
	}
}
