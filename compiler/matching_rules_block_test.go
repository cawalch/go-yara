package compiler

import (
	"context"
	"fmt"
	"testing"
)

func TestMatchingRulesInBlockPreservesLogicalAddressSpace(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule absolute_block {
    strings:
        $a = "needle"
    condition:
        filesize == 4096 and
        uint8(1000) == 0x61 and
        $a at 1003 and
        @a == 1003 and
        !a == 6 and
        $a matches /need/
}
rule block_read_only {
    condition:
        filesize == 4096 and uint8(1000) == 0x61
}
`)
	if err != nil {
		t.Fatal(err)
	}
	block := MemoryBlock{Base: 1000, Data: []byte("abcneedlez")}
	scanner := NewScanner(program, WithFastScan(), WithMatchData(6), WithMatchContext(2, 1))
	defer scanner.Close()

	matches, err := scanner.MatchingRulesInBlock(block, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 2 || matches[0].Rule != "absolute_block" || matches[1].Rule != "block_read_only" {
		t.Fatalf("matches = %+v, want absolute_block and block_read_only", matches)
	}
	patternMatches := matches[0].Matches["$a"]
	if len(patternMatches) != 1 {
		t.Fatalf("pattern matches = %+v, want one", patternMatches)
	}
	match := patternMatches[0]
	if match.Offset != 1003 || match.Base != 1000 || match.Length != 6 ||
		string(match.MatchedData) != "needle" || string(match.ContextBefore) != "bc" ||
		string(match.ContextAfter) != "z" {
		t.Fatalf("match = %+v, want absolute offset, base, and block-local evidence", match)
	}
}

func TestMatchingRulesInBlockMatchesBlockScanner(t *testing.T) {
	program, err := NewCompiler().CompileSource(matchingRulesParitySource)
	if err != nil {
		t.Fatal(err)
	}
	corpus := [][]byte{
		[]byte("clean"),
		[]byte("guard42 alpha foxtrot"),
		[]byte("guard42 beta1 beta2"),
		[]byte("guard42 MZxxPE"),
		[]byte("guard42 DELTA"),
		append([]byte("guard42 "), []byte{'D', 0, 'e', 0, 'l', 0, 't', 0, 'a', 0}...),
		[]byte("guard42 unselected123"),
	}
	options := [][]ScannerOption{
		{},
		{WithFastScan()},
		{WithFastScan(), WithTagsFilter([]string{"selected"})},
		{WithFastScan(), WithMatchData(8), WithMatchContext(2, 3)},
	}
	for _, scannerOptions := range options {
		for _, disablePrefilter := range []bool{false, true} {
			compact := NewScanner(program, scannerOptions...)
			compact.prefilterDisabled = disablePrefilter
			oracle := NewBlockScanner(program, scannerOptions...)
			oracle.scanner.prefilterDisabled = disablePrefilter
			for iteration := range 3 {
				for index, data := range corpus {
					base := int64(1000 + index*100)
					fileSize := base + int64(len(data)) + 17
					got, gotErr := compact.MatchingRulesInBlock(MemoryBlock{Base: base, Data: data}, fileSize)

					oracle.Reset()
					if err := oracle.SetFileSize(fileSize); err != nil {
						t.Fatal(err)
					}
					if err := oracle.Scan(base, data); err != nil {
						t.Fatal(err)
					}
					result, wantErr := oracle.Finish()
					if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
						t.Fatalf("iteration %d input %d errors differ: compact=%v block=%v", iteration, index, gotErr, wantErr)
					}
					if gotErr == nil && !matchingRulesEqual(got, result.MatchedRules) {
						t.Fatalf(
							"prefilter=%v iteration %d input %d:\ncompact=%#v\nblock=%#v",
							disablePrefilter,
							iteration,
							index,
							got,
							result.MatchedRules,
						)
					}
				}
			}
			compact.Close()
			oracle.Close()
		}
	}
}

func TestMatchingRulesInBlockPreservesCaptureEvidence(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule token {
    strings:
        $token = /token=([A-Za-z0-9]+)/ capture(secret = 1)
    evidence:
        candidate = (secret) within 0 of secret
    condition:
        $token
}
`)
	if err != nil {
		t.Fatal(err)
	}
	scanner := NewScanner(program, WithEvidence(32))
	defer scanner.Close()
	matches, err := scanner.MatchingRulesInBlock(
		MemoryBlock{Base: 4096, Data: []byte("token=abcdef")},
		8192,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || len(matches[0].Evidence["candidate"]) != 1 {
		t.Fatalf("matches = %+v, want one evidence finding", matches)
	}
	finding := matches[0].Evidence["candidate"][0]
	if finding.Status != EvidenceStatusReady || finding.Anchor.Offset != 4102 ||
		string(finding.Anchor.Data) != "abcdef" {
		t.Fatalf("finding = %#v, want absolute capture offset and data", finding)
	}
}

func TestMatchingRulesInBlockScannerReuseRestoresByteSliceDomain(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule block_address {
    strings:
        $a = "needle"
    condition:
        filesize == 4096 and $a at 1003
}
rule slice_address {
    strings:
        $a = "needle"
    condition:
        filesize == 10 and $a at 3
}
`)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("abcneedlez")
	scanner := NewScanner(program, WithFastScan())
	defer scanner.Close()

	blockMatches, err := scanner.MatchingRulesInBlock(MemoryBlock{Base: 1000, Data: data}, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if len(blockMatches) != 1 || blockMatches[0].Rule != "block_address" ||
		blockMatches[0].Matches["$a"][0].Offset != 1003 {
		t.Fatalf("block matches = %+v, want block_address at 1003", blockMatches)
	}

	sliceMatches, err := scanner.MatchingRules(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(sliceMatches) != 1 || sliceMatches[0].Rule != "slice_address" {
		t.Fatalf("slice matches = %+v, want slice_address", sliceMatches)
	}
	match := sliceMatches[0].Matches["$a"][0]
	if match.Offset != 3 || match.Base != 0 {
		t.Fatalf("slice match = %+v, want relative offset 3 and base 0", match)
	}
}

func TestMatchingRulesInBlockValidationAndContext(t *testing.T) {
	program, err := NewCompiler().CompileSource("rule true_rule { condition: true }")
	if err != nil {
		t.Fatal(err)
	}
	scanner := NewScanner(program)
	defer scanner.Close()
	if _, err := scanner.MatchingRulesInBlock(MemoryBlock{Base: -1}, 0); err == nil {
		t.Fatal("negative block base was accepted")
	}
	if _, err := scanner.MatchingRulesInBlock(MemoryBlock{}, -1); err == nil {
		t.Fatal("negative file size was accepted")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := scanner.MatchingRulesInBlockWithContext(ctx, MemoryBlock{}, 0); err != context.Canceled {
		t.Fatalf("canceled scan error = %v, want context.Canceled", err)
	}
	if got, err := (*Scanner)(nil).MatchingRulesInBlock(MemoryBlock{}, 0); err != nil || got != nil {
		t.Fatalf("nil scanner result = (%v, %v), want (nil, nil)", got, err)
	}
	if got, err := (*CompiledProgram)(nil).MatchingRulesInBlock(MemoryBlock{}, 0); err != nil || got != nil {
		t.Fatalf("nil program result = (%v, %v), want (nil, nil)", got, err)
	}
}

func TestMatchingRulesInBlockCleanRejectHasNoAllocations(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule routed_secret {
    strings:
        $gate = "api_key"
        $value = /secret_[A-Z]{2}[0-9]{6}/
    condition:
        all of them
}
`)
	if err != nil {
		t.Fatal(err)
	}
	scanner := NewScanner(program, WithFastScan())
	defer scanner.Close()
	block := MemoryBlock{Base: 1000, Data: []byte("ordinary structured field")}
	if _, err := scanner.MatchingRulesInBlock(block, 4096); err != nil {
		t.Fatal(err)
	}
	allocations := testing.AllocsPerRun(100, func() {
		matches, scanErr := scanner.MatchingRulesInBlock(block, 4096)
		if scanErr != nil || matches != nil {
			t.Fatalf("scan = (%v, %v), want (nil, nil)", matches, scanErr)
		}
	})
	if allocations != 0 {
		t.Fatalf("allocations = %v, want 0", allocations)
	}
}

func BenchmarkHighEPSMatchingRulesInBlock(b *testing.B) {
	const ruleCount = 10_000
	program, err := NewCompiler().CompileSource(highEPSRuleSource("mixed", ruleCount))
	if err != nil {
		b.Fatal(err)
	}
	scanner := NewScanner(program, WithFastScan())
	defer scanner.Close()
	block := MemoryBlock{Base: 1000, Data: []byte("ordinary structured field without a matching signature")}
	b.ReportAllocs()
	b.SetBytes(int64(len(block.Data)))
	b.ResetTimer()
	for b.Loop() {
		matches, scanErr := scanner.MatchingRulesInBlock(block, 16_384)
		if scanErr != nil {
			b.Fatal(scanErr)
		}
		highEPSRuleMatchesSink = matches
	}
}
