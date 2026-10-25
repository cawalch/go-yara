package compiler

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"
)

// countingReader wraps an io.Reader and counts total bytes read.
type countingReader struct {
	r         io.Reader
	bytesRead int64
}

func (cr *countingReader) Read(p []byte) (n int, err error) {
	n, err = cr.r.Read(p)
	atomic.AddInt64(&cr.bytesRead, int64(n))
	return n, err
}

func TestStreamingScanner_BoundarySpanning(t *testing.T) {
	ruleSrc := `
rule boundary_text {
	strings:
		$text = "CROSSING_BOUNDARY"
	condition:
		$text
}
rule boundary_hex {
	strings:
		$hex = { 4D 5A 90 00 03 00 00 00 }
	condition:
		$hex
}
rule boundary_regex {
	strings:
		$re = /ALERT_[0-9]{4}_END/
	condition:
		$re
}
`
	prog, err := NewCompiler().CompileSource(ruleSrc)
	if err != nil {
		t.Fatalf("failed to compile: %v", err)
	}

	// We use small chunk size (16 bytes) and overlap size (32 bytes)
	// so the 17-byte string "CROSSING_BOUNDARY" is guaranteed to span boundaries.
	chunkSize := 16
	overlapSize := 32

	var data bytes.Buffer
	data.WriteString("1234567890")             // 10 bytes: ends at 10
	data.WriteString("CROSSING_BOUNDARY")      // 17 bytes: 10..27 (spans boundary at 16)
	data.WriteString("AAAAA")                  // 5 bytes: 27..32 (spans boundary at 32)
	data.Write([]byte{0x4D, 0x5A, 0x90, 0x00}) // 4 bytes: 32..36
	data.Write([]byte{0x03, 0x00, 0x00, 0x00}) // 4 bytes: 36..40
	data.WriteString("BBBBBB")                 // 6 bytes: 40..46
	data.WriteString("ALERT_2026_END")         // 14 bytes: 46..60 (spans boundary at 48)
	data.WriteString("PADDING_TO_END_12345")   // remaining

	payload := data.Bytes()

	scanner := NewScanner(prog,
		WithStreamChunkSize(chunkSize),
		WithStreamOverlapSize(overlapSize),
	)

	res, err := scanner.ScanReader(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("ScanReader error: %v", err)
	}

	expectedRules := map[string]bool{
		"boundary_text":  true,
		"boundary_hex":   true,
		"boundary_regex": true,
	}

	if len(res.MatchedRules) != len(expectedRules) {
		t.Fatalf("matched %d rules, want %d", len(res.MatchedRules), len(expectedRules))
	}

	for _, m := range res.MatchedRules {
		if !expectedRules[m.Rule] {
			t.Errorf("unexpected matched rule: %s", m.Rule)
		}
	}

	// Verify exact match offsets and lengths
	textMatches := res.Matches["boundary_text"]["$text"]
	if len(textMatches) != 1 {
		t.Fatalf("expected 1 match for $text, got %d", len(textMatches))
	}
	if textMatches[0].Offset != 10 || textMatches[0].Length != 17 {
		t.Errorf("$text offset/len: got (%d, %d), want (10, 17)", textMatches[0].Offset, textMatches[0].Length)
	}

	hexMatches := res.Matches["boundary_hex"]["$hex"]
	if len(hexMatches) != 1 {
		t.Fatalf("expected 1 match for $hex, got %d", len(hexMatches))
	}
	if hexMatches[0].Offset != 32 || hexMatches[0].Length != 8 {
		t.Errorf("$hex offset/len: got (%d, %d), want (32, 8)", hexMatches[0].Offset, hexMatches[0].Length)
	}

	reMatches := res.Matches["boundary_regex"]["$re"]
	if len(reMatches) != 1 {
		t.Fatalf("expected 1 match for $re, got %d", len(reMatches))
	}
	if reMatches[0].Offset != 46 || reMatches[0].Length != 14 {
		t.Errorf("$re offset/len: got (%d, %d), want (46, 14)", reMatches[0].Offset, reMatches[0].Length)
	}
}

func TestStreamingScanner_FullwordBoundaryLookahead(t *testing.T) {
	ruleSrc := `
rule fullword_match {
	strings:
		$w = "TOKEN" fullword
	condition:
		$w
}
`
	prog, err := NewCompiler().CompileSource(ruleSrc)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Chunk size 7:
	// Input 1: "!!TOKEN!" -> "!!TOKEN" is in chunk 0 (len 7), '!' is in chunk 1 (offset 7).
	// Because '!' is non-word, "TOKEN" is a valid fullword.
	inputValid := []byte("!!TOKEN!padding")
	scanner := NewScanner(prog, WithStreamChunkSize(7), WithStreamOverlapSize(16))
	res, err := scanner.ScanReader(bytes.NewReader(inputValid))
	if err != nil {
		t.Fatalf("ScanReader error: %v", err)
	}
	if len(res.MatchedRules) != 1 {
		t.Fatalf("expected fullword_match to match inputValid, got %d matches", len(res.MatchedRules))
	}

	// Input 2: "!!TOKENxpadding" -> "!!TOKEN" in chunk 0, 'x' in chunk 1.
	// Because 'x' is a word byte, "TOKEN" is NOT a fullword.
	inputInvalid := []byte("!!TOKENxpadding")
	res, err = scanner.ScanReader(bytes.NewReader(inputInvalid))
	if err != nil {
		t.Fatalf("ScanReader error: %v", err)
	}
	if len(res.MatchedRules) != 0 {
		t.Fatalf("expected 0 matches for inputInvalid, got %d", len(res.MatchedRules))
	}
}

func TestStreamingScanner_ConditionsAndAggregates(t *testing.T) {
	ruleSrc := `
rule multi_chunk_and {
	strings:
		$a = "START_CHUNK"
		$b = "END_CHUNK"
	condition:
		$a and $b
}
rule occurrence_count {
	strings:
		$tag = "HIT"
	condition:
		#tag == 3
}
rule offset_query {
	strings:
		$tag = "HIT"
	condition:
		@tag[2] == 40
}
rule length_query {
	strings:
		$var = /VAR_[0-9]+/
	condition:
		!var[1] == 6
}
rule header_and_filesize {
	condition:
		uint16(0) == 0x5A4D and filesize == 64
}
rule inverted_condition {
	strings:
		$good = "START_CHUNK"
		$bad  = "FORBIDDEN"
	condition:
		$good and not $bad
}
`
	prog, err := NewCompiler().CompileSource(ruleSrc)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Build 64-byte payload:
	// Offset 0: 0x4D, 0x5A ("MZ")
	// Offset 10: "START_CHUNK" (11 bytes) -> 10..21
	// Offset 25: "HIT" (3 bytes) -> 25..28
	// Offset 40: "HIT" (3 bytes) -> 40..43
	// Offset 45: "VAR_12" (6 bytes) -> 45..51
	// Offset 52: "END_CHUNK" (9 bytes) -> 52..61
	// Offset 61: "HIT" (3 bytes) -> 61..64
	buf := make([]byte, 64)
	buf[0] = 0x4D
	buf[1] = 0x5A
	copy(buf[10:], "START_CHUNK")
	copy(buf[25:], "HIT")
	copy(buf[40:], "HIT")
	copy(buf[45:], "VAR_12")
	copy(buf[52:], "END_CHUNK")
	copy(buf[61:], "HIT")

	// Use small chunk size (16 bytes) to force 4 chunks (0..16, 16..32, 32..48, 48..64)
	scanner := NewScanner(prog, WithStreamChunkSize(16), WithStreamOverlapSize(32))

	res, err := scanner.ScanReader(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("ScanReader error: %v", err)
	}

	matchedMap := make(map[string]bool)
	for _, m := range res.MatchedRules {
		matchedMap[m.Rule] = true
	}

	expectedMatches := []string{
		"multi_chunk_and",
		"occurrence_count",
		"offset_query",
		"length_query",
		"header_and_filesize",
		"inverted_condition",
	}

	for _, expected := range expectedMatches {
		if !matchedMap[expected] {
			t.Errorf("expected rule %q to match, but it did not", expected)
		}
	}
}

func TestStreamingScanner_EarlyTermination(t *testing.T) {
	ruleSrc := `
rule early_hit {
	strings:
		$hit = "TRIGGER_HIT"
	condition:
		$hit
}
`
	prog, err := NewCompiler().CompileSource(ruleSrc)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// 10 MB payload with "TRIGGER_HIT" in the first 100 bytes
	totalSize := 10 * 1024 * 1024
	largeBuf := make([]byte, totalSize)
	copy(largeBuf[50:], "TRIGGER_HIT")

	cr := &countingReader{r: bytes.NewReader(largeBuf)}

	// Test MatchesReader (which enables early termination automatically)
	matched, err := prog.MatchesReader(cr)
	if err != nil {
		t.Fatalf("MatchesReader error: %v", err)
	}
	if !matched {
		t.Fatal("expected MatchesReader to return true")
	}

	// With 1MB chunk size, it should have terminated after reading chunk 0 (<= 1.1 MB),
	// NOT the entire 10MB!
	bytesRead := atomic.LoadInt64(&cr.bytesRead)
	if bytesRead >= int64(totalSize) {
		t.Fatalf("early termination failed: read all %d bytes", bytesRead)
	}
	if bytesRead > 2*1024*1024 {
		t.Fatalf("read too many bytes before early terminating: %d bytes", bytesRead)
	}
	t.Logf("Early termination successfully stopped after %d bytes (out of %d total)", bytesRead, totalSize)
}

func TestStreamingScanner_ParityWithScan(t *testing.T) {
	ruleSrc := `
rule r1 {
	strings:
		$a = "alpha"
		$b = "beta"
	condition:
		$a and $b
}
rule r2 {
	strings:
		$c = "gamma"
	condition:
		#c >= 2
}
rule r3 {
	strings:
		$d = "delta"
	condition:
		not $d
}
rule r4 {
	strings:
		$e = /secret_[0-9]+/
	condition:
		$e
}
rule r5 {
	condition:
		uint16(0) == 0x3031 and filesize == 150
}
`
	prog, err := NewCompiler().CompileSource(ruleSrc)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Construct exactly 150-byte payload:
	// Start with "01" (0x3031)
	var sb strings.Builder
	sb.WriteString("01")
	sb.WriteString("..alpha..")
	sb.WriteString("gamma..")
	sb.WriteString("secret_999..")
	sb.WriteString("gamma..")
	sb.WriteString("beta..")
	for sb.Len() < 150 {
		sb.WriteString("X")
	}
	payload := []byte(sb.String()[:150])

	scannerScan := NewScanner(prog)
	resDirect, err := scannerScan.Scan(payload)
	if err != nil {
		t.Fatalf("Scan direct error: %v", err)
	}

	// Run with various streaming chunk sizes: 8, 17, 33, 1024
	chunkSizes := []int{8, 17, 33, 1024}
	for _, cs := range chunkSizes {
		t.Run(fmt.Sprintf("chunk_size_%d", cs), func(t *testing.T) {
			scannerStream := NewScanner(prog, WithStreamChunkSize(cs), WithStreamOverlapSize(32))
			resStream, err := scannerStream.ScanReader(bytes.NewReader(payload))
			if err != nil {
				t.Fatalf("ScanReader error: %v", err)
			}

			if len(resStream.MatchedRules) != len(resDirect.MatchedRules) {
				t.Fatalf("matched count mismatch: direct=%d stream=%d", len(resDirect.MatchedRules), len(resStream.MatchedRules))
			}

			directNames := make(map[string]bool)
			for _, m := range resDirect.MatchedRules {
				directNames[m.Rule] = true
			}
			for _, m := range resStream.MatchedRules {
				if !directNames[m.Rule] {
					t.Errorf("stream matched rule %q not in direct scan", m.Rule)
				}
			}

			// Verify match offset parity for rule r1
			r1DirectMatches := resDirect.Matches["r1"]["$a"]
			r1StreamMatches := resStream.Matches["r1"]["$a"]
			if len(r1DirectMatches) != len(r1StreamMatches) {
				t.Fatalf("r1 matches count mismatch: direct=%d stream=%d", len(r1DirectMatches), len(r1StreamMatches))
			}
			if len(r1DirectMatches) > 0 {
				if r1DirectMatches[0].Offset != r1StreamMatches[0].Offset {
					t.Errorf("offset mismatch: direct=%d stream=%d", r1DirectMatches[0].Offset, r1StreamMatches[0].Offset)
				}
			}
		})
	}
}

func TestStreamingScanner_ContextCancellation(t *testing.T) {
	ruleSrc := `
rule slow {
	strings:
		$s = "TARGET"
	condition:
		$s
}
`
	prog, err := NewCompiler().CompileSource(ruleSrc)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	scanner := NewScanner(prog, WithStreamChunkSize(16))
	_, err = scanner.ScanReaderWithContext(ctx, bytes.NewReader([]byte("TARGET_DATA_HERE")))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
}

func BenchmarkStreamingScan_1MB(b *testing.B) {
	ruleSrc := `
rule bench_match {
	strings:
		$a = "BENCHMARK_TARGET_TOKEN"
	condition:
		$a
}
`
	prog, err := NewCompiler().CompileSource(ruleSrc)
	if err != nil {
		b.Fatalf("compile error: %v", err)
	}

	size := 1024 * 1024
	data := make([]byte, size)
	copy(data[size-100:], "BENCHMARK_TARGET_TOKEN")

	scanner := NewScanner(prog)

	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		res, err := scanner.ScanReader(bytes.NewReader(data))
		if err != nil || len(res.MatchedRules) == 0 {
			b.Fatalf("scan error: %v, matches: %d", err, len(res.MatchedRules))
		}
	}
}

func BenchmarkStreamingScan_10MB(b *testing.B) {
	ruleSrc := `
rule bench_match {
	strings:
		$a = "BENCHMARK_TARGET_TOKEN"
	condition:
		$a
}
`
	prog, err := NewCompiler().CompileSource(ruleSrc)
	if err != nil {
		b.Fatalf("compile error: %v", err)
	}

	size := 10 * 1024 * 1024
	data := make([]byte, size)
	copy(data[size-100:], "BENCHMARK_TARGET_TOKEN")

	scanner := NewScanner(prog)

	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		res, err := scanner.ScanReader(bytes.NewReader(data))
		if err != nil || len(res.MatchedRules) == 0 {
			b.Fatalf("scan error: %v, matches: %d", err, len(res.MatchedRules))
		}
	}
}

func BenchmarkMatchesReaderEarlyTermination_10MB(b *testing.B) {
	ruleSrc := `
rule bench_early {
	strings:
		$a = "BENCHMARK_TARGET_TOKEN"
	condition:
		$a
}
`
	prog, err := NewCompiler().CompileSource(ruleSrc)
	if err != nil {
		b.Fatalf("compile error: %v", err)
	}

	size := 10 * 1024 * 1024
	data := make([]byte, size)
	copy(data[50:], "BENCHMARK_TARGET_TOKEN")

	scanner := NewScanner(prog)

	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		matched, err := scanner.MatchesReader(bytes.NewReader(data))
		if err != nil || !matched {
			b.Fatalf("matches reader error: %v, matched: %v", err, matched)
		}
	}
}
