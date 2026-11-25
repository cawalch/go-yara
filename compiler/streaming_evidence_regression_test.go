package compiler

import (
	"bytes"
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSkipUnmatchedNonTextNotLeakedAcrossScannerReuse(t *testing.T) {
	source := `
rule helper_pad {
	strings:
		$h1 = "PAD_ALPHA"
		$h2 = "PAD_BETA"
	condition:
		any of them
}
rule gated_regex {
	strings:
		$t = "KEY_PRESENT"
		$r = /VAL_[0-9]{4}/
	condition:
		$t and $r
}
`
	program := mustCompileStreamingProgram(t, source)
	scanner := program.NewScanner(WithStreamChunkSize(16), WithStreamOverlapSize(8))
	defer scanner.Close()

	// Warm via Matches() and MatchingRules() which set s.skipUnmatchedNonText = true.
	matched, err := scanner.Matches([]byte("no_match_here"))
	if err != nil || matched {
		t.Fatalf("Matches() = %v, err = %v, want false, nil", matched, err)
	}
	if _, err := scanner.MatchingRules([]byte("still_nothing")); err != nil {
		t.Fatalf("MatchingRules() err = %v", err)
	}

	payload := []byte("KEY_PRESENT-----________________VAL_4242________")
	want, err := scanner.Scan(payload)
	if err != nil {
		t.Fatalf("Scan() err = %v", err)
	}
	if len(want.MatchedRules) != 1 || want.MatchedRules[0].Rule != "gated_regex" {
		t.Fatalf("Scan() matched = %+v, want gated_regex", want.MatchedRules)
	}

	// ScanReader and MatchesReader must reset skipUnmatchedNonText so chunk 1 still runs $r.
	got, err := scanner.ScanReader(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("ScanReader() err = %v", err)
	}
	if len(got.MatchedRules) != 1 || got.MatchedRules[0].Rule != "gated_regex" {
		t.Fatalf("ScanReader() matched = %+v, want gated_regex", got.MatchedRules)
	}

	ok, err := scanner.MatchesReader(bytes.NewReader(payload))
	if err != nil || !ok {
		t.Fatalf("MatchesReader() = %v, err = %v, want true, nil", ok, err)
	}

	// BlockScanner with KEY_PRESENT in block 0 and VAL_4242 in block 1.
	blocks := program.NewBlockScanner()
	defer blocks.Close()
	blocks.scanner.skipUnmatchedNonText = true
	if err := blocks.Scan(0, payload[:16]); err != nil {
		t.Fatalf("BlockScanner.Scan(0) err = %v", err)
	}
	if err := blocks.Scan(16, payload[16:]); err != nil {
		t.Fatalf("BlockScanner.Scan(16) err = %v", err)
	}
	blockRes, err := blocks.Finish()
	if err != nil {
		t.Fatalf("BlockScanner.Finish() err = %v", err)
	}
	if len(blockRes.MatchedRules) != 1 || blockRes.MatchedRules[0].Rule != "gated_regex" {
		t.Fatalf("BlockScanner matched = %+v, want gated_regex", blockRes.MatchedRules)
	}
}

func TestEarlyTerminationDependenciesHeaderEntrypointAndRuleGate(t *testing.T) {
	t.Run("negated_rule_dependency", func(t *testing.T) {
		program := mustCompileStreamingProgram(t, `
private rule blocker {
	strings:
		$b = "BLOCK_LATER"
	condition:
		$b
}
rule trigger {
	strings:
		$a = "HIT_EARLY"
	condition:
		$a and not blocker
}
`)
		data := append([]byte("HIT_EARLY_______"), []byte("________________BLOCK_LATER")...)
		scanner := program.NewScanner(WithStreamChunkSize(16), WithStreamOverlapSize(8), WithStreamEarlyTermination(true))
		defer scanner.Close()

		want, err := scanner.Scan(data)
		if err != nil {
			t.Fatalf("Scan() err = %v", err)
		}
		if len(want.MatchedRules) != 0 {
			t.Fatalf("Scan() matched = %+v, want 0", want.MatchedRules)
		}

		got, err := scanner.ScanReader(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("ScanReader() err = %v", err)
		}
		if len(got.MatchedRules) != 0 {
			t.Fatalf("ScanReader() matched = %+v, want 0", got.MatchedRules)
		}

		matched, err := scanner.MatchesReader(bytes.NewReader(data))
		if err != nil || matched {
			t.Fatalf("MatchesReader() = %v, err = %v, want false, nil", matched, err)
		}
	})

	t.Run("integer_read_before_header_complete", func(t *testing.T) {
		program := mustCompileStreamingProgram(t, `
rule delayed_header_check {
	strings:
		$a = "HIT_EARLY"
	condition:
		$a and not defined uint16(100)
}
`)
		data := make([]byte, 256)
		copy(data, "HIT_EARLY")
		data[100] = 'c'
		data[101] = 'b'

		scanner := program.NewScanner(WithStreamChunkSize(16), WithStreamOverlapSize(8), WithStreamEarlyTermination(true))
		defer scanner.Close()

		matched, err := scanner.MatchesReader(bytes.NewReader(data))
		if err != nil || matched {
			t.Fatalf("MatchesReader() = %v, err = %v, want false, nil", matched, err)
		}
		res, err := scanner.ScanReader(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("ScanReader() err = %v", err)
		}
		if len(res.MatchedRules) != 0 {
			t.Fatalf("ScanReader() matched = %+v, want 0", res.MatchedRules)
		}
	})

	t.Run("entrypoint_disallows_early_termination", func(t *testing.T) {
		program := mustCompileStreamingProgram(t, `
rule ep_rule {
	strings:
		$a = "HIT"
	condition:
		$a and entrypoint >= 0
}
`)
		scanner := program.NewScanner()
		defer scanner.Close()
		if scanner.canRuleEarlyTerminate(program.Rules[0], streamingHeaderSize) {
			t.Fatal("canRuleEarlyTerminate returned true for entrypoint rule")
		}
	})

	t.Run("rule_gate_func_respected", func(t *testing.T) {
		program := mustCompileStreamingProgram(t, `
rule gated_out {
	strings:
		$a = "FIRST"
	condition:
		$a
}
rule allowed {
	strings:
		$b = "SECOND"
	condition:
		$b
}
`)
		data := []byte("FIRST___________SECOND__________")
		scanner := program.NewScanner(
			WithStreamChunkSize(16),
			WithStreamOverlapSize(8),
			WithStreamEarlyTermination(true),
			WithRuleGate(func(r *CompiledRule) bool {
				return r.Name == "allowed"
			}),
		)
		defer scanner.Close()

		matched, err := scanner.MatchesReader(bytes.NewReader(data))
		if err != nil || !matched {
			t.Fatalf("MatchesReader() = %v, err = %v, want true, nil", matched, err)
		}

		res, err := scanner.ScanReader(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("ScanReader() err = %v", err)
		}
		if len(res.MatchedRules) != 1 || res.MatchedRules[0].Rule != "allowed" {
			t.Fatalf("ScanReader() matched = %+v, want [allowed]", res.MatchedRules)
		}
	})
}

func TestScanReaderPrivateStringsAndMatchDataTruncationWithEvidence(t *testing.T) {
	program := mustCompileStreamingProgram(t, `
rule redact_and_capture {
	strings:
		$pub = /token=([a-z]{10})/ capture(secret = 1)
		$priv = "INTERNAL_SECRET" private
	evidence:
		cred = (secret) within 0 of secret
	condition:
		$pub and $priv
}
`)
	data := []byte("xx token=abcdefghij INTERNAL_SECRET yy")

	for _, opts := range [][]ScannerOption{
		{WithStreamChunkSize(7), WithEvidence(64), WithMatchData(4)},
		{WithStreamChunkSize(7), WithEvidence(64), WithMatchData(4), WithReportedMatchesOnly()},
	} {
		scanner := program.NewScanner(opts...)
		res, err := scanner.ScanReader(bytes.NewReader(data))
		scanner.Close()
		if err != nil {
			t.Fatalf("ScanReader() err = %v", err)
		}
		if len(res.MatchedRules) != 1 {
			t.Fatalf("MatchedRules = %+v, want 1", res.MatchedRules)
		}
		rm := res.MatchedRules[0]
		if _, leaked := rm.Matches["$priv"]; leaked {
			t.Fatalf("private string $priv leaked in RuleMatch.Matches: %+v", rm.Matches["$priv"])
		}
		if _, leaked := res.Matches["redact_and_capture"]["$priv"]; leaked {
			t.Fatalf("private string $priv leaked in ScanResult.Matches: %+v", res.Matches["redact_and_capture"]["$priv"])
		}

		pubMatches := res.Matches["redact_and_capture"]["$pub"]
		if len(pubMatches) != 1 {
			t.Fatalf("pubMatches = %+v, want 1", pubMatches)
		}
		if string(pubMatches[0].MatchedData) != "toke" || !pubMatches[0].MatchedDataTruncated {
			t.Fatalf("MatchedData = %q (truncated=%v), want %q (truncated=true)",
				pubMatches[0].MatchedData, pubMatches[0].MatchedDataTruncated, "toke")
		}
		if len(pubMatches[0].Captures) != 1 || string(pubMatches[0].Captures[0].Data) != "abcdefghij" {
			t.Fatalf("Captures = %+v, want full capture %q", pubMatches[0].Captures, "abcdefghij")
		}
		findings := res.Evidence["redact_and_capture"]["cred"]
		if len(findings) != 1 || string(findings[0].Anchor.Data) != "abcdefghij" {
			t.Fatalf("Evidence findings = %+v, want %q", findings, "abcdefghij")
		}
	}
}

func TestScanReaderFastScanFullwordTextParity(t *testing.T) {
	programs := map[string]string{
		"single_rule": `
rule fw {
	strings:
		$w = "ab" fullword
	condition:
		$w
}
`,
		"multi_rule": `
rule pad1 { strings: $p1 = "PAD_ONE" condition: $p1 }
rule pad2 { strings: $p2 = "PAD_TWO" condition: $p2 }
rule fw {
	strings:
		$w = "ab" fullword
	condition:
		$w
}
`,
	}

	inputs := [][]byte{
		[]byte("xab ab"),
		[]byte("xxabx ab!"),
		[]byte("abab! ab "),
		[]byte("xxxxxxab!ab!xxxxx"),
	}

	for name, src := range programs {
		t.Run(name, func(t *testing.T) {
			program := mustCompileStreamingProgram(t, src)
			for _, input := range inputs {
				refScanner := program.NewScanner(WithFastScan())
				want, err := refScanner.Scan(input)
				refScanner.Close()
				if err != nil {
					t.Fatalf("Scan() err = %v", err)
				}
				for _, chunk := range []int{1, 2, 3, 4, 5} {
					for _, overlap := range []int{0, 4, 8} {
						opts := []ScannerOption{WithFastScan(), WithStreamChunkSize(chunk)}
						if overlap > 0 {
							opts = append(opts, WithStreamOverlapSize(overlap))
						}
						streamScanner := program.NewScanner(opts...)
						got, err := streamScanner.ScanReader(bytes.NewReader(input))
						streamScanner.Close()
						if err != nil {
							t.Fatalf("chunk=%d overlap=%d ScanReader() err = %v", chunk, overlap, err)
						}
						if len(got.MatchedRules) != len(want.MatchedRules) {
							t.Fatalf("input=%q chunk=%d overlap=%d matched=%d, want %d",
								input, chunk, overlap, len(got.MatchedRules), len(want.MatchedRules))
						}
					}
				}
			}
		})
	}
}

func TestMaxStreamingOverlapHexPatterns(t *testing.T) {
	t.Run("long_jump_and_nested_alt", func(t *testing.T) {
		program := mustCompileStreamingProgram(t, `
rule long_hex {
	strings:
		$h1 = { 4D 5A [5000] 90 90 }
		$h2 = { 4D 5A ( AA BB [100-5100] CC | DD ) 90 }
	condition:
		any of them
}
`)
		got := program.maxStreamingOverlap()
		// $h2 spans 2 + (2 + 5100 + 1) + 1 = 5106 bytes, plus 4096 context margin = 9202.
		if got < 5106+4096 {
			t.Fatalf("maxStreamingOverlap() = %d, want >= %d", got, 5106+4096)
		}

		// Verify actual ScanReader parity across 1024-byte chunks with default overlap.
		payload := make([]byte, 7000)
		copy(payload[1000:], []byte{0x4D, 0x5A})
		copy(payload[1000+2+5000:], []byte{0x90, 0x90})
		scanner := program.NewScanner(WithStreamChunkSize(1024))
		defer scanner.Close()
		res, err := scanner.ScanReader(bytes.NewReader(payload))
		if err != nil {
			t.Fatalf("ScanReader() err = %v", err)
		}
		if len(res.MatchedRules) != 1 || len(res.Matches["long_hex"]["$h1"]) != 1 {
			t.Fatalf("unexpected ScanReader result: %+v", res)
		}
	})

	t.Run("unbounded_jump_and_overflow_safety", func(t *testing.T) {
		unbounded := mustCompileStreamingProgram(t, `
rule u {
	strings:
		$h = { 4D 5A [-] 90 }
	condition:
		$h
}
`)
		if got := unbounded.maxStreamingOverlap(); got < 2*regexVerificationDistance+4096 {
			t.Fatalf("unbounded hex maxStreamingOverlap() = %d, want >= %d", got, 2*regexVerificationDistance+4096)
		}

		overflowProg := &CompiledProgram{
			Rules: []*CompiledRule{{
				Name: "overflow",
				HexPatterns: map[string]*HexPattern{
					"$h": {
						Tokens: []HexPatternToken{
							{Kind: HexTokenByte, Value: 0x41},
							{Kind: HexTokenJump, Min: 1, Max: math.MaxInt},
							{Kind: HexTokenJump, Min: 1, Max: math.MaxInt},
						},
					},
				},
			}},
		}
		if got := overflowProg.maxStreamingOverlap(); got != math.MaxInt {
			t.Fatalf("overflow maxStreamingOverlap() = %d, want math.MaxInt (%d)", got, math.MaxInt)
		}
	})
}

func TestScanReaderBoundaryAndZeroLengthCaptureReplay(t *testing.T) {
	t.Run("ascii_and_wide_word_boundaries", func(t *testing.T) {
		program := mustCompileStreamingProgram(t, `
rule boundaries {
	strings:
		$non_word = /\B([a-z]{3})\B/ capture(mid = 1)
		$word = /\b([A-Z]{3})\b/ capture(tok = 1)
		$wide_non_word = /\B([a-z]{3})\B/ wide capture(wmid = 1)
	condition:
		all of them
}
`)
		input := append([]byte("xabcy !XYZ! "), wideBytes("pqrst")...)
		refScanner := program.NewScanner(WithEvidence(64))
		want, err := refScanner.Scan(input)
		refScanner.Close()
		if err != nil {
			t.Fatalf("Scan() err = %v", err)
		}

		for _, chunk := range []int{1, 2, 3, 7} {
			s := program.NewScanner(WithStreamChunkSize(chunk), WithEvidence(64))
			got, err := s.ScanReader(bytes.NewReader(input))
			s.Close()
			if err != nil {
				t.Fatalf("chunk=%d ScanReader() err = %v", chunk, err)
			}
			for _, pat := range []string{"$non_word", "$word", "$wide_non_word"} {
				wantMatches := want.Matches["boundaries"][pat]
				gotMatches := got.Matches["boundaries"][pat]
				if len(gotMatches) != len(wantMatches) || len(gotMatches) == 0 {
					t.Fatalf("chunk=%d pat=%s matches=%+v, want %+v", chunk, pat, gotMatches, wantMatches)
				}
				if !reflect.DeepEqual(gotMatches[0].Captures, wantMatches[0].Captures) {
					t.Fatalf("chunk=%d pat=%s captures=%+v, want %+v", chunk, pat, gotMatches[0].Captures, wantMatches[0].Captures)
				}
			}
		}
	})

	t.Run("zero_length_capture", func(t *testing.T) {
		program := mustCompileStreamingProgram(t, `
rule zero_len {
	strings:
		$z = /a*/ capture(whole = 0)
		$g = /(a*)/ capture(sub = 1)
	evidence:
		ev = (whole, sub) within 0 of whole
	condition:
		$z and $g
}
`)
		for _, input := range [][]byte{[]byte("b"), []byte("x")} {
			s := program.NewScanner(WithStreamChunkSize(1), WithEvidence(64))
			res, err := s.ScanReader(bytes.NewReader(input))
			s.Close()
			if err != nil {
				t.Fatalf("input=%q ScanReader() err = %v", input, err)
			}
			if len(res.MatchedRules) != 1 {
				t.Fatalf("input=%q MatchedRules = %+v", input, res.MatchedRules)
			}
			zMatch := res.Matches["zero_len"]["$z"][0]
			if zMatch.Length != 0 || len(zMatch.Captures) != 1 || zMatch.Captures[0].Length != 0 || len(zMatch.Captures[0].Data) != 0 {
				t.Fatalf("zMatch = %+v", zMatch)
			}
			gMatch := res.Matches["zero_len"]["$g"][0]
			if gMatch.Length != 0 || len(gMatch.Captures) != 1 || gMatch.Captures[0].Length != 0 || len(gMatch.Captures[0].Data) != 0 {
				t.Fatalf("gMatch = %+v", gMatch)
			}
			findings := res.Evidence["zero_len"]["ev"]
			if len(findings) == 0 || findings[0].Status != EvidenceStatusReady {
				t.Fatalf("findings = %+v", findings)
			}
		}
	})
}

func TestBorrowedEvidenceClearsRetainedReferences(t *testing.T) {
	program := mustCompileStreamingProgram(t, `
rule leak {
	strings:
		$a = /token=([a-z0-9]+)/ capture(secret = 1)
	evidence:
		cred = (secret) within 0 of secret
	condition:
		$a
}
`)
	scanner := program.NewScanner(WithEvidence(64), WithBorrowedEvidence(true))
	defer scanner.Close()

	input1 := bytes.Repeat([]byte("token=secretvalue123 "), 32)
	res1, err := scanner.Scan(input1)
	if err != nil {
		t.Fatalf("first Scan() err = %v", err)
	}
	if len(res1.Evidence["leak"]["cred"]) != 32 {
		t.Fatalf("findings = %d, want 32", len(res1.Evidence["leak"]["cred"]))
	}

	// Next scan has no matches; resetBorrowedEvidence must clear all pooled slots.
	res2, err := scanner.Scan([]byte("clean_input"))
	if err != nil {
		t.Fatalf("second Scan() err = %v", err)
	}
	if len(res2.MatchedRules) != 0 {
		t.Fatalf("second Scan() matched = %+v, want 0", res2.MatchedRules)
	}

	if scanner.borrowedFieldsMapIdx != 0 || scanner.borrowedFindingsIdx != 0 || scanner.borrowedPlanMapIdx != 0 {
		t.Fatalf("borrowed indices not reset: fields=%d findings=%d plans=%d",
			scanner.borrowedFieldsMapIdx, scanner.borrowedFindingsIdx, scanner.borrowedPlanMapIdx)
	}
	for i, m := range scanner.borrowedFieldsMaps {
		if len(m) != 0 {
			t.Fatalf("borrowedFieldsMaps[%d] retained %d entries", i, len(m))
		}
	}
	for i, m := range scanner.borrowedPlanMaps {
		if len(m) != 0 {
			t.Fatalf("borrowedPlanMaps[%d] retained %d entries", i, len(m))
		}
	}
	for i, f := range scanner.borrowedFindings {
		if !reflect.DeepEqual(f, EvidenceFinding{}) {
			t.Fatalf("borrowedFindings[%d] retained data: %+v", i, f)
		}
	}
	for i, c := range scanner.borrowedCaptureSlab[:cap(scanner.borrowedCaptureSlab)] {
		if !reflect.DeepEqual(c, Capture{}) {
			t.Fatalf("borrowedCaptureSlab[%d] retained capture: %+v", i, c)
		}
	}
	if len(scanner.borrowedEvidenceRuleMap) != 0 {
		t.Fatalf("borrowedEvidenceRuleMap retained %d entries", len(scanner.borrowedEvidenceRuleMap))
	}
}

type stepCancelContext struct {
	failAfter int
	checks    int
}

func (c *stepCancelContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *stepCancelContext) Done() <-chan struct{}       { return nil }
func (c *stepCancelContext) Value(any) any               { return nil }
func (c *stepCancelContext) Err() error {
	c.checks++
	if c.checks > c.failAfter {
		return context.Canceled
	}
	return nil
}

func TestStreamingProcessorPropagatesPeekError(t *testing.T) {
	program := mustCompileStreamingProgram(t, `
rule hit {
	strings:
		$a = "ABCD"
	condition:
		$a
}
`)
	path := filepath.Join(t.TempDir(), "input.bin")
	payload := []byte(strings.Repeat("ABCD", 16)) // 64 bytes
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("os.WriteFile() err = %v", err)
	}

	sp := NewStreamingProcessor(program)
	sp.ChunkSize = 16
	sp.BufferSize = 16

	// Context Err() calls before Peek:
	// 1: ProcessFile initial ctx.Err()
	// 2: processFileChunks loop-top ctx.Err()
	// 3: contextReader.Read inside io.ReadFull(reader, targetSlice[:16])
	// 4: contextReader.Read inside reader.Peek(streamingBoundaryContext) -> fails!
	ctx := &stepCancelContext{failAfter: 3}
	matches, err := sp.ProcessFile(ctx, path)
	if !errors.Is(err, context.Canceled) || err == nil || !strings.Contains(err.Error(), "peek streaming input") {
		t.Fatalf("ProcessFile() matches=%+v, err=%v, want wrapped peek error", matches, err)
	}
}

func TestStreamEarlyTerminationDoesNotTruncateScanOrBlockScanner(t *testing.T) {
	program := mustCompileStreamingProgram(t, `
rule first {
	strings:
		$a = "ALPHA"
	condition:
		$a
}
rule second {
	strings:
		$b = "BETA"
	condition:
		$b
}
`)
	data := []byte("ALPHA and BETA")

	scanner := program.NewScanner(WithStreamEarlyTermination(true))
	defer scanner.Close()

	scanRes, err := scanner.Scan(data)
	if err != nil {
		t.Fatalf("Scan() err = %v", err)
	}
	if len(scanRes.MatchedRules) != 2 {
		t.Fatalf("Scan() MatchedRules = %+v, want 2", scanRes.MatchedRules)
	}

	blocks := program.NewBlockScanner(WithStreamEarlyTermination(true))
	defer blocks.Close()
	if err := blocks.Scan(0, data); err != nil {
		t.Fatalf("BlockScanner.Scan() err = %v", err)
	}
	blockRes, err := blocks.Finish()
	if err != nil {
		t.Fatalf("BlockScanner.Finish() err = %v", err)
	}
	if len(blockRes.MatchedRules) != 2 {
		t.Fatalf("BlockScanner.Finish() MatchedRules = %+v, want 2", blockRes.MatchedRules)
	}

	streamRes, err := scanner.ScanReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ScanReader() err = %v", err)
	}
	if len(streamRes.MatchedRules) != 1 {
		t.Fatalf("ScanReader() with WithStreamEarlyTermination(true) MatchedRules = %+v, want 1", streamRes.MatchedRules)
	}
}
