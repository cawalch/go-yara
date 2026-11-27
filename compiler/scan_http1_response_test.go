package compiler

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"slices"
	"testing"
	"time"

	pcap "github.com/cawalch/go-pcap"
)

func TestPCAPHTTP1ResponseScan(t *testing.T) {
	const fixture = "../examples/pcap/update-review/"
	rules, err := os.ReadFile(fixture + "entity.yar")
	if err != nil {
		t.Fatal(err)
	}
	program, err := NewCompiler().CompileSourceWithContext(t.Context(), string(rules)+`
rule diagnostics_entity {
    strings: $marker = "diagnostics-only"
    condition: $marker
}
rule empty_entity {
    condition: filesize == 0
}
`)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(fixture + "entities.pcap")
	if err != nil {
		t.Fatal(err)
	}
	scanner := program.NewScanner()
	t.Cleanup(scanner.Close)
	ctx := t.Context()
	standalone, err := scanner.ScanWithContext(ctx, []byte("artifact_id=REVOKED-BUILD-042\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(standalone.MatchedRules) != 1 || standalone.MatchedRules[0].Rule != "revoked_update_entity" {
		t.Fatalf("standalone matches = %+v", standalone.MatchedRules)
	}
	hits := standalone.MatchedRules[0].Matches["$id"]
	if len(hits) != 1 || hits[0].Offset != 12 {
		t.Fatalf("standalone offsets = %+v", hits)
	}
	reader := bytes.NewReader(raw)
	sliceCapture, err := pcap.New(raw)
	if err != nil {
		t.Fatal(err)
	}
	readerCapture, err := pcap.NewFromReaderAt(reader, int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []struct {
		name         string
		transactions func() ([]pcap.HTTP1Transaction, error)
	}{
		{"slice", func() ([]pcap.HTTP1Transaction, error) { return sliceCapture.HTTP1Transactions(raw) }},
		{"reader", func() ([]pcap.HTTP1Transaction, error) { return readerCapture.HTTP1TransactionsFromReaderAt(reader) }},
	} {
		t.Run(input.name, func(t *testing.T) {
			rows, err := input.transactions()
			if err != nil || len(rows) != 4 {
				t.Fatalf("transactions = %d, %v", len(rows), err)
			}
			for _, want := range []struct {
				index, bytes, request, response int
				target, rule                    string
				coverage                        pcap.HTTP1ArtifactCoverage
				bodyState                       pcap.HTTPBodyState
				packets                         []int
			}{
				{0, 30, 2, 3, "/updates/client", "revoked_update_entity", pcap.HTTP1ArtifactComplete, pcap.HTTPBodyComplete, []int{2, 3}},
				{1, 17, 6, 7, "/diagnostics", "diagnostics_entity", pcap.HTTP1ArtifactComplete, pcap.HTTPBodyComplete, []int{6, 7}},
				{2, 30, 10, 11, "/updates/range", "", pcap.HTTP1ArtifactPartial, pcap.HTTPBodyComplete, []int{10, 11}},
				{3, 0, 14, -1, "/updates/unseen", "", pcap.HTTP1ArtifactUnavailable, pcap.HTTPBodyUnknown, []int{14}},
				{0, 30, 2, 3, "/updates/client", "revoked_update_entity", pcap.HTTP1ArtifactComplete, pcap.HTTPBodyComplete, []int{2, 3}},
			} {
				row := rows[want.index]
				scan, err := scanner.ScanHTTP1Response(ctx, row.ResponseArtifact())
				if err != nil {
					t.Fatal(err)
				}
				artifact := scan.Artifact
				if row.Request.Target != want.target || artifact.Coverage != want.coverage ||
					artifact.BodyState != want.bodyState || len(artifact.Body) != want.bytes ||
					artifact.ID != (pcap.HTTP1TransactionID{PacketIndex: want.request}) ||
					artifact.ResponsePacketIndex != want.response ||
					!slices.Equal(artifact.ExchangePacketIndices, want.packets) {
					t.Fatalf("%s evidence = %+v", row.Request.Target, artifact)
				}
				if want.response >= 0 && artifact.ResponsePacketPayloadOffset != 0 {
					t.Fatalf("%s response payload offset = %d", want.target, artifact.ResponsePacketPayloadOffset)
				}
				if want.rule == "" {
					if scan.Result != nil {
						t.Fatalf("%s unexpectedly scanned: %+v", want.target, scan.Result)
					}
					continue
				}
				if scan.Result == nil || len(scan.Result.MatchedRules) != 1 || scan.Result.MatchedRules[0].Rule != want.rule {
					t.Fatalf("%s result = %+v", want.target, scan.Result)
				}
				if want.index == 0 && !reflect.DeepEqual(scan.Result, standalone) {
					t.Fatalf("entity result = %+v, standalone = %+v", scan.Result, standalone)
				}
			}
		})
	}
	empty := pcap.HTTP1ResponseArtifact{Coverage: pcap.HTTP1ArtifactComplete, BodyState: pcap.HTTPBodyComplete}
	scan, err := scanner.ScanHTTP1Response(ctx, empty)
	if err != nil || scan.Result == nil || len(scan.Result.MatchedRules) != 1 || scan.Result.MatchedRules[0].Rule != "empty_entity" {
		t.Fatalf("empty result = %+v, %v", scan, err)
	}
	noMatch := empty
	noMatch.Body = []byte("ordinary update")
	scan, err = scanner.ScanHTTP1Response(ctx, noMatch)
	if err != nil || scan.Result == nil || len(scan.Result.MatchedRules) != 0 {
		t.Fatalf("non-matching complete result = %+v, %v", scan, err)
	}
}

func TestPCAPHTTP1ResponseScanError(t *testing.T) {
	program, err := NewCompiler().CompileSourceWithContext(t.Context(), `rule empty { condition: filesize == 0 }`)
	if err != nil {
		t.Fatal(err)
	}
	pollAction := PollAbort
	scanner := program.NewScanner(WithPollHook(func(context.Context, PollProgress) (PollAction, time.Duration) {
		return pollAction, 0
	}, 0))
	t.Cleanup(scanner.Close)
	artifact := pcap.HTTP1ResponseArtifact{
		ID:       pcap.HTTP1TransactionID{PacketIndex: 12},
		Coverage: pcap.HTTP1ArtifactComplete,
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	scan, err := scanner.ScanHTTP1Response(ctx, artifact)
	if !errors.Is(err, context.Canceled) || scan.Result != nil || scan.Artifact.ID != artifact.ID {
		t.Fatalf("canceled scan = %+v, %v", scan, err)
	}
	scan, err = scanner.ScanHTTP1Response(t.Context(), artifact)
	if !errors.Is(err, ErrScanAborted) || scan.Result != nil || scan.Artifact.ID != artifact.ID {
		t.Fatalf("aborted scan = %+v, %v", scan, err)
	}
	pollAction = PollContinue
	scan, err = scanner.ScanHTTP1Response(t.Context(), artifact)
	if err != nil || scan.Result == nil || len(scan.Result.MatchedRules) != 1 {
		t.Fatalf("scan after abort = %+v, %v", scan, err)
	}
	artifact.Body = make([]byte, pcap.MaxHTTPBodyBytes+1)
	scan, err = scanner.ScanHTTP1Response(t.Context(), artifact)
	if !errors.Is(err, pcap.ErrHTTPLimit) || scan.Result != nil || scan.Artifact.ID != artifact.ID {
		t.Fatalf("oversize error = %v, result = %+v", err, scan.Result)
	}
}
