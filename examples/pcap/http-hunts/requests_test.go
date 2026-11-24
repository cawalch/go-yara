package main

import (
	"bytes"
	"os"
	"slices"
	"testing"

	pcap "github.com/cawalch/go-pcap"
)

func TestCaptureHunts(t *testing.T) {
	const path = "testdata/hunts.pcap"
	const want = "unexpected_server_webhook_post frame=2 time_ns=1700000000002469134 flow=0 stream=0 source=192.0.2.10 POST webhook.site\n" +
		"unapproved_decoy_route_access frame=11 time_ns=1700000000013580237 flow=5 stream=3 source=192.0.2.12 GET app.example\n"

	var readerReport bytes.Buffer
	if err := run(path, &readerReport); err != nil {
		t.Fatal(err)
	}
	if got := readerReport.String(); got != want {
		t.Fatalf("ReaderAt findings:\n%s", got)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c, err := pcap.New(data)
	if err != nil {
		t.Fatal(err)
	}
	requests, err := c.HTTPRequests(data)
	if err != nil {
		t.Fatal(err)
	}
	// Ensure the approved integration, scanner, unknown source, ordinary routes,
	// and both requests in frame 7 actually reached the rule adapter. The TCP
	// retransmission in frame 4 must not contribute a duplicate request.
	var frames []int
	for _, r := range requests {
		frames = append(frames, r.PacketIndex+1)
	}
	if !slices.Equal(frames, []int{1, 2, 5, 6, 7, 7, 8, 9, 11}) {
		t.Fatalf("observed frames: %v", frames)
	}
	var sliceReport bytes.Buffer
	if err := report(requests, &sliceReport); err != nil {
		t.Fatal(err)
	}
	if got := sliceReport.String(); got != want {
		t.Fatalf("slice findings:\n%s", got)
	}
}
