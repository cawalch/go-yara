package main

import (
	"bytes"
	"os"
	"testing"

	pcap "github.com/cawalch/go-pcap"
)

func TestRequiredServiceCapture(t *testing.T) {
	const path = "testdata/service.pcap"
	const want = "required_service_dns_failure name=\"api.example\" resolver=192.0.2.53:53 rcode=3 query_frame=1 reply_frame=2\n" +
		"required_service_dns_failure name=\"api.example\" resolver=192.0.2.53:53 rcode=2 query_frame=3 reply_frame=4\n"
	var out bytes.Buffer
	if err := run(path, &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != want {
		t.Fatalf("ReaderAt report:\n%s", &out)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c, err := pcap.New(b)
	if err != nil {
		t.Fatal(err)
	}
	records, err := c.DNS(b)
	if err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := report(records, &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != want {
		t.Fatalf("slice report:\n%s", &out)
	}
}
