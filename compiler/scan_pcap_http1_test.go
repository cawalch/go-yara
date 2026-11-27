package compiler

import (
	"os"
	"testing"

	pcap "github.com/cawalch/go-pcap"
)

func TestPCAPHTTP1ScopedRows(t *testing.T) {
	data, err := os.ReadFile("../examples/pcap/update-review/control.pcap")
	if err != nil {
		t.Fatal(err)
	}
	capture, err := pcap.New(data)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := capture.HTTP1Transactions(data)
	if err != nil || len(rows) != 2 {
		t.Fatalf("transactions = %d, %v", len(rows), err)
	}
	program, err := NewCompiler().CompileSourceWithContext(t.Context(), `import "pcap"
rule scoped {
    condition:
        pcap.dns[0].reply.complete and
        pcap.http[0].request_packet == 8 and pcap.http[0].response_packet == 9 and
        pcap.http[0].target == "/diagnostics"
}
rule empty_view {
    condition: defined pcap.http and not defined pcap.http[0]
}`)
	if err != nil {
		t.Fatal(err)
	}
	scanner := program.NewScanner()
	t.Cleanup(scanner.Close)
	projected, err := scanner.ScanWithPCAPHTTP1(t.Context(), data, rows[1:])
	if err != nil || !projected.RuleResults["scoped"] || projected.RuleResults["empty_view"] {
		t.Fatalf("projected rows = %+v, %v", projected, err)
	}
	empty, err := scanner.ScanWithPCAPHTTP1(t.Context(), data, nil)
	if err != nil || empty.RuleResults["scoped"] || !empty.RuleResults["empty_view"] {
		t.Fatalf("empty view = %+v, %v", empty, err)
	}
	full, err := scanner.ScanWithContext(t.Context(), data)
	if err != nil || full.RuleResults["scoped"] || full.RuleResults["empty_view"] {
		t.Fatalf("original capture = %+v, %v", full, err)
	}
}
