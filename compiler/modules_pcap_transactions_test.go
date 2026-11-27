package compiler

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"testing"
)

func TestPCAPTransactionRules(t *testing.T) {
	const evidence = `
rule dns_evidence {
  condition:
    not pcap.capture_truncated and
    pcap.dns[0].pairing == "paired" and
    pcap.dns[0].query.questions[0].name == "updates.example" and
    pcap.dns[0].reply.complete and pcap.dns[0].reply.rcode == 0 and
    pcap.dns[0].reply.answers[0].address == "192.0.2.20" and
    pcap.dns[0].reply.answers[0].ttl == 30 and pcap.dns[0].reply.packet_index == 1
}
rule http_evidence {
  condition:
    pcap.http[0].request_packet == 4 and pcap.http[0].response_packet == 5 and
    pcap.http[0].request_headers[0].name == "Host" and
    pcap.http[0].response_body_state == "complete" and
    pcap.http[0].packets[0] == 4 and pcap.http[0].packets[1] == 5
}
rule unavailable_reply {
  condition:
    pcap.dns[0].pairing == "no_reply_observed" and not defined pcap.dns[0].reply
}
rule clipped_response {
  condition:
    pcap.capture_truncated and not defined pcap.http[0].response_body
}
rule unavailable {
  condition:
    not defined pcap.capture_truncated and not defined pcap.http and not defined pcap.dns
}
`
	rules, err := os.ReadFile("../examples/pcap/update-review/candidate.yar")
	if err != nil {
		t.Fatal(err)
	}
	program, err := NewCompiler().CompileSource(string(rules) + evidence)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := program.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := UnmarshalCompiledProgram(artifact)
	if err != nil {
		t.Fatal(err)
	}
	for _, program := range []*CompiledProgram{program, restored} {
		scanner := program.NewScanner()
		t.Cleanup(scanner.Close)
		for _, name := range []string{"positive", "control"} {
			raw, err := os.ReadFile("../examples/pcap/update-review/" + name + ".pcap")
			if err != nil {
				t.Fatal(err)
			}
			reader := bytes.NewReader(append([]byte("prefix"), raw...))
			if _, err := reader.Seek(6, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			for _, run := range []func() (*ScanResult, error){
				func() (*ScanResult, error) { return scanner.Scan(raw) },
				func() (*ScanResult, error) { return scanner.ScanReader(reader) },
			} {
				result, err := run()
				if err != nil {
					t.Fatal(err)
				}
				got := result.RuleResults
				if got["revoked_update"] != (name == "positive") || !got["dns_evidence"] ||
					!got["http_evidence"] || !got["observed_update_dns"] || got["unavailable"] {
					t.Fatalf("%s results = %v", name, got)
				}
			}
		}
		positive, err := os.ReadFile("../examples/pcap/update-review/positive.pcap")
		if err != nil {
			t.Fatal(err)
		}
		firstPacketEnd := 24 + 16 + int(binary.LittleEndian.Uint32(positive[32:36]))
		result, err := scanner.Scan(positive[:firstPacketEnd])
		if err != nil || !result.RuleResults["unavailable_reply"] || result.RuleResults["dns_evidence"] {
			t.Fatalf("query-only result = %+v, %v", result, err)
		}
		result, err = scanner.Scan(positive[:len(positive)-10])
		if err != nil || !result.RuleResults["clipped_response"] || result.RuleResults["revoked_update"] {
			t.Fatalf("clipped response result = %+v, %v", result, err)
		}
		result, err = scanner.Scan([]byte("not a capture"))
		if err != nil || !result.RuleResults["unavailable"] || result.RuleResults["http_evidence"] {
			t.Fatalf("invalid input result = %+v, %v", result, err)
		}
	}
}

func TestPCAPLegacyTLSSchema(t *testing.T) {
	program, err := NewCompiler().CompileSource(`import "pcap"
rule visible { condition: defined pcap.tls[0].flow_index }`)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range program.Rules {
		rule.moduleSchemas["pcap"] = pcapTLSSchema
	}
	data, err := program.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := UnmarshalCompiledProgram(data)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../examples/pcap/update-review/positive.pcap")
	if err != nil {
		t.Fatal(err)
	}
	// A valid HTTP-only capture supplies a defined, empty legacy TLS array.
	scanner := restored.NewScanner()
	defer scanner.Close()
	result, err := scanner.Scan(raw)
	if err != nil || result.RuleResults["visible"] || scanner.moduleCache.pcap == nil ||
		scanner.moduleCache.pcap.Type != ModuleArray {
		t.Fatalf("legacy TLS scan = %+v, %v", result, err)
	}
}
