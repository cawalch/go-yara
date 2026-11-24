package compiler

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"io"
	"math/big"
	"os"
	"slices"
	"testing"

	pcap "github.com/cawalch/go-pcap"
)

// Each names entry makes a TLS flow with SNI service.example.test. A nil
// entry omits the server flight, as in a partial capture.
func pcapNameFixture(t *testing.T, names ...[]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := pcap.NewPCAPWriter(&buf, pcap.LinkTypeIPv4, 65535)
	if err != nil {
		t.Fatal(err)
	}
	write := func(packet []byte) {
		t.Helper()
		if err := w.WritePacket(int64(buf.Len()), packet); err != nil {
			t.Fatal(err)
		}
	}

	// Flow zero is unrelated traffic. Place all TLS records beyond the
	// scanner's 64 KiB retained header to exercise actual random access.
	for seq := uint32(1); seq < 66001; seq += 33000 {
		pkt := pcapTCPPacket(41000, false, make([]byte, 33000))
		binary.BigEndian.PutUint32(pkt[24:28], seq)
		write(pkt)
	}

	const host = "service.example.test"
	length16 := func(b []byte) []byte {
		return append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...)
	}
	sni := length16(append([]byte{0}, length16([]byte(host))...))
	extensions := length16(append([]byte{0, 0}, length16(sni)...))
	hello := append([]byte{3, 3}, make([]byte, 32)...)
	hello = append(hello, 0, 0, 2, 0xc0, 0x2b, 1, 0)
	hello = pcapTLSHandshake(1, append(hello, extensions...))
	for i, dnsNames := range names {
		port := uint16(42000 + i)
		write(pcapTCPPacket(port, false, hello))
		if dnsNames == nil {
			continue
		}
		cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: dnsNames}
		key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
		der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		chain := pcapLength24(pcapLength24(der))
		server := append([]byte{3, 3}, make([]byte, 32)...)
		server = pcapTLSHandshake(2, append(server, 0, 0xc0, 0x2b, 0))
		write(pcapTCPPacket(port, true, append(server, pcapTLSHandshake(11, chain)...)))
	}
	return buf.Bytes()
}

func pcapLength24(data []byte) []byte {
	return append([]byte{byte(len(data) >> 16), byte(len(data) >> 8), byte(len(data))}, data...)
}

func pcapTLSHandshake(kind byte, body []byte) []byte {
	message := append([]byte{kind}, pcapLength24(body)...)
	return append(binary.BigEndian.AppendUint16([]byte{22, 3, 3}, uint16(len(message))), message...)
}

func pcapTCPPacket(port uint16, server bool, payload []byte) []byte {
	ip := make([]byte, 40+len(payload))
	ip[0], ip[8], ip[9] = 0x45, 64, 6
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	src, dst := byte(1), byte(2)
	sport, dport := port, uint16(443)
	if server {
		src, dst = dst, src
		sport, dport = dport, sport
	}
	copy(ip[12:16], []byte{192, 0, 2, src})
	copy(ip[16:20], []byte{192, 0, 2, dst})
	binary.BigEndian.PutUint16(ip[20:22], sport)
	binary.BigEndian.PutUint16(ip[22:24], dport)
	binary.BigEndian.PutUint32(ip[24:28], 1)
	ip[32], ip[33] = 5<<4, 0x10
	copy(ip[40:], payload)
	return ip
}

type pcapCountingReader struct {
	*bytes.Reader
	reads int
}

func (r *pcapCountingReader) ReadAt(b []byte, off int64) (int, error) {
	r.reads++
	return r.Reader.ReadAt(b, off)
}

func TestPCAPNameRules(t *testing.T) {
	const source = `import "pcap"
rule wildcard { condition: pcap.tls[0].flow_index == 1 and pcap.tls[0].server_name_match }
rule mismatch { condition: for any row in pcap.tls : (row.flow_index == 2 and defined row.server_name_match and not row.server_name_match) }
rule missing_leaf { condition: pcap.tls[2].flow_index == 3 and not defined pcap.tls[2].server_name_match }
rule incomplete_sans { condition: pcap.tls[3].flow_index == 4 and not defined pcap.tls[3].server_name_match }
rule wrong_flow { condition: for any row in pcap.tls : (row.flow_index != 2 and defined row.server_name_match and not row.server_name_match) }
rule no_extra_rows { condition: not defined pcap.tls[4].flow_index }
rule unavailable { condition: not defined pcap.tls }`
	p, err := NewCompiler().CompileSource(source)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := UnmarshalCompiledProgram(blob)
	if err != nil {
		t.Fatal(err)
	}
	truncated := slices.Repeat([]string{"other.example.test"}, pcap.MaxTLSCertSANsPerKind)
	data := pcapNameFixture(t, []string{"*.example.test"}, []string{"other.example.test"}, nil, append(truncated, "service.example.test"))
	for _, program := range []*CompiledProgram{p, loaded} {
		s := program.NewScanner()
		check := func(result *ScanResult, err error) {
			t.Helper()
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"wildcard", "mismatch", "missing_leaf", "incomplete_sans", "no_extra_rows"} {
				if !result.RuleResults[name] {
					t.Fatalf("%s failed: %+v", name, result.RuleResults)
				}
			}
			if result.RuleResults["unavailable"] {
				t.Fatal("capture unavailable")
			}
			if result.RuleResults["wrong_flow"] {
				t.Fatal("mismatch attributed to the wrong flow")
			}
		}
		check(s.Scan(data))
		r := &pcapCountingReader{Reader: bytes.NewReader(append([]byte("skip"), data...))}
		if _, err := r.Seek(4, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		check(s.ScanReader(r))
		if r.reads == 0 {
			t.Fatal("seekable stream never used ReadAt")
		}
		res, err := s.ScanReader(io.LimitReader(bytes.NewReader(data), int64(len(data))))
		if err != nil || !res.RuleResults["unavailable"] || res.RuleResults["wildcard"] || res.RuleResults["mismatch"] {
			t.Fatalf("sequential reader with partial header: result=%v err=%v", res, err)
		}
		res, err = s.Scan(pcapNameFixture(t, []string{"service.example.test"}))
		if err != nil || !res.RuleResults["wildcard"] || res.RuleResults["mismatch"] || res.RuleResults["missing_leaf"] {
			t.Fatalf("subsequent capture: result=%v err=%v", res, err)
		}
		s.Close()
	}
}

func TestPCAPLazyReads(t *testing.T) {
	data := pcapNameFixture(t, []string{"*.example.test"})
	reads := func(source string) int {
		t.Helper()
		p, err := NewCompiler().CompileSource(source)
		if err != nil {
			t.Fatal(err)
		}
		r := &pcapCountingReader{Reader: bytes.NewReader(data)}
		result, err := p.ScanReader(r)
		if err != nil || !result.RuleResults["check"] {
			t.Fatalf("result=%v, err=%v", result, err)
		}
		s := p.NewScanner()
		defer s.Close()
		if _, err := s.Scan(data); err != nil {
			t.Fatal(err)
		}
		if (s.moduleCache.pcap == nil) != (r.reads == 0) {
			t.Fatal("slice and reader disagree on whether TLS was scanned")
		}
		return r.reads
	}
	for _, rule := range []string{
		`rule check { condition: true }`,
		`import "pcap" rule check { condition: true }`,
		`import "pcap" rule check { condition: defined pcap }`,
	} {
		if got := reads(rule); got != 0 {
			t.Fatalf("unused TLS: %d random reads", got)
		}
	}
	const first = `import "pcap" rule check { condition: pcap.tls[0].server_name_match }`
	one := reads(first)
	two := reads(first + ` rule again { condition: pcap.tls[0].flow_index == 1 and pcap.tls[0].server_name_match }`)
	t.Logf("TLS random reads: unused=0, one rule=%d, two rules=%d", one, two)
	if one == 0 || two != one {
		t.Fatalf("one TLS rule: %d reads, two: %d", one, two)
	}
}

func TestPCAPExampleRules(t *testing.T) {
	rules, err := os.ReadFile("../examples/pcap/tls.yar")
	if err != nil {
		t.Fatal(err)
	}
	program, err := NewCompiler().CompileSourceWithContext(t.Context(), string(rules))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name              string
		sans              []string
		mismatch, missing bool
	}{
		{"wildcard", []string{"*.example.test"}, false, false},
		{"wrong certificate", []string{"other.example.test"}, true, false},
		{"unavailable certificate", nil, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := program.Scan(pcapNameFixture(t, tc.sans))
			if err != nil {
				t.Fatal(err)
			}
			if result.RuleResults["tls_name_mismatch"] != tc.mismatch || result.RuleResults["tls_name_evidence_missing"] != tc.missing {
				t.Fatalf("unexpected matches: %v", result.RuleResults)
			}
		})
	}
}
