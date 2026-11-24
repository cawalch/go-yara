package compiler

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
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

func TestPCAPTriageRules(t *testing.T) {
	rules, err := os.ReadFile("../examples/pcap/tls-triage.yar")
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewCompiler().CompileSource(string(rules))
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
	const multiple = "tls_multiple_name_mismatches"
	const mixed = "tls_mixed_name_results"
	const gaps = "tls_mismatch_with_evidence_gaps"
	const all = "tls_all_observed_names_match"
	good, bad := []string{"*.example.test"}, []string{"other.example.test"}
	for _, program := range []*CompiledProgram{p, loaded} {
		scanner := program.NewScanner()
		for _, tc := range []struct {
			name  string
			names [][]string
			want  []string
		}{
			{"no TLS", nil, nil},
			{"match", [][]string{good}, []string{all}},
			{"two matches", [][]string{good, good}, []string{all}},
			{"one mismatch", [][]string{bad}, nil},
			{"two mismatches", [][]string{bad, bad}, []string{multiple}},
			{"mixed", [][]string{good, bad}, []string{mixed}},
			{"missing only", [][]string{nil}, nil},
			{"match and missing", [][]string{good, nil}, nil},
			{"mismatch and missing", [][]string{bad, nil}, []string{gaps}},
			{"all outcomes", [][]string{good, bad, bad, nil}, []string{multiple, mixed, gaps}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				data := pcapNameFixture(t, tc.names...)
				for _, reader := range []bool{false, true} {
					var result *ScanResult
					var err error
					if reader {
						result, err = scanner.ScanReader(bytes.NewReader(data))
					} else {
						result, err = scanner.Scan(data)
					}
					if err != nil {
						t.Fatal(err)
					}
					for _, name := range []string{multiple, mixed, gaps, all} {
						if result.RuleResults[name] != slices.Contains(tc.want, name) {
							t.Fatalf("reader=%v %s: %v", reader, name, result.RuleResults)
						}
					}
				}
			})
		}
		result, err := scanner.Scan([]byte("not a capture"))
		if err != nil || len(result.MatchedRules) != 0 {
			t.Fatalf("malformed capture: %v %v", result, err)
		}
		scanner.Close()
	}
}

type pcapCancelOnReadAt struct {
	*bytes.Reader
	onReadAt func()
	reads    int
}

func (r *pcapCancelOnReadAt) ReadAt(b []byte, off int64) (int, error) {
	r.reads++
	if r.reads == 1 && r.onReadAt != nil {
		r.onReadAt()
	}
	return r.Reader.ReadAt(b, off)
}

type pcapSeekSpy struct {
	*bytes.Reader
	seeks int
	reads int
}

func (r *pcapSeekSpy) Seek(offset int64, whence int) (int64, error) {
	r.seeks++
	return r.Reader.Seek(offset, whence)
}

func (r *pcapSeekSpy) ReadAt(b []byte, off int64) (int, error) {
	r.reads++
	return r.Reader.ReadAt(b, off)
}

func TestPCAPCancellationAndCacheReuse(t *testing.T) {
	const source = `import "pcap"
rule wildcard { condition: pcap.tls[0].flow_index == 1 and pcap.tls[0].server_name_match }
rule unavailable { condition: not defined pcap.tls }`
	program, err := NewCompiler().CompileSource(source)
	if err != nil {
		t.Fatal(err)
	}
	data := pcapNameFixture(t, []string{"*.example.test"})

	t.Run("pre-canceled scanner does not cache undefined", func(t *testing.T) {
		scanner := program.NewScanner()
		defer scanner.Close()

		canceledCtx, cancel := context.WithCancel(context.Background())
		cancel()

		if _, err := scanner.ScanWithContext(canceledCtx, data); !errors.Is(err, context.Canceled) {
			t.Fatalf("ScanWithContext(canceled) err = %v, want context.Canceled", err)
		}
		if scanner.moduleCache.pcap != nil {
			t.Fatalf("ScanWithContext(canceled) cached pcap = %+v, want nil", scanner.moduleCache.pcap)
		}

		if _, err := scanner.ScanReaderWithContext(canceledCtx, bytes.NewReader(data)); !errors.Is(err, context.Canceled) {
			t.Fatalf("ScanReaderWithContext(canceled) err = %v, want context.Canceled", err)
		}
		if scanner.moduleCache.pcap != nil {
			t.Fatalf("ScanReaderWithContext(canceled) cached pcap = %+v, want nil", scanner.moduleCache.pcap)
		}

		for _, reader := range []bool{false, true} {
			var res *ScanResult
			if reader {
				res, err = scanner.ScanReaderWithContext(context.Background(), bytes.NewReader(data))
			} else {
				res, err = scanner.ScanWithContext(context.Background(), data)
			}
			if err != nil {
				t.Fatalf("reused scanner reader=%v err = %v", reader, err)
			}
			if !res.RuleResults["wildcard"] || res.RuleResults["unavailable"] {
				t.Fatalf("reused scanner reader=%v unexpected results: %+v", reader, res.RuleResults)
			}
		}
	})

	t.Run("mid-scan ReaderAt cancellation does not swallow error or cache", func(t *testing.T) {
		scanner := program.NewScanner()
		defer scanner.Close()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		r := &pcapCancelOnReadAt{Reader: bytes.NewReader(data), onReadAt: cancel}
		if _, err := scanner.ScanReaderWithContext(ctx, r); !errors.Is(err, context.Canceled) {
			t.Fatalf("ScanReaderWithContext(mid-cancel) err = %v, want context.Canceled", err)
		}
		if scanner.moduleCache.pcap != nil {
			t.Fatalf("ScanReaderWithContext(mid-cancel) cached pcap = %+v, want nil", scanner.moduleCache.pcap)
		}

		res, err := scanner.ScanReaderWithContext(context.Background(), bytes.NewReader(data))
		if err != nil {
			t.Fatalf("reused scanner after mid-cancel err = %v", err)
		}
		if !res.RuleResults["wildcard"] || res.RuleResults["unavailable"] {
			t.Fatalf("reused scanner after mid-cancel unexpected results: %+v", res.RuleResults)
		}
	})

	t.Run("interpreter cancellation does not swallow ctx error or cache", func(t *testing.T) {
		canceledCtx, cancel := context.WithCancel(context.Background())
		cancel()

		cache := &moduleCallCache{}
		canceledMatchCtx := &MatchContext{
			Data:        data,
			FileSize:    int64(len(data)),
			moduleCache: cache,
			cancelDone:  canceledCtx.Done(),
		}

		if got := loadPCAP(canceledMatchCtx).object.resolveField("tls"); got.Type != ModuleUndefined {
			t.Fatalf("loadPCAP(canceled).tls = %v, want undefined", got.Type)
		}
		if cache.pcap != nil {
			t.Fatalf("loadPCAP(canceled) cached pcap = %+v, want nil", cache.pcap)
		}

		interpCanceled := NewInterpreter(program.Rules[1].Bytecode)
		defer interpCanceled.Release()
		interpCanceled.SetMatchContext(canceledMatchCtx)
		interpCanceled.setCurrentCompiledRule(program.Rules[1])
		if err := interpCanceled.Execute(); !errors.Is(err, context.Canceled) {
			t.Fatalf("Interpreter.Execute(canceled) err = %v, want context.Canceled", err)
		}
		if cache.pcap != nil {
			t.Fatalf("Interpreter.Execute(canceled) cached pcap = %+v, want nil", cache.pcap)
		}

		liveMatchCtx := &MatchContext{
			Data:        data,
			FileSize:    int64(len(data)),
			moduleCache: cache,
		}
		interpLive := NewInterpreter(program.Rules[0].Bytecode)
		defer interpLive.Release()
		interpLive.SetMatchContext(liveMatchCtx)
		interpLive.setCurrentCompiledRule(program.Rules[0])
		if err := interpLive.Execute(); err != nil {
			t.Fatalf("Interpreter.Execute(live) err = %v", err)
		}
		if !interpLive.ruleResultByIndex(program.Rules[0].Index, program.Rules[0].Name) {
			t.Fatal("Interpreter.Execute(live) wildcard = false, want true")
		}
		if cache.pcap == nil {
			t.Fatal("Interpreter.Execute(live) did not populate cache.pcap")
		}
	})
}

func TestPCAPScanReaderFileOffsetAndFdPreservation(t *testing.T) {
	const source = `import "pcap"
rule wildcard { condition: pcap.tls[0].flow_index == 1 and pcap.tls[0].server_name_match }
rule mismatch { condition: for any row in pcap.tls : (row.flow_index == 2 and defined row.server_name_match and not row.server_name_match) }
rule no_extra_rows { condition: not defined pcap.tls[2].flow_index }
rule unavailable { condition: not defined pcap.tls }
rule wrong_flow { condition: for any row in pcap.tls : (row.flow_index != 2 and defined row.server_name_match and not row.server_name_match) }
rule host_override { condition: pcap.tls[0].flow_index == 99 and pcap.tls[0].server_name_match }`
	program, err := NewCompiler().CompileSource(source)
	if err != nil {
		t.Fatal(err)
	}
	data := pcapNameFixture(t, []string{"*.example.test"}, []string{"other.example.test"})

	dir := t.TempDir()
	pathZero := filepath.Join(dir, "zero.pcap")
	if err := os.WriteFile(pathZero, data, 0o600); err != nil {
		t.Fatal(err)
	}
	pathOffset := filepath.Join(dir, "offset.pcap")
	if err := os.WriteFile(pathOffset, append([]byte("skip"), data...), 0o600); err != nil {
		t.Fatal(err)
	}

	fZero, err := os.Open(pathZero)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fZero.Close() }()

	fOffset, err := os.Open(pathOffset)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fOffset.Close() }()

	cancelCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Verify Fd() uintptr preservation when start == 0 (both with and without ctx.Done())
	// and non-preservation when start > 0 (SectionReader).
	for _, tc := range []struct {
		name string
		ctx  context.Context
	}{
		{"background", context.Background()},
		{"cancelable", cancelCtx},
	} {
		if _, err := fZero.Seek(0, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		raZero := streamPCAPReader(tc.ctx, fZero)
		fdProvider, hasFD := raZero.(interface{ Fd() uintptr })
		if !hasFD || fdProvider.Fd() != fZero.Fd() {
			t.Fatalf("%s start=0 reader missing Fd(): hasFD=%v", tc.name, hasFD)
		}

		if _, err := fOffset.Seek(4, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		raOffset := streamPCAPReader(tc.ctx, fOffset)
		if _, hasFD := raOffset.(interface{ Fd() uintptr }); hasFD {
			t.Fatalf("%s start>0 reader unexpectedly exposed Fd()", tc.name)
		}
	}

	scanner := program.NewScanner()
	defer scanner.Close()

	var zeroResults map[string]bool
	for _, ctx := range []context.Context{context.Background(), cancelCtx} {
		if _, err := fZero.Seek(0, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		resZero, err := scanner.ScanReaderWithContext(ctx, fZero)
		if err != nil {
			t.Fatalf("ScanReaderWithContext(offset=0) err = %v", err)
		}
		if zeroResults == nil {
			zeroResults = resZero.RuleResults
		}

		if _, err := fOffset.Seek(4, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		resOffset, err := scanner.ScanReaderWithContext(ctx, fOffset)
		if err != nil {
			t.Fatalf("ScanReaderWithContext(offset=4) err = %v", err)
		}

		for _, name := range []string{"wildcard", "mismatch", "no_extra_rows"} {
			if !resZero.RuleResults[name] || !resOffset.RuleResults[name] {
				t.Fatalf("%s failed: zero=%+v offset=%+v", name, resZero.RuleResults, resOffset.RuleResults)
			}
		}
		for _, name := range []string{"unavailable", "wrong_flow", "host_override"} {
			if resZero.RuleResults[name] || resOffset.RuleResults[name] {
				t.Fatalf("%s unexpectedly matched: zero=%+v offset=%+v", name, resZero.RuleResults, resOffset.RuleResults)
			}
		}
		if !reflect.DeepEqual(resZero.RuleResults, zeroResults) || !reflect.DeepEqual(resOffset.RuleResults, zeroResults) {
			t.Fatalf("results differed across offset/context: want=%+v zero=%+v offset=%+v", zeroResults, resZero.RuleResults, resOffset.RuleResults)
		}
	}

	// Host-supplied pcap data must bypass native pcap and seeking on ScanReader.
	hostScanner := program.NewScanner(WithModuleData("pcap", map[string]any{
		"tls": []any{
			map[string]any{"flow_index": 99, "server_name_match": true},
		},
	}))
	defer hostScanner.Close()

	spy := &pcapSeekSpy{Reader: bytes.NewReader(data)}
	hostRes, err := hostScanner.ScanReader(spy)
	if err != nil {
		t.Fatalf("host-supplied ScanReader err = %v", err)
	}
	if !hostRes.RuleResults["host_override"] || hostRes.RuleResults["wildcard"] {
		t.Fatalf("host-supplied ScanReader unexpected results: %+v", hostRes.RuleResults)
	}
	if spy.seeks != 0 || spy.reads != 0 {
		t.Fatalf("host-supplied ScanReader unexpectedly sought/readAt: seeks=%d reads=%d", spy.seeks, spy.reads)
	}
}

func TestPCAPDeserializedSchemaInterning(t *testing.T) {
	const source = `import "pcap"
rule tls_flows {
	condition:
		pcap.tls[0].flow_index == 1 and
		pcap.tls[0].server_name_match and
		pcap.tls[1].flow_index == 2 and
		defined pcap.tls[1].server_name_match and
		not pcap.tls[1].server_name_match and
		for any row in pcap.tls : (row.flow_index == 2 and not row.server_name_match)
}`
	program, err := NewCompiler().CompileSource(source)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := program.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := UnmarshalCompiledProgram(blob)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.nativePCAP {
		t.Fatal("deserialized program did not mark nativePCAP")
	}
	if len(loaded.Rules) == 0 || loaded.Rules[0].moduleSchemas["pcap"] != pcapSchema {
		t.Fatal("deserialized program did not intern pcapSchema")
	}

	data := pcapNameFixture(t, []string{"*.example.test"}, []string{"other.example.test"})
	freshRes, err := program.Scan(data)
	if err != nil {
		t.Fatal(err)
	}
	loadedRes, err := loaded.Scan(data)
	if err != nil {
		t.Fatal(err)
	}
	if !freshRes.RuleResults["tls_flows"] || !reflect.DeepEqual(loadedRes.RuleResults, freshRes.RuleResults) {
		t.Fatalf("fresh=%+v loaded=%+v", freshRes.RuleResults, loadedRes.RuleResults)
	}
}
