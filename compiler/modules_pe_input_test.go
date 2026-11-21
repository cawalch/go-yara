package compiler

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"testing/iotest"

	"github.com/cawalch/go-yara/internal/pefixture"
	"github.com/cawalch/go-yara/utils/fs"
)

func peWithOverlay(base []byte, overlaySize int) []byte {
	data := make([]byte, len(base)+overlaySize)
	copy(data, base)
	copy(data[len(base):], bytes.Repeat([]byte("OVLY"), (overlaySize+3)/4)[:overlaySize])
	return data
}

func peChunkedReader(data []byte, chunkSize int) io.Reader {
	return &chunkReader{data: data, chunkSize: chunkSize}
}

type chunkReader struct {
	data      []byte
	chunkSize int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := min(len(p), len(r.data), r.chunkSize)
	copy(p[:n], r.data[:n])
	r.data = r.data[n:]
	return n, nil
}

func TestPEFullScanDataContract(t *testing.T) {
	small := pefixture.Exports(false, 3)

	if _, ok := peFullScanData(nil); ok {
		t.Fatal("nil context unexpectedly satisfied peFullScanData")
	}
	if _, ok := peFullScanData(&MatchContext{Data: []byte{}, FileSize: 0}); ok {
		t.Fatal("empty context unexpectedly satisfied peFullScanData")
	}
	if got, ok := peFullScanData(&MatchContext{Data: small, FileSize: int64(len(small))}); !ok || len(got) != len(small) {
		t.Fatalf("full buffer: ok=%t len=%d want=%d", ok, len(got), len(small))
	}
	if _, ok := peFullScanData(&MatchContext{Data: small[:0x200], FileSize: int64(len(small))}); ok {
		t.Fatal("prefix shorter than FileSize satisfied peFullScanData")
	}
	if _, ok := peFullScanData(&MatchContext{Data: small, FileSize: int64(len(small)) + 1}); ok {
		t.Fatal("mismatched FileSize satisfied peFullScanData")
	}

	// Offset-0 block matching full FileSize succeeds; non-zero or segmented blocks do not.
	if got, ok := peFullScanData(&MatchContext{
		Blocks:   []MemoryBlock{{Base: 0, Data: small}},
		FileSize: int64(len(small)),
	}); !ok || len(got) != len(small) {
		t.Fatalf("full offset-0 block: ok=%t len=%d", ok, len(got))
	}
	if _, ok := peFullScanData(&MatchContext{
		Blocks:   []MemoryBlock{{Base: 4096, Data: small}},
		FileSize: int64(len(small)) + 4096,
	}); ok {
		t.Fatal("non-zero base block satisfied peFullScanData")
	}
	if _, ok := peFullScanData(&MatchContext{
		Blocks: []MemoryBlock{
			{Base: 0, Data: small[:0x800]},
			{Base: 0x800, Data: small[0x800:]},
		},
		FileSize: int64(len(small)),
	}); ok {
		t.Fatal("segmented multi-block scan satisfied peFullScanData")
	}
	large := pefixture.Exports(false, 3500)
	if _, ok := peFullScanData(&MatchContext{
		Blocks:   []MemoryBlock{{Base: 0, Data: large[:streamingHeaderSize]}},
		FileSize: int64(len(large)),
	}); ok {
		t.Fatal("bounded 64 KiB stream prefix satisfied peFullScanData")
	}
}

func TestPEInputAvailabilityMatrix(t *testing.T) {
	const source = `import "pe"
rule headers {
	condition: pe.is_pe and pe.number_of_sections == 2 and pe.entry_point == 0x220
}
rule prefix_imports {
	condition: pe.imports("Example.DLL") == 3 and pe.imphash() == "` + peImphashNamed3 + `"
}
rule exports_present {
	condition: pe.number_of_exports >= 3 and pe.exports("Function00000") and pe.dll_name == "Example.DLL"
}
rule exports_undefined {
	condition: pe.is_pe and not defined pe.number_of_exports and not defined pe.dll_name and not defined pe.exports("Function00000")
}
rule overlay_nonzero {
	condition: pe.overlay.offset > 0 and pe.overlay.size == 512
}
rule not_pe {
	condition: pe.is_pe == 0 and not defined pe.machine and not defined pe.number_of_imports and not defined pe.number_of_exports
}`

	p, err := NewCompiler().CompileSource(source)
	if err != nil {
		t.Fatal(err)
	}
	s := p.NewScanner()
	defer s.Close()

	// Helper to assert expected rule booleans across every RuleResults entry.
	assertRules := func(t *testing.T, label string, r *ScanResult, want ...string) {
		t.Helper()
		wantSet := make(map[string]bool, len(want))
		for _, name := range want {
			wantSet[name] = true
		}
		for name, got := range r.RuleResults {
			if got != wantSet[name] {
				t.Fatalf("%s: rule %s = %t, want %t (results=%v)", label, name, got, wantSet[name], r.RuleResults)
			}
		}
	}

	// Case A: Complete PE <= 64 KiB (with overlay). Every contiguous file-offset path sees full metadata.
	smallPE := peWithOverlay(pefixture.Exports(false, 3), 512)
	if len(smallPE) > streamingHeaderSize {
		t.Fatalf("smallPE exceeded 64 KiB: %d", len(smallPE))
	}
	smallPath := filepath.Join(t.TempDir(), "small.exe")
	if err := os.WriteFile(smallPath, smallPE, 0o600); err != nil {
		t.Fatal(err)
	}

	cancelCtx := t.Context()

	for _, tc := range []struct {
		name string
		run  func() (*ScanResult, error)
	}{
		{"Scan", func() (*ScanResult, error) { return s.Scan(smallPE) }},
		{"ScanWithContext", func() (*ScanResult, error) { return s.ScanWithContext(cancelCtx, smallPE) }},
		{"ScanReader", func() (*ScanResult, error) { return s.ScanReader(bytes.NewReader(smallPE)) }},
		{"ScanReaderWithContext", func() (*ScanResult, error) { return s.ScanReaderWithContext(cancelCtx, bytes.NewReader(smallPE)) }},
		{"ScanFile", func() (*ScanResult, error) { return s.ScanFile(smallPath) }},
		{"ScanFileWithContext(Background)", func() (*ScanResult, error) { return s.ScanFileWithContext(context.Background(), smallPath) }},
		{"ScanFileWithContext(Cancellable)", func() (*ScanResult, error) { return s.ScanFileWithContext(cancelCtx, smallPath) }},
	} {
		r, err := tc.run()
		if err != nil {
			t.Fatalf("small %s: %v", tc.name, err)
		}
		assertRules(t, "small/"+tc.name, r, "headers", "prefix_imports", "exports_present", "overlay_nonzero")
	}

	// Case B: 64 KiB < size < 128 KiB with imports <= 64 KiB and exports extending past 64 KiB.
	// 3500 exports puts the export table around ~94 KiB (< fs.MinMmapFileSize).
	midPE := peWithOverlay(pefixture.Exports(false, 3500), 512)
	if len(midPE) <= streamingHeaderSize || len(midPE) >= fs.MinMmapFileSize {
		t.Fatalf("midPE size %d not strictly between %d and %d", len(midPE), streamingHeaderSize, fs.MinMmapFileSize)
	}
	midPath := filepath.Join(t.TempDir(), "mid.exe")
	if err := os.WriteFile(midPath, midPE, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		run  func() (*ScanResult, error)
		want []string
	}{
		{"Scan", func() (*ScanResult, error) { return s.Scan(midPE) }, []string{"headers", "prefix_imports", "exports_present", "overlay_nonzero"}},
		{"ScanFile", func() (*ScanResult, error) { return s.ScanFile(midPath) }, []string{"headers", "prefix_imports", "exports_present", "overlay_nonzero"}},
		{"ScanFileWithContext(Background)", func() (*ScanResult, error) { return s.ScanFileWithContext(context.Background(), midPath) }, []string{"headers", "prefix_imports", "exports_present", "overlay_nonzero"}},
		{"ScanFileWithContext(Cancellable<128K)", func() (*ScanResult, error) { return s.ScanFileWithContext(cancelCtx, midPath) }, []string{"headers", "prefix_imports", "exports_undefined", "overlay_nonzero"}},
		{"ScanReader", func() (*ScanResult, error) { return s.ScanReader(bytes.NewReader(midPE)) }, []string{"headers", "prefix_imports", "exports_undefined", "overlay_nonzero"}},
		{"ScanReaderWithContext", func() (*ScanResult, error) { return s.ScanReaderWithContext(cancelCtx, bytes.NewReader(midPE)) }, []string{"headers", "prefix_imports", "exports_undefined", "overlay_nonzero"}},
	} {
		r, err := tc.run()
		if err != nil {
			t.Fatalf("mid %s: %v", tc.name, err)
		}
		assertRules(t, "mid/"+tc.name, r, tc.want...)
	}

	// Case C: >= 128 KiB regular file. Cancellable ScanFileWithContext mmaps and exposes full exports;
	// ScanReader remains bounded to 64 KiB prefix.
	largePE := peWithOverlay(pefixture.Exports(false, 5200), 512)
	if len(largePE) < fs.MinMmapFileSize {
		t.Fatalf("largePE size %d < MinMmapFileSize %d", len(largePE), fs.MinMmapFileSize)
	}
	largePath := filepath.Join(t.TempDir(), "large.exe")
	if err := os.WriteFile(largePath, largePE, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		run  func() (*ScanResult, error)
		want []string
	}{
		{"ScanFile", func() (*ScanResult, error) { return s.ScanFile(largePath) }, []string{"headers", "prefix_imports", "exports_present", "overlay_nonzero"}},
		{"ScanFileWithContext(Cancellable>=128K)", func() (*ScanResult, error) { return s.ScanFileWithContext(cancelCtx, largePath) }, []string{"headers", "prefix_imports", "exports_present", "overlay_nonzero"}},
		{"ScanReader", func() (*ScanResult, error) { return s.ScanReader(bytes.NewReader(largePE)) }, []string{"headers", "prefix_imports", "exports_undefined", "overlay_nonzero"}},
	} {
		r, err := tc.run()
		if err != nil {
			t.Fatalf("large %s: %v", tc.name, err)
		}
		assertRules(t, "large/"+tc.name, r, tc.want...)
	}

	// Case D: Block boundaries — file offsets only, never process VAs, no multi-block concatenation.
	rules0, err := s.MatchingRulesInBlock(MemoryBlock{Base: 0, Data: smallPE}, int64(len(smallPE)))
	if err != nil || len(rules0) != 4 {
		t.Fatalf("MatchingRulesInBlock base=0: %v %v", rules0, err)
	}
	rulesNZ, err := s.MatchingRulesInBlock(MemoryBlock{Base: 4096, Data: smallPE}, int64(len(smallPE))+4096)
	if err != nil || len(rulesNZ) != 1 || rulesNZ[0].Rule != "not_pe" {
		t.Fatalf("MatchingRulesInBlock base=4096: %v %v", rulesNZ, err)
	}

	// Segmented BlockScanner: block 0 has headers + imports (0..0x800), block 1 has exports (0x800..).
	b := p.NewBlockScanner()
	defer b.Close()
	if err := b.Scan(0, smallPE[:0x800]); err != nil {
		t.Fatal(err)
	}
	if err := b.Scan(0x800, smallPE[0x800:]); err != nil {
		t.Fatal(err)
	}
	br, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	assertRules(t, "BlockScanner/segmented", br, "headers", "prefix_imports", "exports_undefined", "overlay_nonzero")

	// MatchesReader reports true for header/prefix rules and false when only outside-64KiB exports match.
	onlyExportsProg, err := NewCompiler().CompileSource(`import "pe" rule e { condition: pe.exports("Function00000") }`)
	if err != nil {
		t.Fatal(err)
	}
	if matched, err := onlyExportsProg.Matches(midPE); err != nil || !matched {
		t.Fatalf("Matches(midPE) = %t, %v; want true", matched, err)
	}
	if matched, err := onlyExportsProg.MatchesReader(bytes.NewReader(midPE)); err != nil || matched {
		t.Fatalf("MatchesReader(midPE) = %t, %v; want false past 64 KiB", matched, err)
	}
	if matched, err := onlyExportsProg.MatchesReader(bytes.NewReader(smallPE)); err != nil || !matched {
		t.Fatalf("MatchesReader(smallPE) = %t, %v; want true <= 64 KiB", matched, err)
	}
}

func TestPEShortReadsAndChangingReaders(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe"
rule is32 { condition: pe.is_pe and pe.is_32bit() and pe.imports("Example.DLL") == 3 }
rule is64 { condition: pe.is_pe and pe.is_64bit() and pe.exports("Function00000") }
rule big_prefix { condition: pe.is_pe and pe.imports("Example.DLL") == 3 and not defined pe.number_of_exports and pe.overlay.size == 256 }
rule non_pe { condition: pe.is_pe == 0 and not defined pe.machine }`)
	if err != nil {
		t.Fatal(err)
	}
	s := p.NewScanner()
	defer s.Close()

	pe32Small := pefixture.Exports(false, 3)
	pe64Small := pefixture.Exports(true, 3)
	pe32Mid := peWithOverlay(pefixture.Exports(false, 3500), 256)

	sequence := []struct {
		name   string
		reader func() io.Reader
		want   map[string]bool
	}{
		{"OneByteReader(pe32<=64K)", func() io.Reader { return iotest.OneByteReader(bytes.NewReader(pe32Small)) }, map[string]bool{"is32": true, "is64": false, "big_prefix": false, "non_pe": false}},
		{"DataErrReader(non_pe)", func() io.Reader { return iotest.DataErrReader(bytes.NewReader(bytes.Repeat([]byte("plain"), 20))) }, map[string]bool{"is32": false, "is64": false, "big_prefix": false, "non_pe": true}},
		{"Chunk17(pe32>64K)", func() io.Reader { return peChunkedReader(pe32Mid, 17) }, map[string]bool{"is32": true, "is64": false, "big_prefix": true, "non_pe": false}},
		{"OneByteReader(pe64<=64K)", func() io.Reader { return iotest.OneByteReader(bytes.NewReader(pe64Small)) }, map[string]bool{"is32": false, "is64": true, "big_prefix": false, "non_pe": false}},
		{"EmptyReader", func() io.Reader { return bytes.NewReader(nil) }, map[string]bool{"is32": false, "is64": false, "big_prefix": false, "non_pe": true}},
		{"DataErrReader(pe32>64K)", func() io.Reader { return iotest.DataErrReader(peChunkedReader(pe32Mid, 1021)) }, map[string]bool{"is32": true, "is64": false, "big_prefix": true, "non_pe": false}},
	}

	for _, step := range sequence {
		r, err := s.ScanReader(step.reader())
		if err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		for rule, want := range step.want {
			if r.RuleResults[rule] != want {
				t.Fatalf("%s: rule %s = %t, want %t (%v)", step.name, rule, r.RuleResults[rule], want, r.RuleResults)
			}
		}
	}

	// Verify NT headers moved past 64 KiB still match buffer scans and reject consistently across short reads.
	shifted := make([]byte, 0x11000)
	copy(shifted, pefixture.Imports(false, 3))
	copy(shifted[0x10000:], shifted[0x80:0x1c8])
	binary.LittleEndian.PutUint32(shifted[0x3c:], 0x10000)
	rBuf, err := s.Scan(shifted)
	if err != nil || !rBuf.RuleResults["is32"] || rBuf.RuleResults["non_pe"] {
		t.Fatalf("shifted Scan = %v, %v", rBuf, err)
	}
	rRead, err := s.ScanReader(iotest.OneByteReader(bytes.NewReader(shifted)))
	if err != nil || !rRead.RuleResults["non_pe"] || rRead.RuleResults["is32"] {
		t.Fatalf("shifted OneByteReader = %v, %v", rRead, err)
	}
}

type peMidStreamCancelReader struct {
	data             []byte
	cancelAfterBytes int
	readBytes        int
	cancel           context.CancelFunc
}

func (r *peMidStreamCancelReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := min(len(p), len(r.data), 32*1024)
	copy(p[:n], r.data[:n])
	r.data = r.data[n:]
	r.readBytes += n
	if r.cancel != nil && r.readBytes >= r.cancelAfterBytes {
		r.cancel()
		r.cancel = nil
	}
	return n, nil
}

func TestPECancellationDuringWork(t *testing.T) {
	largeExports := pefixture.Exports(false, 16384)
	largeImports := pefixture.Imports(true, 16384)

	p, err := NewCompiler().CompileSource(`import "pe"
rule init { condition: pe.is_pe }
rule expensive { condition: pe.imphash() != "" and for any e in pe.export_details : (e.name == "Function16383") }`)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Pre-canceled context across all *WithContext entry points.
	preCanceled, cancelNow := context.WithCancel(context.Background())
	cancelNow()

	filePath := filepath.Join(t.TempDir(), "large.exe")
	if err := os.WriteFile(filePath, largeExports, 0o600); err != nil {
		t.Fatal(err)
	}
	s := p.NewScanner()
	defer s.Close()

	if _, err := s.ScanWithContext(preCanceled, largeExports); !errors.Is(err, context.Canceled) {
		t.Fatalf("ScanWithContext = %v, want context.Canceled", err)
	}
	if _, err := s.ScanReaderWithContext(preCanceled, bytes.NewReader(largeExports)); !errors.Is(err, context.Canceled) {
		t.Fatalf("ScanReaderWithContext = %v, want context.Canceled", err)
	}
	if _, err := s.MatchesReaderWithContext(preCanceled, bytes.NewReader(largeExports)); !errors.Is(err, context.Canceled) {
		t.Fatalf("MatchesReaderWithContext = %v, want context.Canceled", err)
	}
	if _, err := s.ScanFileWithContext(preCanceled, filePath); !errors.Is(err, context.Canceled) {
		t.Fatalf("ScanFileWithContext = %v, want context.Canceled", err)
	}
	if _, err := s.MatchingRulesInBlockWithContext(preCanceled, MemoryBlock{Base: 0, Data: largeExports}, int64(len(largeExports))); !errors.Is(err, context.Canceled) {
		t.Fatalf("MatchingRulesInBlockWithContext = %v, want context.Canceled", err)
	}
	bs := p.NewBlockScanner()
	defer bs.Close()
	if err := bs.ScanWithContext(preCanceled, 0, largeExports); !errors.Is(err, context.Canceled) {
		t.Fatalf("BlockScanner.ScanWithContext = %v, want context.Canceled", err)
	}
	if _, err := bs.FinishWithContext(preCanceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("BlockScanner.FinishWithContext = %v, want context.Canceled", err)
	}

	// 2. Mid-evaluation cancellation triggered deterministically between rules via ScanHooks.
	ctx, cancel := context.WithCancel(context.Background())
	hookScanner := p.NewScanner(WithHooks(ScanHooks{
		OnRuleEvaluated: func(profile RuleProfile) {
			if profile.RuleName == "init" {
				cancel()
			}
		},
	}))
	defer hookScanner.Close()
	if _, err := hookScanner.ScanWithContext(ctx, largeExports); !errors.Is(err, context.Canceled) {
		t.Fatalf("hook mid-scan cancellation = %v, want context.Canceled", err)
	}

	// 3. Mid-stream reader cancellation after initial PE bytes are consumed.
	streamCtx, cancelStream := context.WithCancel(context.Background())
	cr := &peMidStreamCancelReader{data: largeExports, cancelAfterBytes: streamingHeaderSize, cancel: cancelStream}
	if _, err := s.ScanReaderWithContext(streamCtx, cr); !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-reader cancellation = %v, want context.Canceled", err)
	}

	// 4. Cooperative PE-internal cancellation preserves clean state and surfaces context.Canceled.
	done := make(chan struct{})
	close(done)
	mctx := &MatchContext{
		Data:        largeImports,
		FileSize:    int64(len(largeImports)),
		moduleCache: &moduleCallCache{},
		cancelDone:  done,
	}
	img := loadPE(mctx)
	if imports := img.loadImports(); imports.valid {
		t.Fatal("canceled loadImports reported valid=true")
	}
	if img.imports != nil {
		t.Fatal("canceled loadImports mutated image.imports cache")
	}
	expCtx := &MatchContext{
		Data:        largeExports,
		FileSize:    int64(len(largeExports)),
		moduleCache: &moduleCallCache{},
		cancelDone:  done,
	}
	expImg := loadPE(expCtx)
	if exports := expImg.loadExports(); exports.valid {
		t.Fatal("canceled loadExports reported valid=true")
	}
	if expImg.exports != nil {
		t.Fatal("canceled loadExports mutated image.exports cache")
	}

	// Run bytecode execution with closed cancelDone over 16,384-export PE.
	ruleExp, err := NewCompiler().CompileSource(`import "pe" rule e { condition: pe.imphash() != "" and for any x in pe.export_details : (x.name == "Function16383") }`)
	if err != nil {
		t.Fatal(err)
	}
	interp := NewInterpreter(ruleExp.Rules[0].Bytecode)
	defer interp.Release()
	interp.setCurrentCompiledRule(ruleExp.Rules[0])
	interp.SetMatchContext(&MatchContext{Data: largeExports, FileSize: int64(len(largeExports)), cancelDone: done})
	if err := interp.Execute(); !errors.Is(err, context.Canceled) {
		t.Fatalf("interpreter PE loop with closed cancelDone = %v, want context.Canceled", err)
	}
}
