package compiler

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/internal/pefixture"
	"github.com/cawalch/go-yara/utils/fs"
)

// referencePEChecksum16 computes the standard textbook 16-bit PE header checksum
// with end-around carry, zeroing the 4-byte CheckSum field. Matches libyara for
// all 4-byte-aligned e_lfanew values.
func referencePEChecksum16(data []byte, eLfanew uint32) int64 {
	checksumOffset := int(eLfanew) + 88
	var sum uint64
	for i := 0; i+1 < len(data); i += 2 {
		if i == checksumOffset || i == checksumOffset+2 {
			continue
		}
		sum += uint64(binary.LittleEndian.Uint16(data[i : i+2]))
		sum = (sum & 0xffff) + (sum >> 16)
	}
	if len(data)%2 != 0 {
		sum += uint64(data[len(data)-1])
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return int64(sum) + int64(len(data))
}

func peChecksumOffset(data []byte) uint32 {
	return binary.LittleEndian.Uint32(data[0x3c:]) + 88
}

func peWithChecksumPattern(base []byte, storedChecksum uint32, fill []byte) []byte {
	data := make([]byte, len(base)+len(fill))
	copy(data, base)
	copy(data[len(base):], fill)
	binary.LittleEndian.PutUint32(data[peChecksumOffset(data):], storedChecksum)
	return data
}

func TestPECalculateChecksumVectors(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		for _, stored := range []uint32{0, 0x12345678, 0xffffffff} {
			for _, extra := range []int{0, 1, 2, 3, 4, 17, 65535} {
				for _, fill := range []byte{0x00, 0xab, 0xff} {
					if extra < 4 && fill == 0xab {
						continue
					}
					data := peWithChecksumPattern(pefixture.New(is64), stored, bytes.Repeat([]byte{fill}, extra))
					want := referencePEChecksum16(data, binary.LittleEndian.Uint32(data[0x3c:]))
					got, examined, ok := peCalculateChecksumBytes(data, binary.LittleEndian.Uint32(data[0x3c:]), nil)
					if !ok || examined != int64(len(data)) || got != want {
						t.Fatalf("is64=%t stored=%#x extra=%d fill=%#x: got=%#x examined=%d ok=%t want=%#x",
							is64, stored, extra, fill, got, examined, ok, want)
					}
				}
			}
		}
	}

	// Verify stored pe.checksum exclusion via compiled rule execution (even/odd/overflow/matches stored).
	validZero := peWithChecksumPattern(pefixture.New(false), 0, []byte{0xff, 0xff, 0xff})
	wantZero := referencePEChecksum16(validZero, 0x80)
	matchingStored := append([]byte(nil), validZero...)
	binary.LittleEndian.PutUint32(matchingStored[peChecksumOffset(matchingStored):], uint32(wantZero))

	p, err := NewCompiler().CompileSource(fmt.Sprintf(`import "pe"
rule def { condition: defined pe.calculate_checksum() }
rule matches_ref { condition: pe.calculate_checksum() == %d }
rule matches_stored { condition: pe.calculate_checksum() == pe.checksum }
rule differs_stored { condition: pe.calculate_checksum() != pe.checksum }`, wantZero))
	if err != nil {
		t.Fatal(err)
	}
	s := p.NewScanner()
	defer s.Close()

	r1, err := s.Scan(validZero)
	if err != nil || !r1.RuleResults["def"] || !r1.RuleResults["matches_ref"] || r1.RuleResults["matches_stored"] || !r1.RuleResults["differs_stored"] {
		t.Fatalf("stale header checksum: %v %v", r1, err)
	}
	r2, err := s.Scan(matchingStored)
	if err != nil || !r2.RuleResults["def"] || !r2.RuleResults["matches_ref"] || !r2.RuleResults["matches_stored"] || r2.RuleResults["differs_stored"] {
		t.Fatalf("matching stored checksum: %v %v", r2, err)
	}

	// Non-PE and truncated inputs leave pe.calculate_checksum() undefined.
	for _, invalid := range [][]byte{nil, []byte("MZ"), pefixture.New(false)[:0x90]} {
		ri, err := s.Scan(invalid)
		if err != nil || ri.RuleResults["def"] {
			t.Fatalf("invalid(%d bytes): %v %v", len(invalid), ri, err)
		}
	}
}

func TestPECalculateChecksumAvailabilityAndBlocks(t *testing.T) {
	small := peWithChecksumPattern(pefixture.New(false), 0x11223344, []byte{0x5a, 0x5a, 0x5a})
	wantSmall := referencePEChecksum16(small, 0x80)

	mid := peWithChecksumPattern(pefixture.Exports(false, 3500), 0x11223344, []byte{0xff})
	if len(mid) <= streamingHeaderSize || len(mid) >= fs.MinMmapFileSize {
		t.Fatalf("unexpected mid size %d", len(mid))
	}
	wantMid := referencePEChecksum16(mid, 0x80)

	large := peWithChecksumPattern(pefixture.Exports(false, 5200), 0xdeadbeef, []byte{0xff, 0xff, 0xff})
	if len(large) < fs.MinMmapFileSize {
		t.Fatalf("unexpected large size %d", len(large))
	}
	wantLarge := referencePEChecksum16(large, 0x80)

	p, err := NewCompiler().CompileSource(fmt.Sprintf(`import "pe"
rule def { condition: defined pe.calculate_checksum() }
rule small { condition: pe.calculate_checksum() == %d }
rule mid { condition: pe.calculate_checksum() == %d }
rule large { condition: pe.calculate_checksum() == %d }`, wantSmall, wantMid, wantLarge))
	if err != nil {
		t.Fatal(err)
	}
	s := p.NewScanner()
	defer s.Close()

	dir := t.TempDir()
	midPath := filepath.Join(dir, "mid.exe")
	largePath := filepath.Join(dir, "large.exe")
	if err := os.WriteFile(midPath, mid, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(largePath, large, 0o600); err != nil {
		t.Fatal(err)
	}

	ctx := t.Context()

	// Complete <= 64 KiB stream & buffer succeed.
	for label, fn := range map[string]func() (*ScanResult, error){
		"small/Scan":       func() (*ScanResult, error) { return s.Scan(small) },
		"small/ScanReader": func() (*ScanResult, error) { return s.ScanReader(bytes.NewReader(small)) },
	} {
		r, err := fn()
		if err != nil || !r.RuleResults["small"] || !r.RuleResults["def"] {
			t.Fatalf("%s: %v %v", label, r, err)
		}
	}

	// Mid (64 KiB < size < 128 KiB): full file/buffer compute checksum; reader and cancellable <128K fallback return undefined.
	for label, fn := range map[string]func() (*ScanResult, error){
		"mid/Scan":                  func() (*ScanResult, error) { return s.Scan(mid) },
		"mid/ScanFile":              func() (*ScanResult, error) { return s.ScanFile(midPath) },
		"mid/ScanFileCtxBackground": func() (*ScanResult, error) { return s.ScanFileWithContext(context.Background(), midPath) },
	} {
		r, err := fn()
		if err != nil || !r.RuleResults["mid"] || !r.RuleResults["def"] {
			t.Fatalf("%s: %v %v", label, r, err)
		}
	}
	for label, fn := range map[string]func() (*ScanResult, error){
		"mid/ScanReader":        func() (*ScanResult, error) { return s.ScanReader(bytes.NewReader(mid)) },
		"mid/ScanFileCtxCancel": func() (*ScanResult, error) { return s.ScanFileWithContext(ctx, midPath) },
		"large/ScanReader":      func() (*ScanResult, error) { return s.ScanReader(bytes.NewReader(large)) },
		"large/ScanReaderCtx":   func() (*ScanResult, error) { return s.ScanReaderWithContext(ctx, bytes.NewReader(large)) },
	} {
		r, err := fn()
		if err != nil || r.RuleResults["def"] {
			t.Fatalf("%s unexpectedly defined calculate_checksum: %v %v", label, r, err)
		}
	}

	// Large (>= 128 KiB): cancellable ScanFileWithContext uses mmap and computes full checksum.
	for label, fn := range map[string]func() (*ScanResult, error){
		"large/ScanFile":          func() (*ScanResult, error) { return s.ScanFile(largePath) },
		"large/ScanFileCtxCancel": func() (*ScanResult, error) { return s.ScanFileWithContext(ctx, largePath) },
	} {
		r, err := fn()
		if err != nil || !r.RuleResults["large"] || !r.RuleResults["def"] {
			t.Fatalf("%s: %v %v", label, r, err)
		}
	}

	// MatchesReader must not report matches for rules relying on outside-64KiB checksums.
	onlyChecksumProg, err := NewCompiler().CompileSource(`import "pe" rule c { condition: defined pe.calculate_checksum() }`)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := onlyChecksumProg.MatchesReader(bytes.NewReader(small)); err != nil || !ok {
		t.Fatalf("MatchesReader(small) = %t, %v; want true", ok, err)
	}
	if ok, err := onlyChecksumProg.MatchesReader(bytes.NewReader(mid)); err != nil || ok {
		t.Fatalf("MatchesReader(mid) = %t, %v; want false", ok, err)
	}

	// Blocks: base=0 complete succeeds; base!=0, mismatched filesize, or segmented blocks leave undefined.
	if rules, err := s.MatchingRulesInBlock(MemoryBlock{Base: 0, Data: small}, int64(len(small))); err != nil || len(rules) != 2 {
		t.Fatalf("MatchingRulesInBlock(base=0 full) = %v, %v", rules, err)
	}
	if rules, err := s.MatchingRulesInBlock(MemoryBlock{Base: 0, Data: small}, int64(len(small))+1); err != nil || len(rules) != 0 {
		t.Fatalf("MatchingRulesInBlock(base=0 mismatched size) = %v, %v", rules, err)
	}
	if rules, err := s.MatchingRulesInBlock(MemoryBlock{Base: 4096, Data: small}, int64(len(small))+4096); err != nil || len(rules) != 0 {
		t.Fatalf("MatchingRulesInBlock(base=4096) = %v, %v", rules, err)
	}

	bs := p.NewBlockScanner()
	defer bs.Close()
	if err := bs.Scan(0, small[:0x200]); err != nil {
		t.Fatal(err)
	}
	if err := bs.Scan(0x200, small[0x200:]); err != nil {
		t.Fatal(err)
	}
	br, err := bs.Finish()
	if err != nil || br.RuleResults["def"] {
		t.Fatalf("segmented BlockScanner defined calculate_checksum: %v %v", br, err)
	}
}

func TestPECalculateChecksumCachingHostSerializationAndReuse(t *testing.T) {
	data := peWithChecksumPattern(pefixture.New(false), 0, []byte{0x33, 0x33, 0x33, 0x33, 0x33})
	want := referencePEChecksum16(data, 0x80)

	// Caching check: directly inspect peImage cache and ensure unrelated directories stay unmaterialized.
	ctx := &MatchContext{Data: data, FileSize: int64(len(data)), moduleCache: &moduleCallCache{}}
	interp := NewInterpreter(nil)
	defer interp.Release()
	interp.SetMatchContext(ctx)
	interp.currentCompiledRule = &CompiledRule{nativePE: true}

	if got := interp.peCalculateChecksum(); got.Type != ModuleInteger || got.Integer != want {
		t.Fatalf("first peCalculateChecksum = %+v, want %d", got, want)
	}
	img := ctx.moduleCache.pe
	if img == nil || !img.calculatedChecksumSet || img.calculatedChecksum.Integer != want {
		t.Fatalf("unexpected image cache state: %+v", img)
	}
	if img.sections.Type != ModuleUndefined || img.directories.Type != ModuleUndefined || img.imports != nil || img.exports != nil {
		t.Fatal("calculate_checksum materialized unrelated PE caches")
	}
	clear(data)
	ctx.Data, ctx.FileSize = nil, 0
	if got := interp.peCalculateChecksum(); got.Type != ModuleInteger || got.Integer != want {
		t.Fatalf("cached peCalculateChecksum changed after input clear: %+v", got)
	}

	// nativePE=false refuses fallback.
	interp.currentCompiledRule.nativePE = false
	if got := interp.peCalculateChecksum(); got.Type != ModuleUndefined {
		t.Fatalf("non-native rule evaluated peCalculateChecksum: %+v", got)
	}

	// Round-trip serialization and scanner reuse across changing inputs.
	p, err := NewCompiler().CompileSource(fmt.Sprintf(`import "pe"
rule exact { condition: pe.calculate_checksum() == %d and pe.calculate_checksum() == %d }
rule missing { condition: not defined pe.calculate_checksum() }`, want, want))
	if err != nil {
		t.Fatal(err)
	}
	blob, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := UnmarshalCompiledProgram(blob)
	if err != nil {
		t.Fatal(err)
	}
	fresh := peWithChecksumPattern(pefixture.New(false), 0, []byte{0x33, 0x33, 0x33, 0x33, 0x33})
	s := restored.NewScanner()
	defer s.Close()
	for i, input := range [][]byte{fresh, nil, fresh, pefixture.New(true), fresh} {
		r, err := s.Scan(input)
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		wantExact := bytes.Equal(input, fresh)
		if r.RuleResults["exact"] != wantExact || r.RuleResults["missing"] != (input == nil) {
			t.Fatalf("step %d: %v", i, r.RuleResults)
		}
	}

	// Host snapshot leaves calculate_checksum undefined without parsing input.
	hs := restored.NewScanner(WithModuleData("pe", map[string]any{"checksum": 42}))
	defer hs.Close()
	hr, err := hs.Scan(fresh)
	if err != nil || !hr.RuleResults["missing"] || hr.RuleResults["exact"] || hs.moduleCache.pe != nil {
		t.Fatalf("host snapshot: %v %v", hr, err)
	}

	// Custom callback override takes precedence over native calculation.
	customMod := NewCompiler().GetOptions().Modules["pe"]
	fn := customMod.Functions["calculate_checksum"]
	fn.Evaluate = func(ModuleContext, []ModuleValue) (ModuleValue, error) {
		return IntegerValue(777), nil
	}
	customMod.Functions["calculate_checksum"] = fn
	cp, err := NewCompiler(WithModule(customMod)).CompileSource(`import "pe" rule custom { condition: pe.calculate_checksum() == 777 }`)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := cp.Matches(fresh); err != nil || !ok {
		t.Fatalf("custom override: %t %v", ok, err)
	}
}

func TestPECalculateChecksumCancellationAndExaminedBytes(t *testing.T) {
	large := peWithChecksumPattern(pefixture.New(false), 0x55555555, bytes.Repeat([]byte{0xff}, 256*1024-0x800+3))
	want := referencePEChecksum16(large, 0x80)

	got, examined, ok := peCalculateChecksumBytes(large, 0x80, nil)
	if !ok || examined != int64(len(large)) || got != want {
		t.Fatalf("uncanceled: got=%d examined=%d ok=%t want=%d len=%d", got, examined, ok, want, len(large))
	}

	closed := make(chan struct{})
	close(closed)
	gotCanceled, examinedCanceled, okCanceled := peCalculateChecksumBytes(large, 0x80, closed)
	if okCanceled || examinedCanceled != 0 || gotCanceled != 0 {
		t.Fatalf("pre-canceled: got=%d examined=%d ok=%t", gotCanceled, examinedCanceled, okCanceled)
	}

	// End-to-end canceled scan stops and returns context.Canceled without caching partial result.
	p, err := NewCompiler().CompileSource(`import "pe" rule cs { condition: defined pe.calculate_checksum() }`)
	if err != nil {
		t.Fatal(err)
	}
	preCanceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.ScanWithContext(preCanceled, large); !errors.Is(err, context.Canceled) {
		t.Fatalf("ScanWithContext canceled = %v, want context.Canceled", err)
	}

	interp := NewInterpreter(p.Rules[0].Bytecode)
	defer interp.Release()
	mctx := &MatchContext{Data: large, FileSize: int64(len(large)), moduleCache: &moduleCallCache{}, cancelDone: closed}
	interp.SetMatchContext(mctx)
	interp.setCurrentCompiledRule(p.Rules[0])
	if err := interp.Execute(); !errors.Is(err, context.Canceled) {
		t.Fatalf("interpreter canceled = %v, want context.Canceled", err)
	}
	if mctx.moduleCache.pe != nil && mctx.moduleCache.pe.calculatedChecksumSet {
		t.Fatal("canceled calculation mutated calculatedChecksumSet cache")
	}
}

func BenchmarkPECalculateChecksum(b *testing.B) {
	small := pefixture.New(false)
	large := peWithChecksumPattern(pefixture.New(false), 0x12345678, bytes.Repeat([]byte{0x5a}, 1024*1024-0x800+3))
	inputs := map[string][]byte{
		"non_pe": bytes.Repeat([]byte("ordinary"), 32),
		"pe_2k":  small,
		"pe_1mb": large,
	}
	for name, data := range inputs {
		for _, rules := range []int{1, 100} {
			var source strings.Builder
			source.WriteString("import \"pe\"\n")
			for idx := range rules {
				fmt.Fprintf(&source, "rule r%d { condition: defined pe.calculate_checksum() }\n", idx)
			}
			prog, err := NewCompiler().CompileSource(source.String())
			if err != nil {
				b.Fatal(err)
			}
			b.Run(fmt.Sprintf("%s/rules=%d", name, rules), func(b *testing.B) {
				s := prog.NewScanner(WithoutMatches(), WithoutRuleResults())
				defer s.Close()
				b.SetBytes(int64(len(data)))
				b.ReportAllocs()
				for b.Loop() {
					if _, err := s.MatchingRules(data); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
