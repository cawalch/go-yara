package compiler

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/cawalch/go-yara/internal/pefixture"
)

func TestPEModuleRegressionMatchingRulesInBlockBaseAndCache(t *testing.T) {
	const src = `import "pe"
rule monotonic_pe_non_zero_base {
	strings:
		$text = ".text"
		$regex = /PE\x00\x00/
	condition:
		pe.is_pe and ($text or $regex)
}
rule subsequent_is_pe {
	condition:
		pe.is_pe == 1
}
rule subsequent_not_pe {
	condition:
		pe.is_pe == 0
}`
	program, err := NewCompiler().CompileSource(src)
	if err != nil {
		t.Fatal(err)
	}
	peBytes := pefixture.New(false)
	s := program.NewScanner()
	defer s.Close()

	// Non-zero base block containing valid PE header bytes must NOT match
	// pe.is_pe and must NOT poison s.moduleCache.pe for subsequent rules.
	matches, err := s.MatchingRulesInBlock(MemoryBlock{Base: 4096, Data: peBytes}, int64(len(peBytes))+4096)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].Rule != "subsequent_not_pe" {
		t.Fatalf("MatchingRulesInBlock(base=4096) = %+v, want [subsequent_not_pe]", matches)
	}
	if s.moduleCache.pe != nil && s.moduleCache.pe.file != nil {
		t.Fatalf("s.moduleCache.pe poisoned at Base=4096: %+v", s.moduleCache.pe)
	}

	// Reusing the same scanner at Base=0 must evaluate cleanly as a PE.
	matches0, err := s.MatchingRulesInBlock(MemoryBlock{Base: 0, Data: peBytes}, int64(len(peBytes)))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches0) != 2 || matches0[0].Rule != "monotonic_pe_non_zero_base" || matches0[1].Rule != "subsequent_is_pe" {
		t.Fatalf("MatchingRulesInBlock(base=0) = %+v", matches0)
	}
}

func TestPEModuleRegressionMatchingRulesInBlockTruncatedFileSize(t *testing.T) {
	const src = `import "pe"
rule not_truncated_monotonic {
	strings:
		$text = ".text"
		$regex = /PE\x00\x00/
	condition:
		pe.is_pe and pe.input_truncated == 0 and ($text or $regex)
}
rule truncated_monotonic {
	strings:
		$text = ".text"
		$regex = /PE\x00\x00/
	condition:
		pe.is_pe and pe.input_truncated == 1 and ($text or $regex)
}`
	program, err := NewCompiler().CompileSource(src)
	if err != nil {
		t.Fatal(err)
	}
	s := program.NewScanner()
	defer s.Close()

	// declared_extent is 0x18a00 (100864). Supply only a 64 KiB block at Base=0,
	// with logical fileSize = 151040 (> declared_extent). input_truncated must be 0.
	large := makeLargeSectionPE(true, 151040, 0x1000)
	block := MemoryBlock{Base: 0, Data: large[:65536]}

	fullMatches, err := s.MatchingRulesInBlock(block, int64(len(large)))
	if err != nil {
		t.Fatal(err)
	}
	if len(fullMatches) != 1 || fullMatches[0].Rule != "not_truncated_monotonic" {
		t.Fatalf("MatchingRulesInBlock(fileSize=%d) = %+v, want [not_truncated_monotonic]", len(large), fullMatches)
	}

	// With logical fileSize = 80000 (< declared_extent 100864), input_truncated must be 1.
	truncMatches, err := s.MatchingRulesInBlock(block, 80000)
	if err != nil {
		t.Fatal(err)
	}
	if len(truncMatches) != 1 || truncMatches[0].Rule != "truncated_monotonic" {
		t.Fatalf("MatchingRulesInBlock(fileSize=80000) = %+v, want [truncated_monotonic]", truncMatches)
	}
}

func TestPEModuleRegression97SectionsDeclaredExtentAndCap(t *testing.T) {
	data := make([]byte, 0x10000)
	copy(data, pefixture.New(false))
	binary.LittleEndian.PutUint16(data[0x86:], 97)
	for i := range 97 {
		section := data[0x178+i*40:]
		copy(section, ".text\x00\x00\x00")
		binary.LittleEndian.PutUint32(section[8:], 0x200)
		binary.LittleEndian.PutUint32(section[12:], uint32(0x1000*(i+1))) //checkednarrow:ignore bounded by 97
		binary.LittleEndian.PutUint32(section[16:], 0x200)
		binary.LittleEndian.PutUint32(section[20:], 0x2000)
	}
	// Extend section 96 (index 96, past libyara's 96-section exposure cap) to [0x8000, 0x9000).
	sec96 := data[0x178+96*40:]
	copy(sec96[:8], ".sec96\x00\x00")
	binary.LittleEndian.PutUint32(sec96[16:], 0x1000)
	binary.LittleEndian.PutUint32(sec96[20:], 0x8000)

	const src = `import "pe"
rule extent_and_cap {
	condition:
		pe.is_pe == 1 and
		pe.number_of_sections == 97 and
		pe.declared_extent == 0x9000 and
		pe.input_truncated == 0 and
		defined pe.sections[95].name and
		not defined pe.sections[96].name and
		pe.rva_to_offset(0x60000) == 0x2000 and
		not defined pe.rva_to_offset(0x61000) and
		not defined pe.section_index(".sec96") and
		not defined pe.section_index(0x8000) and
		pe.overlay.offset == 0x2200
}
rule truncated_at_sec96 {
	condition:
		pe.is_pe == 1 and
		pe.declared_extent == 0x9000 and
		pe.input_truncated == 1
}`
	program, err := NewCompiler().CompileSource(src)
	if err != nil {
		t.Fatal(err)
	}
	s := program.NewScanner()
	defer s.Close()

	res, err := s.Scan(data)
	if err != nil {
		t.Fatal(err)
	}
	if !res.RuleResults["extent_and_cap"] || res.RuleResults["truncated_at_sec96"] {
		t.Fatalf("97-section full scan = %+v", res.RuleResults)
	}

	truncRes, err := s.Scan(data[:0x8800])
	if err != nil {
		t.Fatal(err)
	}
	if !truncRes.RuleResults["truncated_at_sec96"] {
		t.Fatalf("97-section truncated scan = %+v", truncRes.RuleResults)
	}
}

func TestPEModuleRegressionRVAToOffsetAbove4GBUndefined(t *testing.T) {
	prog, err := NewCompiler().CompileSource(`import "pe"
rule above_4gb_undefined {
	condition:
		pe.is_pe == 1 and
		not defined pe.rva_to_offset(0x100000000) and
		pe.rva_to_offset(0x1000) == 0x200
}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, is64 := range []bool{false, true} {
		matched, err := prog.Matches(pefixture.New(is64))
		if err != nil || !matched {
			t.Fatalf("is64=%t: Matches = (%t, %v), want (true, nil)", is64, matched, err)
		}
	}
}

func TestPEModuleRegressionFormatColonHexEmpty(t *testing.T) {
	if got := peFormatColonHex(nil); got != "" {
		t.Fatalf("peFormatColonHex(nil) = %q, want empty string", got)
	}
	if got := peFormatColonHex([]byte{}); got != "" {
		t.Fatalf("peFormatColonHex([]byte{}) = %q, want empty string", got)
	}
	if got := peFormatColonHex([]byte{0x0a, 0xff}); got != "0a:ff" {
		t.Fatalf("peFormatColonHex([0x0a 0xff]) = %q, want 0a:ff", got)
	}
}

func TestPEModuleRegressionCancellationAndIdleCacheReset(t *testing.T) {
	viPE := pefixture.VersionInfoPE(true, pefixture.VersionInfoSpec{
		StringTables: []pefixture.VersionStringTableSpec{{
			Key:     "040904b0",
			Entries: []pefixture.VersionStringEntry{{Key: "CompanyName", Value: "Acme"}},
		}},
	})

	// Canceled loadVersionInfo must not cache partial/empty peVersionData on peImage.
	done := make(chan struct{})
	close(done)
	mctx := &MatchContext{
		Data:        viPE,
		FileSize:    int64(len(viPE)),
		moduleCache: &moduleCallCache{},
		cancelDone:  done,
	}
	img := loadPE(mctx)
	if ver := img.loadVersionInfo(); ver.valid {
		t.Fatal("canceled loadVersionInfo reported valid=true")
	}
	if img.versionInfo != nil {
		t.Fatal("canceled loadVersionInfo mutated image.versionInfo cache")
	}

	// Canceled executeModuleCall for a Cacheable function must not cache results.
	impPE := pefixture.Imports(false, 2)
	prog, err := NewCompiler().CompileSource(`import "pe" rule r { condition: pe.imphash() != "" }`)
	if err != nil {
		t.Fatal(err)
	}
	interp := NewInterpreter(prog.Rules[0].Bytecode)
	defer interp.Release()
	interp.setCurrentCompiledRule(prog.Rules[0])
	cache := &moduleCallCache{}
	interp.SetMatchContext(&MatchContext{
		Data:        impPE,
		FileSize:    int64(len(impPE)),
		moduleCache: cache,
		cancelDone:  done,
	})
	_ = interp.Execute()
	if cache.count != 0 {
		t.Fatalf("canceled Cacheable call populated moduleCache: count=%d", cache.count)
	}

	// CompiledProgram.releaseScanner and BlockScanner.Reset must clear moduleCache.
	if _, err := prog.Scan(impPE); err != nil {
		t.Fatal(err)
	}
	pooled := prog.acquireScanner()
	if pooled.moduleCache.pe != nil || pooled.moduleCache.count != 0 {
		prog.releaseScanner(pooled)
		t.Fatalf("pooled scanner retained moduleCache: pe=%v count=%d", pooled.moduleCache.pe, pooled.moduleCache.count)
	}
	prog.releaseScanner(pooled)

	bs := prog.NewBlockScanner()
	defer bs.Close()
	if err := bs.Scan(0, impPE); err != nil {
		t.Fatal(err)
	}
	if _, err := bs.FinishWithContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if bs.scanner.moduleCache.pe == nil {
		t.Fatal("expected BlockScanner.Finish to populate moduleCache.pe before Reset")
	}
	bs.Reset()
	if bs.scanner.moduleCache.pe != nil || bs.scanner.moduleCache.count != 0 {
		t.Fatalf("BlockScanner.Reset retained moduleCache: pe=%v count=%d", bs.scanner.moduleCache.pe, bs.scanner.moduleCache.count)
	}
}
