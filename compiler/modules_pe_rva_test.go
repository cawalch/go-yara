package compiler

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/cawalch/go-yara/internal/pefixture"
)

func TestPERVAToOffset(t *testing.T) {
	for _, tc := range []struct {
		name      string
		is64      bool
		change    func([]byte)
		condition string
	}{
		{
			name:      "sections",
			condition: `pe.rva_to_offset(0x1000) == 0x200 and pe.rva_to_offset(0x11ff) == 0x3ff and not defined pe.rva_to_offset(0x1200) and pe.rva_to_offset(0x2000) == 0x400 and pe.rva_to_offset(0x21ff) == 0x5ff and not defined pe.rva_to_offset(0x2200)`,
		},
		{
			name:      "headers",
			condition: `pe.rva_to_offset(0) == 0 and pe.rva_to_offset(0x200) == 0x200 and pe.rva_to_offset(0x7ff) == 0x7ff and not defined pe.rva_to_offset(0x800) and not defined pe.rva_to_offset(0xffffffff) and not defined pe.rva_to_offset(0x100000000) and not defined pe.rva_to_offset(-1) and pe.rva_to_offset(pe.entry_point_raw) == pe.entry_point`,
		},
		{
			name: "no-sections",
			change: func(data []byte) {
				binary.LittleEndian.PutUint16(data[0x86:], 0)
			},
			condition: `pe.rva_to_offset(0) == 0 and pe.rva_to_offset(0x7ff) == 0x7ff and not defined pe.rva_to_offset(0x800) and not defined pe.rva_to_offset(0xffffffff) and not defined pe.rva_to_offset(0x100000000)`,
		},
		{
			name: "gap",
			change: func(data []byte) {
				binary.LittleEndian.PutUint32(data[peSectionOffset(data, 1)+12:], 0x3000)
			},
			condition: `pe.rva_to_offset(0x3000) == 0x400 and not defined pe.rva_to_offset(0x2500)`,
		},
		{
			name: "virtual-tail",
			change: func(data []byte) {
				binary.LittleEndian.PutUint32(data[peSectionOffset(data, 0)+8:], 0x400)
			},
			condition: `pe.rva_to_offset(0x11ff) == 0x3ff and not defined pe.rva_to_offset(0x1200)`,
		},
		{
			name: "overlap",
			change: func(data []byte) {
				binary.LittleEndian.PutUint32(data[peSectionOffset(data, 1)+12:], 0x1100)
			},
			condition: `pe.rva_to_offset(0x1050) == 0x250 and pe.rva_to_offset(0x1150) == 0x450`,
		},
		{
			name: "file-alignment",
			change: func(data []byte) {
				binary.LittleEndian.PutUint32(data[peSectionOffset(data, 0)+20:], 0x205)
				binary.LittleEndian.PutUint32(data[0x98+32:], 0x200)
				binary.LittleEndian.PutUint32(data[0x98+36:], 4)
			},
			condition: `pe.rva_to_offset(0x1000) == 0x204`,
		},
		{
			name: "sector-alignment",
			change: func(data []byte) {
				binary.LittleEndian.PutUint32(data[peSectionOffset(data, 0)+20:], 0x3ff)
			},
			condition: `pe.rva_to_offset(0x1000) == 0x200`,
		},
		{
			name:      "pe64",
			is64:      true,
			condition: `pe.rva_to_offset(0x1000) == 0x200 and pe.rva_to_offset(0x2000) == 0x400`,
		},
		{
			name:      "non-pe",
			condition: `not defined pe.rva_to_offset(0)`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := pefixture.New(tc.is64)
			if tc.name == "non-pe" {
				data = []byte("ordinary")
			}
			if tc.change != nil {
				tc.change(data)
			}
			program, err := NewCompiler().CompileSource(`import "pe" rule query { condition: ` + tc.condition + ` }`)
			if err != nil {
				t.Fatal(err)
			}
			if matched, err := program.Matches(data); err != nil || !matched {
				t.Fatalf("query: %t %v", matched, err)
			}
		})
	}
}

func TestPERVAToOffsetScanPathsAndSerialization(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe"
rule text { condition: pe.rva_to_offset(0x1000) == 0x200 }
rule data { condition: pe.rva_to_offset(0x2000) == 0x400 }
rule absent { condition: not defined pe.rva_to_offset(0x800) }`)
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
	for _, program := range []*CompiledProgram{p, restored} {
		data := pefixture.New(false)
		for _, reader := range []bool{false, true} {
			s := program.NewScanner(WithFastScan())
			var result *ScanResult
			if reader {
				result, err = s.ScanReader(bytes.NewReader(data))
			} else {
				result, err = s.Scan(data)
			}
			s.Close()
			if err != nil || !result.RuleResults["text"] || !result.RuleResults["data"] || !result.RuleResults["absent"] {
				t.Fatalf("reader=%t: %v %v", reader, result, err)
			}
		}
		for _, base := range []int64{0, 4096} {
			b := program.NewBlockScanner()
			if err := b.Scan(base, data); err != nil {
				t.Fatal(err)
			}
			result, err := b.Finish()
			b.Close()
			if err != nil || result.RuleResults["text"] != (base == 0) {
				t.Fatalf("block base=%d: %v %v", base, result, err)
			}
		}
	}

	large := make([]byte, 128<<10)
	copy(large, pefixture.New(false))
	binary.LittleEndian.PutUint32(large[peSectionOffset(large, 1)+20:], 0x15000)
	largeProgram, err := NewCompiler().CompileSource(`import "pe"
rule text { condition: pe.rva_to_offset(0x1000) == 0x200 }
rule data { condition: pe.rva_to_offset(0x2000) == 0x15000 and pe.rva_to_offset(0x21ff) == 0x151ff }`)
	if err != nil {
		t.Fatal(err)
	}
	s := largeProgram.NewScanner()
	defer s.Close()
	result, err := s.ScanReader(bytes.NewReader(large))
	if err != nil || !result.RuleResults["text"] || !result.RuleResults["data"] {
		t.Fatalf("large reader: %v %v", result, err)
	}
	if got := peRVAToOffset(loadPE(&MatchContext{Data: large, FileSize: int64(len(large))}).file, 0x2000, -1); got != -1 {
		t.Fatalf("negative fileSize = %d, want -1", got)
	}
}

func TestPERVAToOffsetSectionLimitAnd4GB(t *testing.T) {
	data := make([]byte, 0x10000)
	copy(data, pefixture.New(false))
	binary.LittleEndian.PutUint16(data[0x86:], 97)
	for i := 0; i < 97; i++ {
		section := data[0x178+i*40:]
		copy(section, ".text\x00\x00\x00")
		binary.LittleEndian.PutUint32(section[8:], 0x200)
		binary.LittleEndian.PutUint32(section[12:], uint32(0x1000*(i+1))) //checkednarrow:ignore bounded by 97
		binary.LittleEndian.PutUint32(section[16:], 0x200)
		binary.LittleEndian.PutUint32(section[20:], 0x2000)
	}
	p, err := NewCompiler().CompileSource(`import "pe" rule limit { condition: pe.rva_to_offset(0x60000) == 0x2000 and not defined pe.rva_to_offset(0x61000) }`)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := p.Matches(data); err != nil || !ok {
		t.Fatalf("section limit: %t %v", ok, err)
	}

	cross := make([]byte, 0x3000)
	copy(cross, pefixture.New(false))
	s0 := peSectionOffset(cross, 0)
	binary.LittleEndian.PutUint32(cross[s0+8:], 0x2000)
	binary.LittleEndian.PutUint32(cross[s0+12:], 0xfffff000)
	binary.LittleEndian.PutUint32(cross[s0+16:], 0x2000)
	binary.LittleEndian.PutUint32(cross[s0+20:], 0x200)
	p, err = NewCompiler().CompileSource(`import "pe" rule cross { condition: pe.rva_to_offset(0xffffffff) == 0x11ff and pe.rva_to_offset(0x100000000) == 0x1200 and not defined pe.rva_to_offset(0x100001000) }`)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := p.Matches(cross); err != nil || !ok {
		t.Fatalf("4gb cross: %t %v", ok, err)
	}
}

func TestPERVAToOffsetHeaderCache(t *testing.T) {
	data := pefixture.Exports(true, 3)
	ctx := &MatchContext{Data: data, FileSize: int64(len(data)), moduleCache: &moduleCallCache{}}
	i := &Interpreter{matchContext: ctx, currentCompiledRule: &CompiledRule{nativePE: true}}
	if got := i.peRVAToOffsetQuery([]ModuleValue{IntegerValue(0x1020)}); got.Type != ModuleInteger || got.Integer != 0x220 {
		t.Fatalf("rva_to_offset: %+v", got)
	}
	image := loadPE(ctx)
	if image.imports != nil || image.exports != nil {
		t.Fatal("rva_to_offset parsed directories")
	}
	clear(data)
	ctx.Data, ctx.FileSize = nil, 0
	if got := i.peRVAToOffsetQuery([]ModuleValue{IntegerValue(0x1020)}); got.Type != ModuleInteger || got.Integer != 0x220 {
		t.Fatalf("header snapshot: %+v", got)
	}
	i.currentCompiledRule.nativePE = false
	if got := i.peRVAToOffsetQuery([]ModuleValue{IntegerValue(0x1020)}); got.Type != ModuleUndefined {
		t.Fatal("custom module fell back to native headers")
	}
}

func TestPERVAToOffsetHostData(t *testing.T) {
	program, err := NewCompiler().CompileSource(`import "pe"
rule mapped { condition: pe.rva_to_offset(0x1000) == 0x400 and pe.rva_to_offset(0x10ff) == 0x4ff and pe.rva_to_offset(0) == 0 }
rule headers { condition: pe.rva_to_offset(0) == 0 and not defined pe.rva_to_offset(0x1000) }
rule missing { condition: not defined pe.rva_to_offset(0x1000) and not defined pe.rva_to_offset(0) }`)
	if err != nil {
		t.Fatal(err)
	}
	section := func(va, vs, raw, size int64) map[string]any {
		return map[string]any{"virtual_address": va, "virtual_size": vs, "raw_data_offset": raw, "raw_data_size": size}
	}
	limitSections := make([]any, 97)
	for i := range limitSections {
		limitSections[i] = section(int64(0x1000*(i+1)), 0x100, 0x400, 0x100)
	}
	for _, tc := range []struct {
		name string
		data map[string]any
		want string
	}{
		{"nil", nil, "missing"},
		{"empty", map[string]any{}, "missing"},
		{"zero-sections", map[string]any{
			"number_of_sections": 0,
			"file_alignment":     0x200,
			"section_alignment":  0x1000,
		}, "headers"},
		{"mapped", map[string]any{
			"number_of_sections": 1,
			"file_alignment":     0x200,
			"section_alignment":  0x1000,
			"sections":           []any{section(0x1000, 0x100, 0x400, 0x100)},
		}, "mapped"},
		{"section-limit", map[string]any{
			"number_of_sections": 97,
			"file_alignment":     0x200,
			"section_alignment":  0x1000,
			"sections":           limitSections,
		}, "mapped"},
		{"missing-sections", map[string]any{
			"number_of_sections": 1,
			"file_alignment":     0x200,
			"section_alignment":  0x1000,
		}, "missing"},
		{"missing-alignment", map[string]any{
			"number_of_sections": 1,
			"sections":           []any{section(0x1000, 0x100, 0x400, 0x100)},
		}, "missing"},
		{"out-of-range-alignment", map[string]any{
			"number_of_sections": 1,
			"file_alignment":     int64(1) << 32,
			"section_alignment":  0x1000,
			"sections":           []any{section(0x1000, 0x100, 0x400, 0x100)},
		}, "missing"},
		{"invalid-section", map[string]any{
			"number_of_sections": 1,
			"file_alignment":     0x200,
			"section_alignment":  0x1000,
			"sections":           []any{section(-1, 0x100, 0x300, 0x100)},
		}, "missing"},
		{"incomplete-trailing-section", map[string]any{
			"number_of_sections": 2,
			"file_alignment":     0x200,
			"section_alignment":  0x1000,
			"sections":           []any{section(0x1000, 0x100, 0x400, 0x100), nil},
		}, "missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var opt ScannerOption
			if tc.data == nil {
				opt = WithModuleData("pe", nil)
			} else {
				opt = WithModuleData("pe", tc.data)
			}
			s := program.NewScanner(opt)
			defer s.Close()
			if tc.data != nil {
				clear(tc.data)
			}
			result, err := s.Scan(pefixture.New(false))
			if err != nil || s.moduleCache.pe != nil || len(result.MatchedRules) != 1 || !result.RuleResults[tc.want] {
				t.Fatalf("want %s: %v %v", tc.want, result, err)
			}
		})
	}
}

func TestPERVAToOffsetNonPEAllocations(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe" rule query { condition: defined pe.rva_to_offset(0) }`)
	if err != nil {
		t.Fatal(err)
	}
	s := p.NewScanner(WithoutMatches(), WithoutRuleResults())
	defer s.Close()
	for _, input := range [][]byte{nil, []byte("ordinary data")} {
		if n := testing.AllocsPerRun(100, func() {
			if _, err := s.MatchingRules(input); err != nil {
				t.Fatal(err)
			}
		}); n != 0 {
			t.Fatalf("non-PE rva_to_offset(%d bytes) allocates %g times", len(input), n)
		}
	}
}

func BenchmarkPERVAToOffset(b *testing.B) {
	benchmarkPEHeaderQuery(b, "pe.rva_to_offset(0x1020) == 0x220")
}
