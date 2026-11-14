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
			condition: `pe.rva_to_offset(0) == 0 and pe.rva_to_offset(0x200) == 0x200 and pe.rva_to_offset(0x7ff) == 0x7ff and not defined pe.rva_to_offset(0x800) and not defined pe.rva_to_offset(0xffffffff) and not defined pe.rva_to_offset(-1)`,
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
}

func TestPERVAToOffsetHostData(t *testing.T) {
	program, err := NewCompiler().CompileSource(`import "pe"
rule mapped { condition: pe.rva_to_offset(0x1000) == 0x400 and pe.rva_to_offset(0x10ff) == 0x4ff and pe.rva_to_offset(0) == 0 }
rule missing { condition: not defined pe.rva_to_offset(0x1000) }`)
	if err != nil {
		t.Fatal(err)
	}
	section := func(va, vs, raw, size int64) map[string]any {
		return map[string]any{"virtual_address": va, "virtual_size": vs, "raw_data_offset": raw, "raw_data_size": size}
	}
	for _, tc := range []struct {
		name string
		data map[string]any
		want string
	}{
		{"mapped", map[string]any{
			"number_of_sections": 1,
			"file_alignment":     0x200,
			"section_alignment":  0x1000,
			"sections":           []any{section(0x1000, 0x100, 0x400, 0x100)},
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
		{"invalid-section", map[string]any{
			"number_of_sections": 1,
			"file_alignment":     0x200,
			"section_alignment":  0x1000,
			"sections":           []any{section(-1, 0x100, 0x300, 0x100)},
		}, "missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := program.NewScanner(WithModuleData("pe", tc.data))
			defer s.Close()
			result, err := s.Scan(pefixture.New(false))
			if err != nil || len(result.MatchedRules) != 1 || !result.RuleResults[tc.want] {
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
	if n := testing.AllocsPerRun(100, func() {
		if _, err := s.MatchingRules(nil); err != nil {
			t.Fatal(err)
		}
	}); n != 0 {
		t.Fatalf("non-PE rva_to_offset allocates %g times", n)
	}
}

func BenchmarkPERVAToOffset(b *testing.B) {
	benchmarkPEHeaderQuery(b, "pe.rva_to_offset(0x1020) == 0x220")
}
