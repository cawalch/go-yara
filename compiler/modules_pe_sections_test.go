package compiler

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"testing"

	"github.com/cawalch/go-yara/internal/pefixture"
)

func peSectionOffset(data []byte, index int) int {
	return 0x98 + int(binary.LittleEndian.Uint16(data[0x94:])) + index*40
}

func TestPESectionIndex(t *testing.T) {
	for _, tc := range []struct {
		name      string
		is64      bool
		change    func([]byte)
		condition string
	}{
		{
			name:      "names",
			condition: `pe.section_index(".text") == 0 and pe.section_index(".data") == 1 and not defined pe.section_index(".TEXT") and not defined pe.section_index("")`,
		},
		{
			name: "duplicate",
			change: func(data []byte) {
				copy(data[peSectionOffset(data, 1):], ".text\x00\x00\x00")
			},
			condition: `pe.section_index(".text") == 0`,
		},
		{
			name: "nul",
			change: func(data []byte) {
				offset := peSectionOffset(data, 0)
				copy(data[offset:offset+8], "a\x00bc\x00\x00\x00")
			},
			condition: `pe.section_index("a") == 0 and pe.section_index("a\x00bc") == 0 and not defined pe.section_index("ab")`,
		},
		{
			name:      "offsets",
			condition: `pe.section_index(0x200) == 0 and pe.section_index(0x3ff) == 0 and pe.section_index(0x400) == 1 and pe.section_index(0x5ff) == 1 and not defined pe.section_index(0x1ff) and not defined pe.section_index(0x600) and not defined pe.section_index(-1) and not defined pe.section_index(0x7fffffff)`,
		},
		{
			name: "overlap",
			change: func(data []byte) {
				binary.LittleEndian.PutUint32(data[peSectionOffset(data, 1)+20:], 0x300)
			},
			condition: `pe.section_index(0x300) == 0 and pe.section_index(0x400) == 1`,
		},
		{
			name: "zero-size",
			change: func(data []byte) {
				binary.LittleEndian.PutUint32(data[peSectionOffset(data, 0)+16:], 0)
			},
			condition: `not defined pe.section_index(0x200) and pe.section_index(0x400) == 1`,
		},
		{
			name:      "pe64",
			is64:      true,
			condition: `pe.section_index(".text") == 0 and pe.section_index(0x200) == 0 and pe.section_index(0x400) == 1`,
		},
		{
			name:      "non-pe",
			condition: `not defined pe.section_index(".text") and not defined pe.section_index(0)`,
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

func TestPESectionIndexScanPathsAndSerialization(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe"
rule named { condition: pe.section_index(".text") == 0 and pe.section_index(".data") == 1 }
rule offset { condition: pe.section_index(0x200) == 0 and pe.section_index(0x400) == 1 }
rule absent { condition: not defined pe.section_index(0x600) }`)
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
			if err != nil || !result.RuleResults["named"] || !result.RuleResults["offset"] || !result.RuleResults["absent"] {
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
			if err != nil || result.RuleResults["named"] != (base == 0) {
				t.Fatalf("block base=%d: %v %v", base, result, err)
			}
		}
	}
}

func TestPESectionIndexHostData(t *testing.T) {
	const maxInt64 = int64(^uint64(0) >> 1)
	program, err := NewCompiler().CompileSource(`import "pe"
rule named { condition: pe.section_index(".text") == 0 and pe.section_index(".data") == 1 }
rule offset { condition: pe.section_index(0x200) == 0 and pe.section_index(0x400) == 1 }
rule missing { condition: not defined pe.section_index(".text") and not defined pe.section_index(0x200) }
rule overflow { condition: pe.section_index(` + strconv.FormatInt(maxInt64-5, 10) + `) == 0 }`)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		data map[string]any
		want []string
	}{
		{"sections", map[string]any{
			"number_of_sections": 2,
			"sections": []any{
				map[string]any{"name": ".text", "raw_data_offset": 0x200, "raw_data_size": 0x200},
				map[string]any{"name": ".data", "raw_data_offset": 0x400, "raw_data_size": 0x200},
			},
		}, []string{"named", "offset"}},
		{"incomplete", map[string]any{"number_of_sections": 2}, []string{"missing"}},
		{"missing-count", map[string]any{"sections": []any{
			map[string]any{"name": ".text", "raw_data_offset": 0x200, "raw_data_size": 0x200},
		}}, []string{"missing"}},
		{"overflow", map[string]any{
			"number_of_sections": 1,
			"sections": []any{
				map[string]any{"name": ".text", "raw_data_offset": maxInt64 - 10, "raw_data_size": 20},
			},
		}, []string{"overflow"}},
		{"negative", map[string]any{
			"number_of_sections": 1,
			"sections": []any{
				map[string]any{"name": ".late", "raw_data_offset": -1, "raw_data_size": 10},
			},
		}, []string{"missing"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := program.NewScanner(WithModuleData("pe", tc.data))
			defer s.Close()
			result, err := s.Scan(pefixture.New(false))
			if err != nil || len(result.MatchedRules) != len(tc.want) {
				t.Fatalf("want %v: %v %v", tc.want, result, err)
			}
			for _, rule := range tc.want {
				if !result.RuleResults[rule] {
					t.Fatalf("want %s: %v %v", rule, result, err)
				}
			}
		})
	}
}

func TestPESectionIndexNonPEAllocations(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe" rule query { condition: defined pe.section_index(".text") }`)
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
		t.Fatalf("non-PE section_index allocates %g times", n)
	}
}

func BenchmarkPESectionIndex(b *testing.B) {
	for _, query := range []struct{ name, condition string }{
		{"name", `pe.section_index(".text") == 0`},
		{"offset", `pe.section_index(0x220) == 0`},
	} {
		b.Run(query.name, func(b *testing.B) {
			benchmarkPEHeaderQuery(b, query.condition)
		})
	}
}
