package compiler

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/internal/pefixture"
)

const peExportCondition = `pe.number_of_exports == 3 and
 pe.export_details[0].ordinal == 7 and pe.export_details[0].rva == 0x1020 and
 pe.export_details[0].offset == 0x220 and pe.export_details[0].name == "Function00000" and
 not defined pe.export_details[0].forward_name and pe.export_details[2].name == "Function00002" and
 not defined pe.export_details[3].ordinal and not defined pe.export_details[-1].name`

func TestPEExportsScanPaths(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe"
rule exports {condition: ` + peExportCondition + ` and pe.imports("Example.DLL") == 3}
rule empty {condition: pe.is_pe and pe.number_of_exports == 0}
rule not_pe {condition: not pe.is_pe and not defined pe.number_of_exports}`)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		blob, err := p.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		p, err = UnmarshalCompiledProgram(blob)
		if err != nil {
			t.Fatal(err)
		}
		s := p.NewScanner(WithFastScan())
		defer s.Close()
		for _, is64 := range []bool{false, true} {
			data := pefixture.Exports(is64, 3)
			for _, tc := range []struct {
				data []byte
				want string
			}{{data, "exports"}, {nil, "not_pe"}, {pefixture.New(is64), "empty"}, {data, "exports"}} {
				for _, reader := range []bool{false, true} {
					var result *ScanResult
					if reader {
						result, err = s.ScanReader(bytes.NewReader(tc.data))
					} else {
						result, err = s.Scan(tc.data)
					}
					if err != nil || len(result.MatchedRules) != 1 || !result.RuleResults[tc.want] {
						t.Fatalf("reader=%t want=%s: %v %v", reader, tc.want, result, err)
					}
				}
			}
			blocks := p.NewBlockScanner()
			if err := blocks.Scan(0, data); err != nil {
				t.Fatal(err)
			}
			result, err := blocks.Finish()
			blocks.Close()
			if err != nil || !result.RuleResults["exports"] {
				t.Fatalf("blocks: %v %v", result, err)
			}
		}
	}
}

func TestPEExportsLazySnapshot(t *testing.T) {
	for _, exportsFirst := range []bool{false, true} {
		for _, invalid := range []string{"", "imports", "exports"} {
			data := pefixture.Exports(true, 3)
			switch invalid {
			case "imports":
				binary.LittleEndian.PutUint32(data[0x400:], 0xffffffff)
			case "exports":
				binary.LittleEndian.PutUint32(data[0x81c:], 0xffffffff)
			}
			ctx := &MatchContext{Data: data, FileSize: int64(len(data))}
			root := loadPE(ctx)
			if root.imports != nil || root.exports != nil {
				t.Fatal("header access parsed directories")
			}
			fields := []string{"number_of_imports", "number_of_exports"}
			if exportsFirst {
				fields[0], fields[1] = fields[1], fields[0]
			}
			for _, name := range fields {
				value := root.field(name)
				if (value.Type == ModuleUndefined) != (name == "number_of_"+invalid) {
					t.Fatalf("order=%v invalid=%s field=%s: %+v", fields, invalid, name, value)
				}
			}
			if root.exports.details.Type != ModuleUndefined || root.imports.details.Type != ModuleUndefined {
				t.Fatal("counts constructed detail objects")
			}
			copy(data, pefixture.Exports(true, 3))
			if invalid != "" && root.field("number_of_"+invalid).Type != ModuleUndefined {
				t.Fatal("failed parse retried")
			}
			clear(data)
			ctx.Data, ctx.FileSize = nil, 0
			if invalid != "exports" {
				symbol := root.field("export_details").object.elements[0].object
				if symbol.field("name").String != "Function00000" || symbol.field("offset").Integer != 0x220 {
					t.Fatal("exports retained mutable input or scan size")
				}
			}
		}
	}
	data := pefixture.Exports(false, 3)
	ctx := &MatchContext{Data: data, FileSize: int64(len(data))}
	root := loadPE(ctx)
	ctx.Data = nil
	if root.field("number_of_exports").Type != ModuleUndefined {
		t.Fatal("snapshot retained deferred input")
	}
}

func TestPEExportsTruncation(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe"
rule headers {condition: pe.is_pe}
rule exports {condition: ` + peExportCondition + `}
rule unavailable {condition: pe.is_pe and not defined pe.number_of_exports and not defined pe.export_details}`)
	if err != nil {
		t.Fatal(err)
	}
	s := p.NewScanner()
	defer s.Close()
	for _, is64 := range []bool{false, true} {
		data := pefixture.Exports(is64, 3)
		headerEnd := 0x98 + int(binary.LittleEndian.Uint16(data[0x94:])) + 2*40
		nameEnd := 0x828 + 3*10 + 2*16 + len("Function00002") + 1
		for end := len(data); end >= 0; end-- {
			r, err := s.Scan(data[:end])
			if err != nil {
				t.Fatal(err)
			}
			if r.RuleResults["headers"] != (end >= headerEnd) || r.RuleResults["exports"] != (end >= nameEnd) ||
				r.RuleResults["unavailable"] != (end >= headerEnd && end < nameEnd) {
				t.Fatalf("PE64=%t cut=%#x: %v", is64, end, r.RuleResults)
			}
		}
	}
}

func TestPEExportsReaderAndExposureLimits(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe"
rule exports {condition: pe.number_of_exports == 16384 and pe.export_details[16383].ordinal == 16390 and not defined pe.export_details[16384].ordinal}
rule limited {condition: pe.is_pe and pe.number_of_imports == 1 and not defined pe.number_of_exports}`)
	if err != nil {
		t.Fatal(err)
	}
	data := pefixture.Exports(true, 16385)
	s := p.NewScanner()
	defer s.Close()
	r, err := s.Scan(data)
	if err != nil || !r.RuleResults["exports"] || r.RuleResults["limited"] {
		t.Fatalf("buffer: %v %v", r, err)
	}
	r, err = s.ScanReader(bytes.NewReader(data))
	if err != nil || !r.RuleResults["limited"] || r.RuleResults["exports"] {
		t.Fatalf("reader: %v %v", r, err)
	}
	blocks := p.NewBlockScanner()
	defer blocks.Close()
	for i, block := range [][]byte{data[:0x800], data[0x800:]} {
		if err := blocks.Scan(int64(i*0x800), block); err != nil {
			t.Fatal(err)
		}
	}
	r, err = blocks.Finish()
	if err != nil || !r.RuleResults["limited"] || r.RuleResults["exports"] {
		t.Fatalf("disjoint blocks: %v %v", r, err)
	}
}

func TestPEExportsHostData(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe" rule host {condition: pe.number_of_exports == 1 and pe.export_details[0].ordinal == 42}`)
	if err != nil {
		t.Fatal(err)
	}
	s := p.NewScanner(WithModuleData("pe", map[string]any{
		"number_of_exports": 1,
		"export_details":    []any{map[string]any{"ordinal": 42}},
	}))
	defer s.Close()
	if ok, err := s.Matches(nil); err != nil || !ok || s.moduleCache.pe != nil {
		t.Fatalf("host: %t %v", ok, err)
	}
}

func BenchmarkPEExports(b *testing.B) {
	for _, symbols := range []int{16, 256} {
		for _, details := range []bool{false, true} {
			for _, rules := range []int{1, 100} {
				var source strings.Builder
				source.WriteString("import \"pe\"\n")
				condition := fmt.Sprintf("pe.number_of_exports == %d", symbols)
				if details {
					condition = `for any e in pe.export_details : (e.name == "Function00000" and e.offset == 0x220)`
				}
				for i := range rules {
					fmt.Fprintf(&source, "rule r%d {condition: %s}\n", i, condition)
				}
				p, err := NewCompiler().CompileSource(source.String())
				if err != nil {
					b.Fatal(err)
				}
				data := pefixture.Exports(true, symbols)
				b.Run(fmt.Sprintf("symbols=%d/details=%t/rules=%d", symbols, details, rules), func(b *testing.B) {
					s := p.NewScanner(WithoutMatches(), WithoutRuleResults())
					defer s.Close()
					b.ReportAllocs()
					for b.Loop() {
						matches, err := s.MatchingRules(data)
						if err != nil || len(matches) != rules {
							b.Fatalf("matches=%d: %v", len(matches), err)
						}
					}
				})
			}
		}
	}
}

func TestPEExportsConcurrentScans(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe" rule exports {condition: ` + peExportCondition + `}`)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 8 {
		t.Run(fmt.Sprintf("worker%d", i), func(t *testing.T) {
			t.Parallel()
			for _, data := range [][]byte{pefixture.Exports(false, 3), nil, pefixture.Exports(true, 3)} {
				if ok, err := p.Matches(data); err != nil || ok != (data != nil) {
					t.Fatalf("concurrent: %t %v", ok, err)
				}
			}
		})
	}
}
