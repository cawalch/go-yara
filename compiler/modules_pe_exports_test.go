package compiler

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/internal/pefixture"
)

const peExportCondition = `pe.number_of_exports == 3 and pe.export_timestamp == 0 and pe.dll_name == "Example.DLL" and
 pe.export_details[0].ordinal == 7 and pe.export_details[0].rva == 0x1020 and
 pe.export_details[0].offset == 0x220 and pe.export_details[0].name == "Function00000" and
 not defined pe.export_details[0].forward_name and pe.export_details[2].name == "Function00002" and
 not defined pe.export_details[3].ordinal and not defined pe.export_details[-1].name and
 pe.exports("function00000") and not pe.exports(7) and
 pe.exports_index("function00000") == 0 and pe.export_details[pe.exports_index("Function00002")].ordinal == 9 and
 not defined pe.exports_index(7)`

func TestPEExportsScanPaths(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe"
rule exports {condition: ` + peExportCondition + ` and pe.imports("Example.DLL") == 3}
rule empty {condition: pe.is_pe and pe.number_of_exports == 0 and not defined pe.export_timestamp and not defined pe.dll_name}
rule not_pe {condition: not pe.is_pe and not defined pe.export_timestamp and not defined pe.dll_name and not defined pe.number_of_exports and not defined pe.exports("Function00000") and not defined pe.exports(1) and not defined pe.exports_index("Function00000") and not defined pe.exports_index(1)}`)
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
			binary.LittleEndian.PutUint32(data[0x804:], 0x80000000)
			const forwarder = 0x828 + 3*10 + 3*16
			copy(data[forwarder:], "other.Target\x00")
			binary.LittleEndian.PutUint32(data[0x82c:], forwarder+0x1c00)
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
			fields := []string{"number_of_imports", "number_of_exports", "export_timestamp", "dll_name"}
			if exportsFirst {
				fields[0], fields[3] = fields[3], fields[0]
			}
			for _, name := range fields {
				value := root.field(name)
				if (value.Type == ModuleUndefined) != (name == "number_of_"+invalid || invalid == "exports" && (name == "export_timestamp" || name == "dll_name")) {
					t.Fatalf("order=%v invalid=%s field=%s: %+v", fields, invalid, name, value)
				}
			}
			if root.exports.details.Type != ModuleUndefined || root.imports.details.Type != ModuleUndefined {
				t.Fatal("scalar fields constructed detail objects")
			}
			copy(data, pefixture.Exports(true, 3))
			if invalid != "" && root.field("number_of_"+invalid).Type != ModuleUndefined {
				t.Fatal("failed parse retried")
			}
			clear(data)
			ctx.Data, ctx.FileSize = nil, 0
			if invalid == "exports" {
				continue
			}
			if dll := root.field("dll_name"); dll.Type != ModuleString || dll.String != "Example.DLL" {
				t.Fatalf("DLL name did not retain the export snapshot: %+v", dll)
			}
			if stamp := root.field("export_timestamp"); stamp.Type != ModuleInteger || stamp.Integer != 0x80000000 {
				t.Fatalf("timestamp did not retain the export snapshot: %+v", stamp)
			}
			symbol := root.field("export_details").object.elements[0].object
			if symbol.field("name").String != "Function00000" || symbol.field("offset").Integer != 0x220 {
				t.Fatal("exports retained mutable input or scan size")
			}
			forward := root.field("export_details").object.elements[1].object
			if forward.field("forward_name").String != "other.Target" || forward.field("offset").Type != ModuleUndefined {
				t.Fatal("forwarder retained mutable input or exposed an offset")
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
rule unavailable {condition: pe.is_pe and not defined pe.export_timestamp and not defined pe.dll_name and not defined pe.number_of_exports and not defined pe.export_details and not defined pe.exports("Function00000") and not defined pe.exports(1) and not defined pe.exports_index("Function00000") and not defined pe.exports_index(1)}`)
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
rule exports {condition: pe.number_of_exports == 16384 and pe.export_details[16383].ordinal == 16390 and not defined pe.export_details[16384].ordinal and pe.exports("Function16383") and not pe.exports("Function16384") and pe.exports(16384) and not pe.exports(16385) and pe.exports_index("Function16383") == 16383 and not defined pe.exports_index("Function16384") and pe.exports_index(16384) == 16377 and not defined pe.exports_index(16385)}
rule limited {condition: pe.is_pe and pe.number_of_imports == 1 and not defined pe.export_timestamp and not defined pe.dll_name and not defined pe.number_of_exports and not defined pe.exports("Function00000") and not defined pe.exports(1) and not defined pe.exports_index("Function00000") and not defined pe.exports_index(1)}`)
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

func TestPEExportTimestamp(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe"
rule absent {condition: not defined pe.export_timestamp}
rule zero {condition: defined pe.export_timestamp and pe.export_timestamp == 0}
rule high {condition: pe.export_timestamp == 0xffffffff}`)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		s := p.NewScanner()
		for _, is64 := range []bool{false, true} {
			for _, count := range []int{0, 3} {
				data := pefixture.Exports(is64, count)
				for _, tc := range []struct {
					data []byte
					want string
				}{{data, "zero"}, {pefixture.New(is64), "absent"}, {nil, "absent"}, {data, "zero"}} {
					r, err := s.Scan(tc.data)
					if err != nil || len(r.MatchedRules) != 1 || !r.RuleResults[tc.want] {
						t.Fatalf("PE64=%t count=%d want=%s: %v %v", is64, count, tc.want, r, err)
					}
				}
				binary.LittleEndian.PutUint32(data[0x804:], 0xffffffff)
				r, err := s.Scan(data)
				if err != nil || len(r.MatchedRules) != 1 || !r.RuleResults["high"] {
					t.Fatalf("unsigned timestamp: %v %v", r, err)
				}
			}
		}
		s.Close()
		for _, tc := range []struct {
			data any
			want string
		}{{nil, "absent"}, {map[string]any{}, "absent"},
			{map[string]any{"export_timestamp": 0}, "zero"},
			{map[string]any{"export_timestamp": uint32(0xffffffff)}, "high"}} {
			s := p.NewScanner(WithModuleData("pe", tc.data))
			r, err := s.Scan(pefixture.Exports(false, 3))
			if err != nil || len(r.MatchedRules) != 1 || !r.RuleResults[tc.want] || s.moduleCache.pe != nil {
				t.Fatalf("host want=%s: %v %v", tc.want, r, err)
			}
			s.Close()
		}
		blob, err := p.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		p, err = UnmarshalCompiledProgram(blob)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func BenchmarkPEExports(b *testing.B) {
	for _, symbols := range []int{16, 256} {
		for _, field := range []struct{ name, condition string }{
			{"details=false", fmt.Sprintf("pe.number_of_exports == %d", symbols)},
			{"details=true", `for any e in pe.export_details : (e.name == "Function00000" and e.offset == 0x220)`},
			{"timestamp", `pe.export_timestamp == 0`},
			{"dll_name", `pe.dll_name == "Example.DLL"`},
		} {
			for _, rules := range []int{1, 100} {
				var source strings.Builder
				source.WriteString("import \"pe\"\n")
				for i := range rules {
					fmt.Fprintf(&source, "rule r%d {condition: %s}\n", i, field.condition)
				}
				p, err := NewCompiler().CompileSource(source.String())
				if err != nil {
					b.Fatal(err)
				}
				data := pefixture.Exports(true, symbols)
				b.Run(fmt.Sprintf("symbols=%d/%s/rules=%d", symbols, field.name, rules), func(b *testing.B) {
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
