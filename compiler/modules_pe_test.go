package compiler

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/internal/pefixture"
)

func TestPEScanLifecycle(t *testing.T) {
	const source = `import "pe"
rule image { condition: pe.is_pe == 1 and pe.entry_point == 0x220 and
    pe.sections[0].name == ".text" and pe.sections[1].characteristics & pe.SECTION_MEM_WRITE != 0 }
rule again { condition: image and pe.number_of_sections == 2 }
rule not_image { condition: pe.is_pe == 0 and not defined pe.machine and not defined pe.sections[0].name }
rule constants { condition: pe.MACHINE_AMD64 == 0x8664 and pe.DLL == 0x2000 }`
	program, err := NewCompiler().CompileSource(source)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := program.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := UnmarshalCompiledProgram(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for _, program := range []*CompiledProgram{program, loaded} {
		scanner := program.NewScanner()
		defer scanner.Close()
		for _, data := range [][]byte{pefixture.New(false), nil, pefixture.New(true), []byte("MZ"), pefixture.New(false)} {
			wantPE := len(data) > 64
			for _, reader := range []bool{false, true} {
				var result *ScanResult
				if reader {
					result, err = scanner.ScanReader(bytes.NewReader(data))
				} else {
					result, err = scanner.Scan(data)
				}
				if err != nil {
					t.Fatal(err)
				}
				if result.RuleResults["image"] != wantPE || result.RuleResults["again"] != wantPE || result.RuleResults["not_image"] == wantPE || !result.RuleResults["constants"] {
					t.Fatalf("reader=%v results=%v", reader, result.RuleResults)
				}
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := scanner.ScanWithContext(ctx, pefixture.New(false)); err == nil {
			t.Fatal("canceled scan succeeded")
		}
	}
}

func TestPELazyLoading(t *testing.T) {
	for _, source := range []string{
		`rule no_pe { condition: true }`,
		`import "pe" rule unused { condition: true }`,
		`import "pe" rule constant { condition: pe.MACHINE_I386 == 0x14c }`,
	} {
		p, err := NewCompiler().CompileSource(source)
		if err != nil {
			t.Fatal(err)
		}
		s := p.NewScanner()
		defer s.Close()
		if _, err := s.Scan(pefixture.New(false)); err != nil {
			t.Fatal(err)
		}
		if s.moduleCache.pe != nil {
			t.Fatal("unused PE module was loaded")
		}
	}
	p, err := NewCompiler().CompileSource(`import "pe" rule a { condition: pe.is_pe } rule b { condition: pe.machine }`)
	if err != nil {
		t.Fatal(err)
	}
	s := p.NewScanner()
	defer s.Close()
	if _, err := s.Scan(pefixture.New(false)); err != nil {
		t.Fatal(err)
	}
	cached := s.moduleCache.pe
	// Re-evaluating another rule must use the scan snapshot even if the input
	// scratch reference changes; a new scan must discard the old snapshot.
	s.matchCtx.Data = nil
	if !s.isRuleConditionSatisfied(p.Rules[1]) || s.moduleCache.pe != cached {
		t.Fatal("PE snapshot not reused")
	}
	if _, err := s.Scan(nil); err != nil {
		t.Fatal(err)
	}
	if s.moduleCache.pe != notPE {
		t.Fatal("stale PE snapshot")
	}
}

func TestPECustomData(t *testing.T) {
	custom := Module{Name: "pe", Schema: &ModuleSchema{Fields: map[string]ModuleField{"label": {Kind: ModuleString}}}}
	p, err := NewCompiler(WithModule(custom)).CompileSource(`import "pe" rule custom { condition: pe.label == "host" }`)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	p, err = UnmarshalCompiledProgram(blob)
	if err != nil {
		t.Fatal(err)
	}
	s := p.NewScanner(WithModuleData("pe", map[string]any{"label": "host"}))
	defer s.Close()
	r, err := s.Scan(pefixture.New(false))
	if err != nil || !r.RuleResults["custom"] || s.moduleCache.pe != nil {
		t.Fatalf("custom module: %v %v", r, err)
	}
}

func TestPERetainedHeader(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe" rule image { condition: pe.is_pe } rule entry { condition: pe.entry_point == 0x10020 }`)
	if err != nil {
		t.Fatal(err)
	}
	data := append(pefixture.New(false), make([]byte, 128<<10)...)
	binary.LittleEndian.PutUint32(data[0x178+20:], 0x10000)
	s := p.NewScanner()
	defer s.Close()
	r, err := s.ScanReader(bytes.NewReader(data))
	if err != nil || !r.RuleResults["image"] || !r.RuleResults["entry"] {
		t.Fatalf("retained header: %v %v", r, err)
	}
	// Move the entire NT header and section table beyond the retained prefix.
	copy(data[0x10000:], data[0x80:0x1c8])
	binary.LittleEndian.PutUint32(data[0x3c:], 0x10000)
	r, err = s.Scan(data)
	if err != nil || !r.RuleResults["image"] {
		t.Fatalf("buffer: %v %v", r, err)
	}
	r, err = s.ScanReader(bytes.NewReader(data))
	if err != nil || r.RuleResults["image"] {
		t.Fatalf("reader limit: %v %v", r, err)
	}
}

func TestPEBlocks(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe" rule image { condition: pe.is_pe and pe.entry_point == 0x220 }`)
	if err != nil {
		t.Fatal(err)
	}
	for _, base := range []int64{0, 4096} {
		b := p.NewBlockScanner()
		defer b.Close()
		if err := b.Scan(base, pefixture.New(false)); err != nil {
			t.Fatal(err)
		}
		r, err := b.Finish()
		if err != nil || r.RuleResults["image"] != (base == 0) {
			t.Fatalf("base=%d: %v %v", base, r, err)
		}
	}
}

func TestPEUnsupportedFeatures(t *testing.T) {
	for _, condition := range []string{`pe.imphash() == ""`, `pe.exports("name")`, `pe.exports_index(7) >= 0`, `pe.dll_name == "x"`, `pe.export_timestamp == 0`, `pe.number_of_signatures > 0`, `pe.rich_signature.key == 0`, `pe.imports()`, `pe.imports(1)`, `pe.imports(true)`, `pe.imports("a", "b", "c")`, `pe.imports(/a/, /b/)`, `pe.imports(1, "a.dll", "b")`, `pe.import_details[0].functions[0].rva == 0`, `pe.delayed_import_details[0].library_name == "a"`} {
		if _, err := NewCompiler().CompileSource(`import "pe" rule unsupported { condition: ` + condition + ` }`); err == nil {
			t.Fatalf("unsupported feature compiled: %s", condition)
		}
	}
}

func BenchmarkPEModule(b *testing.B) {
	for name, data := range map[string][]byte{"non_pe": []byte("ordinary input"), "pe32": pefixture.New(false), "pe64": pefixture.New(true)} {
		b.Run(name, func(b *testing.B) {
			ctx := &MatchContext{Data: data, FileSize: int64(len(data))}
			b.ReportAllocs()
			for b.Loop() {
				_ = loadPE(ctx)
			}
		})
	}
}

func BenchmarkPEScanner(b *testing.B) {
	for _, count := range []int{1, 100} {
		for _, enabled := range []bool{false, true} {
			var source strings.Builder
			if enabled {
				source.WriteString(`import "pe"` + "\n")
			}
			for i := 0; i < count; i++ {
				condition := `uint16(0) == 0x5a4d`
				if enabled {
					condition = `pe.is_pe and pe.number_of_sections == 2 and pe.sections[0].name == ".text"`
				}
				fmt.Fprintf(&source, "rule r%d { condition: %s }\n", i, condition)
			}
			p, err := NewCompiler().CompileSource(source.String())
			if err != nil {
				b.Fatal(err)
			}
			for name, data := range map[string][]byte{"non_pe": bytes.Repeat([]byte("ordinary"), 32), "pe": pefixture.New(false)} {
				b.Run(fmt.Sprintf("rules=%d/pe=%t/%s", count, enabled, name), func(b *testing.B) {
					s := p.NewScanner(WithoutMatches(), WithoutRuleResults())
					defer s.Close()
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
}

func TestPENonPEAllocations(t *testing.T) {
	data := bytes.Repeat([]byte("ordinary"), 32)
	ctx := &MatchContext{Data: data, FileSize: int64(len(data))}
	if got := testing.AllocsPerRun(100, func() { _ = loadPE(ctx) }); got != 0 {
		t.Fatalf("non-PE load allocated %g times", got)
	}
	p, err := NewCompiler().CompileSource(`import "pe" rule image { condition: pe.is_pe }`)
	if err != nil {
		t.Fatal(err)
	}
	s := p.NewScanner()
	defer s.Close()
	if got := testing.AllocsPerRun(100, func() {
		if matches, err := s.MatchingRules(data); err != nil || len(matches) != 0 {
			t.Fatalf("scan: %v %v", matches, err)
		}
	}); got != 0 {
		t.Fatalf("non-PE compact scan allocated %g times", got)
	}
}

func TestPEUnusedSchema(t *testing.T) {
	original := NewCompiler()
	for _, c := range []*Compiler{original, NewCompilerWithOptions(original.GetOptions())} {
		p, err := c.CompileSource(`rule no_pe { condition: true }`)
		if err != nil {
			t.Fatal(err)
		}
		if p.moduleSchemas["pe"] != nil {
			t.Fatal("unused built-in schema retained")
		}
	}
}

func TestPESnapshotOwnsNames(t *testing.T) {
	for _, tc := range []struct {
		name, raw, full string
	}{
		{"short", ".text", ".text"},
		{"embedded_nul", "a\x00bc", "a\x00bc"},
		{"coff", "/4", ".long_section_name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := pefixture.New(false)
			clear(data[0x178:0x180])
			copy(data[0x178:], tc.raw)
			if tc.name == "coff" {
				binary.LittleEndian.PutUint32(data[0x8c:], 0x600)
				binary.LittleEndian.PutUint32(data[0x600:], 32)
				copy(data[0x604:], tc.full+"\x00")
			}
			value := loadPE(&MatchContext{Data: data, FileSize: int64(len(data))})
			clear(data)
			section := value.object.field("sections").object.elements[0].object
			if got := section.field("name").String; got != tc.raw {
				t.Fatalf("borrowed section name: %q", got)
			}
			if got := section.field("full_name").String; got != tc.full {
				t.Fatalf("borrowed full section name: %q", got)
			}
			if got := value.object.field("machine").Integer; got != 0x14c {
				t.Fatalf("borrowed header: %x", got)
			}
		})
	}
}

func FuzzPEAdapter(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte("MZ"))
	f.Add(pefixture.New(false))
	f.Add(pefixture.New(true))
	f.Add(pefixture.Exports(false, 3))
	f.Add(pefixture.Exports(true, 3))
	f.Add(pefixture.Imports(false, 3))
	ordinal := pefixture.Imports(true, 3)
	pefixture.ImportOrdinal(ordinal, 1, 7)
	f.Add(ordinal)
	p, err := NewCompiler().CompileSource(`import "pe"
rule headers { condition: pe.is_pe and pe.entry_point >= 0 and pe.machine == pe.MACHINE_I386 }
rule sections { condition: for any s in pe.sections : (s.name == ".text" or s.full_name contains "debug") }
rule directories { condition: for all d in pe.data_directories : (d.size >= 0) }
rule imports { condition: pe.number_of_imports > 0 and pe.number_of_imported_functions > 0 and for any d in pe.import_details : (for any f in d.functions : (f.name == "NamedFunction" or f.ordinal == 7)) }
rule dll_count { condition: pe.imports("Example.DLL") > 0 }
rule exports { condition: pe.number_of_exports > 0 and for any e in pe.export_details : (e.name == "Function00000" or e.ordinal == 7 or defined e.forward_name or e.offset == 0x220) }
rule queries { condition: pe.imports("Example.DLL", "NamedFunction") or pe.imports("Example.DLL", uint16(0)) }`)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if _, err := p.MatchingRules(data); err != nil {
			t.Fatal(err)
		}
	})
}

func TestPEConcurrentScans(t *testing.T) {
	const source = `import "pe" rule image { condition: pe.is_pe and pe.sections[0].name == ".text" }`
	p, err := NewCompiler().CompileSource(source)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 8 {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			t.Parallel()
			// Exercise the immutable semantic schema as well as pooled scanners.
			if _, err := NewCompiler().CompileSource(source); err != nil {
				t.Fatal(err)
			}
			for _, data := range [][]byte{pefixture.New(false), nil, pefixture.New(true)} {
				if matched, err := p.Matches(data); err != nil || matched != (len(data) > 0) {
					t.Fatalf("scan: %t %v", matched, err)
				}
			}
		})
	}
}

func TestPEHostDataOverride(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe" rule host { condition: pe.is_pe == 42 and not defined pe.machine }`)
	if err != nil {
		t.Fatal(err)
	}
	s := p.NewScanner(WithModuleData("pe", map[string]any{"is_pe": 42}))
	defer s.Close()
	if matched, err := s.Matches(pefixture.New(false)); err != nil || !matched {
		t.Fatalf("host data: %t %v", matched, err)
	}
	if s.moduleCache.pe != nil {
		t.Fatal("host data triggered automatic parsing")
	}
}
