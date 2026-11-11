package compiler

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/cawalch/go-yara/internal/pefixture"
)

const peImportCondition = `pe.number_of_imports == 1 and pe.number_of_imported_functions == 3 and
 pe.import_details[0].library_name == "Example.DLL" and pe.import_details[0].number_of_functions == 3 and
 pe.import_details[0].functions[0].name == "NamedFunction" and
 not defined pe.import_details[0].functions[0].ordinal and
 pe.import_details[0].functions[1].ordinal == 7 and
 not defined pe.import_details[0].functions[1].name and
 not defined pe.import_details[1].library_name and
 not defined pe.import_details[0].functions[3].name`

func TestPEImportsScanPaths(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe" rule imports {condition:` + peImportCondition + `}
 rule empty {condition: pe.is_pe and pe.number_of_imports == 0}
 rule not_pe {condition: not pe.is_pe and not defined pe.number_of_imports}`)
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
		s := program.NewScanner(WithFastScan())
		defer s.Close()
		for _, is64 := range []bool{false, true} {
			data := pefixture.Imports(is64, 3)
			pefixture.ImportOrdinal(data, 1, 7)
			for _, input := range [][]byte{data, nil, pefixture.New(is64), data} {
				for _, reader := range []bool{false, true} {
					var result *ScanResult
					if reader {
						result, err = s.ScanReader(bytes.NewReader(input))
					} else {
						result, err = s.Scan(input)
					}
					if err != nil {
						t.Fatal(err)
					}
					want := "imports"
					if input == nil {
						want = "not_pe"
					} else if len(input) == 0x800 {
						want = "empty"
					}
					if len(result.MatchedRules) != 1 || !result.RuleResults[want] {
						t.Fatalf("reader=%t want=%s: %v", reader, want, result.RuleResults)
					}
				}
			}
			// Block scans use only the offset-zero block, not reconstructed memory.
			b := program.NewBlockScanner()
			if err := b.Scan(0, data); err != nil {
				t.Fatal(err)
			}
			r, err := b.Finish()
			if err != nil || !r.RuleResults["imports"] {
				t.Fatalf("blocks: %v %v", r, err)
			}
			b.Close()
		}
	}
}

func TestPEImportsLazySnapshot(t *testing.T) {
	data := pefixture.Imports(false, 3)
	ctx := &MatchContext{Data: data, FileSize: int64(len(data))}
	root := loadPE(ctx)
	// Header-only access must not parse malformed import metadata.
	binary.LittleEndian.PutUint32(data[0x400:], 0xffffffff)
	if root.object.field("is_pe").Integer != 1 {
		t.Fatal("imports invalidated headers")
	}
	if root.object.field("number_of_imports").Type != ModuleUndefined {
		t.Fatal("malformed imports accepted")
	}
	copy(data, pefixture.Imports(false, 3))
	if root.object.field("number_of_imports").Type != ModuleUndefined {
		t.Fatal("failed import parse was retried")
	}

	root = loadPE(ctx)
	if root.object.field("number_of_imported_functions").Integer != 3 {
		t.Fatal("missing imports")
	}
	clear(data)
	ctx.Data = nil
	library := root.object.field("import_details").object.elements[0].object
	if library.field("library_name").String != "Example.DLL" {
		t.Fatal("borrowed DLL name")
	}
	if library.field("functions").object.elements[0].object.field("name").String != "NamedFunction" {
		t.Fatal("borrowed function name")
	}

	// Clearing the scan context must release deferred input too. The PE object
	// must not capture a second reference to the file buffer in pooled scanners.
	data = pefixture.Imports(false, 3)
	ctx = &MatchContext{Data: data, FileSize: int64(len(data))}
	root = loadPE(ctx)
	ctx.Data = nil
	if root.object.field("number_of_imports").Type != ModuleUndefined {
		t.Fatal("PE snapshot retained deferred input")
	}
}

func TestPEImportsReaderLimit(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe"
 rule headers {condition: pe.is_pe and pe.number_of_sections == 2}
 rule imports {condition: pe.number_of_imported_functions == 16384 and pe.imports("Example.DLL", "NamedFunction")}
 rule unavailable {condition: not defined pe.number_of_imports and not defined pe.imports("Example.DLL", "NamedFunction")}`)
	if err != nil {
		t.Fatal(err)
	}
	data := pefixture.Imports(true, 16384)
	s := p.NewScanner()
	defer s.Close()
	r, err := s.Scan(data)
	if err != nil || !r.RuleResults["imports"] {
		t.Fatalf("buffer: %v %v", r, err)
	}
	r, err = s.ScanReader(bytes.NewReader(data))
	if err != nil || !r.RuleResults["headers"] || !r.RuleResults["unavailable"] || r.RuleResults["imports"] {
		t.Fatalf("reader: %v %v", r, err)
	}
	// A cancellable file scan below the mmap threshold follows the reader
	// path too. Preserve that I/O contract in this adapter-only change.
	path := filepath.Join(t.TempDir(), "imports.exe")
	if err := os.WriteFile(path, pefixture.Imports(false, 16384), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, err = s.ScanFileWithContext(ctx, path)
	if err != nil || !r.RuleResults["headers"] || !r.RuleResults["unavailable"] {
		t.Fatalf("cancellable file: %v %v", r, err)
	}
	r, err = s.ScanFile(path)
	if err != nil || !r.RuleResults["imports"] {
		t.Fatalf("complete file: %v %v", r, err)
	}
}

func TestPEImportsTruncation(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe"
 rule headers {condition: pe.is_pe}
 rule imports {condition: pe.imports("Example.DLL", "NamedFunction") and pe.number_of_imports == 1 and pe.number_of_imported_functions == 3 and pe.import_details[0].functions[2].name == "NamedFunction"}
 rule unavailable {condition: pe.is_pe and not defined pe.number_of_imports and not defined pe.number_of_imported_functions and not defined pe.import_details and not defined pe.imports("Example.DLL", "NamedFunction")}`)
	if err != nil {
		t.Fatal(err)
	}
	s := p.NewScanner()
	defer s.Close()
	for _, is64 := range []bool{false, true} {
		data := pefixture.Imports(is64, 3)
		headerEnd := 0x98 + int(binary.LittleEndian.Uint16(data[0x94:])) + 2*40
		nameEnd := int(binary.LittleEndian.Uint32(data[0x440:])) - 0x2000 + 0x400 + 2 + len("NamedFunction") + 1
		// Descending prefixes exercise successful-to-failed cache transitions
		// and every byte boundary in descriptors, thunks, hints, and names.
		for end := len(data); end >= 0; end-- {
			r, err := s.Scan(data[:end])
			if err != nil {
				t.Fatal(err)
			}
			if r.RuleResults["headers"] != (end >= headerEnd) ||
				r.RuleResults["imports"] != (end >= nameEnd) ||
				r.RuleResults["unavailable"] != (end >= headerEnd && end < nameEnd) {
				t.Fatalf("64=%t prefix=%#x: %v", is64, end, r.RuleResults)
			}
		}
	}
}

func TestPEImportsHostData(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe" rule host {condition: pe.number_of_imports == 1 and pe.import_details[0].functions[0].ordinal == 7}`)
	if err != nil {
		t.Fatal(err)
	}
	s := p.NewScanner(WithModuleData("pe", map[string]any{
		"number_of_imports": 1,
		"import_details":    []any{map[string]any{"functions": []any{map[string]any{"ordinal": 7}}}},
	}))
	defer s.Close()
	if ok, err := s.Matches(nil); err != nil || !ok || s.moduleCache.pe != nil {
		t.Fatalf("host: %t %v", ok, err)
	}
}

func TestPELegacyHeaderSchema(t *testing.T) {
	blob, err := os.ReadFile("testdata/serialization/format18-pe-headers.goyara")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		p, err := UnmarshalCompiledProgram(blob)
		if err != nil {
			t.Fatal(err)
		}
		for _, input := range [][]byte{pefixture.New(false), nil} {
			if ok, err := p.Matches(input); err != nil || ok != (input != nil) {
				t.Fatalf("legacy: %t %v", ok, err)
			}
		}
		blob, err = p.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestPEImportsConcurrentScans(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe" rule imports {condition: pe.imports("Example.DLL", "NamedFunction") and pe.number_of_imports == 1 and for any d in pe.import_details : (for any f in d.functions : (f.name == "NamedFunction"))}`)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for _, data := range [][]byte{pefixture.Imports(false, 3), nil, pefixture.Imports(true, 3)} {
				if ok, err := p.Matches(data); err != nil || ok != (data != nil) {
					t.Errorf("concurrent: %t %v", ok, err)
				}
			}
		})
	}
	wg.Wait()
}

func BenchmarkPEImports(b *testing.B) {
	for _, symbols := range []int{16, 256} {
		for _, field := range []string{"counts", "details", "name", "ordinal", "missing"} {
			data := pefixture.Imports(true, symbols)
			condition := fmt.Sprintf("pe.number_of_imported_functions == %d", symbols)
			switch field {
			case "details":
				condition = `for any d in pe.import_details : (for any f in d.functions : (f.name == "NamedFunction"))`
			case "name":
				condition = `pe.imports("example.dll", "namedfunction")`
			case "ordinal":
				pefixture.ImportOrdinal(data, symbols-1, 7)
				condition = `pe.imports("example.dll", 7)`
			case "missing":
				condition = `not pe.imports("example.dll", "absent")`
			}
			for _, rules := range []int{1, 100} {
				var source strings.Builder
				source.WriteString(`import "pe"` + "\n")
				for i := range rules {
					fmt.Fprintf(&source, "rule r%d {condition: %s}\n", i, condition)
				}
				p, err := NewCompiler().CompileSource(source.String())
				if err != nil {
					b.Fatal(err)
				}
				b.Run(fmt.Sprintf("%s/symbols=%d/rules=%d", field, symbols, rules), func(b *testing.B) {
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
