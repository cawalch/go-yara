package compiler

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/cawalch/go-yara/internal/pefixture"
)

const (
	peImphashNamed3      = "52ee6f8c06f82c1a4906c4287b38a731"
	peImphashNamedOrd7   = "0f948aa3b9e326a6839786fa30cdafd2"
	peImphashWS2Accept   = "9eabaab1d2b00efbb780e43d7604d6c6"
	peImphashWS2Fallback = "fce110908ca6849f7afa977d1ae99f5f"
	peImphashOleaut      = "3dc76082b322e4bf41120e4657c7f5c6"
	peImphashHostAlias   = "54bce6b0b949e8b5b8eea5946ce457cd"
	peImphashHostDup     = "1e0a6746ffe22e08256b878390464ba9"
	peImphashEmpty       = "d41d8cd98f00b204e9800998ecf8427e"
)

func TestPEImphash(t *testing.T) {
	for _, tc := range []struct {
		name   string
		data   []byte
		source string
		want   string
	}{
		{"named", pefixture.Imports(false, 3), `pe.imphash() == ` + quote(peImphashNamed3), "match"},
		{"named64", pefixture.Imports(true, 3), `pe.imphash() == ` + quote(peImphashNamed3), "match"},
		{"ordinal", func() []byte {
			data := pefixture.Imports(false, 3)
			pefixture.ImportOrdinal(data, 1, 7)
			return data
		}(), `pe.imphash() == ` + quote(peImphashNamedOrd7), "match"},
		{"ws2-alias", func() []byte {
			data := pefixture.Imports(false, 1)
			pefixture.ImportOrdinal(data, 0, 1)
			copy(data[0x428:], "WS2_32.DLL\x00")
			return data
		}(), `pe.imphash() == ` + quote(peImphashWS2Accept), "match"},
		{"ws2-fallback", func() []byte {
			data := pefixture.Imports(false, 1)
			pefixture.ImportOrdinal(data, 0, 501)
			copy(data[0x428:], "ws2_32.dll\x00")
			return data
		}(), `pe.imphash() == ` + quote(peImphashWS2Fallback), "match"},
		{"oleaut-alias", func() []byte {
			data := pefixture.Imports(false, 1)
			pefixture.ImportOrdinal(data, 0, 2)
			copy(data[0x428:], "OLEAUT32.DLL\x00")
			return data
		}(), `pe.imphash() == ` + quote(peImphashOleaut), "match"},
		{"ocx-stripped", func() []byte {
			data := pefixture.Imports(false, 3)
			copy(data[0x428:], "Example.OCX\x00")
			return data
		}(), `pe.imphash() == ` + quote(peImphashNamed3), "match"},
		{"dll-prefix-quirk", func() []byte {
			data := pefixture.Imports(false, 3)
			copy(data[0x428:], "Example.dllx\x00")
			return data
		}(), `pe.imphash() == ` + quote(peImphashNamed3), "match"},
		{"empty-imports", pefixture.New(false), `pe.imphash() == ` + quote(peImphashEmpty), "match"},
		{"non-pe", []byte("ordinary"), `not defined pe.imphash()`, "match"},
		{"bad-imports", func() []byte {
			data := pefixture.Imports(false, 1)
			binary.LittleEndian.PutUint32(data[0x100:], 0xffffffff)
			return data
		}(), `not defined pe.imphash()`, "match"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := `import "pe" rule checks { condition: ` + tc.source + ` }`
			program, err := NewCompiler().CompileSource(source)
			if err != nil {
				t.Fatal(err)
			}
			if matched, err := program.Matches(tc.data); err != nil || !matched {
				t.Fatalf("%s: %t %v", tc.want, matched, err)
			}
		})
	}
}

func TestPEImphashScanPathsAndSerialization(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe"
rule named { condition: pe.imphash() == ` + quote(peImphashNamed3) + ` }
rule absent { condition: not defined pe.imphash() }`)
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
		data := pefixture.Imports(false, 3)
		for _, reader := range []bool{false, true} {
			s := program.NewScanner(WithFastScan())
			var result *ScanResult
			if reader {
				result, err = s.ScanReader(bytes.NewReader(data))
			} else {
				result, err = s.Scan(data)
			}
			s.Close()
			if err != nil || !result.RuleResults["named"] || result.RuleResults["absent"] {
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

func TestPEImphashHostData(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe"
rule alias { condition: pe.imphash() == ` + quote(peImphashHostAlias) + ` }
rule duplicate { condition: pe.imphash() == ` + quote(peImphashHostDup) + ` }
rule empty { condition: pe.imphash() == ` + quote(peImphashEmpty) + ` }
rule absent { condition: not defined pe.imphash() }`)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		data map[string]any
		want string
	}{
		{"alias", map[string]any{"import_details": []any{
			map[string]any{"library_name": "Example.DLL", "functions": []any{
				map[string]any{"name": "NamedFunction"},
				map[string]any{"ordinal": 7},
			}},
			map[string]any{"library_name": "WS2_32.DLL", "functions": []any{
				map[string]any{"ordinal": 1},
			}},
		}}, "alias"},
		{"duplicate", map[string]any{"import_details": []any{
			map[string]any{"library_name": "Example.DLL", "functions": []any{
				map[string]any{"name": "NamedFunction"},
			}},
			map[string]any{"library_name": "Example.DLL", "functions": []any{
				map[string]any{"name": "NamedFunction"},
			}},
		}}, "duplicate"},
		{"empty", map[string]any{"import_details": []any{}}, "empty"},
		{"missing", map[string]any{"number_of_imports": 1}, "absent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := p.NewScanner(WithModuleData("pe", tc.data))
			defer s.Close()
			result, err := s.Scan([]byte("ordinary"))
			if err != nil || len(result.MatchedRules) != 1 || !result.RuleResults[tc.want] {
				t.Fatalf("want %s: %v %v", tc.want, result, err)
			}
		})
	}
}

func TestPEImphashCustomModule(t *testing.T) {
	module := NewCompiler().GetOptions().Modules["pe"]
	function := module.Functions["imphash"]
	function.Evaluate = func(ModuleContext, []ModuleValue) (ModuleValue, error) {
		return StringValue("custom"), nil
	}
	module.Functions["imphash"] = function
	p, err := NewCompiler(WithModule(module)).CompileSource(`import "pe" rule custom { condition: pe.imphash() == "custom" }`)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if matched, err := p.Matches(pefixture.Imports(false, 3)); err != nil || !matched {
			t.Fatalf("custom callback: %t %v", matched, err)
		}
		p, err = UnmarshalCompiledProgram(blob, module)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func quote(value string) string {
	return `"` + value + `"`
}

func TestPEImphashNonPEAllocations(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe" rule query { condition: defined pe.imphash() }`)
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
		t.Fatalf("non-PE imphash allocates %g times", n)
	}
}

func BenchmarkPEImphash(b *testing.B) {
	program, err := NewCompiler().CompileSource(`import "pe" rule imphash { condition: pe.imphash() != "" }`)
	if err != nil {
		b.Fatal(err)
	}
	data := pefixture.Imports(false, 3)
	b.ReportAllocs()
	for b.Loop() {
		if matched, err := program.Matches(data); err != nil || !matched {
			b.Fatalf("%t %v", matched, err)
		}
	}
}
