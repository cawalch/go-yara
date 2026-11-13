package compiler

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/internal/pefixture"
)

func TestPEExportQueriesCache(t *testing.T) {
	query := `rule query {condition: pe.exports("function00000") and pe.exports(1) and not pe.exports(0) and not pe.exports(4)}`
	count := `rule count {condition: pe.number_of_exports == 3 and pe.export_timestamp == 0 and pe.imports("Example.DLL") == 3}`
	index := `rule index {condition: pe.exports_index("FUNCTION00000") == 0 and pe.exports_index(1) == 0 and pe.exports_index("Function00002") == 2 and pe.exports_index(3) == 2 and not defined pe.exports_index(0) and not defined pe.exports_index(4) and not defined pe.exports_index("missing")}`
	for _, source := range []string{query + count + index, count + index + query, index + query + count} {
		p, err := NewCompiler().CompileSource(`import "pe" ` + source)
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			s := p.NewScanner()
			for _, is64 := range []bool{false, true} {
				data := pefixture.Exports(is64, 3)
				binary.LittleEndian.PutUint32(data[0x810:], 1)
				r, err := s.Scan(data)
				if err != nil || len(r.MatchedRules) != 3 {
					t.Fatalf("initial: %v %v", r, err)
				}
				image := s.moduleCache.pe
				if image.exports.details.Type != ModuleUndefined {
					t.Fatal("queries constructed detail objects")
				}
				for _, base := range []int64{0, 4096} {
					b := p.NewBlockScanner()
					if err := b.Scan(base, data); err != nil {
						t.Fatal(err)
					}
					r, err := b.Finish()
					b.Close()
					want := 0
					if base == 0 {
						want = 3
					}
					if err != nil || len(r.MatchedRules) != want {
						t.Fatalf("block base=%d: %v %v", base, r, err)
					}
				}
				// Queries and fields must keep the snapshot after input changes.
				clear(data)
				for _, rule := range p.Rules {
					if !s.isRuleConditionSatisfied(rule) || s.moduleCache.pe != image {
						t.Fatal("query and counts did not share the snapshot")
					}
				}
				if image.exportField("export_details").object.elements[0].object.field("name").String != "Function00000" {
					t.Fatal("details did not reuse the query snapshot")
				}
				for _, input := range [][]byte{data, nil, pefixture.New(is64)} {
					if ok, err := s.Matches(input); err != nil || ok {
						t.Fatalf("stale exports: %t %v", ok, err)
					}
				}
			}
			s.Close()
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
}

func TestPEExportQueriesHostData(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe"
rule host {condition: pe.exports("HOSTfn") and pe.exports("HostFn\x00suffix") and pe.exports(2) and not pe.exports(0) and not pe.exports(99) and not pe.exports("HostFn\x00other") and not pe.exports("") and pe.exports_index("HOSTfn") == 1 and pe.exports_index(2) == 1 and pe.exports_index("HostFn\x00suffix") == 2 and not defined pe.exports_index(0) and not defined pe.exports_index(99) and not defined pe.exports_index("missing")}
rule file {condition: pe.exports("Function00000")}
rule empty {condition: pe.exports("HostFn") == 0 and pe.exports(2) == 0 and not defined pe.exports_index("HostFn") and not defined pe.exports_index(2)}
rule absent {condition: not defined pe.exports("HostFn") and not defined pe.exports(2) and not defined pe.exports_index("HostFn") and not defined pe.exports_index(2)}`)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		for _, tc := range []struct {
			data any
			want string
		}{
			{map[string]any{"number_of_exports": 99, "export_details": []any{nil,
				map[string]any{"name": "HostFn", "ordinal": 2},
				map[string]any{"name": "HostFn\x00suffix", "ordinal": 99},
				map[string]any{"name": "HOSTFN", "ordinal": 2},
			}}, "host"},
			{nil, "absent"},
			{map[string]any{}, "absent"},
			{map[string]any{"export_details": []any{}}, "empty"},
			{map[string]any{"export_details": []any{nil, map[string]any{}}}, "empty"},
		} {
			s := p.NewScanner(WithModuleData("pe", tc.data))
			r, err := s.Scan(pefixture.Exports(false, 3))
			if err != nil || s.moduleCache.pe != nil {
				t.Fatalf("host data parsed file: %v %v", r, err)
			}
			s.Close()
			if len(r.MatchedRules) != 1 || !r.RuleResults[tc.want] {
				t.Fatalf("want %q: %v", tc.want, r.RuleResults)
			}
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

func TestPEFunctionCustomModule(t *testing.T) {
	for _, tc := range []struct{ name, condition string }{
		{"exports", `pe.exports("anything") == 42 and pe.exports(1) == 42`},
		{"exports_index", `pe.exports_index("anything") == 42 and pe.exports_index(1) == 42`},
		{"is_dll", `pe.is_dll() == 42`},
		{"is_32bit", `pe.is_32bit() == 42`},
		{"is_64bit", `pe.is_64bit() == 42`},
	} {
		query := tc.name
		for _, customSchema := range []bool{false, true} {
			module := NewCompiler().GetOptions().Modules["pe"]
			if customSchema {
				module.Schema = &ModuleSchema{Fields: map[string]ModuleField{"label": {Kind: ModuleString}}}
				module.Functions = map[string]ModuleFunction{query: module.Functions[query]}
			}
			function := module.Functions[query]
			function.Evaluate = func(ModuleContext, []ModuleValue) (ModuleValue, error) { return IntegerValue(42), nil }
			module.Functions[query] = function
			p, err := NewCompiler(WithModule(module)).CompileSource(`import "pe" rule custom {condition: ` + tc.condition + `}`)
			if err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if ok, err := p.Matches(nil); err != nil || !ok {
					t.Fatalf("callback override: %t %v", ok, err)
				}
				blob, err := p.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				if customSchema {
					unbound, err := UnmarshalCompiledProgram(blob)
					if err != nil {
						t.Fatal(err)
					}
					s := unbound.NewScanner()
					ok, err := s.Matches(pefixture.Exports(false, 3))
					if err != nil || ok || s.moduleCache.pe != nil {
						t.Fatalf("custom schema fell back to native parsing: %t %v", ok, err)
					}
					s.Close()
				}
				p, err = UnmarshalCompiledProgram(blob, module)
				if err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

func TestPELegacyExportSchema(t *testing.T) {
	// Preserve bindings across each addition to the sorted function table.
	for _, fixture := range []string{"format18-pe-export-details.goyara", "format18-pe-export-queries.goyara", "format18-pe-export-index.goyara", "format18-pe-export-timestamp.goyara", "format18-pe-dll-name.goyara", "format18-pe-is-dll.goyara"} {
		blob, err := os.ReadFile("testdata/serialization/" + fixture)
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			p, err := UnmarshalCompiledProgram(blob)
			if err != nil {
				t.Fatal(err)
			}
			if ok, err := p.Matches(pefixture.Exports(false, 3)); err != nil || !ok {
				t.Fatalf("historical function IDs: %t %v", ok, err)
			}
			blob, err = p.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestPEExportQueriesNonPEAllocations(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe" rule query {condition: pe.exports("Function00000") or pe.exports(1) or defined pe.exports_index("Function00000") or defined pe.exports_index(1) or defined pe.export_timestamp or defined pe.dll_name or defined pe.is_dll() or defined pe.is_32bit() or defined pe.is_64bit()}`)
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
		t.Fatalf("non-PE queries allocate %g times", n)
	}
}

func BenchmarkPEExportQueries(b *testing.B) {
	for _, symbols := range []int{16, 256} {
		for _, query := range []struct{ name, condition string }{
			{"name_hit", `pe.exports("function00000")`},
			{"ordinal_hit", `pe.exports(7)`},
			{"name_miss", `not pe.exports("missing")`},
			{"ordinal_miss", `not pe.exports(1)`},
			{"name_index_hit", `pe.exports_index("function00000") == 0`},
			{"ordinal_index_hit", `pe.exports_index(7) == 0`},
			{"name_index_miss", `not defined pe.exports_index("missing")`},
			{"ordinal_index_miss", `not defined pe.exports_index(1)`},
		} {
			for _, rules := range []int{1, 100} {
				var source strings.Builder
				source.WriteString("import \"pe\"\n")
				for i := range rules {
					fmt.Fprintf(&source, "rule r%d {condition: %s}\n", i, query.condition)
				}
				p, err := NewCompiler().CompileSource(source.String())
				if err != nil {
					b.Fatal(err)
				}
				data := pefixture.Exports(true, symbols)
				b.Run(fmt.Sprintf("symbols=%d/%s/rules=%d", symbols, query.name, rules), func(b *testing.B) {
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
