package compiler

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/internal/pefixture"
)

func TestPEImportQueriesCache(t *testing.T) {
	query := `rule query {condition: pe.imports("example.dll", "namedfunction") and pe.imports(/example\.dll/i, /^NamedFunction$/) == 2 and pe.imports("EXAMPLE.DLL", 7)}`
	count := `rule count {condition: pe.imports("example.dll") == 3}`
	field := `rule field {condition: pe.number_of_imported_functions == 3}`
	for _, source := range []string{query + count + field, count + field + query, field + query + count} {
		p, err := NewCompiler().CompileSource(`import "pe" ` + source)
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
			s := program.NewScanner()
			defer s.Close()
			for _, is64 := range []bool{false, true} {
				data := pefixture.Imports(is64, 3)
				pefixture.ImportOrdinal(data, 1, 7)
				r, err := s.Scan(data)
				if err != nil || len(r.MatchedRules) != 3 {
					t.Fatalf("initial: %v %v", r, err)
				}
				image := s.moduleCache.pe
				if image.imports.details.Type != ModuleUndefined {
					t.Fatal("queries constructed detail objects")
				}
				for _, base := range []int64{0, 4096} {
					b := program.NewBlockScanner()
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
				// All rule orders must share the same parse, even after the
				// original bytes no longer describe a valid lookup table.
				binary.LittleEndian.PutUint32(data[0x400:], 0xffffffff)
				for _, rule := range program.Rules {
					if !s.isRuleConditionSatisfied(rule) || s.moduleCache.pe != image {
						t.Fatal("query and fields did not share the snapshot")
					}
				}
				for _, input := range [][]byte{data, nil, pefixture.New(is64)} {
					if ok, err := s.Matches(input); err != nil || ok {
						t.Fatalf("stale imports: %t %v", ok, err)
					}
				}
			}
		}
	}
}

func TestPEImportQueriesHostData(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe"
rule host {condition: pe.imports("HOST.dll", "hostfn") and pe.imports(/^HOST\.dll$/i, /^HostFn$/) == 1 and pe.imports(/^host\.dll$/i, /^ord0$/) == 1 and pe.imports(/HOST\.dll/i, /hostfn|ord0/i) >= 2 and pe.imports("host.dll", 0) and pe.imports("host.dll", "ORD0") and not pe.imports("host.dll", "") and not pe.imports(/host\.dll/i, /^$/) and pe.imports("HOST.dll\x00suffix") == 2 and pe.imports("missing.dll") == 0 and pe.imports(/missing\.dll/, /.*/) == 0}
rule ws2 {condition: pe.imports("WS2_32.DLL", "accept") and pe.imports(/^ws2_32\.dll$/i, /^accept$/) == 1 and pe.imports(/^ws2_32\.dll$/i, /ord1/) == 0 and not pe.imports("ws2_32.dll", "ord1") and pe.imports("ws2_32.dll", 1)}
rule file {condition: pe.imports("example.dll", "NamedFunction") or pe.imports(/example/i, /Named/) or pe.imports("example.dll")}
rule absent {condition: not defined pe.imports("host.dll", "hostfn") and not defined pe.imports(/host/i, /hostfn/i) and not defined pe.imports("host.dll")}`)
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
	for _, tc := range []struct {
		data any
		want string
	}{
		{map[string]any{"import_details": []any{nil, map[string]any{
			"library_name": "Host.DLL", "functions": []any{nil, map[string]any{"name": "HostFn"}, map[string]any{"ordinal": 0}},
		}}}, "host"},
		{map[string]any{"import_details": []any{map[string]any{
			"library_name": "Host.DLL\x00suffix", "functions": []any{map[string]any{"name": "HostFn\x00suffix"}, map[string]any{"ordinal": 0}},
		}}}, "host"},
		{map[string]any{"import_details": []any{
			map[string]any{"library_name": "Host.DLL", "number_of_functions": 99, "functions": []any{map[string]any{"name": "HostFn"}}},
			map[string]any{"library_name": "host.dll", "functions": []any{map[string]any{"ordinal": 0}}},
			map[string]any{"library_name": "host.dll"},
			map[string]any{"functions": []any{map[string]any{"name": "ignored"}}},
		}}, "host"},
		{map[string]any{"import_details": []any{
			map[string]any{"library_name": "ws2_32.dll", "functions": []any{map[string]any{"ordinal": 1}}},
		}}, "ws2"},
		{map[string]any{"import_details": []any{
			map[string]any{"library_name": "ws2_32.dll", "functions": []any{map[string]any{"ordinal": 1, "name": "accept"}}},
		}}, "ws2"},
		{nil, "absent"},
		{map[string]any{}, "absent"},
		{map[string]any{"import_details": []any{}}, ""},
	} {
		s := p.NewScanner(WithModuleData("pe", tc.data))
		defer s.Close()
		r, err := s.Scan(pefixture.Imports(false, 3))
		if err != nil || s.moduleCache.pe != nil {
			t.Fatalf("host data parsed file: %v %v", r, err)
		}
		wantCount := 0
		if tc.want != "" {
			wantCount = 1
		}
		if len(r.MatchedRules) != wantCount || tc.want != "" && !r.RuleResults[tc.want] {
			t.Fatalf("want %q: %v", tc.want, r.RuleResults)
		}
	}
}

func TestPEImportQueriesNonPEAllocations(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe" rule query {condition: pe.imports("Example.DLL", "NamedFunction") or pe.imports(/Example\.DLL/, /NamedFunction/) or pe.imports("Example.DLL", 7) or pe.imports("Example.DLL")}`)
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

func TestPEOrdinalQueryNoDetailMaterialization(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe"
rule alias { condition: pe.imports("ws2_32.dll", "accept") and not pe.imports("ws2_32.dll", "ord1") }
rule fallback { condition: pe.imports("ws2_32.dll", "ord501") }
rule alias_regex { condition: pe.imports(/^ws2_32\.dll$/i, /^accept$/) == 1 and pe.imports(/ws2_32/i, /ord1/) == 0 }
rule fallback_regex { condition: pe.imports(/ws2_32/i, /^ord501$/) == 1 }`)
	if err != nil {
		t.Fatal(err)
	}
	data := pefixture.Imports(false, 2)
	copy(data[0x428:], "ws2_32.dll\x00")
	pefixture.ImportOrdinal(data, 0, 1)
	pefixture.ImportOrdinal(data, 1, 501)
	s := p.NewScanner(WithoutMatches(), WithoutRuleResults())
	defer s.Close()
	r, err := s.Scan(data)
	if err != nil || len(r.MatchedRules) != 4 {
		t.Fatalf("ordinal queries: %v %v", r, err)
	}
	if s.moduleCache.pe.imports.details.Type != ModuleUndefined {
		t.Fatal("ordinal queries constructed import_details")
	}
	image := s.moduleCache.pe
	aliasRule := p.Rules[0]
	fallbackRule := p.Rules[1]
	if n := testing.AllocsPerRun(100, func() {
		if !s.isRuleConditionSatisfied(aliasRule) || !s.isRuleConditionSatisfied(fallbackRule) || s.moduleCache.pe != image {
			t.Fatal("cached ordinal query failed")
		}
	}); n != 0 {
		t.Fatalf("cached ordinal query allocated %g times", n)
	}
}

func TestPEImportQueriesCallbackOverride(t *testing.T) {
	module := NewCompiler().GetOptions().Modules["pe"]
	function := module.Functions["imports"]
	function.Evaluate = func(ModuleContext, []ModuleValue) (ModuleValue, error) { return IntegerValue(42), nil }
	module.Functions["imports"] = function
	p, err := NewCompiler(WithModule(module)).CompileSource(`import "pe" rule custom {condition: pe.imports("anything", 7) == 42 and pe.imports("anything") == 42 and pe.imports(/anything/, /anything/) == 42}`)
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
		p, err = UnmarshalCompiledProgram(blob, module)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestPENativeFunctionRegistration(t *testing.T) {
	for query := range peNativeFunctions {
		for _, tc := range []struct {
			name   string
			change func(*Module)
		}{
			{"module_name", func(m *Module) { m.Name = "other" }},
			{"function_name", func(m *Module) {
				m.Functions["other"] = m.Functions[query]
				delete(m.Functions, query)
			}},
			{"schema", func(m *Module) { m.Schema = nil }},
			{"result", func(m *Module) {
				f := m.Functions[query]
				f.ReturnType = ModuleBoolean
				m.Functions[query] = f
			}},
			{"arguments", func(m *Module) {
				m.Functions[query].Signatures[0].Arguments = []ModuleValueType{ModuleBoolean}
			}},
		} {
			t.Run(query+"/"+tc.name, func(t *testing.T) {
				module := NewCompiler().GetOptions().Modules["pe"]
				tc.change(&module)
				if _, err := NewCompiler(WithModule(module)).CompileSource(`rule unused {condition: true}`); err == nil {
					t.Fatal("modified built-in without a callback was accepted")
				}
			})
		}
	}
}

func TestPEImportQueryCustomSchema(t *testing.T) {
	module := NewCompiler().GetOptions().Modules["pe"]
	module.Schema = &ModuleSchema{Fields: map[string]ModuleField{"label": {Kind: ModuleString}}}
	module.Functions = map[string]ModuleFunction{"imports": module.Functions["imports"]}
	f := module.Functions["imports"]
	f.Evaluate = func(ModuleContext, []ModuleValue) (ModuleValue, error) { return IntegerValue(1), nil }
	module.Functions["imports"] = f
	p, err := NewCompiler(WithModule(module)).CompileSource(`import "pe"
rule query {condition: defined pe.imports("example.dll", "NamedFunction")}
rule count {condition: defined pe.imports("example.dll")}`)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	for _, modules := range [][]Module{nil, {module}} {
		p, err := UnmarshalCompiledProgram(blob, modules...)
		if err != nil {
			t.Fatal(err)
		}
		s := p.NewScanner()
		defer s.Close()
		r, err := s.Scan(pefixture.Imports(false, 3))
		if err != nil || r.RuleResults["query"] != (len(modules) != 0) ||
			r.RuleResults["count"] != (len(modules) != 0) || s.moduleCache.pe != nil {
			t.Fatalf("custom schema fell back to native parsing: %v %v", r, err)
		}
	}
}

func TestPELegacyImportSchema(t *testing.T) {
	for _, name := range []string{"format18-pe-import-details.goyara", "format18-pe-import-queries.goyara"} {
		t.Run(name, func(t *testing.T) {
			blob, err := os.ReadFile("testdata/serialization/" + name)
			if err != nil {
				t.Fatal(err)
			}
			data := pefixture.Imports(false, 3)
			pefixture.ImportOrdinal(data, 1, 7)
			for range 2 {
				p, err := UnmarshalCompiledProgram(blob)
				if err != nil {
					t.Fatal(err)
				}
				if ok, err := p.Matches(data); err != nil || !ok {
					t.Fatalf("historical function IDs: %t %v", ok, err)
				}
				blob, err = p.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestPEImportRegexQueriesCancel(t *testing.T) {
	largeImports := pefixture.Imports(true, 16384)
	p, err := NewCompiler().CompileSource(`import "pe" rule i { condition: pe.imports(/^Example\.DLL$/, /^NamedFunction$/) == 16384 }`)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	close(done)
	interp := NewInterpreter(p.Rules[0].Bytecode)
	defer interp.Release()
	interp.setCurrentCompiledRule(p.Rules[0])
	interp.SetMatchContext(&MatchContext{Data: largeImports, FileSize: int64(len(largeImports)), cancelDone: done})
	if err := interp.Execute(); !errors.Is(err, context.Canceled) {
		t.Fatalf("interpreter PE import regex with closed cancelDone = %v, want context.Canceled", err)
	}

	s := p.NewScanner()
	defer s.Close()
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.MatchesWithContext(canceledCtx, largeImports); !errors.Is(err, context.Canceled) {
		t.Fatalf("MatchesWithContext canceled = %v, want context.Canceled", err)
	}
	if ok, err := s.Matches(largeImports); err != nil || !ok {
		t.Fatalf("scanner reuse after cancel = (%t, %v), want (true, nil)", ok, err)
	}
}

func BenchmarkPEImportQueries(b *testing.B) {
	for _, symbols := range []int{16, 256} {
		for _, query := range []struct{ name, condition string }{
			{"dll_count", `pe.imports("example.dll") == ` + strconv.Itoa(symbols)},
			{"fn_hit", `pe.imports("example.dll", "namedfunction")`},
			{"fn_miss", `not pe.imports("example.dll", "missing")`},
			{"ordinal_hit", `pe.imports("example.dll", 7)`},
			{"ordinal_miss", `not pe.imports("example.dll", 99)`},
			{"regex_hit", `pe.imports(/^Example\.DLL$/, /^NamedFunction$/) == ` + strconv.Itoa(symbols-1)},
			{"regex_miss", `pe.imports(/^Example\.DLL$/, /^missing$/) == 0`},
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
				data := pefixture.Imports(true, symbols)
				pefixture.ImportOrdinal(data, symbols-1, 7)
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
