package compiler

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/cawalch/go-yara/internal/pefixture"
)

func TestPEImportQueriesCache(t *testing.T) {
	query := `rule query {condition: pe.imports("example.dll", "namedfunction") and pe.imports("EXAMPLE.DLL", 7)}`
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
rule host {condition: pe.imports("HOST.dll", "hostfn") and pe.imports("host.dll", 0) and not pe.imports("host.dll", "") and pe.imports("HOST.dll\x00suffix") == 2 and pe.imports("missing.dll") == 0}
rule file {condition: pe.imports("example.dll", "NamedFunction") or pe.imports("example.dll")}
rule absent {condition: not defined pe.imports("host.dll", "hostfn") and not defined pe.imports("host.dll")}`)
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
	p, err := NewCompiler().CompileSource(`import "pe" rule query {condition: pe.imports("Example.DLL", "NamedFunction") or pe.imports("Example.DLL", 7) or pe.imports("Example.DLL")}`)
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

func TestPEImportQueriesCallbackOverride(t *testing.T) {
	module := NewCompiler().GetOptions().Modules["pe"]
	function := module.Functions["imports"]
	function.Evaluate = func(ModuleContext, []ModuleValue) (ModuleValue, error) { return IntegerValue(42), nil }
	module.Functions["imports"] = function
	p, err := NewCompiler(WithModule(module)).CompileSource(`import "pe" rule custom {condition: pe.imports("anything", 7) == 42 and pe.imports("anything") == 42}`)
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

func TestPEImportQueryRegistration(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Module)
	}{
		{"module_name", func(m *Module) { m.Name = "other" }},
		{"function_name", func(m *Module) {
			m.Functions["other"] = m.Functions["imports"]
			delete(m.Functions, "imports")
		}},
		{"schema", func(m *Module) { m.Schema = nil }},
		{"result", func(m *Module) {
			f := m.Functions["imports"]
			f.ReturnType = ModuleBoolean
			m.Functions["imports"] = f
		}},
		{"arguments", func(m *Module) {
			m.Functions["imports"].Signatures[0].Arguments[0] = ModuleInteger
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			module := NewCompiler().GetOptions().Modules["pe"]
			tc.change(&module)
			if _, err := NewCompiler(WithModule(module)).CompileSource(`rule unused {condition: true}`); err == nil {
				t.Fatal("modified built-in without a callback was accepted")
			}
		})
	}
}

func TestPEImportQueryCustomSchema(t *testing.T) {
	module := NewCompiler().GetOptions().Modules["pe"]
	module.Schema = &ModuleSchema{Fields: map[string]ModuleField{"label": {Kind: ModuleString}}}
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
