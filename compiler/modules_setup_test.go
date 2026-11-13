package compiler

import (
	"strings"
	"testing"
)

func TestModuleRegistryRetainsOnlyUsedFunctions(t *testing.T) {
	t.Run("text only", func(t *testing.T) {
		program, err := NewCompiler().CompileSource(`rule text { strings: $a = "needle" condition: $a }`)
		if err != nil {
			t.Fatal(err)
		}
		if len(program.Rules) != 1 {
			t.Fatalf("got %d rules, want 1", len(program.Rules))
		}
		if len(program.Rules[0].ModuleFunctions) != 0 || len(program.Rules[0].ModuleNames) != 0 {
			t.Fatalf("text rule retained module metadata: functions=%d names=%d",
				len(program.Rules[0].ModuleFunctions), len(program.Rules[0].ModuleNames))
		}
		payload, err := serializeProgram(program)
		if err != nil {
			t.Fatal(err)
		}
		if len(payload.Rules[0].ModuleNames) != 0 || len(payload.Rules[0].ModuleSignatures) != 0 {
			t.Fatalf("text artifact retained module metadata: names=%d signatures=%d",
				len(payload.Rules[0].ModuleNames), len(payload.Rules[0].ModuleSignatures))
		}
	})

	t.Run("imported but unused", func(t *testing.T) {
		program, err := NewCompiler().CompileSource(`import "pe" rule text { condition: true }`)
		if err != nil {
			t.Fatal(err)
		}
		if len(program.Rules[0].ModuleFunctions) != 0 || len(program.Rules[0].ModuleNames) != 0 {
			t.Fatalf("unused import retained module metadata: functions=%d names=%d",
				len(program.Rules[0].ModuleFunctions), len(program.Rules[0].ModuleNames))
		}
	})

	t.Run("one used function", func(t *testing.T) {
		program, err := NewCompiler().CompileSource(`import "math" rule text { condition: math.mean(0, filesize) > 0 }`)
		if err != nil {
			t.Fatal(err)
		}
		rule := program.Rules[0]
		if len(rule.ModuleFunctions) != 1 || len(rule.ModuleNames) != 1 {
			t.Fatalf("used rule metadata: functions=%d names=%d, want 1/1",
				len(rule.ModuleFunctions), len(rule.ModuleNames))
		}
		for _, name := range rule.ModuleNames {
			if name != "math.mean" {
				t.Fatalf("retained unused function %q", name)
			}
		}
	})
}

func TestModuleRegistryUsesPerRuleBindings(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
import "math"
rule used { condition: math.mean(0, filesize) > 0 }
rule unused { condition: true }
`)
	if err != nil {
		t.Fatal(err)
	}
	if len(program.Rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(program.Rules))
	}
	if len(program.Rules[0].ModuleFunctions) != 1 || len(program.Rules[0].ModuleNames) != 1 {
		t.Fatalf("used rule metadata: functions=%d names=%d, want 1/1",
			len(program.Rules[0].ModuleFunctions), len(program.Rules[0].ModuleNames))
	}
	if len(program.Rules[1].ModuleFunctions) != 0 || len(program.Rules[1].ModuleNames) != 0 {
		t.Fatalf("unused rule retained metadata: functions=%d names=%d",
			len(program.Rules[1].ModuleFunctions), len(program.Rules[1].ModuleNames))
	}
	loaded, err := UnmarshalCompiledProgram(mustMarshal(t, program))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(loaded.Rules[0].ModuleNames); got != 1 {
		t.Fatalf("loaded used rule has %d module names, want 1", got)
	}
	if got := len(loaded.Rules[1].ModuleNames); got != 0 {
		t.Fatalf("loaded unused rule has %d module names, want 0", got)
	}
	if matched, err := loaded.Matches([]byte("four")); err != nil || !matched {
		t.Fatalf("loaded rule scan: %t %v", matched, err)
	}
}

func TestModuleRegistryValidatesUnusedCustomFunctions(t *testing.T) {
	invalid := Module{
		Name: "demo",
		Functions: map[string]ModuleFunction{
			"broken": {ReturnType: ModuleInteger},
		},
	}
	_, err := NewCompiler(WithModule(invalid)).CompileSource(`rule unused { condition: true }`)
	if err == nil || !strings.Contains(err.Error(), "invalid module function demo.broken") {
		t.Fatalf("unused invalid custom registration error = %v", err)
	}

	invalidSchema := Module{
		Name:   "demo",
		Schema: &ModuleSchema{Fields: map[string]ModuleField{"bad": {Kind: ModuleStruct}}},
	}
	_, err = NewCompiler(WithModule(invalidSchema)).CompileSource(`rule unused { condition: true }`)
	if err == nil || !strings.Contains(err.Error(), "module demo") {
		t.Fatalf("unused invalid custom schema error = %v", err)
	}
}

func TestModuleRegistryCustomRebindingUsesOnlyReferencedFunctions(t *testing.T) {
	accept := ModuleFunction{
		Signatures: []ModuleSignature{{Arguments: []ModuleValueType{ModuleInteger}}},
		ReturnType: ModuleBoolean,
		Evaluate: func(_ ModuleContext, args []ModuleValue) (ModuleValue, error) {
			return BooleanValue(args[0].Integer == 7), nil
		},
	}
	unused := ModuleFunction{
		Signatures: []ModuleSignature{{}},
		ReturnType: ModuleInteger,
		Evaluate: func(ModuleContext, []ModuleValue) (ModuleValue, error) {
			return IntegerValue(1), nil
		},
	}
	compiledModule := Module{Name: "demo", Functions: map[string]ModuleFunction{"accept": accept, "unused": unused}}
	program, err := NewCompiler(WithModule(compiledModule)).CompileSource(`
import "demo"
rule custom { condition: demo.accept(7) }
`)
	if err != nil {
		t.Fatal(err)
	}
	blob := mustMarshal(t, program)

	// Removing a function that the artifact never referenced must not prevent
	// name rebinding, even though it changes the sorted function table.
	rebound := Module{Name: "demo", Functions: map[string]ModuleFunction{"accept": accept}}
	loaded, err := UnmarshalCompiledProgram(blob, rebound)
	if err != nil {
		t.Fatalf("rebinding without unused function: %v", err)
	}
	if matched, err := loaded.Matches(nil); err != nil || !matched {
		t.Fatalf("rebound callback scan: %t %v", matched, err)
	}

	// The referenced function is still required.
	missing := Module{Name: "demo", Functions: map[string]ModuleFunction{"unused": unused}}
	if _, err := UnmarshalCompiledProgram(blob, missing); err == nil || !strings.Contains(err.Error(), "demo.accept") {
		t.Fatalf("missing referenced callback error = %v", err)
	}
}
