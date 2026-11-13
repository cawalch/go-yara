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

func TestLibraryCompilerOptionsReuseBuiltinRegistry(t *testing.T) {
	for _, tc := range []struct {
		name string
		opt  Option
	}{
		{"warnings", WithWarnings(false)},
		{"ignore-invalid", WithIgnoreInvalidRules(true)},
		{"max-input", WithMaxInputSize(1024)},
		{"max-include", WithMaxIncludeSize(1024)},
		{"max-depth", WithMaxRecursionDepth(10)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if optionMayMutateModules(tc.opt) {
				t.Fatal("library option classified as module-mutating")
			}
			compiler := NewCompiler(tc.opt)
			if !isBuiltinModuleRegistry(compiler.options.Modules) {
				t.Fatal("library option detached the built-in registry")
			}
		})
	}
}

func TestCustomCompilerOptionsReceiveDetachedRegistry(t *testing.T) {
	option := func(*CompilationOptions) {}
	if !optionMayMutateModules(option) {
		t.Fatal("custom option classified as module-safe")
	}
	compiler := NewCompiler(option)
	if isBuiltinModuleRegistry(compiler.options.Modules) {
		t.Fatal("custom option received the shared built-in registry")
	}
}

func TestModuleOptionsCannotMutateBuiltinRegistry(t *testing.T) {
	override := func(options *CompilationOptions) {
		module := options.Modules["math"]
		mean := module.Functions["mean"]
		mean.Evaluate = func(ModuleContext, []ModuleValue) (ModuleValue, error) {
			return FloatValue(42), nil
		}
		module.Functions["mean"] = mean
	}
	const source = `import "math" rule mean { condition: math.mean(0, filesize) == 42.0 }`

	overridden, err := NewCompiler(override).CompileSource(source)
	if err != nil {
		t.Fatal(err)
	}
	if matched, err := overridden.Matches([]byte{1, 2, 3, 4}); err != nil || !matched {
		t.Fatalf("overridden callback scan: %t %v", matched, err)
	}

	// The option mutated only its own detached registry. A compiler created
	// afterwards must still use the real mean callback.
	fresh, err := NewCompiler().CompileSource(source)
	if err != nil {
		t.Fatal(err)
	}
	if matched, err := fresh.Matches([]byte{1, 2, 3, 4}); err != nil || matched {
		t.Fatalf("built-in registry leaked override: %t %v", matched, err)
	}
}

func TestModuleOptionsCannotBypassUnusedValidation(t *testing.T) {
	inject := func(options *CompilationOptions) {
		module := options.Modules["math"]
		module.Functions["broken"] = ModuleFunction{ReturnType: ModuleInteger}
		options.Modules["math"] = module
	}
	if _, err := NewCompiler(inject).CompileSource(`rule unused { condition: true }`); err == nil ||
		!strings.Contains(err.Error(), "invalid module function math.broken") {
		t.Fatalf("invalid function injected through an option was accepted: %v", err)
	}

	// The mutation must not survive into later compilers, including ones that
	// rebuild the full registry for a custom module.
	custom := Module{
		Name: "demo",
		Functions: map[string]ModuleFunction{
			"accept": {
				Signatures: []ModuleSignature{{}},
				ReturnType: ModuleBoolean,
				Evaluate: func(ModuleContext, []ModuleValue) (ModuleValue, error) {
					return BooleanValue(true), nil
				},
			},
		},
	}
	if _, err := NewCompiler(WithModule(custom)).CompileSource(`import "demo" rule accepted { condition: demo.accept() }`); err != nil {
		t.Fatalf("later compiler saw the mutated built-in registry: %v", err)
	}
}

func TestCompiledModuleFunctionMetadataIsPrivate(t *testing.T) {
	const source = `import "math" rule mean { condition: math.mean("AAA") == 65 }`
	mutateMeanSignature := func(t *testing.T, program *CompiledProgram) {
		t.Helper()
		for id, name := range program.Rules[0].ModuleNames {
			if name != "math.mean" {
				continue
			}
			function := program.Rules[0].ModuleFunctions[id]
			if len(function.Signatures) == 0 || len(function.Signatures[0].Arguments) == 0 {
				t.Fatal("math.mean has no serialized signature")
			}
			function.Signatures[0].Arguments[0] = ModuleBoolean
			return
		}
		t.Fatal("math.mean binding not found")
	}

	program, err := NewCompiler().CompileSource(source)
	if err != nil {
		t.Fatal(err)
	}
	blob := mustMarshal(t, program)
	mutateMeanSignature(t, program)
	fresh, err := NewCompiler().CompileSource(source)
	if err != nil {
		t.Fatalf("metadata mutation leaked into compilation: %v", err)
	}
	if matched, err := fresh.Matches(nil); err != nil || !matched {
		t.Fatalf("fresh compiler after metadata mutation: %t %v", matched, err)
	}

	loaded, err := UnmarshalCompiledProgram(blob)
	if err != nil {
		t.Fatal(err)
	}
	mutateMeanSignature(t, loaded)
	reloaded, err := UnmarshalCompiledProgram(blob)
	if err != nil {
		t.Fatalf("metadata mutation leaked into loading: %v", err)
	}
	if matched, err := reloaded.Matches(nil); err != nil || !matched {
		t.Fatalf("reloaded program after metadata mutation: %t %v", matched, err)
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
