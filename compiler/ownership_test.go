package compiler

import (
	"context"
	"testing"
)

func TestCompilerAccessorsReturnOwnedSnapshots(t *testing.T) {
	t.Run("diagnostics", func(t *testing.T) {
		compiler := NewCompiler()
		compiler.stats = CompilationStats{
			Errors:       []CompilationError{{Message: "original error"}},
			Warnings:     []CompilationWarning{{Message: "original warning"}},
			IgnoredRules: []IgnoredRule{{Rule: "original rule"}},
		}

		stats := compiler.GetStats()
		stats.Errors[0].Message = "changed through stats"
		stats.Warnings[0].Message = "changed through stats"
		stats.IgnoredRules[0].Rule = "changed through stats"
		if got := compiler.GetStats(); got.Errors[0].Message != "original error" ||
			got.Warnings[0].Message != "original warning" ||
			got.IgnoredRules[0].Rule != "original rule" {
			t.Fatalf("GetStats() exposed compiler diagnostics: %+v", got)
		}

		errors := compiler.GetErrors()
		errors[0].Message = "changed through errors"
		warnings := compiler.GetWarnings()
		warnings[0].Message = "changed through warnings"
		if compiler.GetErrors()[0].Message != "original error" {
			t.Fatal("GetErrors() exposed compiler state")
		}
		if compiler.GetWarnings()[0].Message != "original warning" {
			t.Fatal("GetWarnings() exposed compiler state")
		}
	})

	t.Run("options", func(t *testing.T) {
		module := Module{
			Name: "custom",
			Functions: map[string]ModuleFunction{
				"accept": {
					Signatures: []ModuleSignature{{Arguments: []ModuleValueType{ModuleInteger}}},
					ReturnType: ModuleBoolean,
					Evaluate: func(ModuleContext, []ModuleValue) (ModuleValue, error) {
						return BooleanValue(true), nil
					},
				},
			},
		}
		legacyOptions := CompilationOptions{Modules: map[string]Module{"custom": module}}
		legacyCompiler := NewCompilerWithOptions(legacyOptions)
		delete(legacyOptions.Modules, "custom")
		if _, ok := legacyCompiler.GetOptions().Modules["custom"]; !ok {
			t.Fatal("NewCompilerWithOptions() retained caller module map")
		}

		compiler := NewCompiler(WithModule(module))
		delete(module.Functions, "accept")

		options := compiler.GetOptions()
		custom, ok := options.Modules["custom"]
		if !ok {
			t.Fatal("compiler lost custom module after caller mutation")
		}
		function, ok := custom.Functions["accept"]
		if !ok {
			t.Fatal("compiler lost custom function after caller mutation")
		}
		function.Signatures[0].Arguments[0] = ModuleString
		custom.Functions["accept"] = function
		options.Modules["custom"] = custom
		delete(options.Modules, "hash")

		fresh := compiler.GetOptions()
		if _, ok := fresh.Modules["hash"]; !ok {
			t.Fatal("GetOptions() exposed the module registry")
		}
		freshFunction := fresh.Modules["custom"].Functions["accept"]
		if got := freshFunction.Signatures[0].Arguments[0]; got != ModuleInteger {
			t.Fatalf("GetOptions() exposed module signatures: got %v", got)
		}
	})
}

func TestCompilationComponentAccessorsReturnOwnedSnapshots(t *testing.T) {
	t.Run("condition compiler maps", func(t *testing.T) {
		stringOffsets := map[string]int{"$a": 1}
		conditionCompiler := NewConditionCompiler(NewEmitter(), stringOffsets)
		stringOffsets["$a"] = 99
		if got, _ := conditionCompiler.findStringOffset("$a"); got != 1 {
			t.Fatalf("NewConditionCompiler() retained caller map: got %d", got)
		}

		externals := map[string]int{"external": 2}
		globals := map[string]int{"global": 3}
		conditionCompiler.SetExternalVariables(externals)
		conditionCompiler.SetGlobalVariables(globals)
		externals["external"] = 20
		globals["global"] = 30
		if conditionCompiler.GetExternalVariables()["external"] != 2 {
			t.Fatal("SetExternalVariables() retained caller map")
		}
		if conditionCompiler.GetGlobalVariables()["global"] != 3 {
			t.Fatal("SetGlobalVariables() retained caller map")
		}

		conditionCompiler.variableMap["local"] = 4
		variables := conditionCompiler.GetVariableMap()
		variables["local"] = 40
		externalSnapshot := conditionCompiler.GetExternalVariables()
		externalSnapshot["external"] = 200
		globalSnapshot := conditionCompiler.GetGlobalVariables()
		globalSnapshot["global"] = 300
		if conditionCompiler.GetVariableMap()["local"] != 4 ||
			conditionCompiler.GetExternalVariables()["external"] != 2 ||
			conditionCompiler.GetGlobalVariables()["global"] != 3 {
			t.Fatal("condition compiler getter exposed mutable state")
		}
	})

	t.Run("string compiler offsets", func(t *testing.T) {
		stringCompiler := NewStringCompiler()
		stringCompiler.stringOffsets["$a"] = 7
		offsets := stringCompiler.GetStringOffsets()
		offsets["$a"] = 70
		if stringCompiler.GetStringOffsets()["$a"] != 7 {
			t.Fatal("GetStringOffsets() exposed compiler state")
		}
	})

	t.Run("emitter instructions", func(t *testing.T) {
		emitter := NewEmitter()
		emitter.EmitHalt(1, 1)

		instructions := emitter.GetInstructions()
		instructions[0].Opcode = OpNop
		instruction := emitter.GetInstruction(0)
		instruction.Opcode = OpNop
		if got := emitter.GetInstructions()[0].Opcode; got != OpHalt {
			t.Fatalf("instruction accessor exposed emitter state: got %v", got)
		}
	})
}

func TestCompiledArtifactAccessorsReturnOwnedSnapshots(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule owned {
  strings:
    $a = "test"
  condition:
    $a
}`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}
	rule, ok := program.GetRuleByName("owned")
	if !ok {
		t.Fatal("compiled rule not found")
	}

	bytecode := rule.GetBytecode()
	originalOpcode := bytecode[0]
	bytecode[0] ^= 0xff
	if got := rule.GetBytecode()[0]; got != originalOpcode {
		t.Fatal("GetBytecode() exposed compiled bytecode")
	}

	strings := rule.GetStrings()
	strings["$a"][0] = 'X'
	delete(strings, "$a")
	if got := string(rule.GetStrings()["$a"]); got != "test" {
		t.Fatalf("GetStrings() exposed compiled patterns: got %q", got)
	}

	for _, automaton := range []*ACAutomaton{rule.Automaton, program.SharedAutomaton} {
		if automaton == nil || len(automaton.Strings) == 0 {
			continue
		}
		metadata := automaton.GetStrings()
		metadata[0].Identifier = "$changed"
		metadata[0].Data[0] = 'X'
		patterns := automaton.GetPatternData()
		for _, pattern := range patterns {
			pattern[0] = 'X'
			break
		}

		automaton.Strings[0].Identifier = "$changed"
		automaton.Strings[0].Data[0] = 'X'
		automaton.StringCount = 0
		if automaton.GetStringCount() != 1 {
			t.Fatal("GetStringCount() trusted mutable compatibility metadata")
		}
	}

	result, err := program.Scan([]byte("test"))
	if err != nil {
		t.Fatalf("Scan() error after metadata mutation = %v", err)
	}
	if !result.RuleResults["owned"] {
		t.Fatalf("public compatibility metadata changed scan result: %+v", result)
	}

	streamingMatches, err := NewStreamingProcessor(program).ProcessBytes(context.Background(), []byte("test"))
	if err != nil {
		t.Fatalf("ProcessBytes() error after metadata mutation = %v", err)
	}
	if len(streamingMatches) != 1 || streamingMatches[0].Pattern != "$a" {
		t.Fatalf("public compatibility metadata changed streaming matches: %+v", streamingMatches)
	}
}

func TestInterpreterRuleResultsReturnsOwnedSnapshot(t *testing.T) {
	interpreter := NewInterpreter(nil)
	interpreter.SetRuleResults(map[string]bool{"owned": true})
	results := interpreter.GetRuleResults()
	results["owned"] = false
	if !interpreter.GetRuleResults()["owned"] {
		t.Fatal("GetRuleResults() exposed interpreter state")
	}
}
