package compiler

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
)

func TestCompiledProgramSerializationRoundTrip(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
import "hash"
import "math"
external gate
global threshold = 1

rule base : executable sample {
    meta:
        family = "demo"
        score = 7
        active = true
    strings:
        $magic = "MZ"
        $regex = /pay(load|mint)/ nocase
        $hex = { 50 41 ?? 4C 4F 41 44 }
    condition:
        uint16(0) == 0x5a4d and
        $magic at 0 and
        gate and threshold == 1 and
        any of ($regex, $hex) and
        hash.sha256("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
}

rule child {
    condition:
        base and math.mean(0, 2) > 80.0
}
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}

	data, err := program.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	loaded, err := UnmarshalCompiledProgram(data)
	if err != nil {
		t.Fatalf("UnmarshalCompiledProgram() error = %v", err)
	}
	if err := loaded.SetExternalVariables(map[string]any{"gate": true}); err != nil {
		t.Fatalf("SetExternalVariables() error = %v", err)
	}
	if err := program.SetExternalVariables(map[string]any{"gate": true}); err != nil {
		t.Fatalf("original SetExternalVariables() error = %v", err)
	}

	input := []byte("MZ payload")
	want, err := program.Scan(input)
	if err != nil {
		t.Fatalf("original Scan() error = %v", err)
	}
	got, err := loaded.Scan(input)
	if err != nil {
		t.Fatalf("loaded Scan() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loaded result differs\n got: %#v\nwant: %#v", got, want)
	}

	if dependencies := loaded.RuleDependencies("child"); !reflect.DeepEqual(dependencies, []string{"base"}) {
		t.Fatalf("RuleDependencies(child) = %v, want [base]", dependencies)
	}
	if dependents := loaded.RuleDependents("base"); !reflect.DeepEqual(dependents, []string{"child"}) {
		t.Fatalf("RuleDependents(base) = %v, want [child]", dependents)
	}

	originalRule, _ := program.GetRuleByName("base")
	loadedRule, _ := loaded.GetRuleByName("base")
	loadedRegex := loadedRule.RegexPatterns["$regex"]
	originalRegex := originalRule.RegexPatterns["$regex"]
	canonicalizeRegexPlan(&loadedRegex)
	canonicalizeRegexPlan(&originalRegex)
	if !reflect.DeepEqual(loadedRegex, originalRegex) {
		t.Fatalf("regex prefilter plan changed across serialization\n got: %#v\nwant: %#v", loadedRegex, originalRegex)
	}
	if !reflect.DeepEqual(loadedRule.HexPatterns, originalRule.HexPatterns) {
		t.Fatal("hex prefilter plan changed across serialization")
	}
	if !reflect.DeepEqual(loadedRule.HeaderConstraints, originalRule.HeaderConstraints) {
		t.Fatal("header constraints changed across serialization")
	}

	blockScanner := loaded.NewBlockScanner()
	defer blockScanner.Close()
	if err := blockScanner.Scan(0, input); err != nil {
		t.Fatalf("loaded block Scan() error = %v", err)
	}
	blockResult, err := blockScanner.Finish()
	if err != nil {
		t.Fatalf("loaded block Finish() error = %v", err)
	}
	if !reflect.DeepEqual(blockResult.RuleResults, got.RuleResults) {
		t.Fatalf("loaded block RuleResults = %v, want %v", blockResult.RuleResults, got.RuleResults)
	}
}

func canonicalizeRegexPlan(pattern *RegexPattern) {
	if len(pattern.alternativeAtoms) == 0 {
		pattern.alternativeAtoms = nil
	}
	if len(pattern.wideAlternativeAtoms) == 0 {
		pattern.wideAlternativeAtoms = nil
	}
	if len(pattern.fixedByteSets) == 0 {
		pattern.fixedByteSets = nil
	}
}

func TestCompiledProgramWriteToAndRead(t *testing.T) {
	program, err := NewCompiler().CompileSource(`rule always { condition: true }`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}
	var buffer bytes.Buffer
	written, err := program.WriteTo(&buffer)
	if err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}
	if written != int64(buffer.Len()) {
		t.Fatalf("WriteTo() wrote %d, buffer contains %d", written, buffer.Len())
	}
	loaded, err := ReadCompiledProgram(&buffer)
	if err != nil {
		t.Fatalf("ReadCompiledProgram() error = %v", err)
	}
	result, err := loaded.Scan(nil)
	if err != nil || !result.RuleResults["always"] {
		t.Fatalf("loaded Scan() result = %+v, error = %v", result, err)
	}
}

func TestCompiledProgramSerializationRebindsCustomModules(t *testing.T) {
	demo := testSerializationModule()
	program, err := NewCompiler(WithModule(demo)).CompileSource(`
import "demo"
rule custom { condition: demo.accept(7) }
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}
	data, err := program.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	if _, err := UnmarshalCompiledProgram(data); err == nil || !strings.Contains(err.Error(), "demo.accept") {
		t.Fatalf("UnmarshalCompiledProgram() error = %v, want missing demo.accept", err)
	}
	incompatible := testSerializationModule()
	function := incompatible.Functions["accept"]
	function.ReturnType = ModuleInteger
	incompatible.Functions["accept"] = function
	if _, err := UnmarshalCompiledProgram(data, incompatible); err == nil || !strings.Contains(err.Error(), "incompatible signature") {
		t.Fatalf("UnmarshalCompiledProgram(incompatible module) error = %v", err)
	}
	loaded, err := UnmarshalCompiledProgram(data, demo)
	if err != nil {
		t.Fatalf("UnmarshalCompiledProgram(custom module) error = %v", err)
	}
	result, err := loaded.Scan(nil)
	if err != nil || !result.RuleResults["custom"] {
		t.Fatalf("loaded custom-module result = %+v, error = %v", result, err)
	}
}

func TestCompiledProgramSerializationRejectsInvalidHeader(t *testing.T) {
	program, err := NewCompiler().CompileSource(`rule always { condition: true }`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}
	data, err := program.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	badMagic := bytes.Clone(data)
	badMagic[0] = 'X'
	if _, err := UnmarshalCompiledProgram(badMagic); err == nil || !strings.Contains(err.Error(), "magic") {
		t.Fatalf("bad magic error = %v", err)
	}

	badVersion := bytes.Clone(data)
	binary.BigEndian.PutUint16(badVersion[len(compiledProgramMagic):], compiledProgramVersion+1)
	if _, err := UnmarshalCompiledProgram(badVersion); err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("bad version error = %v", err)
	}

	v1 := bytes.Clone(data)
	binary.BigEndian.PutUint16(v1[len(compiledProgramMagic):], 1)
	if _, err := UnmarshalCompiledProgram(v1); err == nil || !strings.Contains(err.Error(), "rebuild") {
		t.Fatalf("v1 error = %v, want explicit rebuild requirement", err)
	}

	if _, err := UnmarshalCompiledProgram(data[:len(data)-1]); err == nil {
		t.Fatal("truncated compiled program unexpectedly loaded")
	}
}

func testSerializationModule() Module {
	return Module{
		Name: "demo",
		Functions: map[string]ModuleFunction{
			"accept": {
				Signatures: []ModuleSignature{{Arguments: []ModuleValueType{ModuleInteger}}},
				ReturnType: ModuleBoolean,
				Evaluate: func(_ ModuleContext, arguments []ModuleValue) (ModuleValue, error) {
					return BooleanValue(arguments[0].Integer == 7), nil
				},
			},
		},
	}
}
