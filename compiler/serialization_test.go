package compiler

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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
        $regex_alternation = /"(phone|phone_number|mobile)":"[0-9]{7}"/
        $regex_case_class = /"[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]":"(REDACTED|null)"/
        $hex = { 50 41 ?? 4C 4F 41 44 }
    condition:
        uint16(0) == 0x5a4d and
        $magic at 0 and
        gate and threshold == 1 and
        any of ($regex, $regex_alternation, $regex_case_class, $hex) and
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
	for id, originalRegex := range originalRule.RegexPatterns {
		loadedRegex := loadedRule.RegexPatterns[id]
		canonicalizeRegexPlan(&loadedRegex)
		canonicalizeRegexPlan(&originalRegex)
		if !reflect.DeepEqual(loadedRegex, originalRegex) {
			t.Fatalf("%s prefilter plan changed across serialization\n got: %#v\nwant: %#v",
				id, loadedRegex, originalRegex)
		}
	}
	if !reflect.DeepEqual(loadedRule.HexPatterns, originalRule.HexPatterns) {
		t.Fatal("hex prefilter plan changed across serialization")
	}
	if !reflect.DeepEqual(loadedRule.HeaderConstraints, originalRule.HeaderConstraints) {
		t.Fatal("header constraints changed across serialization")
	}
	if loadedRule.RequiresStringMatch != originalRule.RequiresStringMatch {
		t.Fatalf(
			"RequiresStringMatch changed across serialization: got %v, want %v",
			loadedRule.RequiresStringMatch,
			originalRule.RequiresStringMatch,
		)
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
	if len(pattern.exactPrefixSuffix) == 0 {
		pattern.exactPrefixSuffix = nil
	}
	if len(pattern.wideExactPrefix) == 0 {
		pattern.wideExactPrefix = nil
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

func TestCompiledProgramSerializationPreservesStringMatchRequirement(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule required {
    strings:
        $a = "alpha"
    condition:
        $a
}
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}
	if !program.Rules[0].RequiresStringMatch {
		t.Fatal("compiled rule is not marked RequiresStringMatch")
	}
	data, err := program.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	loaded, err := UnmarshalCompiledProgram(data)
	if err != nil {
		t.Fatalf("UnmarshalCompiledProgram() error = %v", err)
	}
	if !loaded.Rules[0].RequiresStringMatch {
		t.Fatal("loaded rule lost RequiresStringMatch")
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

	v2 := bytes.Clone(data)
	binary.BigEndian.PutUint16(v2[len(compiledProgramMagic):], 2)
	if _, err := UnmarshalCompiledProgram(v2); err == nil || !strings.Contains(err.Error(), "rebuild") {
		t.Fatalf("v2 error = %v, want rebuild of cached fast-scan analysis", err)
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

func TestCompiledProgramRejectsInvalidVariableSlots(t *testing.T) {
	for _, kind := range []string{"external", "global"} {
		for _, slot := range []int{-1, 0, interpreterMemorySlotCount - 1, interpreterMemorySlotCount} {
			t.Run(fmt.Sprintf("%s/%d", kind, slot), func(t *testing.T) {
				rule := &CompiledRule{Name: "test", Bytecode: []byte{byte(OpPush8), 1, byte(OpHalt)}}
				if kind == "external" {
					rule.ExternalSlots = map[string]int{"value": slot}
				} else {
					rule.GlobalSlots = map[string]int{"value": slot}
				}
				program := NewCompiledProgram([]*CompiledRule{rule})
				invalid := slot < 0 || slot >= interpreterMemorySlotCount
				if err := program.Validate(); (err != nil) != invalid {
					t.Fatalf("Validate() = %v, invalid=%v", err, invalid)
				}
				if _, err := program.Scan(nil); (err != nil) != invalid {
					t.Fatalf("Scan() = %v, invalid=%v", err, invalid)
				}
				payload, err := serializeProgram(program)
				if err != nil {
					t.Fatal(err)
				}
				encoded := bytes.NewBufferString(compiledProgramMagic)
				if err := binary.Write(encoded, binary.BigEndian, compiledProgramVersion); err != nil {
					t.Fatal(err)
				}
				if err := gob.NewEncoder(encoded).Encode(payload); err != nil {
					t.Fatal(err)
				}
				if _, err := UnmarshalCompiledProgram(encoded.Bytes()); (err != nil) != invalid {
					t.Fatalf("UnmarshalCompiledProgram() = %v, invalid=%v", err, invalid)
				}
			})
		}
	}
}

func TestReadCompiledProgramPreservesReaderPosition(t *testing.T) {
	program, err := NewCompiler().CompileSource(`rule test { condition: true }`)
	if err != nil {
		t.Fatal(err)
	}
	for _, generic := range []bool{false, true} {
		var encoded bytes.Buffer
		for range 2 {
			if _, err := program.WriteTo(&encoded); err != nil {
				t.Fatal(err)
			}
		}
		encoded.WriteString("sentinel")
		var reader io.Reader = &encoded
		if generic {
			reader = struct{ io.Reader }{reader}
		}
		for range 2 {
			if _, err := ReadCompiledProgram(reader); err != nil {
				t.Fatal(err)
			}
		}
		if encoded.String() != "sentinel" {
			t.Fatalf("trailing bytes = %q, want sentinel", encoded.String())
		}
	}
}

func deterministicTestCustomModule() Module {
	return Module{
		Name: "custom",
		Schema: &ModuleSchema{
			Fields: map[string]ModuleField{
				"nested": {
					Kind: ModuleStruct,
					Struct: &ModuleSchema{
						Fields: map[string]ModuleField{
							"count": {Kind: ModuleInteger},
							"flag":  {Kind: ModuleBoolean, Constant: func() *ModuleValue { v := BooleanValue(true); return &v }()},
						},
					},
				},
				"dict": {
					Kind:    ModuleDictionary,
					Element: &ModuleField{Kind: ModuleString},
				},
				"items": {
					Kind:    ModuleArray,
					Element: &ModuleField{Kind: ModuleInteger},
				},
			},
		},
		Functions: map[string]ModuleFunction{
			"score": {
				Signatures: []ModuleSignature{{Arguments: []ModuleValueType{ModuleInteger, ModuleString}}},
				ReturnType: ModuleInteger,
				Evaluate: func(_ ModuleContext, _ []ModuleValue) (ModuleValue, error) {
					return IntegerValue(1), nil
				},
			},
		},
	}
}

func compileDeterministicFixture() (*CompiledProgram, error) {
	const src = `
import "pe"
import "math"
import "hash"
import "custom"

external gate
external limit
global weight = 42

rule base_rule : tag_b tag_a {
	meta:
		author = "test"
		severity = 5
		enabled = true
	strings:
		$hex = { 4d 5a ?? 00 }
		$txt = "payload" nocase wide ascii
		$rx = /item_[0-9]{2,4}(alpha|beta)/
		$cap = /key=([a-z0-9]+)/ capture(val = 1)
	condition:
		$hex at 0 and
		2 of ($txt, $rx, $cap) and
		for any of ($txt, $rx) : ($ in (0..128)) and
		gate and limit > 0 and weight == 42 and
		custom.score(custom.nested.count, custom.dict["alpha"]) > 0 and
		pe.number_of_sections >= 0 and
		math.min(1, 2) == 1 and
		hash.md5(0, 2) != ""
}

rule dependent_rule {
	strings:
		$s1 = "one"
		$s2 = "two"
	condition:
		base_rule and 1 of ($s*)
}
`
	return NewCompiler(WithModule(deterministicTestCustomModule())).CompileSource(src)
}

func TestCompiledProgramMarshalBinaryDeterministic(t *testing.T) {
	if outPath := os.Getenv("GO_YARA_DETERMINISTIC_OUT"); outPath != "" {
		prog, err := compileDeterministicFixture()
		if err != nil {
			t.Fatalf("helper CompileSource() error = %v", err)
		}
		data, err := prog.MarshalBinary()
		if err != nil {
			t.Fatalf("helper MarshalBinary() error = %v", err)
		}
		if err := os.WriteFile(outPath, data, 0o600); err != nil {
			t.Fatalf("helper WriteFile() error = %v", err)
		}
		return
	}
	var baseline []byte
	for round := range 20 {
		prog, err := compileDeterministicFixture()
		if err != nil {
			t.Fatalf("round %d CompileSource() error = %v", round, err)
		}
		data, err := prog.MarshalBinary()
		if err != nil {
			t.Fatalf("round %d MarshalBinary() error = %v", round, err)
		}
		var buf bytes.Buffer
		written, err := prog.WriteTo(&buf)
		if err != nil {
			t.Fatalf("round %d WriteTo() error = %v", round, err)
		}
		if written != int64(len(data)) || !bytes.Equal(buf.Bytes(), data) {
			t.Fatalf("round %d WriteTo() output differs from MarshalBinary()", round)
		}
		if round == 0 {
			baseline = data
			continue
		}
		if !bytes.Equal(data, baseline) {
			t.Fatalf("round %d MarshalBinary() produced non-deterministic bytes (len=%d vs %d)", round, len(data), len(baseline))
		}
	}

	loaded, err := UnmarshalCompiledProgram(baseline, deterministicTestCustomModule())
	if err != nil {
		t.Fatalf("UnmarshalCompiledProgram() error = %v", err)
	}
	reEncoded, err := loaded.MarshalBinary()
	if err != nil {
		t.Fatalf("loaded MarshalBinary() error = %v", err)
	}
	if !bytes.Equal(reEncoded, baseline) {
		t.Fatalf("round-tripped MarshalBinary() differs from original")
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable() error = %v", err)
	}
	tempDir := t.TempDir()
	for proc := range 3 {
		outPath := filepath.Join(tempDir, fmt.Sprintf("prog-%d.goyara", proc))
		cmd := exec.Command(exe, "-test.run=^TestCompiledProgramMarshalBinaryDeterministic$") // #nosec G204 -- re-executing current test binary
		cmd.Env = append(os.Environ(), "GO_YARA_DETERMINISTIC_OUT="+outPath)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("subprocess %d failed: %v\n%s", proc, err, output)
		}
		procBytes, err := os.ReadFile(outPath) // #nosec G304 -- temp file created in t.TempDir()
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", outPath, err)
		}
		if !bytes.Equal(procBytes, baseline) {
			t.Fatalf("subprocess %d MarshalBinary() differs from baseline (len=%d vs %d)", proc, len(procBytes), len(baseline))
		}
	}
}
