package compiler

import (
	"sync"
	"testing"
)

func TestProgramPreparationPreservesBorrowedRules(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule first { strings: $a = /abc/ $b = { 61 62 63 } condition: all of them }
rule second { strings: $a = "def" condition: first and $a }
`)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		for range 20 {
			if matched, err := program.Matches([]byte("abcdef")); err != nil || !matched {
				t.Errorf("original scan = (%v, %v)", matched, err)
			}
		}
	}()
	go func() {
		defer workers.Done()
		for range 20 {
			rebuilt := NewCompiledProgram(program.Rules)
			if matched, err := rebuilt.Matches([]byte("abcdef")); err != nil || !matched {
				t.Errorf("rebuilt scan = (%v, %v)", matched, err)
			}
		}
	}()
	workers.Wait()
}

func TestInvalidProgramPreparationReturnsErrors(t *testing.T) {
	for _, rule := range []*CompiledRule{nil, {Name: "empty"}, {Name: "index", Index: 1, Bytecode: []byte{byte(OpHalt)}}} {
		program := NewCompiledProgram([]*CompiledRule{rule})
		if err := program.Validate(); err == nil {
			t.Fatal("Validate accepted invalid rule")
		}
		scanner := NewScanner(program, WithTagsFilter([]string{"selected"}), WithExternalVariables(map[string]any{"value": true}))
		defer scanner.Close()
		if _, err := scanner.Scan(nil); err == nil {
			t.Fatal("Scan accepted invalid rule")
		}
		if _, err := scanner.Matches(nil); err == nil {
			t.Fatal("Matches accepted invalid rule")
		}
		if _, err := scanner.MatchingRules(nil); err == nil {
			t.Fatal("MatchingRules accepted invalid rule")
		}
		if _, err := scanner.MatchingRulesInBlock(MemoryBlock{}, 0); err == nil {
			t.Fatal("MatchingRulesInBlock accepted invalid rule")
		}
		blocks := NewBlockScanner(program)
		defer blocks.Close()
		if err := blocks.Scan(0, nil); err == nil {
			t.Fatal("BlockScanner.Scan accepted invalid rule")
		}
		if _, err := blocks.Finish(); err == nil {
			t.Fatal("BlockScanner.Finish accepted invalid rule")
		}
	}
}

func TestProgramPreparationPreservesUnknownDependencies(t *testing.T) {
	program := NewCompiledProgram([]*CompiledRule{
		{Name: "helper", IsPrivate: true, Bytecode: []byte{byte(OpPush8), 1, byte(OpHalt)}, dependencies: []string{}},
		{Name: "selected", Index: 1, Tags: []string{"selected"}, Bytecode: []byte{byte(OpPushRuleRef), 0, byte(OpHalt)}},
	})
	encoded, err := program.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := UnmarshalCompiledProgram(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []*CompiledProgram{program, loaded} {
		scanner := NewScanner(candidate, WithTagsFilter([]string{"selected"}))
		defer scanner.Close()
		matches, err := scanner.MatchingRules(nil)
		if err != nil || len(matches) != 1 || matches[0].Rule != "selected" {
			t.Fatalf("MatchingRules = (%+v, %v), want selected", matches, err)
		}
	}
}
