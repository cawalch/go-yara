package compiler

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"testing"
)

func TestFixedOffsetNonTextBlocksAndCaptures(t *testing.T) {
	for _, pattern := range []string{`/a/`, `{61}`} {
		program, err := NewCompiler().CompileSource(fmt.Sprintf(`
rule fixed { strings: $a=%s condition: $a at 101 }
rule observed { strings: $a=%s condition: #a >= 0 and $a at 101 }`, pattern, pattern))
		if err != nil {
			t.Fatal(err)
		}
		check := func(matches []RuleMatch) {
			t.Helper()
			if len(matches) != 2 {
				t.Fatalf("rules=%v", matches)
			}
			for _, rule := range matches {
				want := 3
				if rule.Rule == "fixed" {
					want = 1
				}
				if len(rule.Matches["$a"]) != want {
					t.Fatalf("%s: matches=%v", rule.Rule, rule.Matches)
				}
				if want == 1 && rule.Matches["$a"][0].Offset != 101 {
					t.Fatal("lost absolute offset")
				}
			}
		}
		single, err := program.MatchingRulesInBlock(MemoryBlock{Base: 100, Data: []byte("aaa")}, 103)
		if err != nil {
			t.Fatal(err)
		}
		check(single)
		blocks := program.NewBlockScanner(WithMatchData(8))
		if err := blocks.Scan(100, []byte("aaa")); err != nil {
			t.Fatal(err)
		}
		result, err := blocks.Finish()
		blocks.Close()
		if err != nil {
			t.Fatal(err)
		}
		check(result.MatchedRules)

		captured, err := NewCompiler().CompileSource(fmt.Sprintf(`rule r { strings: $a=%s capture(value=0) condition: $a at 1 }`, pattern))
		if err != nil {
			t.Fatal(err)
		}
		if len(captured.Rules[0].fixedOffsets) != 0 {
			t.Fatal("capture evidence was restricted")
		}
		scanner := captured.NewScanner(WithEvidence(16))
		result, err = scanner.Scan([]byte("aaa"))
		scanner.Close()
		if err != nil || len(result.Matches["r"]["$a"]) != 3 {
			t.Fatalf("capture result=%v, err=%v", result, err)
		}
	}
}

func TestFixedOffsetFormat8Serialization(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule text { strings: $a="a" condition: $a at 1 }
rule re { strings: $a=/a/ condition: $a at 1 }
rule hex { strings: $a={61} condition: $a at 1 }`)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := serializeProgram(program)
	if err != nil {
		t.Fatal(err)
	}
	for index := range payload.Rules {
		rule := &payload.Rules[index]
		if rule.Name == "text" {
			rule.FixedTextOffsets = rule.FixedOffsets
		}
		rule.FixedOffsets = nil // Format 8 only stored text restrictions.
	}
	var encoded bytes.Buffer
	encoded.WriteString(compiledProgramMagic)
	if err := binary.Write(&encoded, binary.BigEndian, uint16(8)); err != nil {
		t.Fatal(err)
	}
	if err := gob.NewEncoder(&encoded).Encode(payload); err != nil {
		t.Fatal(err)
	}
	legacy, err := UnmarshalCompiledProgram(encoded.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	result, err := legacy.Scan([]byte("aaa"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"text", "re", "hex"} {
		want := 3
		if name == "text" {
			want = 1
		}
		if len(result.Matches[name]["$a"]) != want {
			t.Fatalf("%s: legacy matches=%v", name, result.Matches)
		}
	}
}
