package compiler

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"testing"
)

func TestFixedOffsetMatchContextsAndOwnership(t *testing.T) {
	program, err := NewCompiler().CompileSource(`rule r { strings: $a="a" condition: $a at 101 }`)
	if err != nil {
		t.Fatal(err)
	}
	for _, compact := range []bool{false, true} {
		ctx := &MatchContext{compact: compact}
		for _, offset := range []int64{0, 1, 2} {
			ctx.AddMatch(Match{Pattern: "$a", Offset: offset, Length: 1})
		}
		ctx.filterFixedOffsets(program.Rules[0].fixedTextOffsets, 100)
		if ctx.matchCount("$a") != 1 || !ctx.hasMatchAt("$a", 1) {
			t.Fatalf("compact=%v: wrong local offsets", compact)
		}
		ctx.filterFixedOffsets(program.Rules[0].fixedTextOffsets, 102)
		if ctx.matchCount("$a") != 0 {
			t.Fatal("offset before block retained")
		}
	}
	single, err := program.MatchingRulesInBlock(MemoryBlock{Base: 100, Data: []byte("aaa")}, 103)
	if err != nil || len(single) != 1 || len(single[0].Matches["$a"]) != 1 || single[0].Matches["$a"][0].Offset != 101 {
		t.Fatalf("single block=%v, err=%v", single, err)
	}
	scanner := program.NewBlockScanner(WithMatchData(8))
	defer scanner.Close()
	data := []byte("aaa")
	if err := scanner.Scan(100, data); err != nil {
		t.Fatal(err)
	}
	result, err := scanner.Finish()
	if err != nil {
		t.Fatal(err)
	}
	matches := result.Matches["r"]["$a"]
	if len(matches) != 1 || matches[0].Offset != 101 || matches[0].Base != 100 || string(matches[0].MatchedData) != "a" {
		t.Fatalf("matches=%+v", matches)
	}
	data[1] = 'b'
	if string(matches[0].MatchedData) != "a" {
		t.Fatal("match data aliases input")
	}

	program, err = NewCompiler().CompileSource(`rule r { strings: $a="a" condition: $a at 1 }`)
	if err != nil {
		t.Fatal(err)
	}
	ctx := BuildMatchContext(program.Rules[0], []byte("aaa"))
	defer ctx.Release()
	if ctx.matchCount("$a") != 1 || !ctx.hasMatchAt("$a", 1) {
		t.Fatal("public match context retained unrestricted occurrences")
	}
}

func TestFixedOffsetLegacySerialization(t *testing.T) {
	program, err := NewCompiler().CompileSource(`rule r { strings: $a="a" condition: $a at 1 }`)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := serializeProgram(program)
	if err != nil {
		t.Fatal(err)
	}
	payload.Rules[0].FixedTextOffsets = nil // Format 7 did not store this analysis.
	var encoded bytes.Buffer
	encoded.WriteString(compiledProgramMagic)
	if err := binary.Write(&encoded, binary.BigEndian, uint16(7)); err != nil {
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
	if err != nil || len(result.Matches["r"]["$a"]) != 3 {
		t.Fatalf("legacy result=%v, err=%v", result, err)
	}
	program.Rules[0].fixedTextOffsets["$missing"] = 1
	if _, err := program.MarshalBinary(); err == nil {
		t.Fatal("invalid fixed-offset string accepted")
	}
}

func TestFixedOffsetPreservesExplicitCaptureEvidence(t *testing.T) {
	program, err := NewCompiler().CompileSource(`rule r {
strings: $a="a" capture(value=0)
condition: $a at 1 }`)
	if err != nil {
		t.Fatal(err)
	}
	if len(program.Rules[0].fixedTextOffsets) != 0 {
		t.Fatal("capture occurrences were restricted")
	}
	scanner := program.NewScanner(WithEvidence(16))
	defer scanner.Close()
	result, err := scanner.Scan([]byte("aaa"))
	if err != nil {
		t.Fatal(err)
	}
	matches := result.Matches["r"]["$a"]
	if len(matches) != 3 {
		t.Fatalf("capture matches=%v", matches)
	}
	if _, err := scanner.Scan([]byte("aba")); err != nil {
		t.Fatal(err)
	}
	for index, match := range matches {
		if match.Offset != int64(index) || len(match.Captures) != 1 {
			t.Fatalf("retained capture=%+v", match)
		}
	}
}
