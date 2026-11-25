package compiler

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestCountInRangeEndToEnd(t *testing.T) {
	for _, tc := range []struct {
		condition string
		want      bool
	}{
		{"#a in (2..3)", false},
		{"#a in (0..2)", true},
		{"#a in (0..4) == 2", true},
		{"#a in (filesize - 7..filesize) == 2", true},
		{"#a in (0..4) + #a in (8..8) == 3", true},
		{"1 + #a in (0..2) == 2", true},
		{"#a in (3..4) of ($a, $b)", true},
		{"#a in (0..8) of them", false},
		{"#a in (0..4) of them in (4..6)", true},
		{"for all of ($a) : (# in (0..4) == 2)", true},
		{"#a in (filesize..0) == 0", true},
		{"#a in (filesize - 100..0) == 1", true},
		{"not defined (#a in (@a[4]..8))", true},
	} {
		t.Run(tc.condition, func(t *testing.T) {
			program := mustCompileStreamingProgram(t, `rule r {
				strings: $a = "a" $b = "b"
				condition: `+tc.condition+` }`)
			scanner := program.NewScanner(WithFastScan(), WithStreamChunkSize(3))
			defer scanner.Close()
			data := []byte("a b a b a b")
			got, err := scanner.Matches(data)
			if err != nil || got != tc.want {
				t.Fatalf("Matches = %v, %v, want %v", got, err, tc.want)
			}
			got, err = scanner.MatchesReader(bytes.NewReader(data))
			if err != nil || got != tc.want {
				t.Fatalf("MatchesReader = %v, %v, want %v", got, err, tc.want)
			}
		})
	}
}

func TestCountInRangeBlockOffsets(t *testing.T) {
	program := mustCompileStreamingProgram(t, `rule r {
		strings: $a = /ab/ wide nocase
		condition: #a in (104..108) == 2 and #a in (0..103) == 0
	}`)
	scanner := program.NewBlockScanner(WithFastScan())
	defer scanner.Close()
	if err := scanner.Scan(104, []byte("A\x00b\x00a\x00B\x00ab")); err != nil {
		t.Fatal(err)
	}
	if err := scanner.Scan(500, []byte("a\x00b\x00")); err != nil {
		t.Fatal(err)
	}
	res, err := scanner.Finish()
	if err != nil || len(res.MatchedRules) != 1 {
		t.Fatalf("Finish = %v, %v", res, err)
	}
}

func TestLegacyCountInRangeBytecode(t *testing.T) {
	program := mustCompileStreamingProgram(t, `rule r { strings: $a="x" condition: #a in (0..1) }`)
	data := []byte("  x")
	if got, err := program.Matches(data); err != nil || got {
		t.Fatalf("new program Matches = %v, %v", got, err)
	}

	legacyRule := *program.Rules[0]
	emit := newEmitter()
	emit.EmitPushString("$a", 0, 0)
	emit.EmitOpcode(OpCount, 0, 0)
	emit.EmitPush(0, 0, 0)
	emit.EmitPush(1, 0, 0)
	emit.EmitOpcode(OpCountIn, 0, 0)
	emit.EmitOpcode(OpHalt, 0, 0)
	legacyRule.StringLiterals = emit.stringLiterals
	var err error
	legacyRule.Bytecode, err = emit.GetBytecode()
	if err != nil {
		t.Fatal(err)
	}
	legacy := NewCompiledProgram([]*CompiledRule{&legacyRule})
	encoded, err := legacy.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(encoded[len(compiledProgramMagic):], 20)
	for _, format := range []int{20, 21} {
		restored, err := UnmarshalCompiledProgram(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := restored.Matches(data); err != nil || !got {
			t.Fatalf("format %d legacy Matches = %v, %v", format, got, err)
		}
		encoded, err = restored.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestCountInRangeUnorderedMatchContext(t *testing.T) {
	emit := newEmitter()
	emit.EmitPushString("$a", 0, 0)
	emit.EmitPush(4, 0, 0)
	emit.EmitPush(8, 0, 0)
	emit.EmitOpcode(OpCountMatchesIn, 0, 0)
	emit.EmitOpcode(OpHalt, 0, 0)
	code, err := emit.GetBytecode()
	if err != nil {
		t.Fatal(err)
	}
	interp := NewInterpreter(code)
	defer interp.Release()
	interp.stringLiterals = emit.stringLiterals
	interp.SetMatchContext(&MatchContext{Matches: map[string][]Match{
		"$a": {{Offset: 9}, {Offset: 4}, {Offset: 0}, {Offset: 8}},
	}})
	if err := interp.Execute(); err != nil {
		t.Fatal(err)
	}
	if got := interp.stack[len(interp.stack)-1].IntVal; got != 2 {
		t.Fatalf("got %d occurrences, want 2", got)
	}
}
