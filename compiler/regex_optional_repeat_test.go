package compiler

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
)

func TestOptionalRepeatOccurrences(t *testing.T) {
	program := mustCompileStreamingProgram(t, `rule p {strings:$a=/(a?.)+/ ascii wide condition:$a}`)
	encoded, err := program.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := UnmarshalCompiledProgram(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []*CompiledProgram{program, restored} {
		for _, cap := range []int{0, 2, regexVerificationDistance} {
			scanner := p.NewScanner(WithStreamChunkSize(1024), WithStreamOverlapSize(1), WithMaxMatchSpan(cap))
			defer scanner.Close()
			for _, input := range [][]byte{{0, '!'}, bytes.Repeat([]byte{'!'}, regexVerificationDistance+3), nil, {0, '!'}} {
				for _, reader := range []bool{false, true} {
					result, err := scanner.Scan(input)
					if reader {
						result, err = scanner.ScanReader(bytes.NewReader(input))
					}
					if err != nil {
						t.Fatal(err)
					}
					matches := result.Matches["p"]["$a"]
					if len(matches) != len(input) {
						t.Fatalf("reader=%v cap=%d: %d matches, want %d", reader, cap, len(matches), len(input))
					}
					for i, match := range matches {
						if match.Offset != int64(i) || match.Length != 1 {
							t.Fatalf("reader=%v cap=%d: match=%+v", reader, cap, match)
						}
					}
				}
			}
		}
	}
}

func TestOptionalRepeatHistoricalProgram(t *testing.T) {
	// This is a genuine pre-fix artifact, not a new payload with an old header.
	encoded, err := os.ReadFile("testdata/serialization/format17-optional-repeat.goyara")
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(encoded[len(compiledProgramMagic):]) != 17 {
		t.Fatal("historical artifact must be format 17")
	}
	program, err := UnmarshalCompiledProgram(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		scanner := program.NewScanner(WithStreamChunkSize(1), WithStreamEarlyTermination(false))
		for _, reader := range []bool{false, true} {
			result, err := scanner.Scan([]byte{0, '!'})
			if reader {
				result, err = scanner.ScanReader(bytes.NewReader([]byte{0, '!'}))
			}
			if err != nil {
				t.Fatal(err)
			}
			matches := result.Matches["p"]["$a"]
			if len(matches) != 2 || matches[0].Offset != 0 || matches[0].Length != 2 || matches[1].Offset != 1 || matches[1].Length != 1 {
				t.Fatalf("historical matches=%+v", matches)
			}
		}
		scanner.Close()
		encoded, err = program.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		program, err = UnmarshalCompiledProgram(encoded)
		if err != nil {
			t.Fatal(err)
		}
	}
}
