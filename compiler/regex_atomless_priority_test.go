package compiler

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"testing"

	"github.com/cawalch/go-yara/regex"
)

func TestAtomlessAlternationPriority(t *testing.T) {
	for _, tc := range []struct {
		pattern, input string
		length         int
	}{
		{`(ab|[a])`, "ab", 2}, {`([a]|ab)`, "ab", 1},
		{`(abc|[a])`, "ab!", 1}, {`(abc|[a]b|[a])`, "ab", 2},
		{`(ab|[a])+?`, "abab", 2}, {`(ab|[a])+`, "abab", 4},
		{`(ab|[a])??`, "ab", 0}, {`(ab|[a]){1,2}?`, "abab", 2},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			program := mustCompileStreamingProgram(t, `rule p {strings:$a=/`+tc.pattern+`/ capture(value=1) condition:$a}`)
			result := scanEvidence(t, program, 32, tc.input)
			matches := result.Matches["p"]["$a"]
			if len(matches) == 0 || matches[0].Offset != 0 || matches[0].Length != tc.length {
				t.Fatalf("matches=%+v, want length %d", matches, tc.length)
			}
			if tc.length > 0 { // A skipped optional group has no capture.
				if len(matches[0].Captures) != 1 {
					t.Fatalf("captures=%+v", matches[0].Captures)
				}
				capture := matches[0].Captures[0]
				want := tc.input[:tc.length]
				if tc.pattern == `(ab|[a])+` {
					want = "ab"
				}
				if !bytes.Equal(capture.Data, []byte(want)) {
					t.Fatalf("capture=%+v, want %q", capture, want)
				}
			}
		})
	}
}

func TestAtomlessPriorityEncodingPreferenceAndReuse(t *testing.T) {
	program := mustCompileStreamingProgram(t, `rule p {strings:$a=/(ab|[a])/ ascii wide condition:$a}`)
	pattern := program.Rules[0].RegexPatterns["$a"]
	if pattern.Flags&regex.FlagsGreedy != 0 {
		t.Fatal("forward priority changed greedy metadata")
	}
	scanner := program.NewScanner(WithFastScan())
	defer scanner.Close()
	for _, data := range [][]byte{{'a', 0, 'b', 0}, nil, []byte("ab"), {'a', 0, 'b', 0}} {
		result, err := scanner.Scan(data)
		if err != nil {
			t.Fatal(err)
		}
		matches := result.Matches["p"]["$a"]
		if len(data) == 0 {
			if len(matches) != 0 {
				t.Fatal("stale matches")
			}
			continue
		}
		want := 1
		if data[1] == 'b' {
			want = 2
		}
		if len(matches) != 1 || matches[0].Length != want {
			t.Fatalf("input=%x matches=%+v", data, matches)
		}
	}
}

func TestAtomlessPriorityFormat10Compatibility(t *testing.T) {
	program := mustCompileStreamingProgram(t, `rule p {strings:$a=/(ab|[a])/ wide condition:$a}`)
	encoded, err := program.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if version := binary.BigEndian.Uint16(encoded[len(compiledProgramMagic):]); version != compiledProgramVersion {
		t.Fatalf("version=%d", version)
	}
	payload, err := serializeProgram(program)
	if err != nil {
		t.Fatal(err)
	}
	pattern := payload.Rules[0].RegexPatterns["$a"]
	pattern.Flags &^= regexForwardPriority
	payload.Rules[0].RegexPatterns["$a"] = pattern
	var legacy bytes.Buffer
	legacy.WriteString(compiledProgramMagic)
	if err := binary.Write(&legacy, binary.BigEndian, uint16(10)); err != nil {
		t.Fatal(err)
	}
	if err := gob.NewEncoder(&legacy).Encode(payload); err != nil {
		t.Fatal(err)
	}
	restored, err := UnmarshalCompiledProgram(legacy.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	result, err := restored.Scan([]byte{'a', 0, 'b', 0})
	if err != nil {
		t.Fatal(err)
	}
	matches := result.Matches["p"]["$a"]
	if len(matches) != 1 || matches[0].Length != 2 {
		t.Fatalf("legacy matches=%+v", matches)
	}
}
