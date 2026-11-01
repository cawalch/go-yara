package compiler

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
)

func TestStartAtomRepeatEntries(t *testing.T) {
	for _, tc := range []struct {
		pattern, input string
		want           [][2]int
	}{
		{`^!(a?.)+`, "!b!b", [][2]int{{0, 2}}},
		{`^!(a?.)+`, "b!b!", nil},
		{`(x|y)(a?.)+`, "x!y!", [][2]int{{0, 2}, {2, 2}}},
		{`(x|xy)(a?.)+`, "xy!!", [][2]int{{0, 3}}},
		{`(xy|x)(a?.)+`, "xy!!", [][2]int{{0, 3}}},
		{`^(x|xy)(a?.)+`, "xy!!", [][2]int{{0, 3}}},
		{`^(x|xy)(a?.)+`, "!xy!!", nil},
		{`\b(x|xy)(a?.)+`, "!xy!!", [][2]int{{1, 3}}},
		{`\b(x|xy)(a?.)+`, "axy!!", nil},
		{`\B(x|xy)(a?.)+`, "axy!!", [][2]int{{1, 3}}},
	} {
		t.Run(tc.pattern+tc.input, func(t *testing.T) {
			p := mustCompileStreamingProgram(t, `rule p {strings:$a=/`+tc.pattern+`/ condition:#a>0}`)
			encoded, err := p.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if binary.BigEndian.Uint16(encoded[len(compiledProgramMagic):]) <= 17 {
				t.Fatal("new atom-dispatch policy requires a format newer than 17")
			}
			restored, err := UnmarshalCompiledProgram(encoded)
			if err != nil {
				t.Fatal(err)
			}
			for _, program := range []*CompiledProgram{p, restored} {
				for _, cap := range []int{0, 3} {
					s := program.NewScanner(WithMaxMatchSpan(cap), WithStreamChunkSize(1), WithStreamOverlapSize(1), WithStreamEarlyTermination(false))
					defer s.Close()
					for _, scan := range []func() (*ScanResult, error){
						func() (*ScanResult, error) { return s.Scan([]byte(tc.input)) },
						func() (*ScanResult, error) { return s.ScanReader(bytes.NewBufferString(tc.input)) },
					} {
						result, err := scan()
						if err != nil {
							t.Fatal(err)
						}
						matches := result.Matches["p"]["$a"]
						if len(matches) != len(tc.want) {
							t.Fatalf("cap=%d matches=%+v want=%v", cap, matches, tc.want)
						}
						for i, want := range tc.want {
							if matches[i].Offset != int64(want[0]) || matches[i].Length != want[1] {
								t.Fatalf("cap=%d match=%+v want=%v", cap, matches[i], want)
							}
						}
					}
				}
			}
		})
	}
}

func TestStartAtomRepeatCaptures(t *testing.T) {
	p := mustCompileStreamingProgram(t, `rule p {strings:$a=/(x|xy)(a?.)+/ capture(prefix=1, part=2) condition:#a>0}`)
	for _, input := range []string{"xy!!", "", "xy!!"} {
		result := scanEvidence(t, p, 16, input)
		matches := result.Matches["p"]["$a"]
		if input == "" {
			if len(matches) != 0 {
				t.Fatal("stale matches")
			}
			continue
		}
		if len(matches) != 1 || matches[0].Length != 3 || len(matches[0].Captures) != 2 {
			t.Fatalf("matches=%+v", matches)
		}
		captures := matches[0].Captures
		if captures[0].Offset != 0 || !bytes.Equal(captures[0].Data, []byte("xy")) || captures[1].Offset != 2 || !bytes.Equal(captures[1].Data, []byte("!")) {
			t.Fatalf("captures=%+v", captures)
		}
	}
}

func TestStartAtomRepeatHistoricalProgram(t *testing.T) {
	encoded, err := os.ReadFile("testdata/serialization/format17-start-atoms.goyara")
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(encoded[len(compiledProgramMagic):]) != 17 {
		t.Fatal("fixture must be genuine format 17")
	}
	for range 2 {
		p, err := UnmarshalCompiledProgram(encoded)
		if err != nil {
			t.Fatal(err)
		}
		s := p.NewScanner(WithStreamChunkSize(1), WithStreamEarlyTermination(false))
		for rule, input := range map[string]string{"anchored": "!b!b", "alternatives": "xy!!"} {
			result, err := s.ScanReader(bytes.NewBufferString(input))
			if err != nil {
				t.Fatal(err)
			}
			matches := result.Matches[rule]["$a"]
			if len(matches) != 1 || matches[0].Offset != 0 || matches[0].Length != 4 {
				t.Fatalf("historical %s matches=%+v", rule, matches)
			}
		}
		s.Close()
		encoded, err = p.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
	}
}
