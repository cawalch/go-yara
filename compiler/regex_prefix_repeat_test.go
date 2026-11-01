package compiler

import (
	"bytes"
	"os"
	"testing"
)

func TestPrefixOptionalRepeatOccurrences(t *testing.T) {
	p := mustCompileStreamingProgram(t, `rule p {strings:$a=/!(a?.)+/ condition:#a==2 and !a[1]==2 and !a[2]==2}`)
	for _, size := range []int{4, 4095, 4096, 4097} {
		data := append([]byte("!b!b"), bytes.Repeat([]byte("b"), size-4)...)
		for _, cap := range []int{0, 3, 4096} {
			s := p.NewScanner(WithStreamChunkSize(1024), WithStreamOverlapSize(1), WithMaxMatchSpan(cap))
			defer s.Close()
			for _, scan := range []func() (*ScanResult, error){
				func() (*ScanResult, error) { return s.Scan(data) },
				func() (*ScanResult, error) { return s.ScanReader(bytes.NewReader(data)) },
			} {
				result, err := scan()
				if err != nil || len(result.MatchedRules) != 1 {
					t.Fatalf("size=%d cap=%d result=%+v err=%v", size, cap, result, err)
				}
				matches := result.Matches["p"]["$a"]
				if len(matches) != 2 || matches[0].Offset != 0 || matches[0].Length != 2 || matches[1].Offset != 2 || matches[1].Length != 2 {
					t.Fatalf("size=%d cap=%d matches=%+v", size, cap, matches)
				}
			}
		}
	}
}

func TestPrefixOptionalRepeatCaptures(t *testing.T) {
	p := mustCompileStreamingProgram(t, `rule p {strings:$a=/!((a?)?.)+/ capture(part=1, head=2) condition:#a>0}`)
	encoded, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := UnmarshalCompiledProgram(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for _, program := range []*CompiledProgram{p, restored} {
		s := program.NewScanner(WithEvidence(16), WithStreamChunkSize(1))
		defer s.Close()
		for _, data := range []string{"!a!a!", "", "!a!a!"} {
			result, err := s.ScanReader(bytes.NewBufferString(data))
			if err != nil {
				t.Fatal(err)
			}
			matches := result.Matches["p"]["$a"]
			if data == "" {
				if len(matches) != 0 {
					t.Fatal("stale occurrences")
				}
				continue
			}
			if len(matches) != 2 || matches[0].Length != 5 || matches[1].Length != 3 {
				t.Fatalf("matches=%+v", matches)
			}
			for _, match := range matches {
				if len(match.Captures) != 2 || match.Captures[0].Offset != 3 || !bytes.Equal(match.Captures[0].Data, []byte("a!")) || match.Captures[1].Offset != 3 || !bytes.Equal(match.Captures[1].Data, []byte("a")) {
					t.Fatalf("captures=%+v", match.Captures)
				}
			}
		}
	}
}

func TestPrefixOptionalRepeatHistoricalProgram(t *testing.T) {
	encoded, err := os.ReadFile("testdata/serialization/format17-prefix-repeat.goyara")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		program, err := UnmarshalCompiledProgram(encoded)
		if err != nil {
			t.Fatal(err)
		}
		s := program.NewScanner(WithEvidence(16), WithStreamChunkSize(1), WithStreamEarlyTermination(false))
		result, err := s.ScanReader(bytes.NewBufferString("!b!b"))
		s.Close()
		if err != nil {
			t.Fatal(err)
		}
		matches := result.Matches["p"]["$a"]
		if len(matches) != 2 || matches[0].Length != 4 || matches[1].Length != 2 || len(matches[0].Captures) != 1 || matches[0].Captures[0].Offset != 3 {
			t.Fatalf("historical matches=%+v", matches)
		}
		encoded, err = program.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestPrefixOptionalRepeatCaptureContinuation(t *testing.T) {
	// The trailing star accepts the same outer span under both loop policies.
	// Replay must still capture the plus's first "b", before its loop stops.
	p := mustCompileStreamingProgram(t, `rule p {strings:$a=/!(a?.)+.*/ capture(part=1) condition:#a>0}`)
	result := scanEvidence(t, p, 16, "!b!b")
	matches := result.Matches["p"]["$a"]
	if len(matches) != 2 || matches[0].Length != 4 || len(matches[0].Captures) != 1 {
		t.Fatalf("matches=%+v", matches)
	}
	capture := matches[0].Captures[0]
	if capture.Offset != 1 || !bytes.Equal(capture.Data, []byte("b")) {
		t.Fatalf("capture=%+v", capture)
	}
}
