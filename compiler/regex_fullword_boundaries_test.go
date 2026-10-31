package compiler

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"testing"

	"github.com/cawalch/go-yara/regex"
)

func TestRegexLiteralAtomEligibility(t *testing.T) {
	for pattern, want := range map[string]bool{
		`a`: true, `(a)`: true, `a+`: true, `a{1,2}`: true, `[a]b`: true, `a[b]`: true, `a*b`: true, `a|b`: true, `(a|[b])c`: true,
		`[a]`: false, `[a]{1}`: false, `[ab]+`: false, `a*`: false, `a?`: false, `a{0,2}`: false, `a|[b]`: false, `(a|b)*`: false, `\w`: false, `.+`: false,
	} {
		parsed, err := regex.NewParser(0).Parse(pattern)
		if err != nil {
			t.Fatal(err)
		}
		if got := regexHasLiteralAtom(parsed.Root); got != want {
			t.Errorf("%s: %v, want %v", pattern, got, want)
		}
	}
}

func TestWideFullwordCapturesAndFastScan(t *testing.T) {
	program := mustCompileStreamingProgram(t, `rule p {strings:$a=/([a]+)/ wide fullword capture(value=1) condition:#a==2}`)
	result := scanEvidence(t, program, 32, "a\x00a\x00")
	matches := result.Matches["p"]["$a"]
	if len(matches) != 2 {
		t.Fatalf("matches=%+v", matches)
	}
	for index, match := range matches {
		if match.Offset != int64(index*2) || match.Length != 4-index*2 || len(match.Captures) != 1 {
			t.Fatalf("match=%+v", match)
		}
		capture := match.Captures[0]
		if capture.Offset != match.Offset || capture.Length != match.Length || !bytes.Equal(capture.Data, []byte("a\x00a\x00")[match.Offset:int(match.Offset)+match.Length]) {
			t.Fatalf("capture=%+v", capture)
		}
	}
	program = mustCompileStreamingProgram(t, `rule p {strings:$a=/[a]/ wide fullword condition:$a}`)
	scanner := program.NewScanner(WithFastScan())
	defer scanner.Close()
	for _, data := range [][]byte{{'a', 0, 'a', 0}, nil, {'a', 0, 'a', 0}} {
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
		if len(matches) != 1 || matches[0].Offset != 2 || matches[0].Length != 2 {
			t.Fatalf("fast matches=%v", matches)
		}
	}
}

func TestWideFullwordFormat9Compatibility(t *testing.T) {
	program := mustCompileStreamingProgram(t, `rule p {strings:$a=/[a]/ wide fullword condition:$a}`)
	encoded, err := program.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if version := binary.BigEndian.Uint16(encoded[len(compiledProgramMagic):]); version != 10 {
		t.Fatalf("version=%d", version)
	}
	payload, err := serializeProgram(program)
	if err != nil {
		t.Fatal(err)
	}
	pattern := payload.Rules[0].RegexPatterns["$a"]
	pattern.Flags &^= regexASCIIWordBoundary // Format 9 did not record this policy.
	payload.Rules[0].RegexPatterns["$a"] = pattern
	var legacy bytes.Buffer
	legacy.WriteString(compiledProgramMagic)
	if err := binary.Write(&legacy, binary.BigEndian, uint16(9)); err != nil {
		t.Fatal(err)
	}
	if err := gob.NewEncoder(&legacy).Encode(payload); err != nil {
		t.Fatal(err)
	}
	restored, err := UnmarshalCompiledProgram(legacy.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	result, err := restored.Scan([]byte{'a', 0, 'a', 0})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.MatchedRules) != 0 {
		t.Fatal("legacy artifact lost its compiled wide boundary policy")
	}
}
