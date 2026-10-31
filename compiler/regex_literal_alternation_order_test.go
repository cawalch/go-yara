package compiler

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"strings"
	"testing"
)

func TestLiteralAlternationAtomOrderCapturesAndReuse(t *testing.T) {
	for _, condition := range []string{`!a[1]==6`, `$a at 1 and !a[1]==6`} {
		p := mustCompileStreamingProgram(t, `rule p {strings:$a=/(abc|ab)/ wide nocase capture(part=1) condition:`+condition+`}`)
		encoded, err := p.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		restored, err := UnmarshalCompiledProgram(encoded)
		if err != nil {
			t.Fatal(err)
		}
		for _, program := range []*CompiledProgram{p, restored} {
			scanner := program.NewScanner(WithFastScan(), WithEvidence(32))
			for _, data := range [][]byte{{'!', 'A', 0, 'B', 0, 'C', 0, 'D', 0}, nil, {'!', 'A', 0, 'B', 0, 'C', 0, 'D', 0}} {
				result, err := scanner.Scan(data)
				if err != nil {
					t.Fatal(err)
				}
				if len(data) == 0 {
					if len(result.MatchedRules) != 0 {
						t.Fatal("stale match")
					}
					continue
				}
				matches := result.Matches["p"]["$a"]
				if len(result.MatchedRules) != 1 || len(matches) != 1 || matches[0].Offset != 1 || matches[0].Length != 6 || len(matches[0].Captures) != 1 {
					t.Fatalf("matches=%+v", matches)
				}
				capture := matches[0].Captures[0]
				if capture.Offset != 1 || capture.Length != 6 || !bytes.Equal(capture.Data, data[1:7]) {
					t.Fatalf("capture=%+v", capture)
				}
			}
			scanner.Close()
		}
	}
}

func TestLiteralAlternationAtomOrderManyBranches(t *testing.T) {
	alternatives := []string{"abc", "ab"}
	for i := 0; i < 257; i++ {
		alternatives = append(alternatives, fmt.Sprintf("x%03d", i))
	}
	p := mustCompileStreamingProgram(t, `rule p {strings:$a=/(`+strings.Join(alternatives, "|")+`)/ wide nocase condition:!a[1]==6}`)
	result, err := p.Scan([]byte{'A', 0, 'B', 0, 'C', 0})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.MatchedRules) != 1 {
		t.Fatalf("matches=%+v", result.Matches)
	}
}

func TestLiteralAlternationFormat12Policy(t *testing.T) {
	p := mustCompileStreamingProgram(t, `rule p {strings:$a=/(abc|ab)/ wide nocase condition:$a}`)
	payload, err := serializeProgram(p)
	if err != nil {
		t.Fatal(err)
	}
	pattern := payload.Rules[0].RegexPatterns["$a"]
	if pattern.BoundedAlternation == nil {
		t.Fatal("missing atom plan")
	}
	// Earlier format-12 compilers did not attach a plan to bare alternatives.
	// Preserve that policy on load; recompilation is what applies the fix.
	pattern.BoundedAlternation = nil
	payload.Rules[0].RegexPatterns["$a"] = pattern
	var legacy bytes.Buffer
	legacy.WriteString(compiledProgramMagic)
	if err := binary.Write(&legacy, binary.BigEndian, uint16(12)); err != nil {
		t.Fatal(err)
	}
	if err := gob.NewEncoder(&legacy).Encode(payload); err != nil {
		t.Fatal(err)
	}
	old, err := UnmarshalCompiledProgram(legacy.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	result, err := old.Scan([]byte{'A', 0, 'B', 0, 'C', 0, 'D', 0})
	if err != nil {
		t.Fatal(err)
	}
	matches := result.Matches["p"]["$a"]
	if len(matches) != 1 || matches[0].Length != 4 {
		t.Fatalf("legacy matches=%+v", matches)
	}
}

func TestLiteralAlternationAtomCandidateOrder(t *testing.T) {
	for _, tc := range []struct {
		pattern, modifier, input string
		length                   int
	}{
		{"abc|ab", "", "abcd", 2},
		{"abc|ab", "wide nocase", "A\x00B\x00C\x00D\x00", 6},
		{"abc|ab", "wide nocase", "a\x00b\x00c\x00d\x00", 4},
		{"abc|ab", "wide nocase", "a\x00b\x00C\x00D\x00", 4},
		{"ab|abc", "wide nocase", "A\x00B\x00C\x00D\x00", 4},
		{"ab|abc", "wide nocase", "a\x00b\x00c\x00d\x00", 6},
		{"abc|ab", "wide nocase fullword", "A\x00B\x00C\x00!\x00", 6},
	} {
		p := mustCompileStreamingProgram(t, fmt.Sprintf(`rule p {strings:$a=/(%s)/ %s condition:$a}`, tc.pattern, tc.modifier))
		result, err := p.Scan([]byte(tc.input))
		if err != nil {
			t.Fatal(err)
		}
		matches := result.Matches["p"]["$a"]
		if len(matches) != 1 || matches[0].Length != tc.length {
			t.Fatalf("/%s/ %s %x: matches=%+v, want %d", tc.pattern, tc.modifier, tc.input, matches, tc.length)
		}
	}
}
