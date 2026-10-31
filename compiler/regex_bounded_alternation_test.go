package compiler

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"strings"
	"testing"
)

func TestBoundedAlternationCapturesAndFixedOffset(t *testing.T) {
	for _, condition := range []string{`$a`, `$a at 1 and !a[1]==3`} {
		program := mustCompileStreamingProgram(t, `rule p {strings:$a=/(a|ab){1,2}/ capture(part=1) condition:`+condition+`}`)
		for _, restored := range []bool{false, true} {
			if restored {
				encoded, err := program.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				program, err = UnmarshalCompiledProgram(encoded)
				if err != nil {
					t.Fatal(err)
				}
			}
			result := scanEvidence(t, program, 32, "!abab")
			matches := result.Matches["p"]["$a"]
			if len(matches) != 2 || matches[0].Offset != 1 || matches[0].Length != 3 || matches[1].Offset != 3 || matches[1].Length != 2 {
				t.Fatalf("matches=%+v", matches)
			}
			capture := matches[0].Captures
			if len(capture) != 1 || capture[0].Offset != 3 || capture[0].Length != 1 || !bytes.Equal(capture[0].Data, []byte("a")) {
				t.Fatalf("captures=%+v", capture)
			}
		}
	}
}

func TestBoundedAlternationFastReuseAndLargeAlternation(t *testing.T) {
	alternatives := []string{"a", "ab"}
	for i := 0; i < 257; i++ {
		alternatives = append(alternatives, fmt.Sprintf("x%03d", i))
	}
	for _, pattern := range []string{`(a|ab){1,2}`, `(` + strings.Join(alternatives, "|") + `){1,2}`} {
		p := mustCompileStreamingProgram(t, `rule p {strings:$a=/`+pattern+`/ condition:$a}`)
		scanner := p.NewScanner(WithFastScan())
		for _, data := range [][]byte{[]byte("abab"), nil, []byte("abab")} {
			r, err := scanner.Scan(data)
			if err != nil {
				t.Fatal(err)
			}
			matches := r.Matches["p"]["$a"]
			if len(data) == 0 {
				if len(matches) != 0 {
					t.Fatal("stale matches")
				}
				continue
			}
			if len(matches) != 1 || matches[0].Offset != 0 || matches[0].Length != 3 {
				t.Fatalf("matches=%+v", matches)
			}
		}
		scanner.Close()
	}
}

func TestBoundedAlternationFormat11Compatibility(t *testing.T) {
	p := mustCompileStreamingProgram(t, `rule p {strings:$a=/(a|ab){1,2}/ condition:$a}`)
	encoded, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if version := binary.BigEndian.Uint16(encoded[len(compiledProgramMagic):]); version != 12 {
		t.Fatalf("version=%d", version)
	}
	payload, err := serializeProgram(p)
	if err != nil {
		t.Fatal(err)
	}
	pattern := payload.Rules[0].RegexPatterns["$a"]
	pattern.BoundedAlternation = nil
	payload.Rules[0].RegexPatterns["$a"] = pattern
	var legacy bytes.Buffer
	legacy.WriteString(compiledProgramMagic)
	if err := binary.Write(&legacy, binary.BigEndian, uint16(11)); err != nil {
		t.Fatal(err)
	}
	if err := gob.NewEncoder(&legacy).Encode(payload); err != nil {
		t.Fatal(err)
	}
	old, err := UnmarshalCompiledProgram(legacy.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	r, err := old.Scan([]byte("abab"))
	if err != nil {
		t.Fatal(err)
	}
	matches := r.Matches["p"]["$a"]
	if len(matches) != 2 || matches[0].Length != 1 || matches[1].Length != 1 {
		t.Fatalf("legacy matches=%+v", matches)
	}
}

// Golden atom locations from libyara 4.5.8's literal heuristic, including
// equal-quality windows and the penalty for repeated common bytes.
func TestBoundedAlternationAtomWindows(t *testing.T) {
	for literal, want := range map[string]int{"abcda": 0, "aaaa!": 1, "\x00\x00\x00\x00a": 1, "\x90\x90\x90\x90!": 1} {
		if got := boundedAtomOffset([]byte(literal)); got != want {
			t.Errorf("%x: offset %d, want %d", literal, got, want)
		}
	}
}

func TestBoundedAtomCandidateOrder(t *testing.T) {
	for _, tc := range []struct {
		pattern, modifier, input string
		length                   int
	}{
		{`(a|ab|bcde|c){1,2}`, "", "abcde", 3},
		{`(a|ab|bcde|c){1,2}`, "fullword", "abcde", 5},
		{`(abc|ab){1,2}`, "wide nocase", "A\x00B\x00C\x00A\x00B\x00C\x00", 4},
		{`(abc|ab){1,2}`, "wide nocase", "a\x00b\x00c\x00a\x00b\x00c\x00", 12},
		{`(ab|a){2,2}?`, "", "abab", 4},
		{`(a|ab){1,2}?`, "", "abab", 1},
		{`(\x21\x00a|!){1,2}`, "ascii wide nocase fullword", "!\x00a!\x00a", 6},
	} {
		p := mustCompileStreamingProgram(t, fmt.Sprintf(`rule p {strings:$a=/%s/ %s condition:#a>0}`, tc.pattern, tc.modifier))
		result, err := p.Scan([]byte(tc.input))
		if err != nil {
			t.Fatal(err)
		}
		matches := result.Matches["p"]["$a"]
		if len(matches) == 0 || matches[0].Offset != 0 || matches[0].Length != tc.length {
			t.Fatalf("/%s/ %s %x: matches=%+v, want length %d", tc.pattern, tc.modifier, tc.input, matches, tc.length)
		}
	}
}

func TestBoundedAlternationDualEncodingFixedOffset(t *testing.T) {
	for _, tc := range []struct {
		pattern, modifier, input string
		length                   int
	}{
		{`ab`, "ascii wide", "ab", 2},
		{`ab`, "ascii wide", "a\x00b\x00", 4},
		{`ab`, "wide", "ab", 0},
		{`ab`, "ascii wide", "ax", 0},
		{`(!\x00a|!){1,2}`, "ascii wide fullword", "!\x00a!\x00a", 6},
	} {
		p := mustCompileStreamingProgram(t, fmt.Sprintf(`rule p {strings:$a=/%s/ %s condition:$a at 0 and !a[1]==%d}`, tc.pattern, tc.modifier, tc.length))
		result, err := p.Scan([]byte(tc.input))
		if err != nil {
			t.Fatal(err)
		}
		if (len(result.MatchedRules) > 0) != (tc.length > 0) {
			t.Fatalf("/%s/ %s %x: matches=%+v", tc.pattern, tc.modifier, tc.input, result.Matches)
		}
	}
}
