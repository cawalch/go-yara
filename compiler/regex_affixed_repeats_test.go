package compiler

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"testing"

	"github.com/cawalch/go-yara/regex"
)

func TestAffixedRepeatPlanSelection(t *testing.T) {
	for pattern, want := range map[string]bool{
		`xy(ab|a)+?`: true, `hello(ab|a)*?b`: true, `hello(ab|a)+?xyz`: true,
		`x(ab|a)+?`: false, `x(ab|a)+?xyz`: false, `(ab|a)+?xyz`: false,
		`x(a|ab){1,2}b`: true, `x(a|ab){1,2}?b`: true,
		`x(a|ab){0,2}xyz`: true, `hello(a|ab){0,0}b`: true,
		`(a|ab){9,9}xyz`: false, `x(a|[b]){1,2}b`: true,
		`hello(ab|[a])+?`: true, `(a|[b]){1,2}xyz`: false,
		`([a]|[b]){1,2}([c]|[d]){1,2}`: false,
	} {
		parsed, err := regex.NewParser(0).Parse(pattern)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := compileLiteralAffixes(ungroupRegexNode(parsed.Root), false, false)
		if err != nil {
			t.Fatal(err)
		}
		if (plan != nil) != want {
			t.Errorf("%s: plan=%v, want %v", pattern, plan != nil, want)
		}
	}
}

func TestAffixedRepeatCopyBounds(t *testing.T) {
	for _, tc := range []struct {
		pattern, input string
		length         int
	}{
		{`x(a|ab){1,2}b`, "xab", 3},
		{`x(a|ab){1,2}b`, "xababab", 5},
		{`x(a|ab){1,2}b`, "xaaab", 0},
		{`x(a|ab){1,2}?b`, "xabab", 3},
		{`x(a|ab){1,2}?a`, "xaaaa", 3},
		{`x(a|ab){0,2}b`, "xb", 2},
		{`(a|ab){0,2}xyz`, "xyz", 3},
		{`(a|ab){0,2}xyz`, "abxyz", 5},
		{`(a|ab){0,2}xyz`, "ababxyz", 7},
		{`(a|ab){2,3}xyz`, "abxyz", 0},
	} {
		p := mustCompileStreamingProgram(t, `rule p{strings:$a=/`+tc.pattern+`/ condition:$a at 0}`)
		result, err := p.Scan([]byte(tc.input))
		if err != nil {
			t.Fatal(err)
		}
		if tc.length == 0 {
			if len(result.MatchedRules) != 0 {
				t.Fatalf("%s: unexpected match", tc.pattern)
			}
			continue
		}
		matches := result.Matches["p"]["$a"]
		if len(result.MatchedRules) != 1 || len(matches) == 0 || matches[0].Offset != 0 || matches[0].Length != tc.length {
			t.Fatalf("%s on %s: matches=%+v", tc.pattern, tc.input, matches)
		}
	}
}

func TestAffixedRepeatCapturesAndFixedOffsets(t *testing.T) {
	for _, tc := range []struct {
		pattern, input, whole, last string
		lastOffset                  int64
	}{
		{`(xy(ab|a)+?)`, "!xyabab!", "xyab", "ab", 3},
		{`(x(a|ab){1,2}b)`, "!xabab!", "xabab", "a", 4},
	} {
		for _, condition := range []string{`$a`, `$a at 1`} {
			p := mustCompileStreamingProgram(t, `rule p{strings:$a=/`+tc.pattern+`/ capture(whole=1,last=2) condition:`+condition+`}`)
			encoded, err := p.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			restored, err := UnmarshalCompiledProgram(encoded)
			if err != nil {
				t.Fatal(err)
			}
			for _, program := range []*CompiledProgram{p, restored} {
				scanner := program.NewScanner(WithFastScan(), WithEvidence(64))
				for _, data := range [][]byte{[]byte(tc.input), nil, []byte(tc.input)} {
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
					if len(result.MatchedRules) != 1 || len(matches) != 1 || matches[0].Offset != 1 || matches[0].Length != len(tc.whole) || len(matches[0].Captures) != 2 {
						t.Fatalf("%s matches=%+v", tc.pattern, matches)
					}
					for _, capture := range matches[0].Captures {
						want, offset := tc.whole, int64(1)
						if capture.Name == "last" {
							want, offset = tc.last, tc.lastOffset
						}
						if capture.Offset != offset || capture.Length != len(want) || !bytes.Equal(capture.Data, []byte(want)) {
							t.Fatalf("%s capture=%+v", tc.pattern, capture)
						}
					}
				}
				scanner.Close()
			}
		}
	}
}

func TestAffixedRepeatFormat12Policy(t *testing.T) {
	for _, pattern := range []string{`xy(ab|a)+?`, `x(a|ab){1,2}b`} {
		p := mustCompileStreamingProgram(t, `rule p{strings:$a=/`+pattern+`/ condition:$a}`)
		payload, err := serializeProgram(p)
		if err != nil {
			t.Fatal(err)
		}
		stored := payload.Rules[0].RegexPatterns["$a"]
		if stored.BoundedAlternation == nil {
			t.Fatal("missing plan")
		}
		stored.BoundedAlternation = nil
		payload.Rules[0].RegexPatterns["$a"] = stored
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
		data := []byte("xabab")
		if pattern == `xy(ab|a)+?` {
			data = []byte("xyabab")
		}
		result, err := old.Scan(data)
		if err != nil {
			t.Fatal(err)
		}
		matches := result.Matches["p"]["$a"]
		if len(matches) != 1 || matches[0].Length != 3 {
			t.Fatalf("legacy %s: %+v", pattern, matches)
		}
	}
}
