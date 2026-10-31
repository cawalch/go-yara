package compiler

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/regex"
)

func TestLiteralAffixCapturesAndFixedOffsets(t *testing.T) {
	for _, condition := range []string{`$a`, `$a at 1 and !a[1]==3`} {
		p := mustCompileStreamingProgram(t, `rule p {strings:$a=/x(a|ab)/ fullword capture(part=1) condition:`+condition+`}`)
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
			for _, data := range [][]byte{[]byte("!xab!"), nil, []byte("!xab!")} {
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
				if len(result.MatchedRules) != 1 || len(matches) != 1 || matches[0].Offset != 1 || matches[0].Length != 3 || len(matches[0].Captures) != 1 {
					t.Fatalf("matches=%+v", matches)
				}
				capture := matches[0].Captures[0]
				if capture.Offset != 2 || capture.Length != 2 || !bytes.Equal(capture.Data, []byte("ab")) {
					t.Fatalf("capture=%+v", capture)
				}
			}
			scanner.Close()
		}
	}
}

func TestLiteralAffixAtomSelection(t *testing.T) {
	for _, tc := range []struct {
		pattern, input string
		length         int
	}{
		{`x(a|ab)`, "xab", 3}, {`abcd(e|ef)`, "abcdef", 0},
		{`abcd(ef|e)`, "abcdef", 6}, {`x(a|ab)(cd|c)`, "xabcd", 5},
		{`x(a|ab)(c|cd)`, "xabcd", 0}, {`(a|ab)(c|cd)xyz`, "abcdxyz", 7},
		{`aaa(bbb|bbbb!)`, "aaabbbb!", 8},
		{`xy(a|abcdef)`, "xyabcdef", 0}, {`xy(abcdef|a)`, "xyabcdef", 8},
	} {
		p := mustCompileStreamingProgram(t, `rule p {strings:$a=/`+tc.pattern+`/ fullword condition:$a}`)
		result, err := p.Scan([]byte(tc.input))
		if err != nil {
			t.Fatal(err)
		}
		matches := result.Matches["p"]["$a"]
		if tc.length == 0 {
			if len(matches) != 0 {
				t.Fatalf("%s: matches=%+v", tc.pattern, matches)
			}
			continue
		}
		if len(matches) != 1 || matches[0].Length != tc.length {
			t.Fatalf("%s: matches=%+v, want length %d", tc.pattern, matches, tc.length)
		}
	}
}

func TestLiteralAffixEligibilityAndBudgets(t *testing.T) {
	for pattern, want := range map[string]bool{
		`x(a|ab)`: true, `(a|ab)xyz`: true, `(a|aa)(a|aa)xyz`: true,
		`hello`: false, `x(ab|cd)`: false, `x(a|[b])`: false, `x(a|ab)+b`: false,
		`x(a|ab){1,2}b`: true,
		`(a|ab)` + strings.Repeat(`(a|b)`, 8) + `aaa`:          false,
		strings.Repeat("a", maxLiteralAffixBytes+1) + `(a|ab)`: false,
	} {
		parsed, err := regex.NewParser(0).Parse(pattern)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := compileLiteralAffixes(ungroupRegexNode(parsed.Root), true, false)
		if err != nil {
			t.Fatal(err)
		}
		if (plan != nil) != want {
			t.Fatalf("%.80s: has plan=%v, want %v", pattern, plan != nil, want)
		}
	}
	// The two decompositions of "aaa" are equivalent before the selected atom.
	parsed, err := regex.NewParser(0).Parse(`(a|aa)(a|aa)xyz`)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := compileLiteralAffixes(parsed.Root, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Branches) != 3 {
		t.Fatalf("prefixes=%d, want 3 unique literals", len(plan.Branches))
	}
}

func TestLiteralAffixFormat12Policy(t *testing.T) {
	p := mustCompileStreamingProgram(t, `rule p {strings:$a=/x(a|ab)/ fullword condition:$a}`)
	payload, err := serializeProgram(p)
	if err != nil {
		t.Fatal(err)
	}
	pattern := payload.Rules[0].RegexPatterns["$a"]
	if pattern.BoundedAlternation == nil {
		t.Fatal("missing plan")
	}
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
	result, err := old.Scan([]byte("xab"))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.MatchedRules) != 0 {
		t.Fatalf("legacy matches=%+v", result.Matches)
	}
}

func TestLiteralAffixAtomLocations(t *testing.T) {
	p := mustCompileStreamingProgram(t, `rule p {strings:$a=/(aa|a)aaaa/ condition:$a}`)
	result, err := p.Scan([]byte("aaaaaa"))
	if err != nil {
		t.Fatal(err)
	}
	matches := result.Matches["p"]["$a"]
	if len(matches) != 2 || matches[0].Length != 5 || matches[1].Offset != 1 || matches[1].Length != 5 {
		t.Fatalf("matches=%+v", matches)
	}
}
