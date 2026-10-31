package compiler

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/regex"
)

func TestLazyFullwordPlusEligibility(t *testing.T) {
	for pattern, want := range map[string]bool{
		`a+?`: true, `(a!)+?`: true, `(ab|a)+?`: true, `(a|ab)+?`: true,
		`((a|ab)|ABC123)+?`: true, `(a|abcdefgh)+?`: true, `(a|b)+?`: true,
		`(a|a!)+?`: false, `(a|a_)+?`: false, `(a|\x00a)+?`: false,
		`(a|\xff)+?`: false, `(ab|[a])+?`: false, `(a|ab)+`: false,
		`(a|ab)*?`: false, `(a|ab){1,2}?`: false, `x(a|ab)+?`: false,
		`(a|ab)+?b`: false, `(a*|ab)+?`: false,
		`(a|` + strings.Repeat("a", 17<<10) + `)+?`:  true,
		`(a|` + strings.Repeat("a", 17<<10) + `!)+?`: false,
	} {
		parsed, err := regex.NewParser(0).Parse(pattern)
		if err != nil {
			t.Fatal(err)
		}
		if got := lazyFullwordPlus(parsed); got != want {
			t.Errorf("%.80s: eligible=%v, want %v", pattern, got, want)
		}
	}
}

func TestLazyFullwordPlusCapturesAndReuse(t *testing.T) {
	for _, condition := range []string{`$a`, `$a at 1 and !a[1]==4`} {
		p := mustCompileStreamingProgram(t, `rule p{strings:$a=/((ab|a)+?)/ fullword capture(part=1) condition:`+condition+`}`)
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
			for _, data := range [][]byte{[]byte("!abab!"), nil, []byte("!abab!")} {
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
				if len(result.MatchedRules) != 1 || len(matches) != 1 || matches[0].Offset != 1 || matches[0].Length != 4 || len(matches[0].Captures) != 1 {
					t.Fatalf("matches=%+v", matches)
				}
				capture := matches[0].Captures[0]
				if capture.Offset != 1 || capture.Length != 4 || !bytes.Equal(capture.Data, []byte("abab")) {
					t.Fatalf("capture=%+v", capture)
				}
			}
			scanner.Close()
		}
	}
}

func TestLazyFullwordPlusSharedCache(t *testing.T) {
	p := mustCompileStreamingProgram(t, `rule p{strings:$a=/(abc|ab)+?/ fullword $b=/(abc|ab)+?/ $guard="!" condition:$guard and #a==1 and !a[1]==6 and #b==2 and !b[1]==2}`)
	data := []byte("abcabc!")
	if !shouldUseSharedPatternAutomaton(data, p) || len(p.sharedLookup) < 3 {
		t.Fatal("fixture must use shared automaton")
	}
	result, err := p.Scan(data)
	if err != nil || len(result.MatchedRules) != 1 {
		t.Fatalf("result=%+v, err=%v", result, err)
	}
}

func TestLazyFullwordPlusFormat12Policy(t *testing.T) {
	p := mustCompileStreamingProgram(t, `rule p{strings:$a=/(ab|a)+?/ fullword condition:$a}`)
	payload, err := serializeProgram(p)
	if err != nil {
		t.Fatal(err)
	}
	pattern := payload.Rules[0].RegexPatterns["$a"]
	if pattern.Flags&regex.FlagsFullwordEnd == 0 {
		t.Fatal("missing fullword retry policy")
	}
	pattern.Flags &^= regex.FlagsFullwordEnd
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
	result, err := old.Scan([]byte("ab"))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.MatchedRules) != 0 {
		t.Fatalf("legacy matches=%+v", result.Matches)
	}
}
