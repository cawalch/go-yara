package compiler

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"strconv"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/regex"
)

func TestSymbolicPrefixBudgets(t *testing.T) {
	for _, n := range []int{7, 8, 20, 64} {
		pattern := `(a|ab)` + strings.Repeat(`(a|b)`, n) + `aaa`
		parsed, err := regex.NewParser(0).Parse(pattern)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := compileLiteralAffixes(parsed.Root, true, false)
		if err != nil || plan == nil {
			t.Fatalf("n=%d plan=%v err=%v", n, plan, err)
		}
		if (plan.Prefix != nil) != (n >= 8) {
			t.Fatalf("n=%d symbolic=%v", n, plan.Prefix != nil)
		}
		if n >= 8 && (len(plan.Branches) != 1 || len(plan.Prefix) > 32*n+32) {
			t.Fatalf("expanded language: branches=%d code=%d", len(plan.Branches), len(plan.Prefix))
		}
		program := mustCompileStreamingProgram(t, `rule p{strings:$a=/`+pattern+`/ fullword condition:#a==1 and !a[1]==`+strconv.Itoa(n+5)+`}`)
		result, err := program.Scan([]byte("ab" + strings.Repeat("a", n) + "aaa"))
		if err != nil || len(result.MatchedRules) != 1 {
			t.Fatalf("n=%d result=%+v err=%v", n, result, err)
		}
	}
	for _, pattern := range []string{
		strings.Repeat(`\x00`, 70) + `(a|ab)` + strings.Repeat(`(a|b)`, 7) + `xyz!`,
		`(a|ab)` + strings.Repeat(`(a|b)`, 7) + strings.Repeat(`\x00`, 70) + `xyz!`,
	} {
		parsed, err := regex.NewParser(0).Parse(pattern)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := compileLiteralAffixes(parsed.Root, true, true)
		if err != nil || plan == nil || plan.Prefix == nil || len(plan.Branches) != 1 || !plan.CheckEncodingOrder {
			t.Fatalf("byte-budget plan=%+v err=%v", plan, err)
		}
	}
}

func TestSymbolicPrefixCapturesAndReuse(t *testing.T) {
	pattern := `((a|ab)` + strings.Repeat(`(a|b)`, 8) + `aaa)`
	for _, condition := range []string{`$a`, `$a at 1 and !a[1]==13`} {
		p := mustCompileStreamingProgram(t, `rule p{strings:$a=/`+pattern+`/ fullword capture(whole=1,first=2) condition:`+condition+`}`)
		encoded, err := p.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if version := binary.BigEndian.Uint16(encoded[len(compiledProgramMagic):]); version != 14 {
			t.Fatalf("version=%d", version)
		}
		restored, err := UnmarshalCompiledProgram(encoded)
		if err != nil {
			t.Fatal(err)
		}
		for _, program := range []*CompiledProgram{p, restored} {
			scanner := program.NewScanner(WithFastScan(), WithEvidence(64))
			defer scanner.Close()
			for _, data := range [][]byte{[]byte("!abaaaaaaaaaaa!"), nil, []byte("!abaaaaaaaaaaa!")} {
				result, err := scanner.Scan(data)
				if err != nil {
					t.Fatal(err)
				}
				if len(data) == 0 {
					if len(result.MatchedRules) > 0 {
						t.Fatal("stale match")
					}
					continue
				}
				matches := result.Matches["p"]["$a"]
				if len(result.MatchedRules) != 1 || len(matches) != 1 || matches[0].Offset != 1 || matches[0].Length != 13 || len(matches[0].Captures) != 2 {
					t.Fatalf("matches=%+v", matches)
				}
				for _, capture := range matches[0].Captures {
					want := "abaaaaaaaaaaa"
					if capture.Name == "first" {
						want = "ab"
					}
					if capture.Offset != 1 || capture.Length != len(want) || !bytes.Equal(capture.Data, []byte(want)) {
						t.Fatalf("capture=%+v", capture)
					}
				}
			}
		}
	}
}

func TestSymbolicPrefixFormat13Policy(t *testing.T) {
	p := mustCompileStreamingProgram(t, `rule p{strings:$a=/(a|ab)`+strings.Repeat(`(a|b)`, 8)+`aaa/ fullword condition:$a}`)
	payload, err := serializeProgram(p)
	if err != nil {
		t.Fatal(err)
	}
	stored := payload.Rules[0].RegexPatterns["$a"]
	if stored.BoundedAlternation == nil || stored.BoundedAlternation.Prefix == nil {
		t.Fatal("missing symbolic prefix")
	}
	stored.BoundedAlternation = nil
	payload.Rules[0].RegexPatterns["$a"] = stored
	var legacy bytes.Buffer
	legacy.WriteString(compiledProgramMagic)
	if err := binary.Write(&legacy, binary.BigEndian, uint16(13)); err != nil {
		t.Fatal(err)
	}
	if err := gob.NewEncoder(&legacy).Encode(payload); err != nil {
		t.Fatal(err)
	}
	old, err := UnmarshalCompiledProgram(legacy.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	result, err := old.Scan([]byte("abaaaaaaaaaaa"))
	if err != nil || len(result.MatchedRules) != 0 {
		t.Fatalf("legacy result=%+v err=%v", result, err)
	}
}

func TestSymbolicPrefixAtomBounds(t *testing.T) {
	for _, tc := range []struct {
		prefix string
		length int
	}{{`(a|aa)`, 12}, {`(a|aa){1,1}`, 17}} {
		pattern := tc.prefix + strings.Repeat(`(a|b)`, 8) + `(a\x00b\x00CCCC|\x00b)`
		p := mustCompileStreamingProgram(t, `rule p{strings:$a=/`+pattern+`/ fullword condition:#a==1 and !a[1]==`+strconv.Itoa(tc.length)+`}`)
		result, err := p.Scan([]byte(strings.Repeat("a", 10) + "\x00b\x00CCCC"))
		if err != nil || len(result.MatchedRules) != 1 {
			t.Fatalf("%s result=%+v err=%v", tc.prefix, result, err)
		}
	}
}
