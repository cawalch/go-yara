package compiler

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/regex"
)

// Occurrence lengths are observable in conditions, including when a shorter
// wide occurrence competes with an ASCII occurrence at the same byte offset.
func TestUnboundedAtomEndpoints(t *testing.T) {
	for _, tc := range []struct {
		pattern, mod, input string
		offsets, lengths    []int
	}{
		{`\x00(\x00|\x00a)+`, "ascii wide nocase", "\x00\x00\x00\x00\x00\x00", []int{0, 1, 2, 3, 4}, []int{6, 5, 4, 3, 2}},
		{`(abc|ab)+`, "wide nocase", "A\x00B\x00C\x00A\x00B\x00C\x00", []int{0, 6}, []int{10, 4}},
		{`(abc|ab)+`, "wide nocase", "a\x00b\x00c\x00a\x00b\x00c\x00", []int{0, 6}, []int{12, 6}},
		{`(abcd!!x|abcd!)+?`, "fullword", "abcd!!x", []int{0}, []int{7}},
		{`(abcd!|abcd!!x)+?`, "fullword", "abcd!!x", []int{0}, []int{5}},
		{`x(ab|a)+?`, "fullword", "xabab", []int{0}, []int{5}},
		{`(!a|!ab)+?`, "fullword", "!a!a", []int{0}, []int{2}},
		{`(ba|ba!!a)+?!`, "fullword", "baba!!a!!a", []int{0}, []int{5}},
		{`(ab|a)+?`, "", "abab", []int{0, 2}, []int{1, 1}},
		{`(a|ab)+xyz`, "", "ababxyz", []int{0, 2}, []int{7, 5}},
		{`(ab|a)*?xyz`, "", "ababxyz", []int{0, 2, 4}, []int{7, 5, 3}},
	} {
		t.Run(tc.pattern+tc.mod, func(t *testing.T) {
			source := fmt.Sprintf(`rule p{strings:$a=/%s/ %s condition:#a==%d and !a[1]==%d}`, tc.pattern, tc.mod, len(tc.offsets), tc.lengths[0])
			p := mustCompileStreamingProgram(t, source)
			encoded, err := p.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if version := binary.BigEndian.Uint16(encoded[len(compiledProgramMagic):]); version != 13 {
				t.Fatalf("version=%d", version)
			}
			restored, err := UnmarshalCompiledProgram(encoded)
			if err != nil {
				t.Fatal(err)
			}
			for _, program := range []*CompiledProgram{p, restored} {
				scanner := program.NewScanner(WithFastScan())
				defer scanner.Close()
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
					if len(result.MatchedRules) != 1 || len(matches) != len(tc.offsets) {
						t.Fatalf("matches=%+v", matches)
					}
					for i, m := range matches {
						if m.Offset != int64(tc.offsets[i]) || m.Length != tc.lengths[i] {
							t.Fatalf("match[%d]=%+v", i, m)
						}
					}
				}
			}
		})
	}
}

func TestUnboundedAtomCaptures(t *testing.T) {
	for _, condition := range []string{`$a`, `$a at 1 and !a[1]==7`} {
		p := mustCompileStreamingProgram(t, `rule p{strings:$a=/((abcd!!x|abcd!)+?)/ fullword capture(whole=1,last=2) condition:`+condition+`}`)
		result := scanEvidence(t, p, 32, "!abcd!!x!")
		matches := result.Matches["p"]["$a"]
		if len(matches) != 1 || len(matches[0].Captures) != 2 {
			t.Fatalf("matches=%+v", matches)
		}
		for _, capture := range matches[0].Captures {
			if capture.Offset != 1 || capture.Length != 7 || !bytes.Equal(capture.Data, []byte("abcd!!x")) {
				t.Fatalf("capture=%+v", capture)
			}
		}
	}
}

func TestUnboundedAtomReachabilityAndCancellation(t *testing.T) {
	parsed, err := regex.NewParser(0).Parse(`(aa|aaa)+?xyz`)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := compileUnboundedAlternation(parsed, true, false)
	if err != nil || plan == nil {
		t.Fatalf("plan=%+v, err=%v", plan, err)
	}
	for _, n := range []int{0, 1, 2, 3, 4, 63, 64, 65, 129, 1024} {
		data := []byte(strings.Repeat("a", n) + "xyz")
		end, _ := plan.execRepeat(data, 0, 0, nil)
		want := len(data)
		if n < 2 {
			want = -1
		}
		if end != want {
			t.Fatalf("n=%d end=%d want=%d", n, end, want)
		}
	}
	done := make(chan struct{})
	close(done)
	if end, _ := plan.execRepeat([]byte("aaaaxyz"), 0, 0, done); end != -1 {
		t.Fatalf("canceled end=%d", end)
	}
	if end, _ := plan.execRepeat([]byte("aaaaxyz"), 0, 0, nil); end != 7 {
		t.Fatalf("reused end=%d", end)
	}
}

func TestUnboundedAtomUnreachableSuffix(t *testing.T) {
	p := mustCompileStreamingProgram(t, `rule p{strings:$a=/(aa|aaaa)+xyz/ fullword condition:$a at 0}`)
	for _, n := range []int{1, 2, 3, 4, 63, 64, 65, 128, 129} {
		result, err := p.Scan([]byte(strings.Repeat("a", n) + "xyz"))
		if err != nil {
			t.Fatal(err)
		}
		if (len(result.MatchedRules) > 0) != (n%2 == 0) {
			t.Fatalf("n=%d matches=%+v", n, result.Matches)
		}
	}
}

func TestUnboundedAtomFormat12Policy(t *testing.T) {
	p := mustCompileStreamingProgram(t, `rule p{strings:$a=/(abc|ab)+/ wide nocase condition:$a}`)
	payload, err := serializeProgram(p)
	if err != nil {
		t.Fatal(err)
	}
	stored := payload.Rules[0].RegexPatterns["$a"]
	if stored.BoundedAlternation == nil || stored.BoundedAlternation.Repeat == nil {
		t.Fatal("missing repetition plan")
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
	result, err := old.Scan([]byte("A\x00B\x00C\x00"))
	if err != nil {
		t.Fatal(err)
	}
	matches := result.Matches["p"]["$a"]
	if len(matches) != 1 || matches[0].Length != 6 {
		t.Fatalf("legacy matches=%+v", matches)
	}
}
