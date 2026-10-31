package compiler

import (
	"testing"

	"github.com/cawalch/go-yara/regex"
)

func TestGreedyLiteralAlternationSelection(t *testing.T) {
	for pattern, want := range map[string]bool{
		"(a|ab)+b": true, "(ab|a)+": true, "((a|ab)|aba)+b": true,
		"(a|ab)*(ab)": true,
		"(A|ab)+b":    true, "(a|b)+b": false, "(abc|abd)+b": false,
		"(a|ab)*": false, "(a|ab)+?b": false, "(ab|a)": false,
		"x(a|ab)+b": true, "x(ab|a)+b": true, "x(a|ab)*xyz": true,
		"hello(a|ab)+b": false, "x(a|ab)*b": false, "!(a|ab)+b": false,
		"x(a|abc|b)+": true, "x(a|abcde|bc|d)+": false,
		"x(a|a!)+a": true, "x(a|a!)*aaa": true,
		"x(a|ab)+?b": false, "x(a|ab){1,2}b": false, "(a|ab){1,2}": false,
		"(a*|ab)+b": false, "(a$|ab)+b": false, "(a|ab)+b?": false,
	} {
		t.Run(pattern, func(t *testing.T) {
			parsed, err := regex.NewParser(0).Parse(pattern)
			if err != nil {
				t.Fatal(err)
			}
			if got := greedyLiteralAlternation(parsed, 0, false); got != want {
				t.Fatalf("selection = %v, want %v", got, want)
			}
		})
	}
}

func TestGreedyAlternationCaptures(t *testing.T) {
	program := mustCompileStreamingProgram(t, `rule probe {
		strings: $a = /(a|ab)+b/ capture(part = 1)
		condition: !a[1] == 4
	}`)
	result := scanEvidence(t, program, 32, "abab")
	matches := result.Matches["probe"]["$a"]
	if len(matches) != 2 || matches[0].Length != 4 || len(matches[0].Captures) != 1 {
		t.Fatalf("matches = %+v", matches)
	}
	capture := matches[0].Captures[0]
	if capture.Offset != 2 || capture.Length != 1 || string(capture.Data) != "a" {
		t.Fatalf("capture = %+v, want the last repetition at [2,3)", capture)
	}
}

func TestPrefixedGreedyWideAtomCoverage(t *testing.T) {
	for pattern, want := range map[string]bool{"x(a|ab)+b": true, "x(a|abc|b)+": false, "x(a|abc|b)+xyz": true} {
		parsed, err := regex.NewParser(0).Parse(pattern)
		if err != nil {
			t.Fatal(err)
		}
		if got := greedyLiteralAlternation(parsed, regex.FlagsWide, false); got != want {
			t.Fatalf("%s: selection=%v, want %v", pattern, got, want)
		}
	}
}

func TestPrefixedGreedyCapturesAndReuse(t *testing.T) {
	p := mustCompileStreamingProgram(t, `rule p {strings:$a=/x(a|ab)+b/ capture(part=1) condition:!a[1]==5}`)
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
		for _, data := range [][]byte{[]byte("xabab"), nil, []byte("xabab")} {
			r, err := scanner.Scan(data)
			if err != nil {
				t.Fatal(err)
			}
			if len(data) == 0 {
				if len(r.MatchedRules) != 0 {
					t.Fatal("stale matches")
				}
				continue
			}
			matches := r.Matches["p"]["$a"]
			if len(matches) != 1 || matches[0].Length != 5 || len(matches[0].Captures) != 1 {
				t.Fatalf("matches=%+v", matches)
			}
			capture := matches[0].Captures[0]
			if capture.Offset != 3 || capture.Length != 1 {
				t.Fatalf("capture=%+v", capture)
			}
		}
		scanner.Close()
	}
}

func TestPrefixedGreedyFullwordContinuationGuard(t *testing.T) {
	for pattern, want := range map[string]bool{"x(a|ab)+b": true, "x(a|a!)+a": false, "x(a|a!)*aaa": true} {
		parsed, err := regex.NewParser(0).Parse(pattern)
		if err != nil {
			t.Fatal(err)
		}
		if got := greedyLiteralAlternation(parsed, 0, true); got != want {
			t.Fatalf("%s: selection=%v, want %v", pattern, got, want)
		}
	}
}

func TestPrefixedGreedyFixedOffset(t *testing.T) {
	p := mustCompileStreamingProgram(t, `rule p {strings:$a=/x(a|ab)+b/ condition:$a at 1 and !a[1]==5}`)
	result, err := p.Scan([]byte("!xabab"))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.MatchedRules) != 1 {
		t.Fatalf("matches=%+v", result.Matches)
	}
}
