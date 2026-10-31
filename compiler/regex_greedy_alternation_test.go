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
		"hello(a|ab)+b": false, "(a|ab){1,2}": false,
		"(a*|ab)+b": false, "(a$|ab)+b": false, "(a|ab)+b?": false,
	} {
		t.Run(pattern, func(t *testing.T) {
			parsed, err := regex.NewParser(0).Parse(pattern)
			if err != nil {
				t.Fatal(err)
			}
			if got := greedyLiteralAlternation(parsed); got != want {
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
