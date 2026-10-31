package compiler

import "testing"

func TestRegexFullwordAlternativeSelection(t *testing.T) {
	for _, tc := range []struct {
		pattern, input string
		length         int
	}{
		{`a|ab`, "ab", 2}, {`ab|a`, "ab", 2},
		{`(a|ab)+`, "abab", 4}, {`(a|ab)+b`, "ababb", 5},
		{`[a!]+`, "a!ab", 0}, {`abcd(e|ef)`, "abcdef", 0},
		{`a|a!`, "a!", 1}, {`a!|a`, "a!", 1},
		{`a|ab`, "abc", 0}, {`a|ab`, "zab", 0},
	} {
		t.Run(tc.pattern+"/"+tc.input, func(t *testing.T) {
			p := mustCompileStreamingProgram(t, `rule p { strings: $a=/`+tc.pattern+`/ fullword condition: $a }`)
			result, err := p.Scan([]byte(tc.input))
			if err != nil {
				t.Fatal(err)
			}
			matches := result.Matches["p"]["$a"]
			if tc.length == 0 {
				if len(matches) != 0 {
					t.Fatalf("unexpected matches: %+v", matches)
				}
				return
			}
			if len(matches) != 1 || matches[0].Length != tc.length {
				t.Fatalf("matches=%+v, want length %d", matches, tc.length)
			}
		})
	}
}

func TestRegexFullwordSharedCache(t *testing.T) {
	p := mustCompileStreamingProgram(t, `rule p {strings:
 $a=/ab|abc/ fullword $b=/ab|abcd/ fullword $guard="!"
 condition: $guard and #a==1 and !a==3 and not $b
 }`)
	data := []byte("abc!")
	if !shouldUseSharedPatternAutomaton(data, p) || len(p.sharedLookup) < 3 {
		t.Fatal("fixture must route regex candidates through the shared automaton")
	}
	result, err := p.Scan(data)
	if err != nil || len(result.MatchedRules) != 1 {
		t.Fatalf("result=%+v, err=%v", result, err)
	}
}

func TestRegexFullwordCaptures(t *testing.T) {
	p := mustCompileStreamingProgram(t, `rule p {strings: $a=/(a|ab)/ fullword capture(value=1) condition: !a==2}`)
	result := scanEvidence(t, p, 32, "ab")
	matches := result.Matches["p"]["$a"]
	if len(matches) != 1 || matches[0].Length != 2 || len(matches[0].Captures) != 1 {
		t.Fatalf("matches=%+v", matches)
	}
	capture := matches[0].Captures[0]
	if capture.Offset != 0 || capture.Length != 2 || string(capture.Data) != "ab" {
		t.Fatalf("capture=%+v", capture)
	}
}
