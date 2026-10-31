package compiler

import "testing"

func TestZeroLengthFullword(t *testing.T) {
	for _, modifier := range []string{"fullword", "wide fullword", "ascii wide fullword"} {
		for _, tc := range []struct {
			input string
			count int
		}{
			{"!", 1}, {"!!", 2}, {"_", 1}, {"b", 0}, {"!b", 1}, {"b!", 0}, {"!\x00!\x00", 4}, {"", 0},
		} {
			t.Run(modifier+"/"+tc.input, func(t *testing.T) {
				p := mustCompileStreamingProgram(t, `rule p {strings:$a=/a{0}/ `+modifier+` condition:$a}`)
				result, err := p.Scan([]byte(tc.input))
				if err != nil {
					t.Fatal(err)
				}
				matches := result.Matches["p"]["$a"]
				if len(matches) != tc.count {
					t.Fatalf("matches=%+v, want %d", matches, tc.count)
				}
				for _, m := range matches {
					if m.Length != 0 || m.Offset >= int64(len(tc.input)) {
						t.Fatalf("invalid span: %+v", m)
					}
				}
			})
		}
	}
}

func TestRegexEmptyInputHasNoOccurrences(t *testing.T) {
	for _, pattern := range []string{`a*`, `^a*`, `a{0}`, `^$`, `$`} {
		p := mustCompileStreamingProgram(t, `rule p {strings:$a=/`+pattern+`/ condition:#a==0 and not $a}`)
		result, err := p.Scan(nil)
		if err != nil || len(result.MatchedRules) != 1 {
			t.Fatalf("%s result=%+v err=%v", pattern, result, err)
		}
		ctx := BuildMatchContext(p.Rules[0], nil)
		if len(ctx.Matches["$a"]) != 0 {
			t.Errorf("%s public context=%+v", pattern, ctx.Matches)
		}
		ctx.Release()
	}
}

func TestFullwordRejectsNegativeSpan(t *testing.T) {
	for _, wide := range []bool{false, true} {
		if isFullwordMatch([]byte("!!"), 0, -1, wide) || isFullwordMatch([]byte("!!"), -1, 0, wide) {
			t.Fatal("invalid span accepted")
		}
	}
}

func TestZeroLengthFullwordFastScan(t *testing.T) {
	p := mustCompileStreamingProgram(t, `rule p {strings:$a=/a*/ ascii wide fullword condition:$a}`)
	s := p.NewScanner(WithFastScan())
	defer s.Close()
	for _, data := range []string{"!!", "b!", "", "!!"} {
		result, err := s.Scan([]byte(data))
		if err != nil || (len(result.MatchedRules) > 0) != (data == "!!") {
			t.Fatalf("data=%q result=%+v err=%v", data, result, err)
		}
	}
}
