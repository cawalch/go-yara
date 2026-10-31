package compiler

import (
	"bytes"
	"fmt"
	"testing"
)

func TestRegexEncodingCollisionSelection(t *testing.T) {
	for _, tc := range []struct {
		pattern, data string
		length        int
	}{
		{`/a+/`, "a\x00", 2},
		{`/[ab]+/`, "a\x00", 2},
		{`/a.*/`, "a\x00bcd", 2}, // Wide wins even when ASCII is longer.
		{`/a+?/`, "a\x00", 1},
		{`/a/`, "a\x00", 1},
		{`"a"`, "a\x00", 1},
	} {
		for _, modifiers := range []string{"ascii wide", "wide ascii"} {
			t.Run(tc.pattern+"/"+modifiers, func(t *testing.T) {
				source := fmt.Sprintf(`rule probe { strings: $a = %s %s condition: #a == 1 and !a[1] == %d }`, tc.pattern, modifiers, tc.length)
				program := mustCompileStreamingProgram(t, source)
				for mode, opts := range map[string][]ScannerOption{
					"normal": nil, "fast": {WithFastScan()},
					"compact": {WithoutMatches(), WithoutRuleResults()},
				} {
					t.Run(mode, func(t *testing.T) {
						scanner := program.NewScanner(opts...)
						defer scanner.Close()
						for _, data := range [][]byte{[]byte(tc.data), []byte("!"), []byte(tc.data)} {
							for _, scan := range []func() (*ScanResult, error){
								func() (*ScanResult, error) { return scanner.Scan(data) },
								func() (*ScanResult, error) { return scanner.ScanReader(bytes.NewReader(data)) },
							} {
								result, err := scan()
								if err != nil {
									t.Fatal(err)
								}
								if got := len(result.MatchedRules) > 0; got != bytes.Equal(data, []byte(tc.data)) {
									t.Fatalf("data %x: result = %+v", data, result)
								}
							}
						}
					})
				}
				ctx := BuildMatchContext(program.Rules[0], []byte(tc.data))
				defer ctx.Release()
				matches := ctx.Matches["$a"]
				if len(matches) != 1 || matches[0].Length != tc.length {
					t.Fatalf("public context matches = %+v, want one length-%d match", matches, tc.length)
				}
			})
		}
	}
}

func TestRegexEncodingCollisionCaches(t *testing.T) {
	for _, tc := range []struct {
		name, source, data string
	}{
		{"fixed", `rule probe { strings:
			$a = /[a]{1}/ ascii wide
			$b = /[a]/ ascii wide
			condition: #a == 1 and !a == 2 and #b == 1 and !b == 1
		}`, "a\x00"},
		{"shared", `rule probe { strings:
			$a = /a\x00+/ ascii wide
			$b = /a\x00/ ascii wide
			$guard = "!"
			condition: $guard and #a == 1 and !a == 4 and #b == 1 and !b == 2
		}`, "a\x00\x00\x00\x00!"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			program := mustCompileStreamingProgram(t, tc.source)
			data := []byte(tc.data)
			if tc.name == "fixed" && !shouldUseFixedRegexDispatch(data, program.fixedRegexScan) {
				t.Fatal("fixture must exercise fixed regex dispatch")
			}
			if tc.name == "shared" && (!shouldUseSharedPatternAutomaton(data, program) || len(program.sharedLookup) < 5) {
				t.Fatal("fixture must route both regex encodings through the shared automaton")
			}
			result, err := program.Scan(data)
			if err != nil || len(result.MatchedRules) != 1 {
				t.Fatalf("result = %+v, err = %v", result, err)
			}
		})
	}
}

func TestRegexEncodingCollisionEvidence(t *testing.T) {
	program := mustCompileStreamingProgram(t, `rule probe {
		strings: $a = /(a+)/ ascii wide capture(value = 1)
		condition: #a == 1 and !a == 2
	}`)
	result := scanEvidence(t, program, 32, "a\x00")
	matches := result.Matches["probe"]["$a"]
	if len(matches) != 1 || matches[0].Length != 2 || len(matches[0].Captures) != 1 {
		t.Fatalf("matches = %+v", matches)
	}
	capture := matches[0].Captures[0]
	if capture.Offset != 0 || capture.Length != 2 || string(capture.Data) != "a\x00" {
		t.Fatalf("capture = %+v, want the wide occurrence", capture)
	}
}
