package compiler

import "testing"

func TestLazyPositiveCapturesAndFastScan(t *testing.T) {
	program := mustCompileStreamingProgram(t, `rule probe { strings:$a=/(a+?)/ capture(part=1) condition:!a[1]==1 }`)
	result := scanEvidence(t, program, 32, "aaa!")
	matches := result.Matches["probe"]["$a"]
	if len(matches) != 3 {
		t.Fatalf("matches=%+v", matches)
	}
	for index, match := range matches {
		if match.Offset != int64(index) || match.Length != 1 || len(match.Captures) != 1 {
			t.Fatalf("match=%+v", match)
		}
		capture := match.Captures[0]
		if capture.Offset != int64(index) || capture.Length != 1 || string(capture.Data) != "a" {
			t.Fatalf("capture=%+v", capture)
		}
	}
	program = mustCompileStreamingProgram(t, `rule p {strings:$a=/a+?/ condition:$a}`)
	scanner := program.NewScanner(WithFastScan())
	defer scanner.Close()
	for _, input := range [][]byte{[]byte("aaa!"), nil, []byte("aa\x00")} {
		result, err := scanner.Scan(input)
		if err != nil {
			t.Fatal(err)
		}
		matches := result.Matches["p"]["$a"]
		if len(input) == 0 {
			if len(matches) != 0 {
				t.Fatalf("stale matches=%v", matches)
			}
			continue
		}
		if len(matches) != 1 || matches[0].Offset != 0 || matches[0].Length != 1 {
			t.Fatalf("fast matches=%v", matches)
		}
	}
}
