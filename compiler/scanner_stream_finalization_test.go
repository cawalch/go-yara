package compiler

import (
	"bytes"
	"strconv"
	"testing"
)

func TestStreamBoundedRegexFinalization(t *testing.T) {
	for _, chunk := range []int{1, 2, 3, 4, 8, defaultStreamChunkSize} {
		t.Run(strconv.Itoa(chunk), func(t *testing.T) {
			p := mustCompileStreamingProgram(t, `rule positive {strings:$a=/a.{0,3}b/ condition:#a==2 and !a[1]==5}
rule inverse {strings:$a=/a.{0,3}b/ condition:#a==2 and !a[1]!=5}`)
			prefix := 0
			if chunk == defaultStreamChunkSize {
				prefix = chunk - 2
			}
			data := append(bytes.Repeat([]byte("!"), prefix), []byte("ab ab")...)
			for _, opts := range [][]ScannerOption{nil, {WithFastScan()}, {WithoutMatches(), WithoutRuleResults()}} {
				s := p.NewScanner(append([]ScannerOption{WithStreamChunkSize(chunk), WithStreamEarlyTermination(false)}, opts...)...)
				result, err := s.ScanReader(bytes.NewReader(data))
				s.Close()
				if err != nil || len(result.MatchedRules) != 1 || result.MatchedRules[0].Rule != "positive" {
					t.Fatalf("result=%+v err=%v", result, err)
				}
				if result.Matches != nil {
					matches := result.Matches["positive"]["$a"]
					if len(matches) != 2 || matches[0].Offset != int64(prefix) || matches[0].Length != 5 || matches[1].Offset != int64(prefix+3) || matches[1].Length != 2 {
						t.Fatalf("matches=%+v", matches)
					}
				}
			}
		})
	}
}

func TestStreamBoundedRegexAutomaticOverlap(t *testing.T) {
	for _, wide := range []bool{false, true} {
		modifier := ""
		if wide {
			modifier = "wide"
		}
		// Keep the match above the default overlap, with each side of the
		// selected XYZ atom inside libyara's 4096-byte verification limit.
		gap := 2500
		if wide {
			gap = 1500
		}
		p := mustCompileStreamingProgram(t, `rule p {strings:$a=/a.{`+strconv.Itoa(gap)+`}XYZ.{`+strconv.Itoa(gap)+`}b/ `+modifier+` condition:#a==1}`)
		data := append([]byte("a"), bytes.Repeat([]byte("x"), gap)...)
		data = append(data, []byte("XYZ")...)
		data = append(data, bytes.Repeat([]byte("x"), gap)...)
		data = append(data, 'b')
		if wide {
			expanded := make([]byte, len(data)*2)
			for i, b := range data {
				expanded[2*i] = b
			}
			data = expanded
		}
		s := p.NewScanner(WithStreamChunkSize(1024))
		result, err := s.ScanReader(bytes.NewReader(data))
		s.Close()
		if err != nil || len(result.MatchedRules) != 1 {
			t.Fatalf("wide=%v result=%+v err=%v", wide, result, err)
		}
		matches := result.Matches["p"]["$a"]
		if len(matches) != 1 || matches[0].Offset != 0 || matches[0].Length != len(data) || !bytes.Equal(matches[0].MatchedData, data) {
			t.Fatalf("wide=%v matches=%+v", wide, matches)
		}
	}
}

func TestStreamFastScanFiltersOwnershipBeforeClipping(t *testing.T) {
	for _, tc := range []struct {
		pattern, input, buffer string
		overlap                int
		offset                 int64
	}{
		{`/^ab|cd/`, "xxxxxxxxxxabcdxxxcd", "cd", 4, 12},
		{`/ab/ fullword`, "xxxxxxab!ab!xxxxx", "ab", 5, 9},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			p := mustCompileStreamingProgram(t, `rule p {strings:$a=`+tc.pattern+` condition:$a}`)
			s := p.NewScanner(WithStreamChunkSize(1), WithStreamOverlapSize(tc.overlap), WithFastScan())
			defer s.Close()
			result, err := s.ScanReader(bytes.NewReader([]byte(tc.input)))
			if err != nil || len(result.MatchedRules) != 1 {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			matches := result.Matches["p"]["$a"]
			if len(matches) != 1 || matches[0].Offset != tc.offset || matches[0].Length != 2 {
				t.Fatalf("matches=%+v", matches)
			}
			result, err = s.Scan([]byte(tc.buffer))
			if err != nil || len(result.MatchedRules) != 1 || result.Matches["p"]["$a"][0].Offset != 0 {
				t.Fatalf("reused buffer result=%+v err=%v", result, err)
			}
		})
	}
}

func TestStreamEarlyTerminationWaitsForBoundedRegex(t *testing.T) {
	p := mustCompileStreamingProgram(t, `rule p {strings:$a=/a.{0,3}b/ fullword condition:$a}`)
	s := p.NewScanner(WithStreamChunkSize(1))
	defer s.Close()
	matched, err := s.MatchesReader(bytes.NewReader([]byte("ab abx")))
	if err != nil || matched {
		t.Fatalf("matched=%v err=%v", matched, err)
	}
	data := append([]byte("ab!"), bytes.Repeat([]byte("!"), 2*defaultStreamChunkSize)...)
	reader := &countingReader{r: bytes.NewReader(data)}
	matched, err = s.MatchesReader(reader)
	if err != nil || !matched || reader.bytesRead >= int64(len(data)) {
		t.Fatalf("matched=%v read=%d err=%v", matched, reader.bytesRead, err)
	}
}
