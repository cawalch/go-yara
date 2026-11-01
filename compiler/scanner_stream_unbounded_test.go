package compiler

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"
)

func TestStreamUnboundedRegexFinalization(t *testing.T) {
	p := mustCompileStreamingProgram(t, `rule positive {strings:$a=/a.*b/ condition:#a==2 and !a[1]==5}
rule inverse {strings:$a=/a.*b/ condition:#a==2 and !a[1]!=5}`)
	for _, chunk := range []int{1, 2, 3, 8} {
		s := p.NewScanner(WithStreamChunkSize(chunk), WithStreamEarlyTermination(false))
		result, err := s.ScanReader(bytes.NewReader([]byte("ab ab")))
		s.Close()
		if err != nil || len(result.MatchedRules) != 1 || result.MatchedRules[0].Rule != "positive" {
			t.Fatalf("chunk=%d result=%+v err=%v", chunk, result, err)
		}
		matches := result.Matches["positive"]["$a"]
		if len(matches) != 2 || matches[0].Offset != 0 || matches[0].Length != 5 || matches[1].Offset != 3 || matches[1].Length != 2 {
			t.Fatalf("chunk=%d matches=%+v", chunk, matches)
		}
	}
}

func TestStreamUnboundedRegexLongMatch(t *testing.T) {
	for _, wide := range []bool{false, true} {
		modifier, gap := "", 2500
		if wide {
			modifier, gap = "wide", 1500
		}
		body := []byte(strings.Repeat("a", gap) + "XYZ" + strings.Repeat("b", gap))
		if wide {
			body = widenRegexPrefix(body)
		}
		p := mustCompileStreamingProgram(t, `rule p {strings:$a=/a+XYZb+/ `+modifier+` fullword condition:#a==1 and @a[1]==13000 and !a[1]==`+strconv.Itoa(len(body))+`}`)
		data := append(bytes.Repeat([]byte("!"), 13000), body...)
		data = append(data, bytes.Repeat([]byte("!"), 9000)...)
		for _, chunk := range []int{511, 2048, 4096} {
			s := p.NewScanner(WithStreamChunkSize(chunk), WithStreamOverlapSize(1))
			result, err := s.ScanReader(bytes.NewReader(data))
			s.Close()
			if err != nil || len(result.MatchedRules) != 1 {
				t.Fatalf("wide=%v chunk=%d result=%+v err=%v", wide, chunk, result, err)
			}
			matches := result.Matches["p"]["$a"]
			if len(matches) != 1 || matches[0].Offset != 13000 || matches[0].Length != len(body) || !bytes.Equal(matches[0].MatchedData, body) {
				t.Fatalf("matches=%+v", matches)
			}
		}
	}
}

func TestStreamUnboundedRegexEarlyTermination(t *testing.T) {
	p := mustCompileStreamingProgram(t, `rule p {strings:$a=/a.*b/ fullword condition:$a}`)
	s := p.NewScanner(WithStreamChunkSize(1), WithStreamOverlapSize(1), WithFastScan())
	defer s.Close()
	matched, err := s.MatchesReader(strings.NewReader("ab abx"))
	if err != nil || matched {
		t.Fatalf("provisional match=%v err=%v", matched, err)
	}
	data := append([]byte("ab!\n"), bytes.Repeat([]byte("!"), 2*defaultStreamChunkSize)...)
	reader := &countingReader{r: bytes.NewReader(data)}
	matched, err = s.MatchesReader(reader)
	if err != nil || !matched || reader.bytesRead >= int64(len(data)) {
		t.Fatalf("match=%v read=%d err=%v", matched, reader.bytesRead, err)
	}
}

func TestStreamUnboundedRegexExplicitSpan(t *testing.T) {
	for _, cap := range []int{2, 3, 4, 5, 4096, 4097} {
		p := mustCompileStreamingProgram(t, `rule p {strings:$a=/a.*b/ condition:#a>0}`)
		s := p.NewScanner(WithMaxMatchSpan(cap), WithStreamChunkSize(1))
		defer s.Close()
		data := []byte("ab ab")
		want, err := s.Scan(data)
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.ScanReader(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		a, b := want.Matches["p"]["$a"], got.Matches["p"]["$a"]
		if len(a) != len(b) {
			t.Fatalf("cap=%d want=%+v got=%+v", cap, a, b)
		}
		for i := range a {
			if a[i].Offset != b[i].Offset || a[i].Length != b[i].Length {
				t.Fatalf("cap=%d want=%+v got=%+v", cap, a, b)
			}
		}
	}
}

func TestStreamUnboundedRegexLegacyHorizon(t *testing.T) {
	p := mustCompileStreamingProgram(t, `rule p {strings:$a=/xyz.*?/ condition:$a}`)
	payload, err := serializeProgram(p)
	if err != nil {
		t.Fatal(err)
	}
	pattern := payload.Rules[0].RegexPatterns["$a"]
	if pattern.Verification != nil || pattern.StreamingHorizon == 0 {
		t.Fatal("fixture must use finite priority proof")
	}
	pattern.StreamingHorizon = 0
	payload.Rules[0].RegexPatterns["$a"] = pattern
	var legacy bytes.Buffer
	legacy.WriteString(compiledProgramMagic)
	if err := binary.Write(&legacy, binary.BigEndian, uint16(16)); err != nil {
		t.Fatal(err)
	}
	if err := gob.NewEncoder(&legacy).Encode(payload); err != nil {
		t.Fatal(err)
	}
	old, err := UnmarshalCompiledProgram(legacy.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	s := old.NewScanner()
	defer s.Close()
	reader := &countingReader{r: strings.NewReader("xyz")}
	result, err := s.ScanReader(reader)
	if result != nil || err == nil || !strings.Contains(err.Error(), "WithMaxMatchSpan") || reader.bytesRead != 0 {
		t.Fatalf("result=%+v error=%v reads=%d", result, err, reader.bytesRead)
	}
	capped := old.NewScanner(WithMaxMatchSpan(16), WithStreamChunkSize(1))
	defer capped.Close()
	result, err = capped.ScanReader(strings.NewReader("xyz"))
	if err != nil || len(result.MatchedRules) != 1 {
		t.Fatalf("result=%+v error=%v", result, err)
	}
	oversized := old.NewScanner(WithMaxMatchSpan(math.MaxInt))
	defer oversized.Close()
	if _, err := oversized.ScanReader(strings.NewReader("xyz")); err == nil {
		t.Fatal("overflowing horizon accepted")
	}
}

func TestStreamUnboundedRegexEvidenceAndErrors(t *testing.T) {
	p := mustCompileStreamingProgram(t, `rule p {strings:$a=/(a.*b)/ capture(part=1) condition:#a==2 and !a[1]==5}`)
	s := p.NewScanner(WithStreamChunkSize(1), WithEvidence(16))
	defer s.Close()
	failure := errors.New("reader failed")
	result, err := s.ScanReader(&streamStepReader{steps: []streamReadStep{{data: "ab"}, {err: failure}}})
	if result != nil || !errors.Is(err, failure) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result, err = s.ScanReaderWithContext(ctx, &cancelingScanReader{cancel: cancel})
	if result != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	for _, data := range []string{"ab ab", "", "ab ab"} {
		result, err = s.ScanReader(strings.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		if data == "" {
			if len(result.MatchedRules) != 0 {
				t.Fatal("stale match")
			}
			continue
		}
		matches := result.Matches["p"]["$a"]
		if len(matches) != 2 || len(matches[0].Captures) != 1 || !bytes.Equal(matches[0].Captures[0].Data, []byte("ab ab")) {
			t.Fatalf("matches=%+v", matches)
		}
	}
}
