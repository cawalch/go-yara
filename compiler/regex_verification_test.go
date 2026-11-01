package compiler

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRegexVerificationDistance(t *testing.T) {
	for _, wide := range []bool{false, true} {
		step, modifier := 1, ""
		if wide {
			step, modifier = 2, "wide"
		}
		for _, n := range []int{4096 / step, 4096/step + 1} {
			condition := `#a==0`
			if n*step == 4096 {
				condition = fmt.Sprintf(`#a==1 and @a[1]==0 and !a[1]==%d`, 4096+3*step)
			}
			p := mustCompileStreamingProgram(t, `rule p{strings:$a=/(ab|a)+xyz/ `+modifier+` fullword condition:`+condition+`}`)
			encoded, err := p.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if binary.BigEndian.Uint16(encoded[len(compiledProgramMagic):]) != 15 {
				t.Fatal("missing verification policy format version")
			}
			restored, err := UnmarshalCompiledProgram(encoded)
			if err != nil {
				t.Fatal(err)
			}
			data := []byte(strings.Repeat("a", n) + "xyz")
			if wide {
				data = widenRegexPrefix(data)
			}
			for _, program := range []*CompiledProgram{p, restored} {
				result, err := program.Scan(data)
				if err != nil || len(result.MatchedRules) != 1 {
					t.Fatalf("wide=%v n=%d result=%+v err=%v", wide, n, result, err)
				}
			}
		}
	}
}

func TestRegexVerificationLegacyPolicy(t *testing.T) {
	p := mustCompileStreamingProgram(t, `rule p{strings:$a=/(ab|a)+xyz/ fullword condition:!a[1]==4100}`)
	pattern := p.Rules[0].RegexPatterns["$a"]
	pattern.verification = nil // Format 14 had no distance programs.
	p.Rules[0].RegexPatterns["$a"] = pattern
	encoded, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(encoded[len(compiledProgramMagic):], 14)
	restored, err := UnmarshalCompiledProgram(encoded)
	if err != nil {
		t.Fatal(err)
	}
	result, err := restored.Scan([]byte(strings.Repeat("a", 4097) + "xyz"))
	if err != nil || len(result.MatchedRules) != 1 {
		t.Fatalf("legacy result=%+v err=%v", result, err)
	}
}

func TestRegexVerificationDistanceWithoutFullword(t *testing.T) {
	for _, wide := range []bool{false, true} {
		step, modifier := 1, ""
		if wide {
			step, modifier = 2, "wide"
		}
		count := 4096 / step
		p := mustCompileStreamingProgram(t, fmt.Sprintf(`rule p{strings:$a=/(ab|a)+xyz/ %s condition:#a==%d and @a[1]==%d and !a[1]==%d and !a[%d]==%d}`, modifier, count, step, 4096+3*step, count, 4*step))
		data := []byte(strings.Repeat("a", count+1) + "xyz")
		if wide {
			data = widenRegexPrefix(data)
		}
		result, err := p.Scan(data)
		if err != nil || len(result.MatchedRules) != 1 {
			t.Fatalf("wide=%v result=%+v err=%v", wide, result, err)
		}
	}
}

func TestRegexVerificationExplicitSpanAndCancellation(t *testing.T) {
	data := []byte(strings.Repeat("a", 3000) + "XYZ" + strings.Repeat("b", 3000))
	for _, limit := range []int{0, 4500, 5000} {
		length := len(data)
		if limit > 0 {
			length = limit
		}
		p := mustCompileStreamingProgram(t, fmt.Sprintf(`rule p{strings:$a=/^a+XYZb+/ condition:#a==1 and !a[1]==%d}`, length))
		scanner := p.NewScanner(WithMaxMatchSpan(limit))
		result, err := scanner.Scan(data)
		scanner.Close()
		if err != nil || len(result.MatchedRules) != 1 {
			t.Fatalf("limit=%d result=%+v err=%v", limit, result, err)
		}
	}
	p := mustCompileStreamingProgram(t, `rule p{strings:$a=/(a|ab)+/ fullword condition:$a}`)
	scanner := p.NewScanner()
	defer scanner.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	timer := time.AfterFunc(time.Millisecond, cancel)
	defer timer.Stop()
	_, err := scanner.ScanWithContext(ctx, bytes.Repeat([]byte("a"), 1<<20))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation=%v", err)
	}
	result, err := scanner.Scan([]byte("ab"))
	if err != nil || len(result.MatchedRules) != 1 {
		t.Fatalf("reuse result=%+v err=%v", result, err)
	}
}

func TestRegexVerificationCaptureAndScanPaths(t *testing.T) {
	p := mustCompileStreamingProgram(t, `rule p{strings:$a=/^(xyz.*)/ capture(whole=1) condition:#a==1 and !a[1]==4096}`)
	data := []byte("xyz" + strings.Repeat("a", 5000))
	path := filepath.Join(t.TempDir(), "input.bin")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	encoded, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := UnmarshalCompiledProgram(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for _, program := range []*CompiledProgram{p, restored} {
		scanner := program.NewScanner(WithEvidence(32))
		defer scanner.Close()
		for _, scan := range []func() (*ScanResult, error){
			func() (*ScanResult, error) { return scanner.Scan(data) },
			func() (*ScanResult, error) { return scanner.ScanFile(path) },
			func() (*ScanResult, error) { return scanner.ScanReader(bytes.NewReader(data)) },
			func() (*ScanResult, error) {
				blocks := program.NewBlockScanner(WithEvidence(32))
				defer blocks.Close()
				if err := blocks.Scan(0, data); err != nil {
					return nil, err
				}
				return blocks.Finish()
			},
		} {
			result, err := scan()
			if err != nil || len(result.MatchedRules) != 1 {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			matches := result.Matches["p"]["$a"]
			if len(matches) != 1 || matches[0].Length != 4096 || len(matches[0].Captures) != 1 {
				t.Fatalf("matches=%+v", matches)
			}
			capture := matches[0].Captures[0]
			if capture.Offset != 0 || capture.Length != 4096 || !capture.DataTruncated || !bytes.Equal(capture.Data, data[:32]) {
				t.Fatalf("capture=%+v", capture)
			}
			if _, err := scanner.Scan(nil); err != nil {
				t.Fatal(err)
			}
		}
	}
}
