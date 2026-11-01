package compiler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const ownedEvidenceRule = `rule owned {
 strings: $a=/token=([a-z]{1,40}):([a-z]{0,40})/ capture(name=1, secret=2, whole=0)
 evidence: pair=(name,secret) within 0 of secret
 condition:#a>0
}`

func evidenceSnapshot(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestEvidenceOwnedAcrossScanLifetimes(t *testing.T) {
	original := mustCompileStreamingProgram(t, ownedEvidenceRule)
	encoded, err := original.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := UnmarshalCompiledProgram(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]*CompiledProgram{"compiled": original, "reloaded": restored} {
		for _, limit := range []int{7, 64} {
			for _, path := range []string{"buffer", "reader", "file", "block"} {
				t.Run(fmt.Sprintf("%s/%d/%s", name, limit, path), func(t *testing.T) {
					input := bytes.Repeat([]byte("token=abcdefghijklmnopqrstuvwx:abcdefghijklmnopqrstuvwxyz!\ntoken=empty:!\n"), 64)
					opts := []ScannerOption{WithEvidence(limit), WithStreamChunkSize(7), WithStreamEarlyTermination(false)}
					s := p.NewScanner(opts...)
					var result *ScanResult
					var scanErr error
					switch path {
					case "buffer":
						result, scanErr = s.Scan(input)
					case "reader":
						result, scanErr = s.ScanReader(bytes.NewReader(input))
					case "file":
						file := filepath.Join(t.TempDir(), "input")
						if err := os.WriteFile(file, input, 0600); err != nil {
							t.Fatal(err)
						}
						result, scanErr = s.ScanFile(file)
						if err := os.WriteFile(file, []byte("replaced"), 0600); err != nil {
							t.Fatal(err)
						}
					case "block":
						blocks := p.NewBlockScanner(opts...)
						defer blocks.Close()
						if err := blocks.Scan(4096, input); err != nil {
							t.Fatal(err)
						}
						result, scanErr = blocks.Finish()
						if scanErr == nil {
							before := evidenceSnapshot(t, result)
							blocks.Reset()
							if err := blocks.Scan(8192, []byte("token=new:other!")); err != nil {
								t.Fatal(err)
							}
							if _, err := blocks.Finish(); err != nil {
								t.Fatal(err)
							}
							blocks.Close()
							if !bytes.Equal(before, evidenceSnapshot(t, result)) {
								t.Fatal("block reuse changed retained result")
							}
						}
					}
					if scanErr != nil {
						t.Fatal(scanErr)
					}
					matches := result.Matches["owned"]["$a"]
					if len(matches) != 128 || len(result.Evidence["owned"]["pair"]) != 128 {
						t.Fatal("missing evidence")
					}
					if len(matches[0].Captures) != 3 || matches[0].Captures[1].Length != 26 || len(matches[0].Captures[1].Data) != min(limit, 26) {
						t.Fatal("wrong capture span or truncation")
					}
					if string(matches[0].Captures[0].Data) != "abcdefghijklmnopqrstuvwx"[:min(limit, 24)] || string(matches[0].Captures[1].Data) != "abcdefghijklmnopqrstuvwxyz"[:min(limit, 26)] {
						t.Fatal("capture bytes differ from input")
					}
					if matches[1].Captures[1].Data == nil || len(matches[1].Captures[1].Data) != 0 {
						t.Fatal("empty capture must remain non-nil")
					}
					before := evidenceSnapshot(t, result)
					clear(input)
					for _, next := range []string{"token=changed:different!", "", strings.Repeat("token=next:replacement!", 128)} {
						if _, err := s.Scan([]byte(next)); err != nil {
							t.Fatal(err)
						}
					}
					s.Close()
					if !bytes.Equal(before, evidenceSnapshot(t, result)) {
						t.Fatal("input mutation, reuse or Close changed retained evidence")
					}
					neighbor := evidenceSnapshot(t, matches[3])
					secret := bytes.Clone(matches[2].Captures[1].Data)
					matches[2].Captures[0].Data = append(matches[2].Captures[0].Data, '!')
					if !bytes.Equal(secret, matches[2].Captures[1].Data) {
						t.Fatal("append crossed capture byte spans")
					}
					matches[2].Captures = append(matches[2].Captures, Capture{Name: "added"})
					if !bytes.Equal(neighbor, evidenceSnapshot(t, matches[3])) {
						t.Fatal("append crossed a capture allocation")
					}
					findings := result.Evidence["owned"]["pair"]
					other := evidenceSnapshot(t, findings[1])
					findings[0].Fields["name"] = append(findings[0].Fields["name"], Capture{Name: "added"})
					if !bytes.Equal(other, evidenceSnapshot(t, findings[1])) {
						t.Fatal("append crossed a finding allocation")
					}
				})
			}
		}
	}
}

func TestEvidenceScratchClearedOnSuccessAndError(t *testing.T) {
	p := mustCompileStreamingProgram(t, ownedEvidenceRule)
	s := p.NewScanner(WithEvidence(64))
	defer s.Close()
	for _, count := range []int{32, 2048, 32} {
		if _, err := s.Scan([]byte(strings.Repeat("token=name:secret!", count))); err != nil {
			t.Fatal(err)
		}
		if cap(s.evidenceOccurrences) > 1024 {
			t.Fatal("oversized evidence scratch retained")
		}
		for _, v := range s.evidenceOccurrences[:cap(s.evidenceOccurrences)] {
			if !reflect.DeepEqual(v, captureOccurrence{}) {
				t.Fatal("scratch retained result data")
			}
		}
	}
	rule, _ := p.GetRuleByName("owned")
	for _, cancel := range []bool{false, true} {
		ctx, stop := context.WithCancel(context.Background())
		matches := map[string][]Match{"$a": make([]Match, 40)}
		calls := 0
		_, err := s.populateRuleEvidence(ctx, rule, matches, func(Match) (captureInput, bool) {
			calls++
			if calls == 20 {
				if !cancel {
					return captureInput{}, false
				}
				stop()
			}
			return captureInput{data: []byte("token=name:secret"), end: 17}, true
		})
		stop()
		if err == nil || cancel && !errors.Is(err, context.Canceled) {
			t.Fatalf("err=%v", err)
		}
		for _, v := range s.evidenceOccurrences[:cap(s.evidenceOccurrences)] {
			if !reflect.DeepEqual(v, captureOccurrence{}) {
				t.Fatal("error retained capture references")
			}
		}
	}
	s.Close()
	if s.evidenceOccurrences != nil {
		t.Fatal("Close retained scratch")
	}
}

func TestEvidenceRetainedResultDuringScannerReuse(t *testing.T) {
	p := mustCompileStreamingProgram(t, ownedEvidenceRule)
	s := p.NewScanner(WithEvidence(64))
	defer s.Close()
	result, err := s.Scan([]byte(strings.Repeat("token=original:retained!", 32)))
	if err != nil {
		t.Fatal(err)
	}
	want := evidenceSnapshot(t, result)
	stop := make(chan struct{})
	ready := make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		close(ready)
		for {
			data, err := json.Marshal(result)
			if err != nil {
				finished <- err
				return
			}
			if !bytes.Equal(data, want) {
				finished <- errors.New("retained result changed during scanner reuse")
				return
			}
			select {
			case <-stop:
				finished <- nil
				return
			default:
			}
		}
	}()
	<-ready
	for range 30 {
		if _, err := s.Scan([]byte(strings.Repeat("token=different:replacement!", 64))); err != nil {
			close(stop)
			readErr := <-finished
			t.Fatalf("scan error: %v; retained-result reader: %v", err, readErr)
		}
	}
	s.Close()
	close(stop)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}
