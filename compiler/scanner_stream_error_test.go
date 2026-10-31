package compiler

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
)

type streamReadStep struct {
	data string
	err  error
}
type streamStepReader struct{ steps []streamReadStep }

func (r *streamStepReader) Read(p []byte) (int, error) {
	if len(r.steps) == 0 {
		return 0, io.EOF
	}
	step := &r.steps[0]
	n := copy(p, step.data)
	step.data = step.data[n:]
	if len(step.data) > 0 {
		return n, nil
	}
	err := step.err
	r.steps = r.steps[1:]
	return n, err
}

func TestScanReaderLookaheadErrors(t *testing.T) {
	program := mustCompileStreamingProgram(t, `rule probe { strings: $a="a" condition: $a }`)
	failure := errors.New("read failed")
	for _, chunk := range []int{1, 8, defaultStreamChunkSize} {
		t.Run(strconv.Itoa(chunk), func(t *testing.T) {
			prefix := "a" + strings.Repeat("!", chunk-1)
			for _, tc := range []struct {
				name  string
				steps []streamReadStep
				want  error
			}{
				{"error", []streamReadStep{{err: failure}}, failure},
				{"data_and_error", []streamReadStep{{data: "x", err: failure}}, failure},
				{"recoverable_error", []streamReadStep{{err: failure}, {data: "tail"}}, failure},
				{"wrapped_error", []streamReadStep{{err: fmt.Errorf("read: %w", failure)}}, failure},
				{"unexpected_eof", []streamReadStep{{err: io.ErrUnexpectedEOF}}, io.ErrUnexpectedEOF},
				{"eof", []streamReadStep{{err: io.EOF}}, nil},
				{"data_and_eof", []streamReadStep{{data: "x", err: io.EOF}}, nil},
			} {
				t.Run(tc.name, func(t *testing.T) {
					for _, mode := range []string{"scan", "early", "compact", "matches"} {
						t.Run(mode, func(t *testing.T) {
							scanner := program.NewScanner(WithStreamChunkSize(chunk), WithStreamEarlyTermination(mode == "early"), WithIncludeMatches(mode != "compact"))
							defer scanner.Close()
							reader := &streamStepReader{steps: append([]streamReadStep{{data: prefix}}, tc.steps...)}
							var err error
							switch mode {
							case "matches":
								var matched bool
								matched, err = scanner.MatchesReader(reader)
								if matched != (tc.want == nil) {
									t.Errorf("matched=%v, error=%v", matched, err)
								}
							default:
								var result *ScanResult
								result, err = scanner.ScanReader(reader)
								if tc.want != nil && result != nil {
									t.Error("failed read returned a scan result")
								}
								if tc.want == nil && (result == nil || len(result.MatchedRules) != 1) {
									t.Errorf("EOF result=%v, error=%v", result, err)
								}
							}
							if !errors.Is(err, tc.want) {
								t.Errorf("error=%v, want %v", err, tc.want)
							}
							// An interrupted scan must not poison the scanner's next input.
							result, err := scanner.ScanReader(strings.NewReader("a"))
							if err != nil || len(result.MatchedRules) != 1 {
								t.Fatalf("reuse result=%v, error=%v", result, err)
							}
						})
					}
				})
			}
		})
	}
}

func TestScanReaderLookaheadCancellation(t *testing.T) {
	program := mustCompileStreamingProgram(t, `rule probe { strings: $a="a" condition: $a }`)
	scanner := program.NewScanner(WithStreamChunkSize(1), WithStreamEarlyTermination(true))
	defer scanner.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader := &cancelingScanReader{cancel: cancel}
	result, err := scanner.ScanReaderWithContext(ctx, reader)
	if result != nil || !errors.Is(err, context.Canceled) || reader.reads != 1 {
		t.Fatalf("result=%v, error=%v, reads=%d", result, err, reader.reads)
	}
	result, err = scanner.ScanReader(bytes.NewReader([]byte("a")))
	if err != nil || len(result.MatchedRules) != 1 {
		t.Fatalf("reuse result=%v, error=%v", result, err)
	}
}
