package compiler

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type cancelingScanReader struct {
	cancel context.CancelFunc
	reads  int
}

func (r *cancelingScanReader) Read(data []byte) (int, error) {
	r.reads++
	if r.reads > 1 {
		return 0, io.EOF
	}
	r.cancel()
	return copy(data, "a"), nil
}

func TestScanReaderStopsBetweenReads(t *testing.T) {
	program := mustCompileStreamingProgram(t, `rule r { strings: $a = "a" condition: $a }`)
	scanner := program.NewScanner()
	defer scanner.Close()
	for _, scan := range []func(context.Context, io.Reader) (*ScanResult, error){program.ScanReaderWithContext, scanner.ScanReaderWithContext} {
		ctx, cancel := context.WithCancel(context.Background())
		reader := &cancelingScanReader{cancel: cancel}
		result, err := scan(ctx, reader)
		cancel()
		if result != nil || !errors.Is(err, context.Canceled) || reader.reads != 1 {
			t.Fatalf("ScanReader = (%v, %v), reads=%d; want cancellation after one read", result, err, reader.reads)
		}
	}

	path := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(path, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result, err := scanner.ScanFileWithContext(ctx, path)
	if err != nil || len(result.MatchedRules) != 1 {
		t.Fatalf("ScanFile after cancellation = (%v, %v)", result, err)
	}
}

func TestStreamingCancellationInsideFinalChunk(t *testing.T) {
	program := mustCompileStreamingProgram(t, `rule r { strings: $a = "a" condition: $a }`)
	data := bytes.Repeat([]byte("a"), 256<<10)
	path := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, early := range []bool{false, true} {
		stream := NewStreamingProcessor(program)
		stream.EarlyTermination = early
		for _, file := range []bool{false, true} {
			ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
			var matches []StreamingMatch
			var err error
			if file {
				matches, err = stream.ProcessFile(ctx, path)
			} else {
				matches, err = stream.ProcessBytes(ctx, data)
			}
			cancel()
			if matches != nil || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("early=%v file=%v: matches=%d, err=%v; want deadline", early, file, len(matches), err)
			}
			if processed, _, _, count := stream.GetProgress(); processed != 0 || count != 0 {
				t.Fatalf("canceled chunk was fully processed: bytes=%d matches=%d", processed, count)
			}
		}
		matches, err := stream.ProcessBytes(t.Context(), []byte("a"))
		if err != nil || len(matches) != 1 {
			t.Fatalf("stream reuse = (%v, %v)", matches, err)
		}
	}
}
