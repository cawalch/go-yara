package compiler

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
)

func TestCompiledProgramStreamingConcurrent(t *testing.T) {
	program := mustCompileStreamingProgram(t, `rule sample { strings: $a = "target" condition: $a }`)
	program.EnableStreaming(true)
	program.EnableStreamingEarlyTermination(false)

	filename := filepath.Join(t.TempDir(), "sample.txt")
	fileData := []byte("x xtarget x target")
	if err := os.WriteFile(filename, fileData, 0600); err != nil {
		t.Fatal(err)
	}
	data := []byte("target y target y target")
	ctx := context.Background()
	start := make(chan struct{})

	var workers sync.WaitGroup
	for worker := range 4 {
		workers.Go(func() {
			<-start
			for range 20 {
				var matches []StreamingMatch
				var err error
				want := []int64{0, 9, 18}
				if worker%2 == 0 {
					matches, err = program.ProcessBytesStreaming(ctx, data)
				} else {
					matches, err = program.ProcessFileStreaming(ctx, filename)
					want = []int64{3, 12}
				}
				if err != nil {
					t.Errorf("streaming scan error = %v", err)
					return
				}
				var got []int64
				for _, match := range matches {
					got = append(got, match.Offset)
					if match.Pattern != "$a" || match.Length != 6 || string(match.Data) != "target" {
						t.Errorf("unexpected match %+v", match)
						return
					}
				}
				if !slices.Equal(got, want) {
					t.Errorf("streaming scan offsets = %v, want %v", got, want)
					return
				}
			}
		})
	}
	workers.Go(func() {
		<-start
		for i := range 100 {
			program.EnableStreaming(true)
			program.SetStreamingChunkSize(1 + i%8)
			program.EnableStreamingEarlyTermination(false)
			if !program.IsStreamingEnabled() {
				t.Error("streaming is disabled")
				return
			}
			processed, total, percent, matches := program.GetStreamingProgress()
			if processed < 0 || total < processed || percent < 0 || percent > 100 || matches < 0 {
				t.Errorf("inconsistent progress = (%d, %d, %g, %d)", processed, total, percent, matches)
				return
			}
		}
	})
	close(start)
	workers.Wait()
}

func TestCompiledProgramStreamingSnapshotsOptionsAndProgress(t *testing.T) {
	program := mustCompileStreamingProgram(t, `rule sample { strings: $a = "target" condition: $a }`)
	program.EnableStreaming(true)
	program.SetStreamingChunkSize(8)
	program.EnableStreamingEarlyTermination(false)

	first, err := program.startStreamingScan()
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	data := []byte("target  target")
	program.EnableStreaming(false)
	if _, err := program.ProcessBytesStreaming(ctx, data); err == nil {
		t.Fatal("ProcessBytesStreaming accepted a scan while disabled")
	}
	program.SetStreamingChunkSize(6)
	program.EnableStreamingEarlyTermination(true)
	program.EnableStreaming(true)
	matches, err := program.ProcessBytesStreaming(ctx, data)
	if err != nil || len(matches) != 1 {
		t.Fatalf("second scan returned %d matches, err = %v, want 1 match", len(matches), err)
	}
	want := streamingProgressExpectation{processed: 6, total: 14, percent: 6.0 / 14 * 100, matches: 1}
	assertStreamingProgress(t, program, want)

	matches, err = first.ProcessBytes(ctx, data)
	if err != nil || len(matches) != 2 {
		t.Fatalf("first scan returned %d matches, err = %v, want 2 matches", len(matches), err)
	}
	assertStreamingProgress(t, program, want)
}
