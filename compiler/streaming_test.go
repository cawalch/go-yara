package compiler

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestCompiledProgramStreamingLifecycleAndProgress(t *testing.T) {
	program := mustCompileStreamingProgram(t, `
rule pattern_only {
  strings:
    $a = "foo"
  condition:
    false
}`)

	if program.IsStreamingEnabled() {
		t.Fatal("streaming must be disabled by default")
	}
	if _, err := program.ProcessBytesStreaming(context.Background(), []byte("foo")); err == nil ||
		err.Error() != "streaming is not enabled" {
		t.Fatalf("ProcessBytesStreaming() error = %v, want streaming-disabled error", err)
	}
	if _, err := program.ProcessFileStreaming(context.Background(), "unused"); err == nil ||
		err.Error() != "streaming is not enabled" {
		t.Fatalf("ProcessFileStreaming() error = %v, want streaming-disabled error", err)
	}
	assertStreamingProgress(t, program, streamingProgressExpectation{})

	program.EnableStreaming(true)
	program.SetStreamingChunkSize(2)
	program.EnableStreamingEarlyTermination(false)
	if !program.IsStreamingEnabled() {
		t.Fatal("EnableStreaming(true) did not enable streaming")
	}

	input := []byte("xxfooxxfoo")
	matches, err := program.ProcessBytesStreaming(context.Background(), input)
	if err != nil {
		t.Fatalf("ProcessBytesStreaming() error = %v", err)
	}
	assertStreamingOffsets(t, matches, streamingOffsets{pattern: "$a", offsets: []int64{2, 7}})
	assertStreamingProgress(t, program, streamingProgressExpectation{
		processed: int64(len(input)),
		total:     int64(len(input)),
		percent:   100,
		matches:   2,
	})

	// Reusing a program starts a fresh progress window rather than accumulating
	// processed bytes and match counts from the prior scan.
	matches, err = program.ProcessBytesStreaming(context.Background(), []byte("bar"))
	if err != nil {
		t.Fatalf("second ProcessBytesStreaming() error = %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("second ProcessBytesStreaming() returned %d matches, want 0", len(matches))
	}
	assertStreamingProgress(t, program, streamingProgressExpectation{processed: 3, total: 3, percent: 100})
}

func TestStreamingFileVerifiesFullwordAtChunkBoundaryWithoutLibraryOutput(t *testing.T) {
	program := mustCompileStreamingProgram(t, `
rule boundary {
  strings:
    $a = "ABCDEF" fullword
  condition:
    $a
}`)
	program.EnableStreaming(true)
	program.SetStreamingChunkSize(8)
	program.EnableStreamingEarlyTermination(false)

	input := []byte("--xABCDEF! ABCDEF!")
	filename := filepath.Join(t.TempDir(), "input.bin")
	if err := os.WriteFile(filename, input, 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	var (
		matches []StreamingMatch
		err     error
	)
	output := captureStdout(t, func() {
		matches, err = program.ProcessFileStreaming(context.Background(), filename)
	})
	if err != nil {
		t.Fatalf("ProcessFileStreaming() error = %v", err)
	}
	if output != "" {
		t.Fatalf("ProcessFileStreaming() wrote to stdout: %q", output)
	}
	if len(matches) != 1 {
		t.Fatalf("ProcessFileStreaming() returned %d matches, want 1: %+v", len(matches), matches)
	}
	match := matches[0]
	if match.Rule != "boundary" || match.Pattern != "$a" || match.Offset != 11 ||
		match.Length != 6 || string(match.Data) != "ABCDEF" {
		t.Fatalf("ProcessFileStreaming() match = %+v, want boundary:$a at offset 11", match)
	}
	assertStreamingProgress(t, program, streamingProgressExpectation{
		processed: int64(len(input)),
		total:     int64(len(input)),
		percent:   100,
		matches:   1,
	})
}

func TestStreamingVerifiesTextCandidatesAndModifiers(t *testing.T) {
	program := mustCompileStreamingProgram(t, `
rule exact_text_matches {
  strings:
    $nocase = "abc" nocase
    $case = "abc"
    $full = "word" fullword
    $private = "secret" private
  condition:
    any of them
}`)
	program.EnableStreaming(true)
	program.SetStreamingChunkSize(14)
	program.EnableStreamingEarlyTermination(false)

	input := []byte("ABC abc xxwordy word secret")
	matches, err := program.ProcessBytesStreaming(context.Background(), input)
	if err != nil {
		t.Fatalf("ProcessBytesStreaming() error = %v", err)
	}

	assertStreamingOffsets(t, matches, streamingOffsets{pattern: "$nocase", offsets: []int64{0, 4}})
	assertStreamingOffsets(t, matches, streamingOffsets{pattern: "$case", offsets: []int64{4}})
	assertStreamingOffsets(t, matches, streamingOffsets{pattern: "$full", offsets: []int64{16}})
	assertStreamingOffsets(t, matches, streamingOffsets{pattern: "$private"})
	assertStreamingProgress(t, program, streamingProgressExpectation{
		processed: int64(len(input)),
		total:     int64(len(input)),
		percent:   100,
		matches:   4,
	})
}

func TestStreamingReportsAllDenseMatches(t *testing.T) {
	program := mustCompileStreamingProgram(t, `
rule dense {
  strings:
    $a = "a"
  condition:
    $a
}`)
	program.EnableStreaming(true)
	program.SetStreamingChunkSize(128)
	program.EnableStreamingEarlyTermination(false)

	const matchCount = 1050
	input := []byte(strings.Repeat("a", matchCount))
	matches, err := program.ProcessBytesStreaming(context.Background(), input)
	if err != nil {
		t.Fatalf("ProcessBytesStreaming() error = %v", err)
	}
	if len(matches) != matchCount {
		t.Fatalf("ProcessBytesStreaming() returned %d matches, want %d", len(matches), matchCount)
	}
	if matches[len(matches)-1].Offset != matchCount-1 {
		t.Fatalf("last match offset = %d, want %d", matches[len(matches)-1].Offset, matchCount-1)
	}
	assertStreamingProgress(t, program, streamingProgressExpectation{
		processed: int64(len(input)),
		total:     int64(len(input)),
		percent:   100,
		matches:   matchCount,
	})
}

func TestStreamingEarlyTerminationReportsPartialProgress(t *testing.T) {
	program := mustCompileStreamingProgram(t, `
rule early {
  strings:
    $a = "foo"
  condition:
    $a
}`)
	program.EnableStreaming(true)
	program.SetStreamingChunkSize(4)

	input := []byte("foo-----foo")
	matches, err := program.ProcessBytesStreaming(context.Background(), input)
	if err != nil {
		t.Fatalf("ProcessBytesStreaming() error = %v", err)
	}
	assertStreamingOffsets(t, matches, streamingOffsets{pattern: "$a", offsets: []int64{0}})
	assertStreamingProgress(t, program, streamingProgressExpectation{
		processed: 4,
		total:     int64(len(input)),
		percent:   float64(4) / float64(len(input)) * 100,
		matches:   1,
	})
}

func TestStreamingHonorsCancellation(t *testing.T) {
	program := mustCompileStreamingProgram(t, `rule canceled { condition: true }`)
	program.EnableStreaming(true)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := program.ProcessBytesStreaming(ctx, []byte("data")); !errors.Is(err, context.Canceled) {
		t.Fatalf("ProcessBytesStreaming() error = %v, want context.Canceled", err)
	}
	if _, err := program.ProcessFileStreaming(ctx, "unused"); !errors.Is(err, context.Canceled) {
		t.Fatalf("ProcessFileStreaming() error = %v, want context.Canceled", err)
	}
}

func mustCompileStreamingProgram(t *testing.T, source string) *CompiledProgram {
	t.Helper()
	program, err := NewCompiler().CompileSource(source)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}
	return program
}

type streamingOffsets struct {
	pattern string
	offsets []int64
}

func assertStreamingOffsets(t *testing.T, matches []StreamingMatch, want streamingOffsets) {
	t.Helper()
	got := make([]int64, 0)
	for _, match := range matches {
		if match.Pattern == want.pattern {
			got = append(got, match.Offset)
		}
	}
	slices.Sort(got)
	if !slices.Equal(got, want.offsets) {
		t.Fatalf("offsets for %s = %v, want %v; matches: %+v", want.pattern, got, want.offsets, matches)
	}
}

type streamingProgressExpectation struct {
	processed int64
	total     int64
	percent   float64
	matches   int
}

func assertStreamingProgress(t *testing.T, program *CompiledProgram, want streamingProgressExpectation) {
	t.Helper()
	processed, total, percent, matches := program.GetStreamingProgress()
	if processed != want.processed || total != want.total || percent != want.percent || matches != want.matches {
		t.Fatalf(
			"GetStreamingProgress() = (%d, %d, %.1f, %d), want (%d, %d, %.1f, %d)",
			processed,
			total,
			percent,
			matches,
			want.processed,
			want.total,
			want.percent,
			want.matches,
		)
	}
}
