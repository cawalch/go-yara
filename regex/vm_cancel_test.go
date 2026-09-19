package regex

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestCancelableRegexPreservesMatches(t *testing.T) {
	tests := []struct {
		pattern string
		input   []byte
		flags   Flags
	}{
		{"a|ab", []byte("zab"), FlagsScan},
		{"a*", nil, FlagsScan},
		{"^a+$", []byte("aaa"), 0},
		{"a+b", []byte("aaaa"), FlagsScan},
		{`\bcat\b`, []byte("a CAT!"), FlagsScan | FlagsNoCase},
		{"a.b", []byte("a\nb"), FlagsDotAll},
		{"a+", []byte{'x', 'a', 0, 'a', 0}, FlagsScan | FlagsWide},
	}
	done := make(chan struct{})
	for _, test := range tests {
		code := mustCompile(t, test.pattern)
		got, err := ExecWithCancel(code, test.input, test.flags, done)
		if want := Exec(code, test.input, test.flags); err != nil || got != want {
			t.Fatalf("ExecWithCancel(%q) = (%v, %v), want %v", test.pattern, got, err, want)
		}
		batch, release := NewVMBatch(len(code))
		for start := 0; start <= len(test.input); start++ {
			want, ws, we := ExecMatchBatch(batch, code, test.input, test.flags, start)
			got, gs, ge, err := ExecMatchBatchWithCancel(batch, code, test.input, test.flags, start, done)
			if err != nil || got != want || gs != ws || ge != we {
				t.Fatalf("batch %q at %d = (%v,%d,%d,%v), want (%v,%d,%d)", test.pattern, start, got, gs, ge, err, want, ws, we)
			}
		}
		release()
	}
}

func TestRegexCancellationDuringAnchoredAttempt(t *testing.T) {
	code := mustCompile(t, "^a+$")
	done := make(chan struct{})
	close(done)
	if matched, err := ExecWithCancel(code, []byte("aaa"), FlagsScan, done); matched || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Exec = (%v, %v)", matched, err)
	}
	data := bytes.Repeat([]byte{'a'}, 8<<20)
	batch, release := NewVMBatch(len(code))
	defer release()
	for _, state := range []*VMBatch{nil, batch} {
		ctx, cancel := context.WithCancel(context.Background())
		timer := time.AfterFunc(time.Millisecond, cancel)
		matched, _, _, err := ExecMatchBatchWithCancel(state, code, data, 0, 0, ctx.Done())
		timer.Stop()
		cancel()
		if matched || !errors.Is(err, context.Canceled) {
			t.Fatalf("in-flight cancellation = (%v,%v)", matched, err)
		}
		matched, start, end, err := ExecMatchBatchWithCancel(state, code, []byte("aaa"), 0, 0, nil)
		if !matched || start != 0 || end != 3 || err != nil {
			t.Fatalf("reuse after interruption = (%v,%d,%d,%v)", matched, start, end, err)
		}
	}
}
