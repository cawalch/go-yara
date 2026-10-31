package regex

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestVMAllEndpoints(t *testing.T) {
	for _, tc := range []struct {
		pattern, input string
		flags          Flags
		start          int
		want           []int
	}{
		{`(a|ab)`, "abab", 0, 0, []int{1, 2}},
		{`(a|a|ab)`, "abab", 0, 0, []int{1, 2}},
		{`(ab|a){0,3}?`, "ababab!", 0, 0, []int{0, 1, 2, 3, 4, 5, 6}},
		{`a+`, "aaaa!", 0, 0, []int{1, 2, 3, 4}},
		{`a+?`, "aaaa!", FlagsGreedy, 0, []int{1, 2, 3, 4}},
		{`a*`, "", 0, 0, []int{0}},
		{`(a|ab)`, "!A\x00B\x00", FlagsWide | FlagsNoCase, 1, []int{3, 5}},
		{`(a|ab)`, "a\x00b\x01", FlagsWide, 0, []int{2}},
		{`(a|ab)`, "a\x00b", FlagsWide, 0, []int{2}},
		{`a+`, "!aaa", FlagsScan, 0, nil},
		{`a+`, "!aaa", FlagsScan, 1, []int{2, 3, 4}},
		{`a+$`, "aaa!", 0, 0, nil},
		{`a+$`, "aaa", 0, 0, []int{3}},
		{`(a|a!)+`, "a!a!b", FlagsFullwordEnd, 0, []int{1, 3}},
	} {
		t.Run(tc.pattern+tc.input, func(t *testing.T) {
			code := mustCompile(t, tc.pattern)
			batch := &VMBatch{}
			defer batch.Release()
			for _, bs := range []*VMBatch{nil, batch, batch} {
				ends, err := ExecMatchEndsBatchWithCancel(bs, code, []byte(tc.input), tc.flags, tc.start, nil)
				want := tc.want
				if err != nil || !slices.Equal(ends, want) {
					t.Fatalf("ends=%v err=%v want=%v", ends, err, want)
				}
			}
		})
	}
}

func TestVMAllEndpointsCancellationAndReuse(t *testing.T) {
	batch := &VMBatch{}
	defer batch.Release()
	done := make(chan struct{})
	close(done)
	if ends, err := ExecMatchEndsBatchWithCancel(batch, mustCompile(t, `a*`), []byte("aaa"), 0, 0, done); !errors.Is(err, context.Canceled) || len(ends) != 0 {
		t.Fatalf("ends=%v err=%v", ends, err)
	}
	input := []byte(strings.Repeat("a", 16<<20))
	code := mustCompile(t, `a*`)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	timer := time.AfterFunc(time.Millisecond, cancel)
	defer timer.Stop()
	ends, err := ExecMatchEndsBatchWithCancel(batch, code, input, 0, 0, ctx.Done())
	if !errors.Is(err, context.Canceled) || len(ends) != 0 {
		t.Fatalf("partial ends=%d err=%v", len(ends), err)
	}
	code = mustCompile(t, `(a|ab)`)
	ends, err = ExecMatchEndsBatchWithCancel(batch, code, []byte("ab"), 0, 0, nil)
	if err != nil || !slices.Equal(ends, []int{1, 2}) {
		t.Fatalf("reused ends=%v err=%v", ends, err)
	}
	matched, _, end, err := ExecMatchBatchWithCancel(batch, code, []byte("ab"), FlagsGreedy, 0, nil)
	if !matched || end != 1 || err != nil || !slices.Equal(ends, []int{1, 2}) {
		t.Fatalf("ordinary priority changed: matched=%v end=%d err=%v", matched, end, err)
	}
	for _, start := range []int{-1, 3} {
		ends, err = ExecMatchEndsBatchWithCancel(batch, code, []byte("ab"), 0, start, nil)
		if err != nil || len(ends) != 0 {
			t.Fatalf("invalid start=%d ends=%v err=%v", start, ends, err)
		}
	}
	ends, err = ExecMatchEndsBatchWithCancel(batch, nil, nil, 0, 0, nil)
	if err != nil || len(ends) != 0 {
		t.Fatalf("empty code ends=%v err=%v", ends, err)
	}
}

func TestVMAllEndpointsThenEmptyTail(t *testing.T) {
	batch := &VMBatch{}
	defer batch.Release()
	code := []byte{OpMatch}
	for range 3 {
		ends, err := ExecMatchEndsBatchWithCancel(batch, code, []byte("abc"), 0, 0, nil)
		if err != nil || !slices.Equal(ends, []int{0}) {
			t.Fatalf("ends=%v err=%v", ends, err)
		}
		matched, _, end, err := ExecMatchBatchWithCancel(batch, code, []byte("abc"), 0, 0, nil)
		if !matched || end != 0 || err != nil {
			t.Fatalf("empty tail matched=%v end=%d err=%v", matched, end, err)
		}
	}
}

func TestVMAllEndpointsTemporaryBatchOwnership(t *testing.T) {
	code := mustCompile(t, `a*`)
	ends, err := ExecMatchEndsBatchWithCancel(nil, code, []byte("aaa"), 0, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	for range 10 {
		_, err := ExecMatchEndsBatchWithCancel(nil, code, []byte("!aaaa"), 0, 1, nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(ends, []int{0, 1, 2, 3}) {
		t.Fatalf("temporary batch results overwritten: %v", ends)
	}
}
