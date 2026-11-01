package regex

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestFailureReuseMatchesOrdinaryVM(t *testing.T) {
	for _, pattern := range []string{`a.*b`, `a.*?b`, `a[^b]*b`, `a(a|aa)*b`, `a(.*b|.*c)`, `a.*\bb`, `a.*\Bb`, `a.*b$`, `(^a|a).*b`, `(a?.)+b`, `a.*`, `a+b`} {
		t.Run(pattern, func(t *testing.T) {
			code := mustCompile(t, pattern)
			for _, flags := range []Flags{0, FlagsGreedy, FlagsGreedy | FlagsNoCase, FlagsGreedy | FlagsDotAll, FlagsGreedy | FlagsFullwordEnd, FlagsGreedy | FlagsWide} {
				input := append(bytes.Repeat([]byte("a"), 256), []byte("\nabb!aac!AAB!\n")...)
				if flags&FlagsWide != 0 {
					wide := make([]byte, len(input)*2)
					for i, b := range input {
						wide[2*i] = b
					}
					input = wide
				}
				reused, release := NewVMBatch(len(code))
				defer release()
				ordinary, releaseOrdinary := NewVMBatch(len(code))
				defer releaseOrdinary()
				reused.EnableFailureReuse()
				for start := range input {
					// Match the scanner's advancing windows while retaining their common end.
					left := max(0, start-32)
					data := input[left:]
					got, _, end, err := ExecMatchBatchWithCancel(reused, code, data, flags, start-left, nil)
					want, _, wantEnd, wantErr := ExecMatchBatchWithCancel(ordinary, code, data, flags, start-left, nil)
					if got != want || end != wantEnd || err != nil || wantErr != nil {
						t.Fatalf("flags=%d start=%d got=(%v,%d,%v) want=(%v,%d,%v)", flags, start, got, end, err, want, wantEnd, wantErr)
					}
				}
			}
		})
	}
}

func TestFailureReuseBoundsAndReset(t *testing.T) {
	code := mustCompile(t, `a.*b`)
	b, release := NewVMBatch(len(code))
	defer release()
	for _, size := range []int{127, 128, 512, 4096, 4097} {
		b.Prepare(len(code))
		b.EnableFailureReuse()
		input := bytes.Repeat([]byte("a"), size)
		for start := 0; start < 3; start++ {
			if got, _, _ := ExecMatchBatch(b, code, input, FlagsGreedy, start); got {
				t.Fatal("unexpected match")
			}
		}
		if cap(b.st.failureMasks)*8 > 32*1024 {
			t.Fatal("unbounded scratch")
		}
		if size == 512 || size == 4096 {
			before := b.gen
			if got, _, _ := ExecMatchBatch(b, code, input[16:], FlagsGreedy, 16); got {
				t.Fatal("unexpected match")
			}
			if b.gen-before > 4 {
				t.Fatal("failed suffix was rescanned")
			}
		}
		// A caller can mutate the same backing bytes after starting a fresh batch.
		input[len(input)-1] = 'b'
		b.Prepare(len(code))
		b.EnableFailureReuse()
		if got, _, end := ExecMatchBatch(b, code, input, FlagsGreedy, 0); !got || end != len(input) {
			t.Fatal("stale failure after Prepare")
		}
	}
	b.Release()
	if b.failure.input != nil {
		t.Fatal("Release retained input")
	}
}

func TestFailureReuseIdentityAndCancellation(t *testing.T) {
	code := mustCompile(t, `a.*b`)
	otherCode := mustCompile(t, `a.*B`)
	input := append(bytes.Repeat([]byte("a"), 256), 'B')
	other := append(bytes.Repeat([]byte("a"), 256), 'b')
	b, release := NewVMBatch(len(code))
	defer release()
	for _, tc := range []struct {
		code, input []byte
		flags       Flags
	}{
		{code, input, FlagsGreedy | FlagsNoCase}, {code, other, FlagsGreedy}, {otherCode, input, FlagsGreedy},
	} {
		b.Prepare(len(code))
		b.EnableFailureReuse()
		for start := 0; start < 3; start++ {
			ExecMatchBatch(b, code, input, FlagsGreedy, start)
		}
		if got, _, _ := ExecMatchBatch(b, tc.code, tc.input, tc.flags, 0); !got {
			t.Fatal("stale cache identity")
		}
	}
	code = mustCompile(t, `a.*b$`)
	input = append(bytes.Repeat([]byte("a"), 256), 'b', '!')
	b.Prepare(len(code))
	b.EnableFailureReuse()
	for start := 0; start < 3; start++ {
		ExecMatchBatch(b, code, input, FlagsGreedy, start)
	}
	if got, _, _ := ExecMatchBatch(b, code, input[:len(input)-1], FlagsGreedy, 0); !got {
		t.Fatal("stale physical end")
	}
	done := make(chan struct{})
	close(done)
	if _, _, _, err := ExecMatchBatchWithCancel(b, code, input, FlagsGreedy, 0, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
}

func TestFailureReuseRequiresEntireFrontier(t *testing.T) {
	code := mustCompile(t, `((a|c).*b|c.*d)`)
	input := append(bytes.Repeat([]byte("a"), 256), []byte("caaaaaaaaad")...)
	b, release := NewVMBatch(len(code))
	defer release()
	b.EnableFailureReuse()
	for _, start := range []int{0, 1} {
		if got, _, _ := ExecMatchBatch(b, code, input, FlagsGreedy, start); got {
			t.Fatal("unexpected match")
		}
	}
	if got, _, end := ExecMatchBatch(b, code, input, FlagsGreedy, 256); !got || end != len(input)-256 {
		t.Fatal("a live alternative was discarded with failed states")
	}
	// The first expensive failure only arms learning. A later successful attempt
	// must not turn its trace into a failed-state proof.
	b.Prepare(len(code))
	b.EnableFailureReuse()
	ExecMatchBatch(b, code, input, FlagsGreedy, 0)
	for range 2 {
		if got, _, _ := ExecMatchBatch(b, code, input, FlagsGreedy, 256); !got {
			t.Fatal("successful trace reused as failure")
		}
	}
}

func TestFailureReuseDoesNotRetainUnvisitedPositions(t *testing.T) {
	code := mustCompile(t, `a.*b`)
	input := bytes.Repeat([]byte("a"), 512)
	b, release := NewVMBatch(len(code))
	defer release()
	b.EnableFailureReuse()
	for start := 0; start < 3; start++ {
		ExecMatchBatch(b, code, input, FlagsGreedy, start)
	}
	input[256] = '\n'
	input[511] = 'b'
	b.Prepare(len(code))
	b.EnableFailureReuse()
	for start := 0; start < 3; start++ {
		ExecMatchBatch(b, code, input, FlagsGreedy, start)
	}
	if got, _, end := ExecMatchBatch(b, code, input, FlagsGreedy, 300); !got || end != 212 {
		t.Fatal("old proof survived outside the new trace")
	}
}

func TestFailureReuseLargeProgramFallback(t *testing.T) {
	code := mustCompile(t, `a(a|aa|aaa|aaaa|aaaaa|aaaaaa)*b`)
	if len(code) <= 64 {
		t.Fatal("fixture must exceed the mask width")
	}
	input := bytes.Repeat([]byte("a"), 256)
	b, release := NewVMBatch(len(code))
	defer release()
	b.EnableFailureReuse()
	for start := 0; start < 3; start++ {
		if got, _, _ := ExecMatchBatch(b, code, input, FlagsGreedy, start); got {
			t.Fatal("unexpected match")
		}
	}
	if b.failure.ready || b.failure.learning {
		t.Fatal("oversized program must use ordinary verification")
	}
}
