package regex

import (
	"context"
	"errors"
	"slices"
	"testing"
)

func TestVMVerificationDistance(t *testing.T) {
	for _, tc := range []struct {
		pattern, input  string
		flags           Flags
		start, distance int
		want            []int
	}{
		{`a+`, "aaaaa", 0, 0, 3, []int{3}},
		{`a+?`, "aaaaa", 0, 0, 3, []int{1}},
		{`a+$`, "aaaaa", 0, 0, 3, nil},
		{`a+\b`, "aaaaa", 0, 0, 3, nil},
		{`a+\b`, "aaa!a", 0, 0, 3, []int{3}},
		{`a+`, "!A\x00A\x00A\x00", FlagsWide | FlagsNoCase, 1, 5, []int{5}},
		{`a+`, "a\x00a\x01", FlagsWide, 0, 4, []int{2}},
		{`a*`, "aaaaa", FlagsBackwards, 5, 3, []int{5, 4, 3, 2}},
		{`a+^`, "aaaaa", FlagsBackwards, 5, 4, nil},
		{`a+^`, "aaaaa", FlagsBackwards, 5, 5, []int{0}},
		{`a+\b`, "!aaaa!", FlagsBackwards, 5, 4, []int{1}},
		{`a+`, "!A\x00A\x00A\x00", FlagsWide | FlagsNoCase | FlagsBackwards, 7, 5, []int{5, 3}},
	} {
		t.Run(tc.pattern+tc.input, func(t *testing.T) {
			code := mustCompile(t, tc.pattern)
			batch := &VMBatch{}
			defer batch.Release()
			for _, bs := range []*VMBatch{nil, batch, batch} {
				ends, err := ExecVerifyBatchWithCancel(bs, code, []byte(tc.input), tc.flags, tc.start, tc.distance, nil)
				if err != nil || !slices.Equal(ends, tc.want) {
					t.Fatalf("ends=%v error=%v want=%v", ends, err, tc.want)
				}
			}
		})
	}
}

func TestVMVerificationCancellationReuse(t *testing.T) {
	batch := &VMBatch{}
	defer batch.Release()
	code := mustCompile(t, `a+`)
	done := make(chan struct{})
	close(done)
	for _, flags := range []Flags{0, FlagsBackwards} {
		if ends, err := ExecVerifyBatchWithCancel(batch, code, []byte("aaa"), flags, 0, 3, done); !errors.Is(err, context.Canceled) || len(ends) != 0 {
			t.Fatalf("ends=%v err=%v", ends, err)
		}
	}
	ends, err := ExecVerifyBatchWithCancel(batch, code, []byte("aaa"), 0, 0, 2, nil)
	if err != nil || !slices.Equal(ends, []int{2}) {
		t.Fatalf("ends=%v err=%v", ends, err)
	}
}
