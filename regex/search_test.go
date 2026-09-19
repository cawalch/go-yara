package regex

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestBooleanSearchParity(t *testing.T) {
	patterns := []string{"a", "a+b", "a|ab", "a*", "a?b", "(a|b)+a", "(a?)*b", "a{1,3}b", "a+?b", ".*b", "^a+$", "$", "^$", `\ba\b`, `\Ba\B`, "[ab]+", "[^a]b", `[A-Z]\d?`, `\w\W`, `\s\S`, `\D\d`, "a.b"}
	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			code := mustCompile(t, pattern)
			var visit func([]byte)
			visit = func(input []byte) {
				for bits := range 16 {
					flags := Flags(bits<<4) | FlagsScan
					assertBooleanSearchParity(t, code, input, flags)
				}
				if len(input) < 4 {
					for _, ch := range []byte{'a', 'b', 'A', 0, '\n', ' '} {
						visit(append(input, ch))
					}
				}
			}
			visit(nil)
			visit([]byte("xa\x00b\x00"))
			visit([]byte("a\x00!a\x00b\x00"))
		})
	}
}

//nolint:revive // comparison requires code, input, and flags
func assertBooleanSearchParity(t testing.TB, code, input []byte, flags Flags) {
	t.Helper()
	batch, release := NewVMBatch(len(code))
	defer release()
	want := false
	for start := 0; start <= len(input); start++ {
		if matched, _, _ := ExecMatchBatch(batch, code, input, flags, start); matched {
			want = true
			break
		}
	}
	if got, err := ExecWithCancel(code, input, flags|FlagsScan, nil); err != nil || got != want {
		t.Fatalf("input %q flags %x: got (%v, %v), want %v", input, flags, got, err, want)
	}
}

func FuzzBooleanSearchParity(f *testing.F) {
	for _, pattern := range []string{"a+b", "(a?)*b", `\ba\b`, "^a*$", ".*"} {
		f.Add(pattern, []byte("a\x00b\x00"), byte(0))
	}
	f.Fuzz(func(t *testing.T, pattern string, input []byte, bits byte) {
		if len(pattern) > 128 || len(input) > 128 {
			t.Skip()
		}
		ast, err := NewParser(0).Parse(pattern)
		if err != nil {
			t.Skip()
		}
		code, err := Compile(ast)
		if err != nil {
			t.Skip()
		}
		assertBooleanSearchParity(t, code, input, Flags(bits)|FlagsScan)
	})
}

func TestBooleanSearchCancellation(t *testing.T) {
	code := mustCompile(t, "a+b")
	for _, flags := range []Flags{FlagsScan, FlagsScan | FlagsWide} {
		input := bytes.Repeat([]byte{'a'}, 8<<20)
		if flags&FlagsWide != 0 {
			input = bytes.Repeat([]byte{'a', 0}, 4<<20)
		}
		ctx, cancel := context.WithCancel(context.Background())
		timer := time.AfterFunc(time.Millisecond, cancel)
		matched, err := ExecWithCancel(code, input, flags, ctx.Done())
		timer.Stop()
		cancel()
		if matched || !errors.Is(err, context.Canceled) {
			t.Fatalf("in-flight cancellation = (%v, %v)", matched, err)
		}
	}
}
