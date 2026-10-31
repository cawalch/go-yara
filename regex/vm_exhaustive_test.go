package regex

import "testing"

func TestVMExhaustiveAlternation(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		input   string
		end     int
	}{
		{"(a|ab)+b", "abab", 4},
		{"(ab|a)+b", "abab", 4},
		{"(a|ab)+", "abab", 4},
		{"(a|ab)*b", "abab", 4},
		{"a(|.*)", "abab", 4}, // Acceptance in a split must retain its sibling.
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			code := mustCompile(t, tc.pattern)
			batch, release := NewVMBatch(len(code))
			defer release()
			for _, flags := range []Flags{0, FlagsWide, FlagsNoCase, FlagsWide | FlagsNoCase} {
				input := []byte(tc.input)
				end := tc.end
				if flags&FlagsNoCase != 0 {
					input[0] = 'A'
				}
				if flags&FlagsWide != 0 {
					wide := make([]byte, len(input)*2)
					for i, b := range input {
						wide[2*i] = b
					}
					input, end = wide, end*2
				}
				for _, bs := range []*VMBatch{nil, batch} {
					matched, start, gotEnd, err := ExecMatchBatchWithCancel(bs, code, input, flags|FlagsGreedy|FlagsExhaustive, 0, nil)
					if err != nil || !matched || start != 0 || gotEnd != end {
						t.Fatalf("flags %x: (%v, %d, %d, %v), want [0,%d)", flags, matched, start, gotEnd, err, end)
					}
				}
			}
		})
	}
}

func TestGreedyAlternationCaptureReplay(t *testing.T) {
	code := mustCompileCaptures(t, "(a|ab)+b", []int{1})
	for _, scratch := range []*CaptureScratch{nil, {}} {
		captures, matched := ExecCapturesAtWithScratch(scratch, code, []byte("abab"), FlagsGreedy|FlagsExhaustive, 0, 4, 1)
		want := CaptureSpan{Start: 2, End: 3, Matched: true}
		if !matched || len(captures) != 1 || captures[0] != want {
			t.Fatalf("captures = %+v, matched = %v, want %+v", captures, matched, want)
		}
	}
}
