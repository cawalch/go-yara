package regex

import "testing"

func TestVMFullwordEndAcceptance(t *testing.T) {
	for _, tc := range []struct {
		pattern, input string
		flags          Flags
		end            int
	}{
		{"a|ab", "ab", 0, 2}, {"ab|a", "ab", 0, 2},
		{"a!|a", "a!", 0, 1}, {"a|ab", "abc", 0, -1},
		{"a|ab", "a_b", 0, 1}, {"a|ab", "a1", 0, -1},
		{"a|ab", "a\x00b\x00", FlagsWide, 4},
		{"a|ab", "a\x00bX", FlagsWide, 2},
		{"a|ab", "a\x00b", FlagsWide, 2},
		{"a|ab", "a\x00b\x00c\x00", FlagsWide, -1},
		{"a|ab", "AB", FlagsNoCase, 2},
		{"a+", "ab", FlagsGreedy, -1}, // Terminal-loop fast-forward must respect acceptance.
	} {
		t.Run(tc.pattern+"/"+tc.input, func(t *testing.T) {
			code := mustCompile(t, tc.pattern)
			batch, release := NewVMBatch(len(code))
			defer release()
			for _, state := range []*VMBatch{nil, batch, batch} {
				matched, start, end, err := ExecMatchBatchWithCancel(state, code, []byte(tc.input), tc.flags|FlagsFullwordEnd, 0, nil)
				if err != nil || matched != (tc.end >= 0) || matched && (start != 0 || end != tc.end) {
					t.Fatalf("got (%v,%d,%d,%v), want end %d", matched, start, end, err, tc.end)
				}
			}
		})
	}
}
