package regex

import "testing"

func TestVMLazyPositiveRepetition(t *testing.T) {
	for _, tc := range []struct {
		pattern, input string
		end            int
	}{
		{`a+?`, "aa\x00", 1}, {`a\x00+?`, "a\x00\x00\x00!", 2},
		{`[a]+?`, "aaa!", 1}, {`[^x]+?`, "aaax", 1}, {`.+?`, "abc\n", 1},
		{`\d+?`, "123!", 1}, {`\D+?`, "abc1", 1}, {`\w+?`, "abc!", 1},
		{`\W+?`, "!!!a", 1}, {`\s+?`, "   a", 1}, {`\S+?`, "aaa ", 1},
		{`a{1,3}?`, "aaaa", 1}, {`a{2,4}?`, "aaaaa", 2}, {`a{2,}?`, "aaaaa", 2},
		{`a+`, "aaa!", 3}, {`[a]+`, "aaa!", 3}, {`a{2,4}`, "aaaaa", 4},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			parsed, err := NewParser(0).Parse(tc.pattern)
			if err != nil {
				t.Fatal(err)
			}
			code, err := Compile(parsed)
			if err != nil {
				t.Fatal(err)
			}
			batch, release := NewVMBatch(len(code))
			defer release()
			for _, wide := range []bool{false, true} {
				input := []byte(tc.input)
				end := tc.end
				flags := parsed.Flags
				if wide {
					input = nil
					for _, b := range []byte(tc.input) {
						input = append(input, b, 0)
					}
					end *= 2
					flags |= FlagsWide
				}
				for _, state := range []*VMBatch{nil, batch, batch} {
					matched, start, got, err := ExecMatchBatchWithCancel(state, code, input, flags, 0, nil)
					if err != nil || !matched || start != 0 || got != end {
						t.Fatalf("wide=%v: (%v,%d,%d,%v), want [0,%d)", wide, matched, start, got, err, end)
					}
				}
			}
		})
	}
}
