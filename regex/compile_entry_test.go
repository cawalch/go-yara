package regex

import "testing"

func TestForwardRepeatEntry(t *testing.T) {
	for _, tc := range []struct {
		pattern, input string
		end            int
	}{
		{`(a?.)+`, "!!", 1},
		{`(a?.)+`, "!a!a!", 5},
		{`((a?)?.)+`, "!!", 1},
		{`((a?.){1,2})+`, "!!!!", 2},
		{`((a?.){2})+`, "!!!!!", 2},
		{`(a??.)+?`, "a!", 1},
		{`(a??.)+?`, "!!", 1},
		{`(a?.)*`, "!!", 2},
		{`(a?.){1,3}`, "!!!!", 3},
		{`(a*.)+`, "!!", 2},
	} {
		t.Run(tc.pattern+tc.input, func(t *testing.T) {
			parsed, err := NewParser(0).Parse(tc.pattern)
			if err != nil {
				t.Fatal(err)
			}
			code, err := CompileForward(parsed)
			if err != nil {
				t.Fatal(err)
			}
			batch, release := NewVMBatch(len(code))
			defer release()
			for _, wide := range []bool{false, true} {
				input, end, flags := []byte(tc.input), tc.end, parsed.Flags|FlagsGreedy
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

func TestForwardRepeatCaptures(t *testing.T) {
	for _, pattern := range []string{`(a?.)+`, `((a?)?.)+`, `(a??.)+?`} {
		parsed, err := NewParser(0).Parse(pattern)
		if err != nil {
			t.Fatal(err)
		}
		groups := []int{1}
		if parsed.GroupCount == 2 {
			groups = append(groups, 2)
		}
		code, err := CompileForwardCaptures(parsed, groups)
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			input string
			start int
		}{
			{"!", 0}, {"!a!", 1}, {"a!a!", 2},
		} {
			spans, ok := ExecCapturesAt(code, []byte(tc.input), 0, 0, len(tc.input), len(groups))
			if !ok || len(spans) != len(groups) || spans[0] != (CaptureSpan{tc.start, len(tc.input), true}) {
				t.Fatalf("%s on %q: %v, %+v", pattern, tc.input, ok, spans)
			}
			if len(groups) == 2 && tc.start > 0 && spans[1] != (CaptureSpan{tc.start, tc.start + 1, true}) {
				t.Fatalf("nested capture: %+v", spans)
			}
		}
	}
}
