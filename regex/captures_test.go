package regex

import (
	"reflect"
	"testing"
)

func mustCompileCaptures(t *testing.T, pattern string, groups []int) []byte {
	t.Helper()
	ast, err := NewParser(0).Parse(pattern)
	if err != nil {
		t.Fatalf("parse %q: %v", pattern, err)
	}
	code, err := CompileCaptures(ast, groups)
	if err != nil {
		t.Fatalf("compile captures %q groups %v: %v", pattern, groups, err)
	}
	return code
}

// matchedSpans builds the expected span list for (slotCount) groups from
// coordinate pairs (start, end) per group slot.
func matchedSpans(spanCount int, coords ...int) []CaptureSpan {
	if len(coords) != spanCount*2 {
		panic("matchedSpans: need two coordinates per span")
	}
	out := make([]CaptureSpan, spanCount)
	for span := range out {
		out[span] = CaptureSpan{Start: coords[span*2], End: coords[span*2+1], Matched: true}
	}
	return out
}

// TestExecCapturesReplaySpans exercises the capture replay VM directly:
// inline-slot packs, alternation branches, optional and nested groups,
// quantifier resets, nocase, wide strides, zero-width matches, and the
// input-bound guards. These kill save-slot arithmetic, thread-routing, and
// guard mutations that scanner-level evidence tests never observe.
func TestExecCapturesReplaySpans(t *testing.T) {
	type tc struct {
		name           string
		pattern        string
		groups         []int
		flags          Flags
		input          string
		start          int
		end            int
		slotCount      int
		want           []CaptureSpan
		expectsNoMatch bool
	}

	tests := []tc{
		{
			name: "two groups", pattern: "(abc)(def)", groups: []int{1, 2}, slotCount: 2,
			input: "abcdef", want: matchedSpans(2, 0, 3, 3, 6),
		},
		{
			name: "group order mapping", pattern: "(abc)(def)", groups: []int{2, 1}, slotCount: 2,
			input: "abcdef", want: matchedSpans(2, 3, 6, 0, 3),
		},
		{
			name: "nested group", pattern: "(a(b))", groups: []int{1, 2}, slotCount: 2,
			input: "ab", want: matchedSpans(2, 0, 2, 1, 2),
		},
		{
			name: "alternation second branch", pattern: "(abc|xyz)", groups: []int{1}, slotCount: 1,
			input: "xyz", want: matchedSpans(1, 0, 3),
		},
		{
			name: "alternation first branch", pattern: "(abc|xyz)", groups: []int{1}, slotCount: 1,
			input: "abc", want: matchedSpans(1, 0, 3),
		},
		{
			name: "optional group unmatched", pattern: "(abc)(def)?", groups: []int{1, 2}, slotCount: 2,
			input: "abc", want: []CaptureSpan{{Start: 0, End: 3, Matched: true}, {}},
		},
		{
			name: "optional group matched", pattern: "(abc)(def)?", groups: []int{1, 2}, slotCount: 2,
			input: "abcdef", want: matchedSpans(2, 0, 3, 3, 6),
		},
		{
			name: "zero-width optional groups between literals", pattern: "(a?)(bc)(d?)(e)", groups: []int{1, 2, 3, 4}, slotCount: 4,
			input: "bce", want: matchedSpans(4, 0, 0, 0, 2, 2, 2, 2, 3),
		},
		{
			name: "zero-width group anchors at middle offset", pattern: "(a?)(bc)", groups: []int{1, 2}, slotCount: 2,
			input: "zbc", start: 1, end: 3, want: matchedSpans(2, 1, 1, 1, 3),
		},
		{
			name: "start equals end accepts empty", pattern: "(a?)", groups: []int{1}, slotCount: 1,
			input: "", want: matchedSpans(1, 0, 0),
		},
		{
			name: "nocase input uppercase", pattern: "(abc)", groups: []int{1}, flags: FlagsNoCase, slotCount: 1,
			input: "ABC", want: matchedSpans(1, 0, 3),
		},
		{
			name: "nocase pattern uppercase", pattern: "(ABC)", groups: []int{1}, flags: FlagsNoCase, slotCount: 1,
			input: "abc", want: matchedSpans(1, 0, 3),
		},
		{
			name: "wide stride", pattern: "(abc)", groups: []int{1}, flags: FlagsWide, slotCount: 1,
			input: "\x61\x00\x62\x00\x63\x00", want: matchedSpans(1, 0, 6),
		},
		{
			name: "wide nocase", pattern: "(ab)", groups: []int{1}, flags: FlagsWide | FlagsNoCase, slotCount: 1,
			input: "\x41\x00\x42\x00", want: matchedSpans(1, 0, 4),
		},
		{
			name: "start equals end on non-accepting pattern", pattern: "(abc)", groups: []int{1}, slotCount: 1,
			input: "abc", start: 0, end: 0, expectsNoMatch: true,
		},
		{
			name: "start below zero", pattern: "(abc)", groups: []int{1}, slotCount: 1,
			input: "abc", start: -1, end: 3, expectsNoMatch: true,
		},
		{
			name: "end before start", pattern: "(abc)", groups: []int{1}, slotCount: 1,
			input: "abc", start: 2, end: 1, expectsNoMatch: true,
		},
		{
			name: "end beyond length", pattern: "(abc)", groups: []int{1}, slotCount: 1,
			input: "abc", start: 0, end: 4, expectsNoMatch: true,
		},
		{
			name: "negative slotCount", pattern: "(abc)", groups: []int{1}, slotCount: -1,
			input: "abc", start: 0, end: 3, expectsNoMatch: true,
		},
		{
			// Wide replay rejects an odd tail: the stride-2 walk cannot accept
			// a broken UTF-16 pair and must fail instead of treating a wide
			// byte as ASCII (which would corrupt span arithmetic).
			name: "wide odd tail rejects", pattern: "(abc)", groups: []int{1}, flags: FlagsWide, slotCount: 1,
			input: "\x61\x00\x62\x00\x63", start: 0, end: 5, expectsNoMatch: true,
		},
		{
			name: "no match inside larger input", pattern: "(abc)", groups: []int{1}, slotCount: 1,
			input: "abx", start: 0, end: 3, expectsNoMatch: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code := mustCompileCaptures(t, test.pattern, test.groups)
			start, end := test.start, test.end
			if start == 0 && end == 0 && !test.expectsNoMatch {
				end = len(test.input)
			}
			var scratch CaptureScratch
			captured, matched := ExecCapturesAtWithScratch(&scratch, code, []byte(test.input), test.flags, start, end, test.slotCount)

			if test.expectsNoMatch {
				if matched || captured != nil {
					t.Fatalf("%q start=%d end=%d: matched=%v captured=%v, want reject", test.pattern, start, end, matched, captured)
				}
				return
			}
			if !matched {
				t.Fatalf("%q input %q start=%d end=%d: expected match", test.pattern, test.input, start, end)
			}
			if !reflect.DeepEqual(captured, test.want) {
				t.Fatalf("%q spans = %+v, want %+v", test.pattern, captured, test.want)
			}
		})
	}
}

// TestExecCapturesOverflowSlotPaths drives replay with nine groups (18 coords
// > maxInlineCaptureCoords) so the heap slot path, slot-count guards, and
// scratch-buffer reuse are covered directly.
func TestExecCapturesOverflowSlotPaths(t *testing.T) {
	pattern := "(a)(b)(c)(d)(e)(f)(g)(h)(i)"
	groups := []int{1, 2, 3, 4, 5, 6, 7, 8, 9}
	code := mustCompileCaptures(t, pattern, groups)
	input := "abcdefghi"

	want := []CaptureSpan{
		{Start: 0, End: 1, Matched: true}, {Start: 1, End: 2, Matched: true},
		{Start: 2, End: 3, Matched: true}, {Start: 3, End: 4, Matched: true},
		{Start: 4, End: 5, Matched: true}, {Start: 5, End: 6, Matched: true},
		{Start: 6, End: 7, Matched: true}, {Start: 7, End: 8, Matched: true},
		{Start: 8, End: 9, Matched: true},
	}

	captures, matched := ExecCapturesAtWithScratch(nil, code, []byte(input), 0, 0, len(input), len(groups))
	if !matched || !reflect.DeepEqual(captures, want) {
		t.Fatalf("nine-group replay = %+v matched %v, want %+v", captures, matched, want)
	}

	// Scratch reuse across rounds must stay stable (no stale slot carryover).
	var scratch CaptureScratch
	for round := range 3 {
		captures, matched := ExecCapturesAtWithScratch(&scratch, code, []byte(input), 0, 0, len(input), len(groups))
		if !matched || !reflect.DeepEqual(captures, want) {
			t.Fatalf("scratch round %d = %+v matched %v", round, captures, matched)
		}
	}
}
