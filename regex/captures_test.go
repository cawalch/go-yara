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

// TestExecCapturesInlineBoundaryEightGroups pins the coordCount ==
// maxInlineCaptureCoords boundary: exactly eight groups must initialize and
// materialize through the inline path. Mutating either boundary to "<" makes the
// init and materialize modes disagree and returns zeroed spans.
func TestExecCapturesInlineBoundaryEightGroups(t *testing.T) {
	pattern := "(a)(b)(c)(d)(e)(f)(g)(h)"
	groups := []int{1, 2, 3, 4, 5, 6, 7, 8}
	code := mustCompileCaptures(t, pattern, groups)
	input := "abcdefgh"

	want := make([]CaptureSpan, 8)
	for i := range want {
		want[i] = CaptureSpan{Start: i, End: i + 1, Matched: true}
	}
	captures, matched := ExecCapturesAtWithScratch(nil, code, []byte(input), 0, 0, len(input), len(groups))
	if !matched || !reflect.DeepEqual(captures, want) {
		t.Fatalf("eight-group inline replay = %+v matched %v, want %+v", captures, matched, want)
	}
}

// TestExecCapturesZeroSlotCount pins the slotCount < 0 guard at its boundary:
// zero slots is valid and must replay with an empty span list.
func TestExecCapturesZeroSlotCount(t *testing.T) {
	code := mustCompileCaptures(t, "abc", nil)
	captures, matched := ExecCapturesAtWithScratch(nil, code, []byte("abc"), 0, 0, 3, 0)
	if !matched || len(captures) != 0 {
		t.Fatalf("zero-slot replay = %+v matched %v, want empty match", captures, matched)
	}
}

// TestExecCapturesHeapUnmatchedSlot pins the heap-mode slot initialization to
// -1: with nine groups and an optional ninth group, the untouched heap slots
// must stay unmatched rather than defaulting to a match at offset 1.
func TestExecCapturesHeapUnmatchedSlot(t *testing.T) {
	pattern := "(a)(b)(c)(d)(e)(f)(g)(h)(i)?"
	groups := []int{1, 2, 3, 4, 5, 6, 7, 8, 9}
	code := mustCompileCaptures(t, pattern, groups)
	input := "abcdefgh"

	want := make([]CaptureSpan, 9)
	for i := 0; i < 8; i++ {
		want[i] = CaptureSpan{Start: i, End: i + 1, Matched: true}
	}
	captures, matched := ExecCapturesAtWithScratch(nil, code, []byte(input), 0, 0, len(input), len(groups))
	if !matched || !reflect.DeepEqual(captures, want) {
		t.Fatalf("heap unmatched replay = %+v matched %v, want %+v", captures, matched, want)
	}
}

// TestExecCapturesDotAllNewline pins the dotAll flag gate: with the flag a dot
// consumes a newline, without it the replay must reject the same span.
func TestExecCapturesDotAllNewline(t *testing.T) {
	code := mustCompileCaptures(t, "(a.b)", []int{1})
	input := "a\nb"

	captures, matched := ExecCapturesAtWithScratch(nil, code, []byte(input), FlagsDotAll, 0, len(input), 1)
	if !matched || !reflect.DeepEqual(captures, matchedSpans(1, 0, 3)) {
		t.Fatalf("dotAll replay = %+v matched %v, want span (0,3)", captures, matched)
	}
	if captures, matched := ExecCapturesAtWithScratch(nil, code, []byte(input), 0, 0, len(input), 1); matched || captures != nil {
		t.Fatalf("non-dotAll replay = %+v matched %v, want reject", captures, matched)
	}
}

// TestExecCapturesMatchSpanShorterThanPattern pins the loop bound: a known span
// that ends while a consuming thread is still alive must be rejected without
// stepping one byte past end.
func TestExecCapturesMatchSpanShorterThanPattern(t *testing.T) {
	code := mustCompileCaptures(t, "(ab)", []int{1})
	captures, matched := ExecCapturesAtWithScratch(nil, code, []byte("a"), 0, 0, 1, 1)
	if matched || captures != nil {
		t.Fatalf("short-span replay = %+v matched %v, want reject", captures, matched)
	}
}

// TestExecCapturesBranchPriority pins split branch order: when both
// alternatives of ((a)|(a)) accept the same span, the first branch must win so
// group 2 is recorded and group 3 stays unmatched.
func TestExecCapturesBranchPriority(t *testing.T) {
	code := mustCompileCaptures(t, "((a)|(a))", []int{1, 2, 3})
	captures, matched := ExecCapturesAtWithScratch(nil, code, []byte("a"), 0, 0, 1, 3)
	want := []CaptureSpan{
		{Start: 0, End: 1, Matched: true},
		{Start: 0, End: 1, Matched: true},
		{},
	}
	if !matched || !reflect.DeepEqual(captures, want) {
		t.Fatalf("branch priority replay = %+v matched %v, want %+v", captures, matched, want)
	}
}

// TestExecCapturesHeapBranchClone pins per-branch slot cloning in heap mode:
// the first alternative writes a zero-width group before the second alternative
// matches, and that write must not leak into the accepted thread's slots.
func TestExecCapturesHeapBranchClone(t *testing.T) {
	pattern := "(a)(b)(c)(d)(e)(f)(g)(h)((z?)|i)"
	groups := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	code := mustCompileCaptures(t, pattern, groups)
	input := "abcdefghi"

	want := make([]CaptureSpan, 10)
	for i := 0; i < 8; i++ {
		want[i] = CaptureSpan{Start: i, End: i + 1, Matched: true}
	}
	want[8] = CaptureSpan{Start: 8, End: 9, Matched: true}
	captures, matched := ExecCapturesAtWithScratch(nil, code, []byte(input), 0, 0, len(input), len(groups))
	if !matched || !reflect.DeepEqual(captures, want) {
		t.Fatalf("heap branch clone replay = %+v matched %v, want %+v", captures, matched, want)
	}
}

// TestExecCapturesMalformedBytecode drives replay with hand-built, truncated or
// out-of-range programs. Each case must be rejected without reading past the end
// of the buffer; these bounds guards are otherwise unreachable through
// well-formed compiled programs.
func TestExecCapturesMalformedBytecode(t *testing.T) {
	tests := []struct {
		name      string
		code      []byte
		input     string
		start     int
		end       int
		slotCount int
	}{
		{name: "jump past end", code: []byte{OpJump, 3, 0}, input: "a", slotCount: 1},
		{name: "truncated split", code: []byte{OpSplitA, 0}, input: "a", slotCount: 1},
		{name: "truncated jump", code: []byte{OpJump, 0}, input: "a", slotCount: 1},
		{name: "truncated save", code: []byte{OpSaveStart}, input: "a", slotCount: 1},
		{name: "save slot at coord count", code: []byte{OpSaveStart, 8}, input: "a", slotCount: 8},
		{name: "truncated literal operand", code: []byte{OpLiteral}, input: "a", end: 1, slotCount: 1},
		{name: "truncated masked operand", code: []byte{OpMaskedLiteral, 0xF0}, input: "a", end: 1, slotCount: 1},
		{name: "truncated class bitmap", code: append([]byte{OpClass}, make([]byte, 32)...), input: "a", end: 1, slotCount: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			captures, matched := ExecCapturesAtWithScratch(nil, tt.code, []byte(tt.input), 0, tt.start, tt.end, tt.slotCount)
			if matched || captures != nil {
				t.Fatalf("malformed %v: matched=%v captures=%v, want reject", tt.code, matched, captures)
			}
		})
	}
}

// Mutation-test classification for regex/captures.go (gremlins v0.6.0,
// --workers 1):
//   - Wide-stride guard 117:18/117:21: equivalent-mode. isWidePair already
//     bounds-checks pos+1 < len(input), so the explicit pos+1 >= len(input)
//     disjunct is redundant.
//   - Main-loop pc guard 130:20: equivalent-mode. addCaptureThread only appends
//     consuming threads with pc < len(code) and resolves jumps internally, so
//     the guard is unreachable defense-in-depth.
//   - Split-time slot clone 238:20: equivalent-mode. Every OpSaveStart/OpSaveEnd
//     already copies thread.slots before writing (copy-on-write), so the
//     per-branch clone at the split is redundant.

// TestExecCapturesMaskedLiteral covers the OpMaskedLiteral/OpMaskedNotLiteral
// operand decoding, which no parser-produced capture program reaches.
func TestExecCapturesMaskedLiteral(t *testing.T) {
	tests := []struct {
		name  string
		op    byte
		value byte
		mask  byte
		ch    byte
		want  bool
	}{
		{name: "masked match", op: OpMaskedLiteral, value: 0xF0, mask: 0xF0, ch: 0xF5, want: true},
		{name: "masked miss", op: OpMaskedLiteral, value: 0xF0, mask: 0xF0, ch: 0x0F, want: false},
		{name: "masked not match", op: OpMaskedNotLiteral, value: 0xF0, mask: 0xF0, ch: 0x0F, want: true},
		{name: "masked not miss", op: OpMaskedNotLiteral, value: 0xF0, mask: 0xF0, ch: 0xF5, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := []byte{tt.op, tt.value, tt.mask, OpMatch}
			captures, matched := ExecCapturesAtWithScratch(nil, code, []byte{tt.ch}, 0, 0, 1, 0)
			if matched != tt.want {
				t.Fatalf("masked replay op=%#x ch=%#x matched=%v, want %v", tt.op, tt.ch, matched, tt.want)
			}
			if matched && len(captures) != 0 {
				t.Fatalf("masked replay returned spans %+v, want empty", captures)
			}
		})
	}
}

// TestExecCapturesShorthandClasses covers the OpWordChar/OpNonWordChar,
// OpSpace/OpNonSpace and OpDigit/OpNonDigit replay arms.
func TestExecCapturesShorthandClasses(t *testing.T) {
	pattern := `(\w)(\W)(\d)(\D)(\s)(\S)`
	groups := []int{1, 2, 3, 4, 5, 6}
	code := mustCompileCaptures(t, pattern, groups)
	input := "a!1a z"

	want := matchedSpans(6, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6)
	captures, matched := ExecCapturesAtWithScratch(nil, code, []byte(input), 0, 0, len(input), len(groups))
	if !matched || !reflect.DeepEqual(captures, want) {
		t.Fatalf("shorthand replay = %+v matched %v, want %+v", captures, matched, want)
	}
}

// TestExecCapturesWordBoundaries covers the OpWordBoundary and
// OpNonWordBoundary replay arms.
func TestExecCapturesWordBoundaries(t *testing.T) {
	boundary := mustCompileCaptures(t, `(\bword\b)`, []int{1})
	captures, matched := ExecCapturesAtWithScratch(nil, boundary, []byte("word"), 0, 0, 4, 1)
	if !matched || !reflect.DeepEqual(captures, matchedSpans(1, 0, 4)) {
		t.Fatalf("word boundary replay = %+v matched %v, want span (0,4)", captures, matched)
	}

	nonBoundary := mustCompileCaptures(t, `(a\Bb)`, []int{1})
	captures, matched = ExecCapturesAtWithScratch(nil, nonBoundary, []byte("ab"), 0, 0, 2, 1)
	if !matched || !reflect.DeepEqual(captures, matchedSpans(1, 0, 2)) {
		t.Fatalf("non-word boundary replay = %+v matched %v, want span (0,2)", captures, matched)
	}
}

// TestExecCapturesNilScratchEarlyReturns drives the start==end-accept and
// wide-invalid early returns with a nil scratch, where the scratch reset must be
// skipped rather than dereferenced.
func TestExecCapturesNilScratchEarlyReturns(t *testing.T) {
	empty := mustCompileCaptures(t, "(a?)", []int{1})
	captures, matched := ExecCapturesAtWithScratch(nil, empty, nil, 0, 0, 0, 1)
	if !matched || !reflect.DeepEqual(captures, matchedSpans(1, 0, 0)) {
		t.Fatalf("nil-scratch empty replay = %+v matched %v, want span (0,0)", captures, matched)
	}

	wide := mustCompileCaptures(t, "(abc)", []int{1})
	odd := []byte{0x61, 0x00, 0x62, 0x00, 0x63}
	if captures, matched := ExecCapturesAtWithScratch(nil, wide, odd, FlagsWide, 0, len(odd), 1); matched || captures != nil {
		t.Fatalf("nil-scratch wide odd tail = %+v matched %v, want reject", captures, matched)
	}
}

// TestCaptureScratchBufferReuse pins the exact-capacity reuse in the capture
// scratch buffers: cap == required length must not reallocate.
func TestCaptureScratchBufferReuse(t *testing.T) {
	visited := &CaptureScratch{visited: make([]bool, 8)}
	visitedBase := &visited.visited[0]
	if got := visited.prepareVisited(8); &got[0] != visitedBase {
		t.Fatal("prepareVisited reallocated visited despite exact capacity")
	}

	stack := make([]bool, 8)
	if got := prepareStackVisited(stack, 8); &got[0] != &stack[0] {
		t.Fatal("prepareStackVisited allocated instead of reusing the exact-fit stack buffer")
	}

	spans := &CaptureScratch{spans: make([]CaptureSpan, 3)}
	spansBase := &spans.spans[0]
	if got := captureSpansInto(spans, []int{0, 1, 2, 3, 4, 5}); &got[0] != spansBase {
		t.Fatal("captureSpansInto reallocated spans despite exact capacity")
	}
}
