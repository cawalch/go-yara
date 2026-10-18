package regex

import (
	"context"
	"errors"
	"testing"
)

func TestExecMatchEntryGuards(t *testing.T) {
	if matched, start, end := ExecMatch(nil, []byte("a"), 0); matched || start != -1 || end != -1 {
		t.Fatalf("ExecMatch(empty) = (%v,%d,%d), want (false,-1,-1)", matched, start, end)
	}
	if matched, start, end := ExecMatch(mustCompile(t, "a"), []byte("b"), FlagsScan); matched || start != -1 || end != -1 {
		t.Fatalf("ExecMatch(scan no-match) = (%v,%d,%d), want (false,-1,-1)", matched, start, end)
	}
	if matched, start, end := ExecMatch(mustCompile(t, "a"), []byte("b"), 0); matched || start != -1 || end != -1 {
		t.Fatalf("ExecMatch(anchored no-match) = (%v,%d,%d), want (false,-1,-1)", matched, start, end)
	}
	// Scan must consider the empty match at end of input (start == len(input)).
	if matched, start, end := ExecMatch(mustCompile(t, "$"), []byte("a"), FlagsScan); !matched || start != 1 || end != 1 {
		t.Fatalf("ExecMatch($, scan) = (%v,%d,%d), want (true,1,1)", matched, start, end)
	}
}

func TestExecWithCancelWideEmptyInput(t *testing.T) {
	if matched, err := ExecWithCancel(mustCompile(t, "a"), nil, FlagsScan|FlagsWide, nil); matched || err != nil {
		t.Fatalf("ExecWithCancel(wide, empty) = (%v,%v), want (false,nil)", matched, err)
	}
}

func TestExecMatchBatchCancelGuards(t *testing.T) {
	code := mustCompile(t, "a")
	input := []byte("a")

	done := make(chan struct{})
	close(done)
	if matched, s, e, err := ExecMatchBatchWithCancel(nil, code, input, 0, 0, done); matched || s != -1 || e != -1 || !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled = (%v,%d,%d,%v), want (false,-1,-1,canceled)", matched, s, e, err)
	}
	if matched, s, e, err := ExecMatchBatchWithCancel(nil, nil, input, 0, 0, nil); matched || s != -1 || e != -1 || err != nil {
		t.Fatalf("empty code = (%v,%d,%d,%v), want (false,-1,-1,nil)", matched, s, e, err)
	}
	if matched, s, e, err := ExecMatchBatchWithCancel(nil, code, input, 0, -1, nil); matched || s != -1 || e != -1 || err != nil {
		t.Fatalf("negative start = (%v,%d,%d,%v), want (false,-1,-1,nil)", matched, s, e, err)
	}
	if matched, s, e, err := ExecMatchBatchWithCancel(nil, code, input, 0, 2, nil); matched || s != -1 || e != -1 || err != nil {
		t.Fatalf("start past end = (%v,%d,%d,%v), want (false,-1,-1,nil)", matched, s, e, err)
	}
	if matched, s, e, err := ExecMatchBatchWithCancel(nil, mustCompile(t, "b"), input, 0, 0, nil); matched || s != -1 || e != -1 || err != nil {
		t.Fatalf("no match = (%v,%d,%d,%v), want (false,-1,-1,nil)", matched, s, e, err)
	}
	// Relative end must be end-start, not end+start.
	if matched, s, e, err := ExecMatchBatchWithCancel(nil, mustCompile(t, "ab"), []byte("xab"), 0, 1, nil); !matched || s != 0 || e != 2 || err != nil {
		t.Fatalf("offset match = (%v,%d,%d,%v), want (true,0,2,nil)", matched, s, e, err)
	}
}

func TestRunMatchCancellation(t *testing.T) {
	done := make(chan struct{})
	close(done)
	if matched, _ := runMatch(mustCompile(t, "a"), []byte("a"), 0, 0, done, false); matched {
		t.Fatal("runMatch reported a match after cancellation")
	}
}

func TestRunAtMatchBatchCancellation(t *testing.T) {
	done := make(chan struct{})
	close(done)
	code := mustCompile(t, "a")

	asciiBatch, release := NewVMBatch(len(code))
	if matched, _ := runAtMatchBatchWithCancel(asciiBatch, code, []byte("a"), 0, 0, done); matched {
		t.Fatal("ascii batch reported a match after cancellation")
	}
	release()

	wideBatch, releaseWide := NewVMBatch(len(code))
	if matched, _ := runAtMatchBatchWithCancel(wideBatch, code, []byte{'a', 0}, FlagsWide, 0, done); matched {
		t.Fatal("wide batch reported a match after cancellation")
	}
	releaseWide()
}

func TestASCIIFoldHelpers(t *testing.T) {
	if got := toLowerASCII('A'); got != 'a' {
		t.Fatalf("toLowerASCII('A') = %q", got)
	}
	if got := toLowerASCII('Z'); got != 'z' {
		t.Fatalf("toLowerASCII('Z') = %q", got)
	}
	if got := toLowerASCII('a'); got != 'a' {
		t.Fatalf("toLowerASCII('a') = %q", got)
	}
	if got := toUpperASCII('a'); got != 'A' {
		t.Fatalf("toUpperASCII('a') = %q", got)
	}
	if got := toUpperASCII('z'); got != 'Z' {
		t.Fatalf("toUpperASCII('z') = %q", got)
	}
	if got := toUpperASCII('A'); got != 'A' {
		t.Fatalf("toUpperASCII('A') = %q", got)
	}
}

func TestIsWordEndpoints(t *testing.T) {
	for _, b := range []byte{'a', 'z', 'A', 'Z', '0', '9', '_'} {
		if !isWord(b) {
			t.Fatalf("isWord(%q) = false, want true", b)
		}
	}
	for _, b := range []byte{' ', '-', '/', ':', '~'} {
		if isWord(b) {
			t.Fatalf("isWord(%q) = true, want false", b)
		}
	}
}

func TestIsWordBoundaryWide(t *testing.T) {
	s := []byte{'a', 0, ' ', 0}
	if !isWordBoundaryWide(s, 2) {
		t.Fatal("isWordBoundaryWide(wide, 2) = false, want true")
	}
	if !isWordBoundaryWide(s, 0) {
		t.Fatal("isWordBoundaryWide(wide, 0) = false, want true (start of word)")
	}
	inside := []byte{'a', 0, 'b', 0}
	if isWordBoundaryWide(inside, 2) {
		t.Fatal("isWordBoundaryWide(inside word) = true, want false")
	}
}

func TestIsWidePairBounds(t *testing.T) {
	if isWidePair([]byte{'a', 'b'}, 1) {
		t.Fatal("isWidePair at last byte = true, want false")
	}
	if !isWidePair([]byte{'a', 0}, 0) {
		t.Fatal("isWidePair valid pair = false, want true")
	}
	if isWidePair([]byte{'a', 1}, 0) {
		t.Fatal("isWidePair nonzero high byte = true, want false")
	}
}

func TestCheckAndReturnIfExhaustedBestEnd(t *testing.T) {
	var matched bool
	var length int
	if !checkAndReturnIfExhausted(nil, &matched, &length, 0) {
		t.Fatal("empty cur with bestEnd 0 = not exhausted")
	}
	if !matched || length != 0 {
		t.Fatalf("bestEnd 0 -> (%v,%d), want (true,0)", matched, length)
	}

	matched, length = false, 0
	if !checkAndReturnIfExhausted(nil, &matched, &length, -1) {
		t.Fatal("empty cur with bestEnd -1 = not exhausted")
	}
	if matched || length != 0 {
		t.Fatalf("bestEnd -1 -> (%v,%d), want (false,0)", matched, length)
	}

	if checkAndReturnIfExhausted([]thread{{pc: 0}}, &matched, &length, -1) {
		t.Fatal("non-empty cur reported exhausted")
	}
}

func TestCheckBitmapMembershipBounds(t *testing.T) {
	if checkBitmapMembership(make([]byte, 32), 1, 0xFF, false) {
		t.Fatal("out-of-range bitmap read reported membership")
	}
	code := make([]byte, 33)
	code[1+12] = 1 << (97 % 8) // 'a' (97) -> idx 12, bit 1
	if !checkBitmapMembership(code, 1, 'a', false) {
		t.Fatal("in-range bitmap bit not reported")
	}
	if checkBitmapMembership(code, 1, 'b', false) {
		t.Fatal("unset bitmap bit reported membership")
	}
}

func TestHandleLiteralOpBounds(t *testing.T) {
	bestEnd := -1
	var next []thread
	if handleLiteralOp([]byte{OpLiteral}, nil, &next, 0, 'a', 0, 1, false, false, false, &bestEnd, nil, 0) {
		t.Fatal("truncated literal matched")
	}

	bestEnd = -1
	next = next[:0]
	if !handleLiteralOp([]byte{OpLiteral, 'a', OpMatch}, nil, &next, 0, 'a', 0, 1, false, false, false, &bestEnd, make([]int64, 3), 1) {
		t.Fatal("literal match not reported")
	}
	if bestEnd != 1 {
		t.Fatalf("literal bestEnd = %d, want 1", bestEnd)
	}
}

func TestHandleMaskedLiteralOpBounds(t *testing.T) {
	bestEnd := -1
	var next []thread
	if handleMaskedLiteralOp([]byte{OpMaskedLiteral, 0xF0}, nil, &next, 0, 0xF5, 0, 1, false, false, &bestEnd, nil, 0) {
		t.Fatal("truncated masked literal matched")
	}

	bestEnd = -1
	next = next[:0]
	if !handleMaskedLiteralOp([]byte{OpMaskedLiteral, 0xF0, 0xF0, OpMatch}, nil, &next, 0, 0xF5, 0, 1, false, false, &bestEnd, make([]int64, 4), 1) {
		t.Fatal("masked literal match not reported")
	}
}

func TestHandleAnyOpBounds(t *testing.T) {
	bestEnd := -1
	var next []thread
	if !handleAnyOp([]byte{OpAny, OpMatch}, nil, &next, 0, 'x', 0, 1, false, false, &bestEnd, make([]int64, 2), 1) {
		t.Fatal("any match not reported")
	}

	next = next[:0]
	bestEnd = 5
	if !handleAnyOp([]byte{OpAny, OpMatch}, nil, &next, 0, 'x', 5, 1, false, false, &bestEnd, make([]int64, 2), 1) {
		t.Fatal("any match at pos 5 not reported")
	}
	if bestEnd != 6 {
		t.Fatalf("any bestEnd = %d, want 6", bestEnd)
	}
}

func TestHandleClassOpBounds(t *testing.T) {
	bestEnd := -1
	var next []thread
	if handleClassOp(make([]byte, 33), nil, &next, 0, 'a', 0, 1, false, false, &bestEnd, nil, 0) {
		t.Fatal("truncated class matched")
	}
}

func TestHandleCharClassOpBounds(t *testing.T) {
	bestEnd := -1
	var next []thread
	if !handleCharClassOp([]byte{OpDigit, OpMatch}, nil, &next, 0, '5', 0, 1, isDigit, false, &bestEnd, make([]int64, 2), 1) {
		t.Fatal("digit match not reported")
	}
}

func TestAddThreadGuards(t *testing.T) {
	var list []thread
	if addThread([]byte{OpMatch}, nil, &list, 1, 0, make([]int64, 1), 1, false) {
		t.Fatal("addThread(pc == len) matched")
	}
	if addThread([]byte{OpSplitA, 0, 0}, nil, &list, 0, 0, make([]int64, 3), 1, false) {
		t.Fatal("addThread(truncated split) matched")
	}
	if addThread([]byte{OpJump, 0}, nil, &list, 0, 0, make([]int64, 2), 1, false) {
		t.Fatal("addThread(truncated jump) matched")
	}
}

func TestFastForwardGreedyTerminalLoopGuards(t *testing.T) {
	pos := 0
	bestEnd := -1

	cur := []thread{{pc: 1}}
	if fastForwardGreedyTerminalLoop([]byte{OpMatch}, &cur, []byte("a"), &pos, 0, &bestEnd, nil) {
		t.Fatal("pc == len fast-forwarded")
	}

	cur = []thread{{pc: 0}}
	if fastForwardGreedyTerminalLoop([]byte{OpLiteral}, &cur, []byte("a"), &pos, 0, &bestEnd, nil) {
		t.Fatal("truncated literal fast-forwarded")
	}

	cur = []thread{{pc: 0}}
	if fastForwardGreedyTerminalLoop([]byte{OpNotLiteral}, &cur, []byte("a"), &pos, 0, &bestEnd, nil) {
		t.Fatal("truncated not-literal fast-forwarded")
	}

	classCode := append([]byte{OpClass}, make([]byte, 32)...)
	cur = []thread{{pc: 0}}
	if fastForwardGreedyTerminalLoop(classCode, &cur, []byte("a"), &pos, 0, &bestEnd, nil) {
		t.Fatal("truncated class fast-forwarded")
	}

	splitCode := []byte{OpLiteral, 'a', OpSplitA, 0, 0}
	cur = []thread{{pc: 0}}
	if fastForwardGreedyTerminalLoop(splitCode, &cur, []byte("a"), &pos, 0, &bestEnd, nil) {
		t.Fatal("truncated split fast-forwarded")
	}
}

func TestHandleLiteralOpNegatedNoCase(t *testing.T) {
	bestEnd := -1
	var next []thread
	// Negated nocase literal: 'A' folds to 'a', so it must not match [^a].
	if handleLiteralOp([]byte{OpNotLiteral, 'a', OpMatch}, nil, &next, 0, 'A', 0, 1, true, true, false, &bestEnd, make([]int64, 3), 1) {
		t.Fatal("negated nocase literal matched the folded target")
	}
}

func TestHandleMaskedLiteralOpBestEnd(t *testing.T) {
	bestEnd := -1
	var next []thread
	// The end-anchor makes the thread position observable, so the pos+advance
	// argument (not just pc+3) is load-bearing.
	if !handleMaskedLiteralOp([]byte{OpMaskedLiteral, 0xF0, 0xF0, OpMatchAtEnd, OpMatch}, []byte("x"), &next, 0, 0xF5, 0, 1, false, false, &bestEnd, make([]int64, 5), 1) {
		t.Fatal("masked literal followed by end-anchor not reported")
	}
	if bestEnd != 1 {
		t.Fatalf("masked literal bestEnd = %d, want 1", bestEnd)
	}
}

func TestHandleAnyOpMatchAtEnd(t *testing.T) {
	bestEnd := -1
	var next []thread
	if !handleAnyOp([]byte{OpAny, OpMatchAtEnd, OpMatch}, []byte("x"), &next, 0, 'x', 0, 1, false, false, &bestEnd, make([]int64, 3), 1) {
		t.Fatal("any followed by end-anchor not reported")
	}
}

func TestHandleCharClassOpMatchAtEnd(t *testing.T) {
	bestEnd := -1
	var next []thread
	if !handleCharClassOp([]byte{OpDigit, OpMatchAtEnd, OpMatch}, []byte("5"), &next, 0, '5', 0, 1, isDigit, false, &bestEnd, make([]int64, 3), 1) {
		t.Fatal("digit followed by end-anchor not reported")
	}
}

func TestAddThreadNonWordBoundary(t *testing.T) {
	var list []thread
	if !addThread([]byte{OpNonWordBoundary, OpMatch}, nil, &list, 0, 0, make([]int64, 2), 1, false) {
		t.Fatal("non-word-boundary at empty input should reach match")
	}
}

// classLoopCode builds an OpClass loop whose split branches back to the class
// op and exits to OpMatch: [OpClass][32-byte bitmap][neg][OpSplitB][id][rel][OpMatch].
func classLoopCode() []byte {
	code := make([]byte, 0, 40)
	code = append(code, OpClass)
	bm := make([]byte, 32)
	for _, b := range []byte{'a', 'b'} {
		bm[b>>3] |= 1 << (b & 7)
	}
	code = append(code, bm...)
	code = append(code, 0) // not negated
	// Split at pc 34 must jump back to the class op at pc 0: rel = -34.
	rel := -34
	code = append(code, OpSplitB, 0, byte(rel&0xff), byte((rel>>8)&0xff))
	code = append(code, OpMatch)
	return code
}

func TestFastForwardGreedyTerminalLoopSplitAndCancellation(t *testing.T) {
	plus := []byte{OpLiteral, 'a', OpSplitB, 0, 0xFE, 0xFF, OpMatch}
	pos := 0
	bestEnd := -1
	cur := []thread{{pc: 0}}
	if !fastForwardGreedyTerminalLoop(plus, &cur, []byte("aaa"), &pos, 0, &bestEnd, nil) {
		t.Fatal("plus loop should fast-forward")
	}
	if pos != 3 || bestEnd != 3 {
		t.Fatalf("plus loop -> pos %d bestEnd %d, want 3,3", pos, bestEnd)
	}

	// An OpSplitA loop must still be recognised (branch-priority mutation).
	ungreedy := []byte{OpLiteral, 'a', OpSplitA, 0, 0xFE, 0xFF, OpMatch}
	pos = 0
	bestEnd = -1
	cur = []thread{{pc: 0}}
	if !fastForwardGreedyTerminalLoop(ungreedy, &cur, []byte("aaa"), &pos, 0, &bestEnd, nil) {
		t.Fatal("OpSplitA loop should fast-forward")
	}

	// An exit past the end of the buffer must be rejected without panicking.
	noMatch := []byte{OpLiteral, 'a', OpSplitB, 0, 0xFE, 0xFF}
	pos = 0
	bestEnd = -1
	cur = []thread{{pc: 0}}
	if fastForwardGreedyTerminalLoop(noMatch, &cur, []byte("aaa"), &pos, 0, &bestEnd, nil) {
		t.Fatal("missing OpMatch exit should not fast-forward")
	}

	done := make(chan struct{})
	close(done)

	// Cancellation in the default predicate loop.
	pos = 0
	bestEnd = -1
	cur = []thread{{pc: 0}}
	if !fastForwardGreedyTerminalLoop(plus, &cur, []byte("aaa"), &pos, 0, &bestEnd, done) {
		t.Fatal("canceled fast-forward should still report handling")
	}
	if pos != 0 || bestEnd != -1 {
		t.Fatalf("canceled fast-forward -> pos %d bestEnd %d, want 0,-1", pos, bestEnd)
	}

	// A non-zero start position exercises the (p-startPos) cancellation index.
	pos = 1
	bestEnd = -1
	cur = []thread{{pc: 0}}
	if !fastForwardGreedyTerminalLoop(plus, &cur, []byte("aaa"), &pos, 0, &bestEnd, done) {
		t.Fatal("canceled fast-forward at start 1 should still report handling")
	}
	if pos != 1 || bestEnd != -1 {
		t.Fatalf("canceled fast-forward(start 1) -> pos %d bestEnd %d, want 1,-1", pos, bestEnd)
	}

	// Cancellation in the OpClass specialised loop.
	pos = 0
	bestEnd = -1
	cur = []thread{{pc: 0}}
	if !fastForwardGreedyTerminalLoop(classLoopCode(), &cur, []byte("aaa"), &pos, 0, &bestEnd, done) {
		t.Fatal("canceled class fast-forward should still report handling")
	}
	if pos != 0 || bestEnd != -1 {
		t.Fatalf("canceled class fast-forward -> pos %d bestEnd %d, want 0,-1", pos, bestEnd)
	}

	pos = 1
	bestEnd = -1
	cur = []thread{{pc: 0}}
	if !fastForwardGreedyTerminalLoop(classLoopCode(), &cur, []byte("aaa"), &pos, 0, &bestEnd, done) {
		t.Fatal("canceled class fast-forward at start 1 should still report handling")
	}
	if pos != 1 || bestEnd != -1 {
		t.Fatalf("canceled class fast-forward(start 1) -> pos %d bestEnd %d, want 1,-1", pos, bestEnd)
	}
}

func TestRunAtMatchBatchCancellationArithmetic(t *testing.T) {
	done := make(chan struct{})
	close(done)
	// An alternation keeps len(cur) > 1 so the greedy fast-forward does not
	// mask the outer-loop cancellation check.
	code := mustCompile(t, "(a|b)c")

	// A non-zero start position makes the (pos-start) cancellation index
	// observable in both the ascii and wide batch loops.
	ascii, release := NewVMBatch(len(code))
	if matched, _ := runAtMatchBatchWithCancel(ascii, code, []byte("xxac"), 0, 2, done); matched {
		t.Fatal("ascii batch matched after cancellation at start 2")
	}
	release()

	wide, releaseWide := NewVMBatch(len(code))
	if matched, _ := runAtMatchBatchWithCancel(wide, code, []byte{'x', 0, 'a', 0, 'c', 0}, FlagsWide, 2, done); matched {
		t.Fatal("wide batch matched after cancellation at start 2")
	}
	releaseWide()
}

func TestFastForwardOpAnyAndOpNotLiteral(t *testing.T) {
	anyLoop := []byte{OpAny, OpSplitB, 0, 0xFF, 0xFF, OpMatch}
	pos := 0
	bestEnd := -1
	cur := []thread{{pc: 0}}
	if !fastForwardGreedyTerminalLoop(anyLoop, &cur, []byte("abc"), &pos, 0, &bestEnd, nil) {
		t.Fatal("OpAny loop should fast-forward")
	}
	if pos != 3 || bestEnd != 3 {
		t.Fatalf("OpAny loop -> pos %d bestEnd %d, want 3,3", pos, bestEnd)
	}

	notLoop := []byte{OpNotLiteral, 'a', OpSplitB, 0, 0xFE, 0xFF, OpMatch}
	pos = 0
	bestEnd = -1
	cur = []thread{{pc: 0}}
	if !fastForwardGreedyTerminalLoop(notLoop, &cur, []byte("bbb"), &pos, 0, &bestEnd, nil) {
		t.Fatal("OpNotLiteral loop should fast-forward")
	}
	if pos != 3 || bestEnd != 3 {
		t.Fatalf("OpNotLiteral loop -> pos %d bestEnd %d, want 3,3", pos, bestEnd)
	}

	// The excluded byte at index 0 stops the not-literal fast-forward
	// immediately, so neither the index comparison nor the bestEnd update fires.
	pos = 0
	bestEnd = -1
	cur = []thread{{pc: 0}}
	if !fastForwardGreedyTerminalLoop(notLoop, &cur, []byte("abb"), &pos, 0, &bestEnd, nil) {
		t.Fatal("OpNotLiteral immediate stop should still report handling")
	}
	if pos != 0 || bestEnd != -1 {
		t.Fatalf("OpNotLiteral immediate stop -> pos %d bestEnd %d, want 0,-1", pos, bestEnd)
	}
}

func TestRunAtMatchBatchGreedyLongest(t *testing.T) {
	code, flags := mustCompileWithFlags(t, "a+")

	ascii, release := NewVMBatch(len(code))
	if matched, length := runAtMatchBatchWithCancel(ascii, code, []byte("aaa"), flags, 0, nil); !matched || length != 3 {
		t.Fatalf("ascii greedy a+ = (%v,%d), want (true,3)", matched, length)
	}
	release()

	wide, releaseWide := NewVMBatch(len(code))
	if matched, length := runAtMatchBatchWithCancel(wide, code, []byte{'a', 0, 'a', 0, 'a', 0}, flags|FlagsWide, 0, nil); !matched || length != 6 {
		t.Fatalf("wide greedy a+ = (%v,%d), want (true,6)", matched, length)
	}
	releaseWide()
}

func TestFastForwardOpAnyNewlineStop(t *testing.T) {
	anyLoop := []byte{OpAny, OpSplitB, 0, 0xFF, 0xFF, OpMatch}
	pos := 0
	bestEnd := -1
	cur := []thread{{pc: 0}}
	if !fastForwardGreedyTerminalLoop(anyLoop, &cur, []byte("\nbc"), &pos, 0, &bestEnd, nil) {
		t.Fatal("OpAny newline loop should still report handling")
	}
	if pos != 0 || bestEnd != -1 {
		t.Fatalf("OpAny newline -> pos %d bestEnd %d, want 0,-1", pos, bestEnd)
	}
}

func TestRunAtMatchBatchGreedyAlternation(t *testing.T) {
	// The alternation keeps len(cur) > 1, so the ascii greedy loop is exercised
	// instead of the single-thread fast-forward.
	code, flags := mustCompileWithFlags(t, "(a|b)+")
	ascii, release := NewVMBatch(len(code))
	if matched, length := runAtMatchBatchWithCancel(ascii, code, []byte("abab"), flags, 0, nil); !matched || length != 4 {
		t.Fatalf("ascii greedy (a|b)+ = (%v,%d), want (true,4)", matched, length)
	}
	release()
}

// Mutation-test classification for regex/vm.go (gremlins v0.6.0, --workers 1).
// All 37 remaining lived mutants are equivalent-mode:
//   - 143:19, 169:19, 211:18, 239:19, 254:19 (pos+advance > *bestEnd): the
//     boundary only differs at equality, where the same bestEnd is assigned.
//   - 30:48 (len(input) > 0 on the wide scan): the extra start is a no-op that
//     runMatch rejects, and never panics on empty input.
//   - 296:20, 338:12, 441:20 (pc < 0 || pc >= len(code)): addThread only appends
//     consuming threads with pc < len(code), so these guards are unreachable
//     defence-in-depth.
//   - 339:25/56, 480:57, 503:57, 868:58, 905:58 (p-startPos and
//     vmCancellationInterval-1): cancellation timing only; offset 0 always
//     satisfies "offset & mask == 0" for any mask, so the first check always
//     fires and the arithmetic cannot change a verdict.
//   - 347:23/35, 373:51, 384:35 (main-loop bestEnd/pos boundaries): the scan
//     break and end-of-input empty-match handling converge on the same result.
//   - 419:21 (cap < codeLen): reallocation is a capacity-only optimization.
//   - 479:24/27 (wide loop pos+1 < len(s)): an extra odd position is rejected
//     by isWidePair and yields the same verdict.
//   - 491:43, 518:43 (bestEnd >= 0 in the greedy early-return): equivalent at
//     equality, where the same match is recorded.
//   - 849:12, 855:12 (fast-forward exitPC guards): a recognised loop always has
//     exitPC in range, and 849 rejects the out-of-range case first.
//   - 108:17/21 (-1 sentinels on the post-match cancellation): the same
//     sentinels are exercised by the pre-cancellation path (95:17/21); reaching
//     this one requires a cancellation to land mid-run, which is inherently
//     racy.
//
// The 11 NOT COVERED mutants are dead code or Go-coverage artifacts: 760/772/783
// are predicate closures superseded by the specialised OpClass/OpAny/OpNotLiteral
// fast-forward loops, and 833/836/839/863/878/889 are switch case conditions,
// for which Go coverage emits no block.
