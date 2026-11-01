package regex

import (
	"context"
	"encoding/binary"
)

// Exec runs the Thompson VM for the given bytecode on input.
// - If FlagsScan is set, it searches from every start position (scan semantics).
// - Otherwise it attempts only from position 0 (anchored semantics).
// Other flags like DOT_ALL and NO_CASE are honored by the VM.
func Exec(code, input []byte, flags Flags) bool {
	matched, _ := ExecWithCancel(code, input, flags, nil)
	return matched
}

// ExecWithCancel returns context.Canceled if done closes during matching.
//
//nolint:revive // cancellation signal accompanies the existing VM arguments
func ExecWithCancel(code, input []byte, flags Flags, done <-chan struct{}) (bool, error) {
	if vmCanceled(done) {
		return false, context.Canceled
	}
	if len(code) == 0 {
		return false, nil
	}
	scan := flags&FlagsScan != 0 && code[0] != OpMatchAtStart
	lastStart := 0
	if scan && flags&FlagsWide != 0 && len(input) > 0 {
		lastStart = 1 // Search both wide alignments, including odd byte offsets.
	}
	for start := 0; start <= lastStart; start++ {
		matched, _ := runMatch(code, input, flags, start, done, scan)
		if vmCanceled(done) {
			return false, context.Canceled
		}
		if matched {
			return true, nil
		}
	}
	return false, nil
}

func vmCanceled(done <-chan struct{}) bool {
	if done == nil {
		return false
	}
	select {
	case <-done:
		return true
	default:
		return false
	}
}

const vmCancellationInterval = 4096

// ExecMatch behaves like Exec but also returns the [start,end) byte range of the
// first match found. If no match is found it returns (false, -1, -1).
func ExecMatch(code, input []byte, flags Flags) (matched bool, start, end int) {
	if len(code) == 0 {
		return false, -1, -1
	}
	if (flags & FlagsScan) != 0 {
		for start = 0; start <= len(input); start++ { //nolint:intrange // keeping traditional for loop for compatibility
			if matched, end = runAtMatch(code, input, flags, start, nil); matched {
				return true, start, end
			}
		}
		return false, -1, -1
	}
	if matched, end = runAtMatch(code, input, flags, 0, nil); matched {
		return true, 0, end
	}
	return false, -1, -1
}

// ExecMatchBatch is like ExecMatch but uses a pre-pinned vmBatchState
// to avoid sync.Pool Get/Put overhead. The match is anchored at `start`.
// Returns (matched, relativeStart, relativeEnd) where positions are relative
// to the slice beginning at `start`.
//
//nolint:revive // argument-limit: performance-critical VM entry point
func ExecMatchBatch(bs *VMBatch, code, input []byte, flags Flags, start int) (matched bool, startOff, endOff int) {
	matched, startOff, endOff, _ = ExecMatchBatchWithCancel(bs, code, input, flags, start, nil)
	return
}

// ExecMatchBatchWithCancel supports cancellation and a nil (temporary) batch.
//
//nolint:revive // cancellation signal accompanies the existing VM arguments
func ExecMatchBatchWithCancel(bs *VMBatch, code, input []byte, flags Flags, start int, done <-chan struct{}) (bool, int, int, error) {
	if vmCanceled(done) {
		return false, -1, -1, context.Canceled
	}
	if len(code) == 0 || start < 0 || start > len(input) {
		return false, -1, -1, nil
	}
	var matched bool
	var end int
	if bs == nil {
		matched, end = runAtMatch(code, input, flags, start, done)
	} else {
		bs.prepareFailureReuse(code, input, flags)
		gen := bs.gen
		matched, end = runAtMatchBatchWithCancel(bs, code, input, flags, start, done)
		bs.finishFailureReuse(matched, vmCanceled(done), bs.gen-gen)
	}
	if vmCanceled(done) {
		return false, -1, -1, context.Canceled
	}
	if matched {
		return true, 0, end - start, nil
	}
	return false, -1, -1, nil
}

type thread struct {
	pc int
}

// handleLiteralOp handles OpLiteral and OpNotLiteral opcodes
//
//nolint:revive // argument-limit: performance-critical VM hot path; struct would add indirection overhead
func handleLiteralOp(code, s []byte, next *[]thread, pc int, ch byte, pos, advance int, noCase bool, negated bool, flags Flags, bestEnd *int, visited []int64, gen int64) bool {
	if pc+1 >= len(code) {
		return false
	}
	want := code[pc+1]
	var ok bool
	if negated {
		ok = ch != want
		if noCase {
			ok = toLowerASCII(ch) != toLowerASCII(want)
		}
	} else {
		ok = ch == want
		if !ok && noCase {
			ok = equalNoCase(ch, want)
		}
	}

	if ok {
		if addThread(code, s, next, pc+2, pos+advance, visited, gen, flags) {
			if pos+advance > *bestEnd {
				*bestEnd = pos + advance
			}
			return true
		}
	}
	return false
}

// handleMaskedLiteralOp handles OpMaskedLiteral and OpMaskedNotLiteral opcodes
//
//nolint:revive // argument-limit: performance-critical VM hot path
func handleMaskedLiteralOp(code, s []byte, next *[]thread, pc int, ch byte, pos, advance int, negated bool, flags Flags, bestEnd *int, visited []int64, gen int64) bool {
	if pc+2 >= len(code) {
		return false
	}
	val := code[pc+1]
	mask := code[pc+2]
	matches := (ch & mask) == (val & mask)

	if negated {
		matches = !matches
	}

	if matches {
		if addThread(code, s, next, pc+3, pos+advance, visited, gen, flags) {
			if pos+advance > *bestEnd {
				*bestEnd = pos + advance
			}
			return true
		}
	}
	return false
}

// handleAnyOp handles OpAny opcode
// checkBitmapMembership checks if a byte is in the bitmap, with optional case-insensitive matching
//
//nolint:revive // argument-limit: performance-critical VM hot path
func checkBitmapMembership(code []byte, bmStart int, ch byte, noCase bool) bool {
	inBitmap := func(b byte) bool {
		idx := int(b) / 8
		bit := byte(1 << (int(b) % 8))
		return bmStart+idx < len(code) && (code[bmStart+idx]&bit) != 0
	}

	inSet := inBitmap(ch)
	if noCase {
		lc := toLowerASCII(ch)
		uc := toUpperASCII(ch)
		if lc != ch {
			inSet = inSet || inBitmap(lc)
		}
		if uc != ch && uc != lc {
			inSet = inSet || inBitmap(uc)
		}
	}
	return inSet
}

// handleAnyOp handles the OpAny opcode (matches any character)
//
//nolint:revive // argument-limit: performance-critical VM hot path
func handleAnyOp(code, s []byte, next *[]thread, pc int, ch byte, pos, advance int, dotAll bool, flags Flags, bestEnd *int, visited []int64, gen int64) bool {
	if !dotAll && ch == '\n' {
		return false
	}
	if addThread(code, s, next, pc+1, pos+advance, visited, gen, flags) {
		if pos+advance > *bestEnd {
			*bestEnd = pos + advance
		}
		return true
	}
	return false
}

// handleClassOp handles OpClass opcode
//
//nolint:revive // argument-limit: performance-critical VM hot path
func handleClassOp(code, s []byte, next *[]thread, pc int, ch byte, pos, advance int, noCase bool, flags Flags, bestEnd *int, visited []int64, gen int64) bool {
	// Layout: [op][32-byte bitmap][1-byte neg]
	bmStart := pc + 1
	negIdx := bmStart + 32
	if negIdx >= len(code) {
		return false
	}

	neg := code[negIdx] != 0
	inSet := checkBitmapMembership(code, bmStart, ch, noCase)

	if neg {
		inSet = !inSet
	}

	if inSet {
		if addThread(code, s, next, negIdx+1, pos+advance, visited, gen, flags) {
			if pos+advance > *bestEnd {
				*bestEnd = pos + advance
			}
			return true
		}
	}
	return false
}

// handleCharClassOp handles character class opcodes (OpDigit, OpSpace, etc.)
//
//nolint:revive // argument-limit: performance-critical VM hot path
func handleCharClassOp(code, s []byte, next *[]thread, pc int, ch byte, pos, advance int, charClassFunc func(byte) bool, flags Flags, bestEnd *int, visited []int64, gen int64) bool {
	if charClassFunc(ch) {
		if addThread(code, s, next, pc+1, pos+advance, visited, gen, flags) {
			if pos+advance > *bestEnd {
				*bestEnd = pos + advance
			}
			return true
		}
	}
	return false
}

// newVMStep shares consuming transitions while the drivers retain their local
// thread buffers and state lifetimes. It is inlined at both call sites.
//
//nolint:revive // the once-per-attempt factory binds the VM's existing buffers
func newVMStep(code, s []byte, flags Flags, visited []int64, cur, next *[]thread, gen *int64, bestEnd *int) func(int, byte, int) {
	dotAll := flags&FlagsDotAll != 0
	noCase := flags&FlagsNoCase != 0
	return func(pos int, ch byte, advance int) {
		*next = (*next)[:0]
		// One generation identifies the full closure for this input position,
		// deduplicating paths reached from different threads.
		(*gen)++
		for _, t := range *cur {
			pc := t.pc
			if pc < 0 || pc >= len(code) {
				continue
			}
			var m bool
			switch code[pc] {
			case OpLiteral:
				m = handleLiteralOp(code, s, next, pc, ch, pos, advance, noCase, false, flags, bestEnd, visited, *gen)
			case OpNotLiteral:
				m = handleLiteralOp(code, s, next, pc, ch, pos, advance, noCase, true, flags, bestEnd, visited, *gen)
			case OpMaskedLiteral:
				m = handleMaskedLiteralOp(code, s, next, pc, ch, pos, advance, false, flags, bestEnd, visited, *gen)
			case OpMaskedNotLiteral:
				m = handleMaskedLiteralOp(code, s, next, pc, ch, pos, advance, true, flags, bestEnd, visited, *gen)
			case OpAny:
				m = handleAnyOp(code, s, next, pc, ch, pos, advance, dotAll, flags, bestEnd, visited, *gen)
			case OpClass:
				m = handleClassOp(code, s, next, pc, ch, pos, advance, noCase, flags, bestEnd, visited, *gen)
			case OpWordChar:
				m = handleCharClassOp(code, s, next, pc, ch, pos, advance, isWord, flags, bestEnd, visited, *gen)
			case OpNonWordChar:
				m = handleCharClassOp(code, s, next, pc, ch, pos, advance, notWord, flags, bestEnd, visited, *gen)
			case OpSpace:
				m = handleCharClassOp(code, s, next, pc, ch, pos, advance, isSpace, flags, bestEnd, visited, *gen)
			case OpNonSpace:
				m = handleCharClassOp(code, s, next, pc, ch, pos, advance, notSpace, flags, bestEnd, visited, *gen)
			case OpDigit:
				m = handleCharClassOp(code, s, next, pc, ch, pos, advance, isDigit, flags, bestEnd, visited, *gen)
			case OpNonDigit:
				m = handleCharClassOp(code, s, next, pc, ch, pos, advance, notDigit, flags, bestEnd, visited, *gen)
			}
			if m && flags&FlagsExhaustive == 0 {
				break
			}
		}
	}
}

//nolint:revive // VM arguments shared with the batch entry point
func runAtMatch(code, s []byte, flags Flags, start int, done <-chan struct{}) (bool, int) {
	return runMatch(code, s, flags, start, done, false)
}

func runMatch(code, s []byte, flags Flags, start int, done <-chan struct{}, scan bool) (matched bool, length int) { //nolint:cyclop,revive,maintidx,nakedret // performance-critical VM dispatch
	wide := (flags & FlagsWide) != 0

	// Get pooled buffers: visited (generation counter), cur, next thread slices.
	st, gen := getVMState(len(code))
	visited := st.visited[:len(code)]
	cur := st.cur
	next := st.next

	// Track the accepting endpoint while surviving continuations run.
	bestEnd := -1

	// Epsilon/assertion closure at the start position.
	if addThread(code, s, &cur, 0, start, visited, gen, flags) {
		// MATCH reachable without consuming; end at current position.
		bestEnd = start
	}

	step := newVMStep(code, s, flags, visited, &cur, &next, &gen, &bestEnd)

	advance := 1
	if wide {
		advance = 2
	}
	exhausted := false
	pos := start
	for ; pos < len(s); pos += advance {
		if done != nil && (pos-start)&(vmCancellationInterval-1) == 0 && vmCanceled(done) {
			exhausted = true
			break
		}
		// Merge new starts into the current closure: each state runs once per position.
		if scan && addThread(code, s, &cur, 0, pos, visited, gen, flags) {
			bestEnd = pos
		}
		if (scan && bestEnd >= 0) || pos+advance > len(s) {
			break
		}
		if wide && !isWidePair(s, pos) {
			cur = cur[:0]
			if scan {
				gen++
				continue
			}
			if checkAndReturnIfExhausted(cur, &matched, &length, bestEnd) {
				exhausted = true
				break
			}
			continue
		}
		if !scan && !wide && len(cur) == 1 {
			if fastForwardGreedyTerminalLoop(code, &cur, s, &pos, flags, &bestEnd, done) {
				if checkAndReturnIfExhausted(cur, &matched, &length, bestEnd) {
					exhausted = true
					break
				}
				continue
			}
		}
		step(pos, s[pos], advance)
		cur, next = next, cur
		if !scan && (flags&FlagsGreedy) == 0 && bestEnd >= 0 {
			matched, length = true, bestEnd
			exhausted = true
			break
		}
		if !scan && checkAndReturnIfExhausted(cur, &matched, &length, bestEnd) {
			exhausted = true
			break
		}
	}

	if !exhausted && scan && bestEnd < 0 && pos == len(s) {
		if addThread(code, s, &cur, 0, pos, visited, gen, flags) {
			bestEnd = pos
		}
	}

	// Restore pooled buffers on both exhaustion and end of input.
	st.cur = cur[:0]
	st.next = next[:0]
	st.gen = gen
	putVMState(st)
	if exhausted {
		return matched, length
	}
	if bestEnd >= 0 {
		return true, bestEnd
	}
	return false, 0
}

// runAtMatchBatch is like runAtMatch but uses a pre-pinned VMBatch
// to avoid sync.Pool Get/Put overhead. Use when calling runAtMatch
// thousands of times in a tight loop (e.g., addRegexMatches).
func runAtMatchBatchWithCancel(bs *VMBatch, code, s []byte, flags Flags, start int, done <-chan struct{}) (matched bool, length int) { //nolint:nestif,revive // argument-limit: performance-critical VM hot path; nested wide/ascii loops are intentional for VM dispatch
	wide := (flags & FlagsWide) != 0
	var reuse *failureReuse
	if bs.failure.learning || bs.failure.ready {
		reuse = &bs.failure
	}

	st := bs.st
	codeLen := len(code)
	if cap(st.visited) < codeLen {
		st.visited = make([]int64, codeLen)
	}
	st.visited = st.visited[:codeLen]
	st.cur = st.cur[:0]
	st.next = st.next[:0]
	gen := bs.gen
	visited := st.visited[:len(code)]
	cur := st.cur
	next := st.next

	bestEnd := -1

	if addThread(code, s, &cur, 0, start, visited, gen, flags) {
		bestEnd = start
	}

	stepFn := newVMStep(code, s, flags, visited, &cur, &next, &gen, &bestEnd)

	var exhausted bool
	if wide { //nolint:nestif // wide/ascii loop dispatch is intentional for VM
		for pos := start; pos+1 < len(s); pos += 2 {
			if done != nil && (pos-start)&(vmCancellationInterval-1) == 0 && vmCanceled(done) {
				exhausted = true
				break
			}
			if reuse != nil && reuse.rejects(cur, pos) {
				cur = cur[:0]
				exhausted = checkAndReturnIfExhausted(cur, &matched, &length, bestEnd)
				break
			}
			if !isWidePair(s, pos) {
				cur = cur[:0]
				exhausted = checkAndReturnIfExhausted(cur, &matched, &length, bestEnd)
				break
			}
			stepFn(pos, s[pos], 2)
			cur, next = next, cur
			if (flags&FlagsGreedy) == 0 && bestEnd >= 0 {
				matched, length = true, bestEnd
				exhausted = true
				break
			}
			if checkAndReturnIfExhausted(cur, &matched, &length, bestEnd) {
				exhausted = true
				break
			}
		}
	} else {
		for pos := start; pos < len(s); pos++ {
			if done != nil && (pos-start)&(vmCancellationInterval-1) == 0 && vmCanceled(done) {
				exhausted = true
				break
			}
			if reuse != nil && reuse.rejects(cur, pos) {
				cur = cur[:0]
				exhausted = checkAndReturnIfExhausted(cur, &matched, &length, bestEnd)
				break
			}
			if len(cur) == 1 {
				if fastForwardGreedyTerminalLoop(code, &cur, s, &pos, flags, &bestEnd, done) {
					if checkAndReturnIfExhausted(cur, &matched, &length, bestEnd) {
						exhausted = true
						break
					}
					continue
				}
			}
			stepFn(pos, s[pos], 1)
			cur, next = next, cur
			if (flags&FlagsGreedy) == 0 && bestEnd >= 0 {
				matched, length = true, bestEnd
				exhausted = true
				break
			}
			if checkAndReturnIfExhausted(cur, &matched, &length, bestEnd) {
				exhausted = true
				break
			}
		}
	}

	bs.gen = gen + 1
	st.cur = cur[:0]
	st.next = next[:0]
	st.gen = gen
	if exhausted {
		return matched, length
	}

	if bestEnd >= 0 {
		return true, bestEnd
	}
	return false, 0
}

// addThread computes the epsilon/assertion closure from (pc,pos) and appends
// consuming states into list. Returns true if OpMatch is reachable in the
// closure at the given position.
// visited is a generation-counter []int; gen is the current generation token.
func addThread(code, s []byte, list *[]thread, pc, pos int, visited []int64, gen int64, flags Flags) bool { //nolint:revive,cyclop // argument-limit and complexity are explicit for VM closure clarity
	wide := flags&FlagsWide != 0
	for {
		if pc < 0 || pc >= len(code) {
			return false
		}
		if visited[pc] == gen {
			return false
		}
		visited[pc] = gen
		op := code[pc]
		switch op {
		case OpSplitA, OpSplitB:
			// Layout: [op][u16 rel]
			if pc+2 >= len(code) {
				return false
			}
			u16 := binary.LittleEndian.Uint16(code[pc+1 : pc+3])
			rel := int16(u16) //checkednarrow:ignore uint16 bits encode a signed relative offset
			// sequential next
			nextPC := pc + 3
			altPC := pc + int(rel)
			return addSplitThreads(code, s, list, nextPC, altPC, pos, visited, gen, flags, op)
		case OpJump:
			// Layout: [op][u16 rel]
			if pc+2 >= len(code) {
				return false
			}
			u16 := binary.LittleEndian.Uint16(code[pc+1 : pc+3])
			rel := int16(u16) //checkednarrow:ignore uint16 bits encode a signed relative offset
			pc += int(rel)
			continue
		case OpMatchAtStart:
			if pos != 0 {
				return false
			}
			pc++
			continue
		case OpMatchAtEnd:
			if pos != len(s) {
				return false
			}
			pc++
			continue
		case OpWordBoundary:
			if wide {
				if !isWordBoundaryWide(s, pos) {
					return false
				}
			} else {
				if !isWordBoundary(s, pos) {
					return false
				}
			}
			pc++
			continue
		case OpNonWordBoundary:
			if wide {
				if isWordBoundaryWide(s, pos) {
					return false
				}
			} else {
				if isWordBoundary(s, pos) {
					return false
				}
			}
			pc++
			continue
		case OpMatch:
			return flags&FlagsFullwordEnd == 0 || fullwordEnd(s, pos, wide)
		default:
			// A consuming op: add to list and stop closure expansion
			*list = append(*list, thread{pc: pc})
			return false
		}
	}
}

func toLowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func toUpperASCII(b byte) byte {
	if b >= 'a' && b <= 'z' {
		return b - ('a' - 'A')
	}
	return b
}

func equalNoCase(a, b byte) bool { return toLowerASCII(a) == toLowerASCII(b) }

func isWord(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func isSpace(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r', '\f', '\v':
		return true
	default:
		return false
	}
}

// Pre-allocated predicate functions to avoid closure allocation in the hot path.
var (
	notWord  = func(b byte) bool { return !isWord(b) }
	notSpace = func(b byte) bool { return !isSpace(b) }
	notDigit = func(b byte) bool { return !isDigit(b) }
)

func isWordBoundary(s []byte, pos int) bool {
	var leftWord, rightWord bool
	if pos > 0 {
		leftWord = isWord(s[pos-1])
	}
	if pos < len(s) {
		rightWord = isWord(s[pos])
	}
	return leftWord != rightWord
}

// In WIDE mode a "character" is two bytes [lo, hi] where hi must be 0x00 for ASCII.
// Word boundaries are computed across 2-byte steps.
func isWordBoundaryWide(s []byte, pos int) bool {
	var leftWord, rightWord bool
	// Left char ends at pos-1; ensure we have a full pair ending at pos-1 => pos>=2 and hi==0
	if pos >= 2 && s[pos-1] == 0 {
		leftWord = isWord(s[pos-2])
	}
	// Right char starts at pos; ensure we have a full pair starting at pos => pos+1 < len and hi==0
	if pos+1 < len(s) && s[pos+1] == 0 {
		rightWord = isWord(s[pos])
	}
	return leftWord != rightWord
}

// Validates that at position pos we have a valid WIDE ASCII pair (hi byte zero).
func isWidePair(s []byte, pos int) bool {
	return pos+1 < len(s) && s[pos+1] == 0
}

// checkAndReturnIfExhausted checks if all threads have died and returns early if so
//
//nolint:revive // argument-limit: performance-critical VM hot path
func checkAndReturnIfExhausted(cur []thread, matched *bool, length *int, bestEnd int) bool {
	if len(cur) == 0 {
		if bestEnd >= 0 {
			*matched, *length = true, bestEnd
		} else {
			*matched, *length = false, 0
		}
		return true
	}
	return false
}

// addSplitThreads preserves split priority unless exhaustive verification is requested.
//
//nolint:revive // argument-limit: performance-critical VM hot path
func addSplitThreads(code, s []byte, list *[]thread, nextPC, altPC, pos int, visited []int64, gen int64, flags Flags, op uint8) bool {
	if op == OpSplitB {
		nextPC, altPC = altPC, nextPC
	}
	matched := addThread(code, s, list, nextPC, pos, visited, gen, flags)
	if matched && flags&FlagsExhaustive == 0 {
		return true
	}
	alternativeMatched := addThread(code, s, list, altPC, pos, visited, gen, flags)
	return matched || alternativeMatched
}

// fullword uses alphanumeric bytes, unlike \b, which also treats '_' as a word byte.
func fullwordEnd(input []byte, end int, wide bool) bool {
	if end >= len(input) {
		return true
	}
	if wide && (end+1 >= len(input) || input[end+1] != 0) {
		return true
	}
	b := input[end]
	return !isWord(b) || b == '_'
}
