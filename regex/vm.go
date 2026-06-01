package regex

import (
	"encoding/binary"
)

// Exec runs the Thompson VM for the given bytecode on input.
// - If FlagsScan is set, it searches from every start position (scan semantics).
// - Otherwise it attempts only from position 0 (anchored semantics).
// Other flags like DOT_ALL and NO_CASE are honored by the VM.
func Exec(code, input []byte, flags Flags) bool {
	if len(code) == 0 {
		return false
	}
	if (flags & FlagsScan) != 0 {
		for start := 0; start <= len(input); start++ {
			if ok, _ := runAtMatch(code, input, flags, start); ok {
				return true
			}
		}
		return false
	}
	ok, _ := runAtMatch(code, input, flags, 0)
	return ok
}

// ExecMatch behaves like Exec but also returns the [start,end) byte range of the
// first match found. If no match is found it returns (false, -1, -1).
func ExecMatch(code, input []byte, flags Flags) (matched bool, start, end int) {
	if len(code) == 0 {
		return false, -1, -1
	}
	if (flags & FlagsScan) != 0 {
		for start = 0; start <= len(input); start++ { //nolint:intrange // keeping traditional for loop for compatibility
			if matched, end = runAtMatch(code, input, flags, start); matched {
				return true, start, end
			}
		}
		return false, -1, -1
	}
	if matched, end = runAtMatch(code, input, flags, 0); matched {
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
func ExecMatchBatch(bs *vmBatchState, code, input []byte, flags Flags, start int) (matched bool, startOff, endOff int) {
	if len(code) == 0 || start > len(input) {
		return false, -1, -1
	}
	matched, l := runAtMatchBatch(bs, code, input, flags, start)
	if matched {
		// l is the absolute end position; convert to length relative to start
		return true, 0, l - start
	}
	return false, -1, -1
}

type thread struct {
	pc int
}

// handleLiteralOp handles OpLiteral and OpNotLiteral opcodes
//
//nolint:revive // argument-limit: performance-critical VM hot path; struct would add indirection overhead
func handleLiteralOp(code, s []byte, next *[]thread, pc int, ch byte, pos, advance int, noCase bool, negated bool, wide bool, bestEnd *int, visited []int64, gen int64) bool {
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
		if addThread(code, s, next, pc+2, pos+advance, visited, gen, wide) {
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
func handleMaskedLiteralOp(code, s []byte, next *[]thread, pc int, ch byte, pos, advance int, negated bool, wide bool, bestEnd *int, visited []int64, gen int64) bool {
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
		if addThread(code, s, next, pc+3, pos+advance, visited, gen, wide) {
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
func handleAnyOp(code, s []byte, next *[]thread, pc int, ch byte, pos, advance int, dotAll bool, wide bool, bestEnd *int, visited []int64, gen int64) bool {
	if !dotAll && ch == '\n' {
		return false
	}
	if addThread(code, s, next, pc+1, pos+advance, visited, gen, wide) {
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
func handleClassOp(code, s []byte, next *[]thread, pc int, ch byte, pos, advance int, noCase bool, wide bool, bestEnd *int, visited []int64, gen int64) bool {
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
		if addThread(code, s, next, negIdx+1, pos+advance, visited, gen, wide) {
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
func handleCharClassOp(code, s []byte, next *[]thread, pc int, ch byte, pos, advance int, charClassFunc func(byte) bool, wide bool, bestEnd *int, visited []int64, gen int64) bool {
	if charClassFunc(ch) {
		if addThread(code, s, next, pc+1, pos+advance, visited, gen, wide) {
			if pos+advance > *bestEnd {
				*bestEnd = pos + advance
			}
			return true
		}
	}
	return false
}

func runAtMatch(code, s []byte, flags Flags, start int) (matched bool, length int) { //nolint:cyclop,revive,maintidx,nakedret // complex but performance-critical; splitting would hurt hot path, arg count intentional
	dotAll := (flags & FlagsDotAll) != 0
	noCase := (flags & FlagsNoCase) != 0
	wide := (flags & FlagsWide) != 0

	// Get pooled buffers: visited (generation counter), cur, next thread slices.
	st, gen := getVMState(len(code))
	visited := st.visited[:len(code)]
	cur := st.cur
	next := st.next
	// gen is a unique token from a global atomic counter. Each step increments
	// it locally so visited[] entries from the previous step are stale.
	// A block of 1M generation values is reserved per match in getVMState.

	// Track leftmost-longest end for this start position.
	bestEnd := -1

	// Epsilon/assertion closure at the start position.
	if addThread(code, s, &cur, 0, start, visited, gen, wide) {
		// MATCH reachable without consuming; end at current position.
		bestEnd = start
	}

	step := func(pos int, ch byte, advance int) {
		// Step all current threads consuming one "character" (1 or 2 bytes)
		next = next[:0]
		for _, t := range cur {
			pc := t.pc
			if pc < 0 || pc >= len(code) {
				continue
			}
			// Increment generation so visited[] entries from the previous step are stale.
			gen++

			switch code[pc] {
			case OpLiteral:
				handleLiteralOp(code, s, &next, pc, ch, pos, advance, noCase, false, wide, &bestEnd, visited, gen)
			case OpNotLiteral:
				handleLiteralOp(code, s, &next, pc, ch, pos, advance, noCase, true, wide, &bestEnd, visited, gen)
			case OpMaskedLiteral:
				handleMaskedLiteralOp(code, s, &next, pc, ch, pos, advance, false, wide, &bestEnd, visited, gen)
			case OpMaskedNotLiteral:
				handleMaskedLiteralOp(code, s, &next, pc, ch, pos, advance, true, wide, &bestEnd, visited, gen)
			case OpAny:
				handleAnyOp(code, s, &next, pc, ch, pos, advance, dotAll, wide, &bestEnd, visited, gen)
			case OpClass:
				handleClassOp(code, s, &next, pc, ch, pos, advance, noCase, wide, &bestEnd, visited, gen)
			case OpWordChar:
				handleCharClassOp(code, s, &next, pc, ch, pos, advance, isWord, wide, &bestEnd, visited, gen)
			case OpNonWordChar:
				handleCharClassOp(code, s, &next, pc, ch, pos, advance, notWord, wide, &bestEnd, visited, gen)
			case OpSpace:
				handleCharClassOp(code, s, &next, pc, ch, pos, advance, isSpace, wide, &bestEnd, visited, gen)
			case OpNonSpace:
				handleCharClassOp(code, s, &next, pc, ch, pos, advance, notSpace, wide, &bestEnd, visited, gen)
			case OpDigit:
				handleCharClassOp(code, s, &next, pc, ch, pos, advance, isDigit, wide, &bestEnd, visited, gen)
			case OpNonDigit:
				handleCharClassOp(code, s, &next, pc, ch, pos, advance, notDigit, wide, &bestEnd, visited, gen)
			default:
				// Unknown or assertion/non-consuming op remains handled in addThread; skip here
			}
		}
	}

	runWideLoop := func() bool {
		for pos := start; pos+1 < len(s); pos += 2 {
			if !isWidePair(s, pos) {
				continue
			}
			ch := s[pos]
			step(pos, ch, 2)
			cur, next = next, cur

			if checkAndReturnIfExhausted(cur, &matched, &length, bestEnd) {
				return true
			}
		}
		return false
	}

	runAsciiLoop := func() bool {
		for pos := start; pos < len(s); pos++ {
			ch := s[pos]
			step(pos, ch, 1)
			cur, next = next, cur

			if checkAndReturnIfExhausted(cur, &matched, &length, bestEnd) {
				return true
			}
		}
		return false
	}

	var exhausted bool
	if wide {
		exhausted = runWideLoop()
	} else {
		exhausted = runAsciiLoop()
	}

	if exhausted {
		putVMState(st)
		return
	}

	// End of input: return the longest match (if any) for this start.
	if bestEnd >= 0 {
		matched, length = true, bestEnd
	} else {
		matched, length = false, 0
	}
	putVMState(st)
	return //nolint:nakedret
}

// runAtMatchBatch is like runAtMatch but uses a pre-pinned vmBatchState
// to avoid sync.Pool Get/Put overhead. Use when calling runAtMatch
// thousands of times in a tight loop (e.g., addRegexMatches).
func runAtMatchBatch(bs *vmBatchState, code, s []byte, flags Flags, start int) (matched bool, length int) { //nolint:nestif,revive // argument-limit: performance-critical VM hot path; nested wide/ascii loops are intentional for VM dispatch
	dotAll := (flags & FlagsDotAll) != 0
	noCase := (flags & FlagsNoCase) != 0
	wide := (flags & FlagsWide) != 0

	st := bs.st
	codeLen := len(code)
	if cap(st.visited) < codeLen {
		st.visited = make([]int64, codeLen)
	}
	st.visited = st.visited[:codeLen]
	st.cur = st.cur[:0]
	st.next = st.next[:0]
	gen := bs.gen
	bs.gen--
	if bs.gen == 0 {
		bs.gen = vmGen.Add(1 << 20)
	}
	visited := st.visited[:len(code)]
	cur := st.cur
	next := st.next

	bestEnd := -1

	if addThread(code, s, &cur, 0, start, visited, gen, wide) {
		bestEnd = start
	}

	stepFn := func(pos int, ch byte, advance int) {
		next = next[:0]
		for _, t := range cur {
			pc := t.pc
			if pc < 0 || pc >= len(code) {
				continue
			}
			gen++
			switch code[pc] {
			case OpLiteral:
				handleLiteralOp(code, s, &next, pc, ch, pos, advance, noCase, false, wide, &bestEnd, visited, gen)
			case OpNotLiteral:
				handleLiteralOp(code, s, &next, pc, ch, pos, advance, noCase, true, wide, &bestEnd, visited, gen)
			case OpMaskedLiteral:
				handleMaskedLiteralOp(code, s, &next, pc, ch, pos, advance, false, wide, &bestEnd, visited, gen)
			case OpMaskedNotLiteral:
				handleMaskedLiteralOp(code, s, &next, pc, ch, pos, advance, true, wide, &bestEnd, visited, gen)
			case OpAny:
				handleAnyOp(code, s, &next, pc, ch, pos, advance, dotAll, wide, &bestEnd, visited, gen)
			case OpClass:
				handleClassOp(code, s, &next, pc, ch, pos, advance, noCase, wide, &bestEnd, visited, gen)
			case OpWordChar:
				handleCharClassOp(code, s, &next, pc, ch, pos, advance, isWord, wide, &bestEnd, visited, gen)
			case OpNonWordChar:
				handleCharClassOp(code, s, &next, pc, ch, pos, advance, notWord, wide, &bestEnd, visited, gen)
			case OpSpace:
				handleCharClassOp(code, s, &next, pc, ch, pos, advance, isSpace, wide, &bestEnd, visited, gen)
			case OpNonSpace:
				handleCharClassOp(code, s, &next, pc, ch, pos, advance, notSpace, wide, &bestEnd, visited, gen)
			case OpDigit:
				handleCharClassOp(code, s, &next, pc, ch, pos, advance, isDigit, wide, &bestEnd, visited, gen)
			case OpNonDigit:
				handleCharClassOp(code, s, &next, pc, ch, pos, advance, notDigit, wide, &bestEnd, visited, gen)
			}
		}
	}

	var exhausted bool
	if wide { //nolint:nestif // wide/ascii loop dispatch is intentional for VM
		for pos := start; pos+1 < len(s); pos += 2 {
			if !isWidePair(s, pos) {
				continue
			}
			stepFn(pos, s[pos], 2)
			cur, next = next, cur
			if checkAndReturnIfExhausted(cur, &matched, &length, bestEnd) {
				exhausted = true
				break
			}
		}
	} else {
		for pos := start; pos < len(s); pos++ {
			stepFn(pos, s[pos], 1)
			cur, next = next, cur
			if checkAndReturnIfExhausted(cur, &matched, &length, bestEnd) {
				exhausted = true
				break
			}
		}
	}

	if exhausted {
		return
	}

	if bestEnd >= 0 {
		matched, length = true, bestEnd
	} else {
		matched, length = false, 0
	}
	return
}

// addThread computes the epsilon/assertion closure from (pc,pos) and appends
// consuming states into list. Returns true if OpMatch is reachable in the
// closure at the given position.
// visited is a generation-counter []int; gen is the current generation token.
func addThread(code, s []byte, list *[]thread, pc, pos int, visited []int64, gen int64, wide bool) bool { //nolint:revive,cyclop // argument-limit and complexity are explicit for VM closure clarity
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
			// Layout: [op][id][u16 rel]
			if pc+3 >= len(code) {
				return false
			}
			u16 := binary.LittleEndian.Uint16(code[pc+2 : pc+4])
			// Safe conversion with explicit truncation
			rel := int16(u16 & 0xFFFF) // #nosec G115 - safe conversion with explicit masking
			// sequential next
			nextPC := pc + 4
			altPC := pc + int(rel)
			return addSplitThreads(code, s, list, nextPC, altPC, pos, visited, gen, wide, op)
		case OpJump:
			// Layout: [op][u16 rel]
			if pc+2 >= len(code) {
				return false
			}
			u16 := binary.LittleEndian.Uint16(code[pc+1 : pc+3])
			// Safe conversion with explicit truncation
			rel := int16(u16 & 0xFFFF) // #nosec G115 - safe conversion with explicit masking
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
			return true
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

// addSplitThreads adds threads for split operations based on the operation type
// addSplitThreads adds threads for OpSplitA/OpSplitN opcodes.
//
//nolint:revive // argument-limit: performance-critical VM hot path
func addSplitThreads(code, s []byte, list *[]thread, nextPC, altPC, pos int, visited []int64, gen int64, wide bool, op uint8) bool {
	if op == OpSplitA {
		if addThread(code, s, list, nextPC, pos, visited, gen, wide) {
			return true
		}
		return addThread(code, s, list, altPC, pos, visited, gen, wide)
	}

	// OpSplitN - add alternative thread first, then next
	if addThread(code, s, list, altPC, pos, visited, gen, wide) {
		return true
	}
	return addThread(code, s, list, nextPC, pos, visited, gen, wide)
}
