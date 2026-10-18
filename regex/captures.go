package regex

import "encoding/binary"

// CaptureSpan is a byte range recovered from a replay-only capture program.
type CaptureSpan struct {
	Start   int
	End     int
	Matched bool
}

const (
	maxInlineCaptureCoords = 16
	stackCaptureVisitedLen = 4096
)

type captureThread struct {
	pc     int
	inline [maxInlineCaptureCoords]int
	slots  []int
}

// CaptureScratch holds reusable thread, visited, and span buffers for capture replay.
type CaptureScratch struct {
	cur     []captureThread
	next    []captureThread
	visited []bool
	spans   []CaptureSpan
}

type captureReplayState struct {
	code           []byte
	input          []byte
	visited        []bool
	acceptedSlots  []int
	acceptedInline [maxInlineCaptureCoords]int
	coordCount     int
	expectedEnd    int
	wide           bool
	hasAccepted    bool
}

// ExecCapturesAt replays a tagged regex at a known [start,end) match. It uses
// the original input so anchors and word boundaries retain scan-time meaning.
//
//nolint:revive // replay API keeps the known outer-match coordinates explicit
func ExecCapturesAt(code, input []byte, flags Flags, start, end, slotCount int) ([]CaptureSpan, bool) {
	return ExecCapturesAtWithScratch(nil, code, input, flags, start, end, slotCount)
}

// ExecCapturesAtWithScratch replays a tagged regex at a known [start,end) match
// using reusable scratch buffers when provided.
//
//nolint:revive // replay API keeps the known outer-match coordinates and scratch explicit
func ExecCapturesAtWithScratch(
	scratch *CaptureScratch,
	code, input []byte,
	flags Flags,
	start, end, slotCount int,
) ([]CaptureSpan, bool) {
	if len(code) == 0 || start < 0 || end < start || end > len(input) || slotCount < 0 {
		return nil, false
	}
	coordCount := slotCount * 2
	initThread := captureThread{pc: 0}
	if coordCount <= maxInlineCaptureCoords {
		for index := range coordCount {
			initThread.inline[index] = -1
		}
	} else {
		slots := make([]int, coordCount)
		for index := range slots {
			slots[index] = -1
		}
		initThread.slots = slots
	}

	var cur, next []captureThread
	var visited []bool
	if scratch != nil {
		cur = scratch.cur[:0]
		next = scratch.next[:0]
		visited = scratch.prepareVisited(len(code))
	} else {
		var curBuf, nextBuf [32]captureThread
		cur = curBuf[:0]
		next = nextBuf[:0]
		var visitedBuf [stackCaptureVisitedLen]bool
		visited = prepareStackVisited(visitedBuf[:], len(code))
	}

	wide := flags&FlagsWide != 0
	state := captureReplayState{
		code:        code,
		input:       input,
		visited:     visited,
		coordCount:  coordCount,
		expectedEnd: end,
		wide:        wide,
	}
	addCaptureThread(&state, &cur, initThread, start)
	if start == end && state.hasAccepted {
		if scratch != nil {
			scratch.cur = cur[:0]
			scratch.next = next[:0]
		}
		return state.materializeSpans(scratch), true
	}

	dotAll := flags&FlagsDotAll != 0
	noCase := flags&FlagsNoCase != 0
	advance := 1
	if wide {
		advance = 2
	}
	for pos := start; pos < end; pos += advance {
		if wide && (pos+1 >= len(input) || !isWidePair(input, pos)) {
			if scratch != nil {
				scratch.cur = cur[:0]
				scratch.next = next[:0]
			}
			return nil, false
		}
		ch := input[pos]
		next = next[:0]
		clear(state.visited)
		state.hasAccepted = false
		for index := range cur {
			pc := cur[index].pc
			if pc < 0 || pc >= len(code) {
				continue
			}
			nextPC, matches := captureInstructionMatches(code, pc, ch, dotAll, noCase)
			if !matches {
				continue
			}
			thread := cur[index]
			thread.pc = nextPC
			addCaptureThread(&state, &next, thread, pos+advance)
		}
		cur, next = next, cur
		if pos+advance == end && state.hasAccepted {
			if scratch != nil {
				scratch.cur = cur[:0]
				scratch.next = next[:0]
			}
			return state.materializeSpans(scratch), true
		}
		if len(cur) == 0 {
			if scratch != nil {
				scratch.cur = cur[:0]
				scratch.next = next[:0]
			}
			return nil, false
		}
	}
	if scratch != nil {
		scratch.cur = cur[:0]
		scratch.next = next[:0]
	}
	return nil, false
}

func (s *CaptureScratch) prepareVisited(codeLen int) []bool {
	if cap(s.visited) < codeLen {
		s.visited = make([]bool, codeLen)
	}
	visited := s.visited[:codeLen]
	clear(visited)
	return visited
}

func prepareStackVisited(buf []bool, codeLen int) []bool {
	if codeLen <= len(buf) {
		return buf[:codeLen]
	}
	return make([]bool, codeLen)
}

func (s *captureReplayState) materializeSpans(scratch *CaptureScratch) []CaptureSpan {
	if s.coordCount <= maxInlineCaptureCoords {
		return captureSpansInto(scratch, s.acceptedInline[:s.coordCount])
	}
	return captureSpansInto(scratch, s.acceptedSlots)
}

func captureSpansInto(scratch *CaptureScratch, slots []int) []CaptureSpan {
	count := len(slots) / 2
	var spans []CaptureSpan
	if scratch != nil {
		if cap(scratch.spans) < count {
			scratch.spans = make([]CaptureSpan, count)
		}
		spans = scratch.spans[:count]
		clear(spans)
	} else {
		spans = make([]CaptureSpan, count)
	}
	for slot := range spans {
		start, end := slots[slot*2], slots[slot*2+1]
		if start >= 0 && end >= start {
			spans[slot] = CaptureSpan{Start: start, End: end, Matched: true}
		}
	}
	return spans
}

//nolint:revive // tagged-VM hot path avoids allocating a state wrapper per closure expansion
func addCaptureThread(
	state *captureReplayState,
	list *[]captureThread,
	thread captureThread,
	pos int,
) {
	code := state.code
	input := state.input
	visited := state.visited
	wide := state.wide
	pc := thread.pc
	for {
		if pc < 0 || pc >= len(code) || visited[pc] {
			return
		}
		visited[pc] = true
		switch code[pc] {
		case OpSplitA, OpSplitB:
			if pc+2 >= len(code) {
				return
			}
			rel := int(int16(binary.LittleEndian.Uint16(code[pc+1 : pc+3]))) //checkednarrow:ignore uint16 bits encode a signed relative offset
			nextPC, altPC := pc+3, pc+rel
			first, second := nextPC, altPC
			if code[pc] == OpSplitB {
				first, second = altPC, nextPC
			}
			branch := thread
			branch.pc = first
			if branch.slots != nil {
				branch.slots = cloneCaptureSlots(branch.slots)
			}
			addCaptureThread(state, list, branch, pos)
			thread.pc = second
			addCaptureThread(state, list, thread, pos)
			return
		case OpJump:
			if pc+2 >= len(code) {
				return
			}
			pc += int(int16(binary.LittleEndian.Uint16(code[pc+1 : pc+3]))) //checkednarrow:ignore uint16 bits encode a signed relative offset
		case OpSaveStart, OpSaveEnd:
			if pc+1 >= len(code) {
				return
			}
			slot := int(code[pc+1]) * 2
			if code[pc] == OpSaveEnd {
				slot++
			}
			if slot >= state.coordCount {
				return
			}
			if thread.slots != nil {
				thread.slots = cloneCaptureSlots(thread.slots)
				thread.slots[slot] = pos
			} else {
				thread.inline[slot] = pos
			}
			pc += 2
		case OpMatchAtStart:
			if pos != 0 {
				return
			}
			pc++
		case OpMatchAtEnd:
			if pos != len(input) {
				return
			}
			pc++
		case OpWordBoundary:
			if wide && !isWordBoundaryWide(input, pos) || !wide && !isWordBoundary(input, pos) {
				return
			}
			pc++
		case OpNonWordBoundary:
			if wide && isWordBoundaryWide(input, pos) || !wide && isWordBoundary(input, pos) {
				return
			}
			pc++
		case OpMatch:
			if pos == state.expectedEnd && !state.hasAccepted {
				state.hasAccepted = true
				if thread.slots != nil {
					state.acceptedSlots = cloneCaptureSlots(thread.slots)
				} else {
					state.acceptedInline = thread.inline
				}
			}
			return
		default:
			thread.pc = pc
			*list = append(*list, thread)
			return
		}
	}
}

//nolint:revive // tagged-VM hot path keeps instruction inputs explicit
func captureInstructionMatches(code []byte, pc int, ch byte, dotAll, noCase bool) (int, bool) {
	switch code[pc] {
	case OpLiteral, OpNotLiteral:
		if pc+1 >= len(code) {
			return 0, false
		}
		match := ch == code[pc+1]
		if noCase {
			match = equalNoCase(ch, code[pc+1])
		}
		if code[pc] == OpNotLiteral {
			match = !match
		}
		return pc + 2, match
	case OpMaskedLiteral, OpMaskedNotLiteral:
		if pc+2 >= len(code) {
			return 0, false
		}
		match := ch&code[pc+2] == code[pc+1]&code[pc+2]
		if code[pc] == OpMaskedNotLiteral {
			match = !match
		}
		return pc + 3, match
	case OpAny:
		return pc + 1, dotAll || ch != '\n'
	case OpClass:
		if pc+33 >= len(code) {
			return 0, false
		}
		match := checkBitmapMembership(code, pc+1, ch, noCase)
		if code[pc+33] != 0 {
			match = !match
		}
		return pc + 34, match
	case OpWordChar:
		return pc + 1, isWord(ch)
	case OpNonWordChar:
		return pc + 1, !isWord(ch)
	case OpSpace:
		return pc + 1, isSpace(ch)
	case OpNonSpace:
		return pc + 1, !isSpace(ch)
	case OpDigit:
		return pc + 1, isDigit(ch)
	case OpNonDigit:
		return pc + 1, !isDigit(ch)
	default:
		return 0, false
	}
}

func cloneCaptureSlots(slots []int) []int {
	return append([]int(nil), slots...)
}
