package regex

import "encoding/binary"

// CaptureSpan is a byte range recovered from a replay-only capture program.
type CaptureSpan struct {
	Start   int
	End     int
	Matched bool
}

type captureThread struct {
	pc    int
	slots []int
}

// ExecCapturesAt replays a tagged regex at a known [start,end) match. It uses
// the original input so anchors and word boundaries retain scan-time meaning.
//
//nolint:revive // replay API keeps the known outer-match coordinates explicit
func ExecCapturesAt(code, input []byte, flags Flags, start, end, slotCount int) ([]CaptureSpan, bool) {
	if len(code) == 0 || start < 0 || end < start || end > len(input) || slotCount < 0 {
		return nil, false
	}
	slots := make([]int, slotCount*2)
	for index := range slots {
		slots[index] = -1
	}
	cur := make([]captureThread, 0, 16)
	visited := make([]bool, len(code))
	var accepted []int
	addCaptureThread(code, input, &cur, captureThread{pc: 0, slots: slots}, start, end, visited,
		flags&FlagsWide != 0, &accepted)
	if start == end && accepted != nil {
		return captureSpans(accepted), true
	}

	dotAll := flags&FlagsDotAll != 0
	noCase := flags&FlagsNoCase != 0
	wide := flags&FlagsWide != 0
	advance := 1
	if wide {
		advance = 2
	}
	for pos := start; pos < end; pos += advance {
		if wide && (pos+1 >= len(input) || !isWidePair(input, pos)) {
			return nil, false
		}
		ch := input[pos]
		next := make([]captureThread, 0, len(cur))
		clear(visited)
		accepted = nil
		for _, thread := range cur {
			pc := thread.pc
			if pc < 0 || pc >= len(code) {
				continue
			}
			nextPC, matches := captureInstructionMatches(code, pc, ch, dotAll, noCase)
			if !matches {
				continue
			}
			addCaptureThread(code, input, &next, captureThread{pc: nextPC, slots: thread.slots},
				pos+advance, end, visited, wide, &accepted)
		}
		cur = next
		if pos+advance == end && accepted != nil {
			return captureSpans(accepted), true
		}
		if len(cur) == 0 {
			return nil, false
		}
	}
	return nil, false
}

func captureSpans(slots []int) []CaptureSpan {
	spans := make([]CaptureSpan, len(slots)/2)
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
	code, input []byte,
	list *[]captureThread,
	thread captureThread,
	pos, expectedEnd int,
	visited []bool,
	wide bool,
	accepted *[]int,
) {
	pc := thread.pc
	slots := thread.slots
	for {
		if pc < 0 || pc >= len(code) || visited[pc] {
			return
		}
		visited[pc] = true
		switch code[pc] {
		case OpSplitA, OpSplitB:
			if pc+3 >= len(code) {
				return
			}
			rel := int(int16(binary.LittleEndian.Uint16(code[pc+2 : pc+4])))
			nextPC, altPC := pc+4, pc+rel
			first, second := nextPC, altPC
			if code[pc] == OpSplitB {
				first, second = altPC, nextPC
			}
			addCaptureThread(code, input, list, captureThread{pc: first, slots: cloneCaptureSlots(slots)},
				pos, expectedEnd, visited, wide, accepted)
			addCaptureThread(code, input, list, captureThread{pc: second, slots: slots},
				pos, expectedEnd, visited, wide, accepted)
			return
		case OpJump:
			if pc+2 >= len(code) {
				return
			}
			pc += int(int16(binary.LittleEndian.Uint16(code[pc+1 : pc+3])))
		case OpSaveStart, OpSaveEnd:
			if pc+1 >= len(code) {
				return
			}
			slot := int(code[pc+1]) * 2
			if code[pc] == OpSaveEnd {
				slot++
			}
			if slot >= len(slots) {
				return
			}
			slots = cloneCaptureSlots(slots)
			slots[slot] = pos
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
			if pos == expectedEnd && *accepted == nil {
				*accepted = cloneCaptureSlots(slots)
			}
			return
		default:
			*list = append(*list, captureThread{pc: pc, slots: slots})
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
