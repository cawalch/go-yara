package regex

import (
	"bytes"
	"encoding/binary"
)

// fastForwardGreedyTerminalLoop accelerates single-thread greedy loops that
// branch directly to OpMatch. Instead of stepping Thompson NFA states for every
// byte in long matching runs (such as .* or [^\s]+ over hundreds of kilobytes),
// it scans forward through matching bytes in a direct, tight loop.
//
//nolint:revive,cyclop,gocognit,funlen // performance-critical VM hot-path fast-forward
func fastForwardGreedyTerminalLoop(code []byte, cur *[]thread, s []byte, pos *int, flags Flags, bestEnd *int, done <-chan struct{}) bool {
	if len(*cur) != 1 {
		return false
	}
	pc := (*cur)[0].pc
	if pc < 0 || pc >= len(code) {
		return false
	}
	op := code[pc]
	var splitPC int
	var pred func(byte) bool

	noCase := (flags & FlagsNoCase) != 0
	dotAll := (flags & FlagsDotAll) != 0

	switch op {
	case OpClass:
		bmStart := pc + 1
		negIdx := bmStart + 32
		if negIdx >= len(code) {
			return false
		}
		neg := code[negIdx] != 0
		splitPC = negIdx + 1
		if !noCase {
			pred = func(b byte) bool {
				return ((code[bmStart+int(b>>3)] & (1 << (b & 7))) != 0) != neg
			}
		} else {
			pred = func(b byte) bool {
				return checkBitmapMembership(code, bmStart, b, true) != neg
			}
		}
	case OpAny:
		splitPC = pc + 1
		if dotAll {
			pred = func(b byte) bool { return true }
		} else {
			pred = func(b byte) bool { return b != '\n' }
		}
	case OpNotLiteral:
		if pc+1 >= len(code) {
			return false
		}
		target := code[pc+1]
		splitPC = pc + 2
		if noCase {
			pred = func(b byte) bool { return !equalNoCase(b, target) }
		} else {
			pred = func(b byte) bool { return b != target }
		}
	case OpLiteral:
		if pc+1 >= len(code) {
			return false
		}
		target := code[pc+1]
		splitPC = pc + 2
		if noCase {
			pred = func(b byte) bool { return equalNoCase(b, target) }
		} else {
			pred = func(b byte) bool { return b == target }
		}
	case OpSpace:
		splitPC = pc + 1
		pred = isSpace
	case OpNonSpace:
		splitPC = pc + 1
		pred = notSpace
	case OpDigit:
		splitPC = pc + 1
		pred = isDigit
	case OpNonDigit:
		splitPC = pc + 1
		pred = notDigit
	case OpWordChar:
		splitPC = pc + 1
		pred = isWord
	case OpNonWordChar:
		splitPC = pc + 1
		pred = notWord
	default:
		return false
	}

	if splitPC+2 >= len(code) {
		return false
	}
	splitOp := code[splitPC]
	if splitOp != OpSplitA && splitOp != OpSplitB {
		return false
	}

	u16 := binary.LittleEndian.Uint16(code[splitPC+1 : splitPC+3])
	rel := int16(u16) //checkednarrow:ignore uint16 bits encode a signed relative offset
	altPC := splitPC + int(rel)
	nextPC := splitPC + 3

	var loopPC, exitPC int
	switch {
	case splitOp == OpSplitB:
		loopPC = altPC
		exitPC = nextPC
	case altPC == pc:
		loopPC = altPC
		exitPC = nextPC
	case nextPC == pc:
		loopPC = nextPC
		exitPC = altPC
	default:
		return false
	}

	if loopPC != pc {
		return false
	}
	if exitPC < 0 || exitPC >= len(code) {
		return false
	}
	if code[exitPC] == OpSaveEnd {
		exitPC += 2
	}
	if exitPC >= len(code) || code[exitPC] != OpMatch {
		return false
	}

	startPos := *pos
	p := startPos

	switch {
	case op == OpClass && !noCase:
		bmStart := pc + 1
		neg := code[bmStart+32] != 0
		bm := code[bmStart : bmStart+32]
		for p < len(s) {
			if done != nil && (p-startPos)&(vmCancellationInterval-1) == 0 && vmCanceled(done) {
				break
			}
			b := s[p]
			if ((bm[b>>3] & (1 << (b & 7))) != 0) == neg {
				break
			}
			p++
			*bestEnd = p
		}
	case op == OpNotLiteral && !noCase:
		target := code[pc+1]
		idx := bytes.IndexByte(s[p:], target)
		if idx >= 0 {
			p += idx
		} else {
			p = len(s)
		}
		if p > startPos {
			*bestEnd = p
		}
	case op == OpAny:
		if dotAll {
			p = len(s)
		} else {
			idx := bytes.IndexByte(s[p:], '\n')
			if idx >= 0 {
				p += idx
			} else {
				p = len(s)
			}
		}
		if p > startPos {
			*bestEnd = p
		}
	default:
		for p < len(s) {
			if done != nil && (p-startPos)&(vmCancellationInterval-1) == 0 && vmCanceled(done) {
				break
			}
			if !pred(s[p]) {
				break
			}
			p++
			*bestEnd = p
		}
	}

	*pos = p
	*cur = (*cur)[:0]
	return true
}
