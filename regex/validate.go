package regex

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ValidateBytecode checks a complete ordinary or directional VM program.
// Capture replay programs must be checked with ValidateCaptureBytecode.
func ValidateBytecode(code []byte) error {
	return validateBytecode(code, 0)
}

// ValidateCaptureBytecode also permits save instructions referencing one of
// slotCount capture slots. Slot indices in the bytecode occupy one byte.
func ValidateCaptureBytecode(code []byte, slotCount int) error {
	if slotCount < 0 || slotCount > 256 {
		return fmt.Errorf("regex: invalid capture slot count %d", slotCount)
	}
	return validateBytecode(code, slotCount)
}

var instructionWidth = [256]uint8{
	OpAny: 1, OpLiteral: 2, OpNotLiteral: 2, OpMaskedLiteral: 3, OpMaskedNotLiteral: 3,
	OpClass: 34, OpWordChar: 1, OpNonWordChar: 1, OpSpace: 1, OpNonSpace: 1,
	OpDigit: 1, OpNonDigit: 1, OpMatchAtStart: 1, OpMatchAtEnd: 1,
	OpWordBoundary: 1, OpNonWordBoundary: 1, OpMatch: 1,
	OpSplitA: 3, OpSplitB: 3, OpJump: 3, OpSaveStart: 2, OpSaveEnd: 2,
}

func validateBytecode(code []byte, captureSlots int) error {
	if len(code) == 0 || len(code) > MaxBytecodeSize {
		return fmt.Errorf("regex: invalid program size %d", len(code))
	}
	var small [4]uint64
	starts := small[:]
	if len(code) > len(small)*64 {
		starts = make([]uint64, (len(code)+63)/64)
	}
	hasBranches := false
	for pc := 0; pc < len(code); {
		op := code[pc]
		width := int(instructionWidth[op])
		if width == 0 {
			return fmt.Errorf("regex: unsupported opcode %#x at %d", op, pc)
		}
		if width > len(code)-pc {
			return fmt.Errorf("regex: incomplete instruction at %d", pc)
		}
		starts[pc/64] |= 1 << (pc % 64)
		switch op {
		case OpSplitA, OpSplitB, OpJump:
			hasBranches = true
		case OpSaveStart, OpSaveEnd:
			if int(code[pc+1]) >= captureSlots {
				return fmt.Errorf("regex: invalid capture slot at %d", pc)
			}
		case OpClass:
			if code[pc+33] > 1 {
				return fmt.Errorf("regex: invalid class negation at %d", pc)
			}
		case OpMatch:
			if pc != len(code)-1 {
				return fmt.Errorf("regex: nonterminal match at %d", pc)
			}
		}
		if pc+width == len(code) && op != OpMatch {
			return errors.New("regex: missing final match")
		}
		pc += width
	}
	if hasBranches {
		for pc := 0; pc < len(code); pc += int(instructionWidth[code[pc]]) {
			switch code[pc] {
			case OpSplitA, OpSplitB, OpJump:
				offset := int(int16(binary.LittleEndian.Uint16(code[pc+1 : pc+3]))) //checkednarrow:ignore bytecode encodes a signed relative offset
				target := pc + offset
				if target < 0 || target >= len(code) || starts[target/64]&(1<<(target%64)) == 0 {
					return fmt.Errorf("regex: invalid branch target %d at %d", target, pc)
				}
			}
		}
	}
	return nil
}
