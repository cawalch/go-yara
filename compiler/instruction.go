package compiler

import (
	"encoding/binary"
	"fmt"
)

// Instruction represents a single bytecode instruction
type Instruction struct {
	Opcode   Opcode
	Operand  Operand
	Line     int // Source line number for debugging
	Position int // Byte position in source for diagnostics
}

// NewInstruction creates a new instruction with given opcode
func NewInstruction(opcode Opcode, line, pos int) *Instruction {
	return &Instruction{
		Opcode:   opcode,
		Operand:  Operand{Type: OperandNone},
		Line:     line,
		Position: pos,
	}
}

// NewInstructionWithOperand creates a new instruction with opcode and operand
//
//nolint:revive // argument-limit: factory method
func NewInstructionWithOperand(opcode Opcode, operand Operand, line, pos int) *Instruction {
	return &Instruction{
		Opcode:   opcode,
		Operand:  operand,
		Line:     line,
		Position: pos,
	}
}

// formatImmediateOperand formats immediate operands
func (inst *Instruction) formatImmediateOperand(bits int) string {
	value := inst.Operand.Value

	switch bits {
	case 8:
		if value <= 0xFF {
			return fmt.Sprintf(" 0x%02X", value)
		}
		return fmt.Sprintf(" 0x%02X (truncated)", value&0xFF)
	case 16:
		if value <= 0xFFFF {
			return fmt.Sprintf(" 0x%04X", value)
		}
		return fmt.Sprintf(" 0x%04X (truncated)", value&0xFFFF)
	case 32:
		if value <= 0xFFFFFFFF {
			return fmt.Sprintf(" 0x%08X", value)
		}
		return fmt.Sprintf(" 0x%08X (truncated)", value&0xFFFFFFFF)
	case 64:
		return fmt.Sprintf(" 0x%016X", value)
	default:
		return fmt.Sprintf(" (invalid bit width %d)", bits)
	}
}

// formatRelativeOperand formats relative jump operands
func (inst *Instruction) formatRelativeOperand(bits int) string {
	value := inst.Operand.Value

	switch bits {
	case 8:
		if value <= 0x7F {
			return fmt.Sprintf(" %+d", value)
		}
		return fmt.Sprintf(" %+d (truncated)", value&0xFF)
	case 16:
		if value <= 0x7FFF {
			return fmt.Sprintf(" %+d", value)
		}
		return fmt.Sprintf(" %+d (truncated)", value&0xFFFF)
	case 32:
		if value <= 0x7FFFFFFF {
			return fmt.Sprintf(" %+d", value)
		}
		return fmt.Sprintf(" %+d (truncated)", value&0xFFFFFFFF)
	default:
		return fmt.Sprintf(" (invalid bit width %d)", bits)
	}
}

// formatAbsoluteOperand formats absolute address operands
func (inst *Instruction) formatAbsoluteOperand(bits int) string {
	value := inst.Operand.Value

	switch bits {
	case 32:
		if value <= 0xFFFFFFFF {
			return fmt.Sprintf(" @0x%08X", value)
		}
		return fmt.Sprintf(" @0x%08X (truncated)", value&0xFFFFFFFF)
	case 64:
		return fmt.Sprintf(" @0x%016X", value)
	default:
		return fmt.Sprintf(" (invalid bit width %d)", bits)
	}
}

// formatOperand formats operand for display
func (inst *Instruction) formatOperand() string {
	if inst.Operand.Type == OperandNone {
		return ""
	}

	if result, ok := inst.formatTypedOperand(); ok {
		return result
	}

	return fmt.Sprintf(" (invalid operand type %d)", inst.Operand.Type)
}

// formatTypedOperand formats the operand based on its type
func (inst *Instruction) formatTypedOperand() (string, bool) {
	switch inst.Operand.Type {
	case OperandImmediate8, OperandImmediate16, OperandImmediate32, OperandImmediate64:
		bits := inst.getOperandBits()
		return inst.formatImmediateOperand(bits), true

	case OperandRelative8, OperandRelative16, OperandRelative32:
		bits := inst.getOperandBits()
		return inst.formatRelativeOperand(bits), true

	case OperandAbsolute32, OperandAbsolute64:
		bits := inst.getOperandBits()
		return inst.formatAbsoluteOperand(bits), true

	default:
		return "", false
	}
}

// getOperandBits returns the bit size for the current operand
func (inst *Instruction) getOperandBits() int {
	switch inst.Operand.Type {
	case OperandImmediate8, OperandRelative8:
		return 8
	case OperandImmediate16, OperandRelative16:
		return 16
	case OperandImmediate32, OperandRelative32, OperandAbsolute32:
		return 32
	case OperandImmediate64, OperandAbsolute64:
		return 64
	default:
		return 0
	}
}

func (inst *Instruction) String() string {
	return inst.Opcode.String() + inst.formatOperand()
}

// appendImmediateOperand appends immediate operand bytes to buffer
func (inst *Instruction) appendImmediateOperand(buf []byte, bits int) []byte {
	value := inst.Operand.Value

	switch bits {
	case 8:
		if value > 0xFF {
			value &= 0xFF
		}
		buf = append(buf, byte(value))
	case 16:
		if value > 0xFFFF {
			value &= 0xFFFF
		}
		tmp := make([]byte, 2)
		binary.LittleEndian.PutUint16(tmp, uint16(value)) // #nosec G115 - bounds checked above
		buf = append(buf, tmp...)
	case 32:
		if value > 0xFFFFFFFF {
			value &= 0xFFFFFFFF
		}
		tmp := make([]byte, 4)
		binary.LittleEndian.PutUint32(tmp, uint32(value)) // #nosec G115 - bounds checked above
		buf = append(buf, tmp...)
	case 64:
		buf = binary.LittleEndian.AppendUint64(buf, value)
	}
	return buf
}

// appendRelativeOperand appends relative operand bytes to buffer
func (inst *Instruction) appendRelativeOperand(buf []byte, bits int) []byte {
	value := inst.Operand.Value

	switch bits {
	case 8:
		if value > 0x7F {
			value = 0x7F
		}
		buf = append(buf, byte(value))
	case 16:
		if value > 0x7FFF {
			value = 0x7FFF
		}
		tmp := make([]byte, 2)
		binary.LittleEndian.PutUint16(tmp, uint16(value)) // #nosec G115 - bounds checked above
		buf = append(buf, tmp...)
	case 32:
		if value > 0x7FFFFFFF {
			value = 0x7FFFFFFF
		}
		tmp := make([]byte, 4)
		binary.LittleEndian.PutUint32(tmp, uint32(value)) // #nosec G115 - bounds checked above
		buf = append(buf, tmp...)
	}
	return buf
}

// appendAbsoluteOperand appends absolute operand bytes to buffer
func (inst *Instruction) appendAbsoluteOperand(buf []byte, bits int) []byte {
	value := inst.Operand.Value

	switch bits {
	case 32:
		if value > 0xFFFFFFFF {
			value &= 0xFFFFFFFF
		}
		tmp := make([]byte, 4)
		binary.LittleEndian.PutUint32(tmp, uint32(value)) // #nosec G115 - bounds checked above
		buf = append(buf, tmp...)
	case 64:
		buf = binary.LittleEndian.AppendUint64(buf, value)
	}
	return buf
}

// appendOperand appends operand bytes to buffer
func (inst *Instruction) appendOperand(buf []byte) []byte {
	if inst.Operand.Type == OperandNone {
		return buf
	}

	return inst.appendTypedOperand(buf)
}

// appendTypedOperand appends the operand to the buffer based on its type
func (inst *Instruction) appendTypedOperand(buf []byte) []byte {
	switch inst.Operand.Type {
	case OperandImmediate8, OperandImmediate16, OperandImmediate32, OperandImmediate64:
		bits := inst.getOperandBits()
		return inst.appendImmediateOperand(buf, bits)

	case OperandRelative8, OperandRelative16, OperandRelative32:
		bits := inst.getOperandBits()
		return inst.appendRelativeOperand(buf, bits)

	case OperandAbsolute32, OperandAbsolute64:
		bits := inst.getOperandBits()
		return inst.appendAbsoluteOperand(buf, bits)

	default:
		return buf
	}
}

// AppendBytes appends binary representation of instruction to dst and returns dst
func (inst *Instruction) AppendBytes(dst []byte) []byte {
	dst = append(dst, byte(inst.Opcode))
	return inst.appendOperand(dst)
}

// Size returns size of instruction in bytes
func (inst *Instruction) Size() int {
	size := 1 // opcode
	switch inst.Operand.Type {
	case OperandNone:
		// No operand
	case OperandImmediate8, OperandRelative8:
		size++
	case OperandImmediate16, OperandRelative16:
		size += 2
	case OperandImmediate32, OperandRelative32, OperandAbsolute32:
		size += 4
	case OperandImmediate64, OperandAbsolute64:
		size += 8
	}
	return size
}

// IsJump returns true if this instruction is a jump
func (inst *Instruction) IsJump() bool {
	return (inst.Opcode >= OpJundef && inst.Opcode <= OpJzP) ||
		inst.Opcode == OpIterNext
}
