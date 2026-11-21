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

func appendLittleUint(buf []byte, value uint64, bits int) []byte {
	switch bits {
	case 8:
		return append(buf, byte(value))
	case 16:
		return binary.LittleEndian.AppendUint16(buf, uint16(value)) // #nosec G115 - masked/bounded by caller
	case 32:
		return binary.LittleEndian.AppendUint32(buf, uint32(value)) // #nosec G115 - masked/bounded by caller
	case 64:
		return binary.LittleEndian.AppendUint64(buf, value)
	default:
		return buf
	}
}

// appendImmediateOperand appends immediate operand bytes to buffer
func (inst *Instruction) appendImmediateOperand(buf []byte, bits int) []byte {
	return appendLittleUint(buf, inst.Operand.Value, bits)
}

// appendRelativeOperand appends relative operand bytes to buffer
func (inst *Instruction) appendRelativeOperand(buf []byte, bits int) []byte {
	value := inst.Operand.Value
	switch bits {
	case 8:
		value = min(value, 0x7F)
	case 16:
		value = min(value, 0x7FFF)
	case 32:
		value = min(value, 0x7FFFFFFF)
	}
	return appendLittleUint(buf, value, bits)
}

// appendAbsoluteOperand appends absolute operand bytes to buffer
func (inst *Instruction) appendAbsoluteOperand(buf []byte, bits int) []byte {
	return appendLittleUint(buf, inst.Operand.Value, bits)
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
