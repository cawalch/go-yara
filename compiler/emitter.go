package compiler

import (
	"fmt"
	"math"
	"slices"
)

// Emitter manages bytecode generation and instruction emission
type emitter struct {
	instructions []Instruction
	// Maps for fixups and relocations
	fixups map[int]int // Maps instruction index to fixup location
	// Compilation state
	currentOffset int
	lineNumbers   map[int]int // Maps bytecode offset to source line
	// String literal pool for OpPushStr
	stringLiterals     []string
	stringLiteralIndex map[string]int
}

// NewEmitter creates a new bytecode emitter
func newEmitter() *emitter {
	return &emitter{
		instructions:       make([]Instruction, 0),
		fixups:             make(map[int]int),
		currentOffset:      0,
		lineNumbers:        make(map[int]int),
		stringLiterals:     make([]string, 0, 16),
		stringLiteralIndex: make(map[string]int),
	}
}

// ReserveInstructions ensures that instruction buffer has capacity for at least n entries
func (e *emitter) ReserveInstructions(n int) {
	if n <= 0 {
		return
	}
	// If current capacity is less than desired, grow to n while preserving contents
	if cap(e.instructions) < n {
		newSlice := make([]Instruction, len(e.instructions), n)
		copy(newSlice, e.instructions)
		e.instructions = newSlice
	}
}

// Emit adds an instruction to the bytecode stream
func (e *emitter) Emit(inst *Instruction) int {
	offset := e.currentOffset
	e.instructions = append(e.instructions, *inst)
	e.currentOffset += inst.Size()

	// Track line number information
	if inst.Line > 0 {
		e.lineNumbers[offset] = inst.Line
	}

	return offset
}

// EmitOpcode emits an instruction with just an opcode
func (e *emitter) EmitOpcode(opcode Opcode, line, pos int) int {
	inst := NewInstruction(opcode, line, pos)
	return e.Emit(inst)
}

// EmitOpcodeWithOperand emits an instruction with opcode and operand
//
//nolint:revive // argument-limit: API surface
func (e *emitter) EmitOpcodeWithOperand(opcode Opcode, operand Operand, line, pos int) int {
	inst := NewInstructionWithOperand(opcode, operand, line, pos)
	return e.Emit(inst)
}

// EmitPush emits a push instruction with various operand sizes
func (e *emitter) EmitPush(value uint64, line, pos int) int {
	switch {
	case value <= math.MaxUint8:
		return e.EmitOpcodeWithOperand(
			OpPush8,
			Operand{Type: OperandImmediate8, Value: value},
			line,
			pos,
		)
	case value <= math.MaxUint16:
		return e.EmitOpcodeWithOperand(
			OpPush16,
			Operand{Type: OperandImmediate16, Value: value},
			line,
			pos,
		)
	case value <= math.MaxUint32:
		return e.EmitOpcodeWithOperand(
			OpPush32,
			Operand{Type: OperandImmediate32, Value: value},
			line,
			pos,
		)
	default:
		return e.EmitOpcodeWithOperand(
			OpPush64,
			Operand{Type: OperandImmediate64, Value: value},
			line,
			pos,
		)
	}
}

// EmitPushDouble emits a push instruction for floating point values
func (e *emitter) EmitPushDouble(value float64, line, pos int) int {
	return e.EmitOpcodeWithOperand(
		OpPushDbl,
		Operand{Type: OperandImmediate64, Value: math.Float64bits(value)},
		line,
		pos,
	)
}

// EmitPushString emits a push instruction for string values
func (e *emitter) EmitPushString(value string, line, pos int) int {
	index := e.internStringLiteral(value)
	return e.EmitOpcodeWithOperand(
		OpPushStr,
		Operand{Type: OperandImmediate32, Value: uint64(index)},
		line,
		pos,
	)
}

func (e *emitter) internStringLiteral(value string) int {
	if idx, ok := e.stringLiteralIndex[value]; ok {
		return idx
	}
	idx := len(e.stringLiterals)
	e.stringLiterals = append(e.stringLiterals, value)
	e.stringLiteralIndex[value] = idx
	return idx
}

// GetStringLiterals returns a copy of the current string literal pool.
func (e *emitter) GetStringLiterals() []string {
	if len(e.stringLiterals) == 0 {
		return nil
	}
	out := make([]string, len(e.stringLiterals))
	copy(out, e.stringLiterals)
	return out
}

// jumpConfig holds configuration for jump instruction emission
type jumpConfig struct {
	Opcode Opcode
	Target int
	Line   int
	Pos    int
}

// EmitJump emits a jump instruction and returns an offset for potential fixup
func (e *emitter) EmitJump(config jumpConfig) int {
	var operand Operand

	// Emit a zero displacement; FixupJumps writes the final target later.
	switch config.Opcode {
	case OpJz, OpJzP, OpJtrue, OpJtrueP, OpJfalse, OpJfalseP:
		operand = Operand{Type: OperandRelative32, Value: 0}
	case OpIterNext:
		operand = Operand{Type: OperandRelative16, Value: 0}
	default:
		operand = Operand{Type: OperandRelative32, Value: 0}
	}

	offset := e.EmitOpcodeWithOperand(config.Opcode, operand, config.Line, config.Pos)

	// Mark this instruction for fixup
	e.fixups[offset] = config.Target

	return offset
}

// FixupJumps resolves all jump targets that were previously emitted
func (e *emitter) FixupJumps() error {
	for jumpOffset, targetOffset := range e.fixups {
		if err := e.validateJumpInstruction(jumpOffset); err != nil {
			return err
		}

		jumpIndex, _ := e.FindInstructionIndexByOffset(jumpOffset)
		inst := &e.instructions[jumpIndex]
		relativeOffset := e.calculateRelativeOffset(jumpOffset, targetOffset, inst)

		if err := e.updateJumpOperand(inst, relativeOffset); err != nil {
			return err
		}
	}

	clear(e.fixups)
	return nil
}

// validateJumpInstruction validates that a jump instruction exists at the given offset
func (e *emitter) validateJumpInstruction(jumpOffset int) error {
	jumpIndex, err := e.FindInstructionIndexByOffset(jumpOffset)
	if err != nil {
		return err
	}

	inst := &e.instructions[jumpIndex]
	if !inst.IsJump() {
		return fmt.Errorf("instruction at offset %d is not a jump", jumpOffset)
	}
	return nil
}

// calculateRelativeOffset calculates the relative offset for a jump instruction
// Both jumpOffset and targetOffset are byte offsets within the bytecode stream.
// The relative offset is measured from the end of the jump instruction (after its operand).
func (e *emitter) calculateRelativeOffset(jumpOffset, targetOffset int, inst *Instruction) int32 {
	currentInstEnd := jumpOffset + inst.Size()
	offset := targetOffset - currentInstEnd
	return e.clampToInt32(offset)
}

// clampToInt32 clamps an integer to 32-bit signed range
func (e *emitter) clampToInt32(value int) int32 {
	if value > 0x7FFFFFFF {
		return 0x7FFFFFFF
	}
	if value < -0x80000000 {
		return -0x80000000
	}
	return int32(value)
}

// updateJumpOperand updates the operand of a jump instruction with the relative offset
func (e *emitter) updateJumpOperand(inst *Instruction, relativeOffset int32) error {
	switch inst.Operand.Type {
	case OperandRelative16:
		if relativeOffset > math.MaxInt16 || relativeOffset < math.MinInt16 {
			return fmt.Errorf("jump offset %d too large for 16-bit relative jump", relativeOffset)
		}
		inst.Operand.Value = e.convertToUint64(relativeOffset)
	case OperandRelative32:
		inst.Operand.Value = e.convertToUint64(relativeOffset)
	default:
		return fmt.Errorf("unsupported operand type for jump fixup: %v", inst.Operand.Type)
	}
	return nil
}

// convertToUint64 safely converts int32 to uint64
func (e *emitter) convertToUint64(value int32) uint64 {
	return uint64(value)
}

// GetInstructions returns an owned snapshot of all emitted instructions.
func (e *emitter) GetInstructions() []Instruction {
	return slices.Clone(e.instructions)
}

// GetBytecode returns the final bytecode as bytes
func (e *emitter) GetBytecode() ([]byte, error) {
	// First, fix up any jump targets
	if err := e.FixupJumps(); err != nil {
		return nil, fmt.Errorf("fixing up jumps: %w", err)
	}

	// Preallocate final buffer using tracked size to avoid growth
	bytecode := make([]byte, 0, e.currentOffset)

	for _, inst := range e.instructions {
		bytecode = inst.AppendBytes(bytecode)
	}

	return bytecode, nil
}

// GetSize returns the total size of the generated bytecode in bytes
func (e *emitter) GetSize() int {
	return e.currentOffset
}

// GetInstructionCount returns the number of instructions emitted
func (e *emitter) GetInstructionCount() int {
	return len(e.instructions)
}

// Reset clears all emitted instructions and resets the emitter state
func (e *emitter) Reset() {
	e.instructions = e.instructions[:0]
	clear(e.fixups)
	e.currentOffset = 0
	clear(e.lineNumbers)
	e.stringLiterals = e.stringLiterals[:0]
	clear(e.stringLiteralIndex)
}

// EmitHalt emits a halt instruction to terminate execution
func (e *emitter) EmitHalt(line, pos int) int {
	return e.EmitOpcode(OpHalt, line, pos)
}

// EmitNop emits a no-operation instruction
func (e *emitter) EmitNop(line, pos int) int {
	return e.EmitOpcode(OpNop, line, pos)
}

// GetStats returns statistics about the generated bytecode
func (e *emitter) GetStats() map[string]any {
	stats := make(map[string]any, 5)

	stats["instruction_count"] = len(e.instructions)
	stats["bytecode_size"] = e.currentOffset
	stats["fixup_count"] = len(e.fixups)

	// Count instructions by category
	categories := make(map[string]int, 4)
	for _, inst := range e.instructions {
		category := inst.Opcode.GetCategory()
		categories[category]++
	}
	stats["categories"] = categories

	// Average instruction size
	if len(e.instructions) > 0 {
		stats["avg_instruction_size"] = float64(e.currentOffset) / float64(len(e.instructions))
	}

	return stats
}

// UpdateOperandByIndex updates the operand of an instruction at the given array index
func (e *emitter) UpdateOperandByIndex(index int, operand Operand) error {
	if index < 0 || index >= len(e.instructions) {
		return fmt.Errorf("instruction index %d out of range", index)
	}
	e.instructions[index].Operand = operand
	return nil
}

// FindInstructionIndexByOffset finds the instruction slice index from its byte offset.
func (e *emitter) FindInstructionIndexByOffset(offset int) (int, error) {
	currentOffset := 0
	for i := range e.instructions {
		if currentOffset == offset {
			return i, nil
		}
		if currentOffset > offset {
			break
		}
		currentOffset += e.instructions[i].Size()
	}
	return -1, fmt.Errorf("instruction not found at byte offset %d", offset)
}

// GetInstruction returns an owned snapshot of the instruction at the given
// slice index. Use UpdateOperandByIndex to mutate emitted instructions.
func (e *emitter) GetInstruction(index int) *Instruction {
	if index < 0 || index >= len(e.instructions) {
		panic(fmt.Sprintf("instruction index %d out of range [0, %d)", index, len(e.instructions)))
	}
	instruction := e.instructions[index]
	return &instruction
}

// SetFixup explicitly adds a jump resolution request for a jump offset to a target offset
func (e *emitter) SetFixup(jumpOffset int, targetOffset int) {
	e.fixups[jumpOffset] = targetOffset
}
