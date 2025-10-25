// Package compiler provides bytecode generation and compilation for YARA rules.
package compiler

import (
	"fmt"
	"math"
)

// Emitter manages bytecode generation and instruction emission
type Emitter struct {
	instructions []Instruction
	// Maps for fixups and relocations
	fixups map[int]int // Maps instruction index to fixup location
	// Compilation state
	currentOffset int
	lineNumbers   map[int]int // Maps bytecode offset to source line
}

// NewEmitter creates a new bytecode emitter
func NewEmitter() *Emitter {
	return &Emitter{
		instructions:  make([]Instruction, 0),
		fixups:        make(map[int]int),
		currentOffset: 0,
		lineNumbers:   make(map[int]int),
	}
}

// ReserveInstructions ensures that instruction buffer has capacity for at least n entries
func (e *Emitter) ReserveInstructions(n int) {
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
func (e *Emitter) Emit(inst *Instruction) int {
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
func (e *Emitter) EmitOpcode(opcode Opcode, line, pos int) int {
	inst := NewInstruction(opcode, line, pos)
	return e.Emit(inst)
}

// EmitOpcodeWithOperand emits an instruction with opcode and operand
func (e *Emitter) EmitOpcodeWithOperand(opcode Opcode, operand Operand, line, pos int) int {
	inst := NewInstructionWithOperand(opcode, operand, line, pos)
	return e.Emit(inst)
}

// EmitPush emits a push instruction with various operand sizes
func (e *Emitter) EmitPush(value uint64, line, pos int) int {
	var opcode Opcode
	var operand Operand

	// Choose the most efficient push instruction based on value size
	if value <= math.MaxUint8 {
		opcode = OP_PUSH_8
		operand = Operand{Type: OperandImmediate8, Value: value}
	} else if value <= math.MaxUint16 {
		opcode = OP_PUSH_16
		operand = Operand{Type: OperandImmediate16, Value: value}
	} else if value <= math.MaxUint32 {
		opcode = OP_PUSH_32
		operand = Operand{Type: OperandImmediate32, Value: value}
	} else {
		opcode = OP_PUSH_U
		operand = Operand{Type: OperandImmediate64, Value: value}
	}

	return e.EmitOpcodeWithOperand(opcode, operand, line, pos)
}

// EmitJump emits a jump instruction and returns an offset for potential fixup
func (e *Emitter) EmitJump(opcode Opcode, target int, line, pos int) int {
	var operand Operand

	// For now, emit a placeholder offset (0)
	// This will be fixed up later when the target is known
	switch opcode {
	case OP_JZ, OP_JZ_P, OP_JTRUE, OP_JTRUE_P, OP_JFALSE, OP_JFALSE_P:
		operand = Operand{Type: OperandRelative32, Value: 0}
	case OP_ITER_NEXT:
		operand = Operand{Type: OperandRelative16, Value: 0}
	default:
		operand = Operand{Type: OperandRelative32, Value: 0}
	}

	offset := e.EmitOpcodeWithOperand(opcode, operand, line, pos)

	// Mark this instruction for fixup
	e.fixups[offset] = target

	return offset
}

// EmitLabel emits a label (no-op) at the current position
// This is used as a target for jumps
func (e *Emitter) EmitLabel(label int, line, pos int) int {
	return e.EmitOpcode(OP_NOP, line, pos)
}

// FixupJumps resolves all jump targets that were previously emitted
func (e *Emitter) FixupJumps() error {
	for jumpOffset, targetOffset := range e.fixups {
		if jumpOffset >= len(e.instructions) {
			return fmt.Errorf("jump offset %d out of bounds", jumpOffset)
		}

		inst := &e.instructions[jumpOffset]
		if !inst.IsJump() {
			return fmt.Errorf("instruction at offset %d is not a jump", jumpOffset)
		}

		// Calculate relative offset from jump instruction to target
		var relativeOffset int32

		if targetOffset >= 0 && targetOffset < len(e.instructions) {
			// Calculate the offset from the end of the current instruction
			currentInstEnd := jumpOffset + inst.Size()
			// Safe conversion with overflow check
			offset := targetOffset - currentInstEnd
			if offset > 0x7FFFFFFF {
				relativeOffset = int32(0x7FFFFFFF)
			} else if offset < -0x80000000 {
				relativeOffset = int32(-0x80000000)
			} else {
				relativeOffset = int32(offset)
			}
		} else {
			// Target is beyond current instructions (forward reference)
			// Safe conversion with overflow check
			if targetOffset > 0x7FFFFFFF {
				relativeOffset = int32(0x7FFFFFFF)
			} else if targetOffset < -0x80000000 {
				relativeOffset = int32(-0x80000000)
			} else {
				relativeOffset = int32(targetOffset)
			}
		}

		// Update the operand with the correct relative offset
		switch inst.Operand.Type {
		case OperandRelative16:
			if relativeOffset > math.MaxInt16 || relativeOffset < math.MinInt16 {
				return fmt.Errorf("jump offset %d too large for 16-bit relative jump", relativeOffset)
			}
			// Safe conversion with overflow check
			if relativeOffset < 0 {
				inst.Operand.Value = uint64(0)
			} else {
				// Safe conversion with overflow check
				if relativeOffset < 0 {
					inst.Operand.Value = uint64(0)
				} else {
					inst.Operand.Value = uint64(relativeOffset)
				}
			}
		case OperandRelative32:
			// Safe conversion with explicit truncation
			inst.Operand.Value = uint64(relativeOffset)
		default:
			return fmt.Errorf("unsupported operand type for jump fixup: %v", inst.Operand.Type)
		}
	}

	// Clear fixups after resolving
	e.fixups = make(map[int]int)
	return nil
}

// GetInstructions returns all emitted instructions
func (e *Emitter) GetInstructions() []Instruction {
	return e.instructions
}

// GetBytecode returns the final bytecode as bytes
func (e *Emitter) GetBytecode() ([]byte, error) {
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
func (e *Emitter) GetSize() int {
	return e.currentOffset
}

// GetInstructionCount returns the number of instructions emitted
func (e *Emitter) GetInstructionCount() int {
	return len(e.instructions)
}

// GetLineNumber returns the source line number for a given bytecode offset
func (e *Emitter) GetLineNumber(offset int) (int, bool) {
	line, exists := e.lineNumbers[offset]
	return line, exists
}

// Reset clears all emitted instructions and resets the emitter state
func (e *Emitter) Reset() {
	e.instructions = e.instructions[:0]
	e.fixups = make(map[int]int)
	e.currentOffset = 0
	e.lineNumbers = make(map[int]int)
}

// EmitArithmetic emits arithmetic operation instructions
// Returns -1 and does not emit if opcode is not arithmetic
func (e *Emitter) EmitArithmetic(op Opcode, line, pos int) int {
	if !isArithmeticOp(op) {
		// Log error but don't panic - caller should handle invalid opcodes
		fmt.Printf("warning: opcode %s is not an arithmetic operation\n", op.String())
		return -1
	}
	return e.EmitOpcode(op, line, pos)
}

// EmitComparison emits comparison operation instructions
// Returns -1 and does not emit if opcode is not a comparison
func (e *Emitter) EmitComparison(op Opcode, line, pos int) int {
	if !isComparisonOp(op) {
		fmt.Printf("warning: opcode %s is not a comparison operation\n", op.String())
		return -1
	}
	return e.EmitOpcode(op, line, pos)
}

// EmitLogical emits logical operation instructions
// Returns -1 and does not emit if opcode is not logical
func (e *Emitter) EmitLogical(op Opcode, line, pos int) int {
	if !isLogicalOp(op) {
		fmt.Printf("warning: opcode %s is not a logical operation\n", op.String())
		return -1
	}
	return e.EmitOpcode(op, line, pos)
}

// EmitDataTypeFunction emits data type conversion function instructions
func (e *Emitter) EmitDataTypeFunction(op Opcode, line, pos int) int {
	if !isDataTypeFunction(op) {
		panic(fmt.Sprintf("opcode %s is not a data type function", op.String()))
	}
	return e.EmitOpcode(op, line, pos)
}

// Helper functions for opcode classification
func isArithmeticOp(op Opcode) bool {
	return (op >= OP_INT_ADD && op <= OP_INT_MINUS) ||
		(op >= OP_DBL_ADD && op <= OP_DBL_MINUS) ||
		op == OP_ADD_M || op == OP_INCR_M
}

func isComparisonOp(op Opcode) bool {
	return (op >= OP_INT_EQ && op <= OP_INT_GE) ||
		(op >= OP_DBL_EQ && op <= OP_DBL_GE) ||
		(op >= OP_STR_EQ && op <= OP_STR_GE) ||
		op == OP_CONTAINS || op == OP_MATCHES ||
		op == OP_STARTSWITH || op == OP_ENDSWITH
}

func isLogicalOp(op Opcode) bool {
	return op == OP_AND || op == OP_OR || op == OP_NOT ||
		op == OP_BITWISE_AND || op == OP_BITWISE_OR || op == OP_BITWISE_XOR ||
		op == OP_BITWISE_NOT
}

func isDataTypeFunction(op Opcode) bool {
	return op >= OP_READ_INT && op <= OP_UINT32BE
}

// EmitStringOperation emits string operation instructions
func (e *Emitter) EmitStringOperation(op Opcode, line, pos int) int {
	if !isStringOperation(op) {
		panic(fmt.Sprintf("opcode %s is not a string operation", op.String()))
	}
	return e.EmitOpcode(op, line, pos)
}

func isStringOperation(op Opcode) bool {
	return (op >= OP_CONTAINS && op <= OP_IEQUALS) ||
		(op >= OP_FOUND && op <= OP_OF_FOUND_AT) ||
		op == OP_MATCHES
}

// EmitHalt emits a halt instruction to terminate execution
func (e *Emitter) EmitHalt(line, pos int) int {
	return e.EmitOpcode(OP_HALT, line, pos)
}

// EmitNop emits a no-operation instruction
func (e *Emitter) EmitNop(line, pos int) int {
	return e.EmitOpcode(OP_NOP, line, pos)
}

// Debug printing functions

// PrintInstructions prints all instructions with their offsets
func (e *Emitter) PrintInstructions() {
	fmt.Println("Bytecode Instructions:")
	fmt.Printf("%-4s %-8s %-12s %-s\n", "Addr", "Opcode", "Operand", "Disassembly")
	fmt.Println("─────────────────────────────────────────")

	for i, inst := range e.instructions {
		offset := 0
		for j := 0; j < i; j++ {
			offset += e.instructions[j].Size()
		}

		operandStr := ""
		if inst.Operand.Type != OperandNone {
			operandStr = fmt.Sprintf("0x%X", inst.Operand.Value)
		}

		fmt.Printf("%-4X %-8s %-12s %-s\n",
			offset,
			inst.Opcode.String(),
			operandStr,
			inst.String())
	}
}

// PrintBytecode prints the raw bytecode in hex format
func (e *Emitter) PrintBytecode() error {
	bytecode, err := e.GetBytecode()
	if err != nil {
		return err
	}

	fmt.Println("Raw Bytecode:")
	for i := 0; i < len(bytecode); i += 16 {
		end := i + 16
		if end > len(bytecode) {
			end = len(bytecode)
		}

		// Print offset
		fmt.Printf("%08X: ", i)

		// Print hex bytes
		for j := i; j < end; j++ {
			fmt.Printf("%02X ", bytecode[j])
		}

		// Print ASCII representation
		fmt.Printf(" |")
		for j := i; j < end; j++ {
			if bytecode[j] >= 32 && bytecode[j] <= 126 {
				fmt.Printf("%c", bytecode[j])
			} else {
				fmt.Printf(".")
			}
		}
		fmt.Printf("|\n")
	}

	return nil
}

// GetStats returns statistics about the generated bytecode
func (e *Emitter) GetStats() map[string]interface{} {
	stats := make(map[string]interface{})

	stats["instruction_count"] = len(e.instructions)
	stats["bytecode_size"] = e.currentOffset
	stats["fixup_count"] = len(e.fixups)

	// Count instructions by category
	categories := make(map[string]int)
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
