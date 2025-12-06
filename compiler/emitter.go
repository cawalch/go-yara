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
		opcode = OpPush8
		operand = Operand{Type: OperandImmediate8, Value: value}
	} else if value <= math.MaxUint16 {
		opcode = OpPush16
		operand = Operand{Type: OperandImmediate16, Value: value}
	} else if value <= math.MaxUint32 {
		opcode = OpPush32
		operand = Operand{Type: OperandImmediate32, Value: value}
	} else {
		opcode = OpPushU
		operand = Operand{Type: OperandImmediate64, Value: value}
	}

	return e.EmitOpcodeWithOperand(opcode, operand, line, pos)
}

// EmitPushDouble emits a push instruction for floating point values
func (e *Emitter) EmitPushDouble(value float64, line, pos int) int {
	// Convert float64 to uint64 bits for storage
	bits := math.Float64bits(value)
	operand := Operand{Type: OperandImmediate64, Value: bits}
	return e.EmitOpcodeWithOperand(OpPushDbl, operand, line, pos)
}

// EmitPushString emits a push instruction for string values
func (e *Emitter) EmitPushString(value string, line, pos int) int {
	// For string values, we'll need to store them in a separate string table
	// For now, let's use a simple approach by encoding the string in the immediate value
	// This is a simplified implementation - a full solution would need a proper string pool
	hash := e.hashString(value)
	operand := Operand{Type: OperandImmediate64, Value: hash}
	return e.EmitOpcodeWithOperand(OpPushDbl, operand, line, pos)
}

// hashString creates a simple hash for string identification
func (e *Emitter) hashString(s string) uint64 {
	// Simple hash function for string identification
	// In a full implementation, this would be replaced with proper string pool management
	hash := uint64(5381)
	for _, c := range s {
		hash = ((hash << 5) + hash) + uint64(c)
	}
	// Use high bit to distinguish from numeric values
	return hash | 0x8000000000000000
}

// JumpConfig holds configuration for jump instruction emission
type JumpConfig struct {
	Opcode Opcode
	Target int
	Line   int
	Pos    int
}

// EmitJump emits a jump instruction and returns an offset for potential fixup
func (e *Emitter) EmitJump(config JumpConfig) int {
	var operand Operand

	// For now, emit a placeholder offset (0)
	// This will be fixed up later when the target is known
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

// EmitLabel emits a label (no-op) at the current position
// This is used as a target for jumps
func (e *Emitter) EmitLabel(_, line, pos int) int {
	return e.EmitOpcode(OpNop, line, pos)
}

// FixupJumps resolves all jump targets that were previously emitted
func (e *Emitter) FixupJumps() error {
	for jumpOffset, targetOffset := range e.fixups {
		if err := e.validateJumpInstruction(jumpOffset); err != nil {
			return err
		}

		inst := &e.instructions[jumpOffset]
		relativeOffset := e.calculateRelativeOffset(jumpOffset, targetOffset, inst)

		if err := e.updateJumpOperand(inst, relativeOffset); err != nil {
			return err
		}
	}

	e.fixups = make(map[int]int)
	return nil
}

// validateJumpInstruction validates that a jump instruction exists at the given offset
func (e *Emitter) validateJumpInstruction(jumpOffset int) error {
	if jumpOffset >= len(e.instructions) {
		return fmt.Errorf("jump offset %d out of bounds", jumpOffset)
	}

	inst := &e.instructions[jumpOffset]
	if !inst.IsJump() {
		return fmt.Errorf("instruction at offset %d is not a jump", jumpOffset)
	}
	return nil
}

// calculateRelativeOffset calculates the relative offset for a jump instruction
func (e *Emitter) calculateRelativeOffset(jumpOffset, targetOffset int, inst *Instruction) int32 {
	if targetOffset >= 0 && targetOffset < len(e.instructions) {
		currentInstEnd := jumpOffset + inst.Size()
		offset := targetOffset - currentInstEnd
		return e.clampToInt32(offset)
	}
	return e.clampToInt32(targetOffset)
}

// clampToInt32 clamps an integer to 32-bit signed range
func (e *Emitter) clampToInt32(value int) int32 {
	if value > 0x7FFFFFFF {
		return 0x7FFFFFFF
	}
	if value < -0x80000000 {
		return -0x80000000
	}
	return int32(value)
}

// updateJumpOperand updates the operand of a jump instruction with the relative offset
func (e *Emitter) updateJumpOperand(inst *Instruction, relativeOffset int32) error {
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
func (e *Emitter) convertToUint64(value int32) uint64 {
	if value < 0 {
		return 0
	}
	return uint64(value)
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
func (e *Emitter) EmitDataTypeFunction(op Opcode, line, pos int) (int, error) {
	if !isDataTypeFunction(op) {
		return -1, fmt.Errorf("opcode %s is not a data type function", op.String())
	}
	return e.EmitOpcode(op, line, pos), nil
}

// Helper functions for opcode classification
func isArithmeticOp(op Opcode) bool {
	return (op >= OpIntAdd && op <= OpIntMinus) ||
		(op >= OpDblAdd && op <= OpDblMinus) ||
		op == OpAddM || op == OpIncrM ||
		op == OpConcat
}

func isComparisonOp(op Opcode) bool {
	return (op >= OpIntEq && op <= OpIntGe) ||
		(op >= OpDblEq && op <= OpDblGe) ||
		(op >= OpStrEq && op <= OpStrGe) ||
		op == OpContains || op == OpMatches ||
		op == OpStartswith || op == OpEndswith
}

func isLogicalOp(op Opcode) bool {
	return op == OpAnd || op == OpOr || op == OpNot ||
		op == OpBitwiseAnd || op == OpBitwiseOr || op == OpBitwiseXor ||
		op == OpBitwiseNot
}

func isDataTypeFunction(op Opcode) bool {
	return op >= OpReadInt && op <= OpUint64be
}

// EmitStringOperation emits string operation instructions
func (e *Emitter) EmitStringOperation(op Opcode, line, pos int) (int, error) {
	if !isStringOperation(op) {
		return -1, fmt.Errorf("opcode %s is not a string operation", op.String())
	}
	return e.EmitOpcode(op, line, pos), nil
}

func isStringOperation(op Opcode) bool {
	return (op >= OpContains && op <= OpIequals) ||
		(op >= OpFound && op <= OpOfFoundAt) ||
		op == OpMatches
}

// EmitHalt emits a halt instruction to terminate execution
func (e *Emitter) EmitHalt(line, pos int) int {
	return e.EmitOpcode(OpHalt, line, pos)
}

// EmitNop emits a no-operation instruction
func (e *Emitter) EmitNop(line, pos int) int {
	return e.EmitOpcode(OpNop, line, pos)
}

// Debug printing functions

// PrintInstructions prints all instructions with their offsets
func (e *Emitter) PrintInstructions() {
	fmt.Println("Bytecode Instructions:")
	fmt.Printf("%-4s %-8s %-12s %-s\n", "Addr", "Opcode", "Operand", "Disassembly")
	fmt.Println("─────────────────────────────────────────")

	for i, inst := range e.instructions {
		offset := 0
		for j := range i {
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
		end := min(i+16, len(bytecode))

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
func (e *Emitter) GetStats() map[string]any {
	stats := make(map[string]any)

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

// GetLength returns the current bytecode length (alias for GetSize)
func (e *Emitter) GetLength() int {
	return e.currentOffset
}

// UpdateOperand updates the operand of an instruction at the given position
func (e *Emitter) UpdateOperand(position int, operand Operand) error {
	if position < 0 || position >= len(e.instructions) {
		return fmt.Errorf("instruction position %d out of range", position)
	}

	// Update the operand of the instruction
	inst := &e.instructions[position]
	inst.Operand = operand

	return nil
}
