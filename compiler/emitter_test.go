// Package compiler provides tests for bytecode emission
package compiler

import (
	"testing"
)

// TestEmitter tests the bytecode emitter
func TestEmitter(t *testing.T) {
	emitter := NewEmitter()

	// Test basic emission
	offset1 := emitter.EmitOpcode(OP_PUSH, 1, 1)
	offset2 := emitter.EmitOpcode(OP_NOP, 1, 5)

	if offset1 != 0 {
		t.Errorf("First instruction offset = %v, want 0", offset1)
	}

	if offset2 != 1 {
		t.Errorf("Second instruction offset = %v, want 1", offset2)
	}

	// Test push operations
	pushOffset := emitter.EmitPush(0x12345678, 1, 10)
	if pushOffset != 2 {
		t.Errorf("Push instruction offset = %v, want 2", pushOffset)
	}

	// Test instruction count
	if count := emitter.GetInstructionCount(); count != 3 {
		t.Errorf("Instruction count = %v, want 3", count)
	}

	// Test bytecode generation
	bytecode, err := emitter.GetBytecode()
	if err != nil {
		t.Errorf("GetBytecode() error = %v", err)
	}

	expectedSize := emitter.GetSize()
	if len(bytecode) != expectedSize {
		t.Errorf("Bytecode length = %v, want %v", len(bytecode), expectedSize)
	}
}

// TestEmitterStats tests emitter statistics
func TestEmitterStats(t *testing.T) {
	emitter := NewEmitter()

	// Emit some instructions
	emitter.EmitOpcode(OP_PUSH, 1, 1)
	emitter.EmitOpcode(OP_NOP, 1, 2)
	emitter.EmitPush(0x12345678, 1, 3)

	stats := emitter.GetStats()

	if stats["instruction_count"] != 3 {
		t.Errorf("Instruction count = %v, want 3", stats["instruction_count"])
	}

	expectedSize := 1 + 1 + 5 // PUSH + NOP + PUSH_32
	if stats["bytecode_size"] != expectedSize {
		t.Errorf("Bytecode size = %v, want %v", stats["bytecode_size"], expectedSize)
	}
}
