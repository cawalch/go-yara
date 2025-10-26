// Package compiler provides tests for opcodes and instructions
package compiler

import (
	"testing"
)

// TestBytecodeOpcodes tests all bytecode opcodes
func TestBytecodeOpcodes(t *testing.T) {
	tests := []struct {
		opcode   Opcode
		expected string
		category string
	}{
		{OP_ERROR, "ERROR", OpCategoryControl},
		{OP_HALT, "HALT", OpCategoryControl},
		{OP_NOP, "NOP", OpCategoryControl},
		{OP_AND, "AND", OpCategoryLogical},
		{OP_OR, "OR", OpCategoryLogical},
		{OP_NOT, "NOT", OpCategoryLogical},
		{OP_PUSH, "PUSH", OpCategoryStack},
		{OP_POP, "POP", OpCategoryStack},
		{OP_INT_ADD, "INT_ADD", OpCategoryArithmetic},
		{OP_INT_EQ, "INT_EQ", OpCategoryArithmetic},
		{OP_FILESIZE, "FILESIZE", OpCategoryObject},
		{OP_CONTAINS, "CONTAINS", OpCategoryString},
		{OP_JZ, "JZ", OpCategoryJump},
		{OP_INT8, "INT8", OpCategoryTypeFunc},
	}

	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			if got := test.opcode.String(); got != test.expected {
				t.Errorf("Opcode.String() = %v, want %v", got, test.expected)
			}

			if got := test.opcode.GetCategory(); got != test.category {
				t.Errorf("Opcode.GetCategory() = %v, want %v", got, test.category)
			}
		})
	}
}

// TestInstructionCreation tests instruction creation and encoding
func TestInstructionCreation(t *testing.T) {
	tests := []struct {
		name     string
		inst     *Instruction
		expected string
		size     int
	}{
		{
			name:     "simple opcode",
			inst:     NewInstruction(OP_NOP, 1, 1),
			expected: "NOP",
			size:     1,
		},
		{
			name: "push 8-bit",
			inst: NewInstructionWithOperand(
				OP_PUSH_8,
				Operand{Type: OperandImmediate8, Value: 0x42},
				1,
				1,
			),
			expected: "PUSH_8 0x42",
			size:     2,
		},
		{
			name: "push 32-bit",
			inst: NewInstructionWithOperand(
				OP_PUSH_32,
				Operand{Type: OperandImmediate32, Value: 0x12345678},
				1,
				1,
			),
			expected: "PUSH_32 0x12345678",
			size:     5,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.inst.String(); got != test.expected {
				t.Errorf("Instruction.String() = %v, want %v", got, test.expected)
			}

			if got := test.inst.Size(); got != test.size {
				t.Errorf("Instruction.Size() = %v, want %v", got, test.size)
			}

			// Test that Bytes() doesn't panic and returns correct size
			bytes := test.inst.Bytes()
			if len(bytes) != test.size {
				t.Errorf("len(Instruction.Bytes()) = %v, want %v", len(bytes), test.size)
			}
		})
	}
}
