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
		{OpError, "ERROR", OpCategoryControl},
		{OpHalt, "HALT", OpCategoryControl},
		{OpNop, "NOP", OpCategoryControl},
		{OpAnd, "AND", OpCategoryLogical},
		{OpOr, "OR", OpCategoryLogical},
		{OpNot, "NOT", OpCategoryLogical},
		{OpPush, "PUSH", OpCategoryStack},
		{OpPop, "POP", OpCategoryStack},
		{OpIntAdd, "INT_ADD", OpCategoryArithmetic},
		{OpIntEq, "INT_EQ", OpCategoryArithmetic},
		{OpFilesize, "FILESIZE", OpCategoryObject},
		{OpContains, "CONTAINS", OpCategoryString},
		{OpJz, "JZ", OpCategoryJump},
		{OpInt8, "INT8", OpCategoryTypeFunc},
		{OpUint64, "UINT64", OpCategoryTypeFunc},
		{OpInt64be, "INT64BE", OpCategoryTypeFunc},
		{OpUint64be, "UINT64BE", OpCategoryTypeFunc},
		{OpConcat, "CONCAT", OpCategoryString},
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

func TestReadIntOpcodesDoNotCollideWithControlOrStringOps(t *testing.T) {
	readOps := []Opcode{
		OpInt8, OpInt16, OpInt32, OpUint8, OpUint16, OpUint32,
		OpInt8be, OpInt16be, OpInt32be, OpUint8be, OpUint16be, OpUint32be,
		OpInt64, OpUint64, OpInt64be, OpUint64be,
	}
	reserved := map[Opcode]string{
		OpConcat: "CONCAT",
		OpNop:    "NOP",
		OpHalt:   "HALT",
	}

	seen := make(map[Opcode]struct{}, len(readOps))
	for _, op := range readOps {
		if name, exists := reserved[op]; exists {
			t.Fatalf("read opcode %s collides with %s", op, name)
		}
		if _, exists := seen[op]; exists {
			t.Fatalf("duplicate read opcode value: %s", op)
		}
		seen[op] = struct{}{}
		if got := op.GetCategory(); got != OpCategoryTypeFunc {
			t.Fatalf("read opcode %s category = %s, want %s", op, got, OpCategoryTypeFunc)
		}
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
			inst:     NewInstruction(OpNop, 1, 1),
			expected: "NOP",
			size:     1,
		},
		{
			name: "push 8-bit",
			inst: NewInstructionWithOperand(
				OpPush8,
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
				OpPush32,
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
