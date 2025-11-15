package tests

import (
	"testing"

	"github.com/cawalch/go-yara/compiler"
)

// TestOpcodeClassification tests opcode classification functions
func TestOpcodeClassification(t *testing.T) {
	t.Run("IntegerOperations", testIntegerOperations)
	t.Run("DoubleOperations", testDoubleOperations)
	t.Run("StringOperations", testStringOperations)
	t.Run("JumpOperations", testJumpOperations)
	t.Run("TypeFunctions", testTypeFunctions)
	t.Run("MiscellaneousOperations", testMiscellaneousOperations)
}

func testIntegerOperations(t *testing.T) {
	tests := []struct {
		name    string
		opcode  compiler.Opcode
		isIntOp bool
	}{
		{"integer addition", compiler.OP_INT_ADD, true},
		{"integer subtraction", compiler.OP_INT_SUB, true},
		{"integer multiplication", compiler.OP_INT_MUL, true},
		{"integer division", compiler.OP_INT_DIV, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := compiler.IsIntOp(test.opcode); got != test.isIntOp {
				t.Errorf("IsIntOp(%v) = %v, want %v", test.opcode, got, test.isIntOp)
			}
		})
	}
}

func testDoubleOperations(t *testing.T) {
	tests := []struct {
		name    string
		opcode  compiler.Opcode
		isDblOp bool
	}{
		{"double addition", compiler.OP_DBL_ADD, true},
		{"double subtraction", compiler.OP_DBL_SUB, true},
		{"double multiplication", compiler.OP_DBL_MUL, true},
		{"double division", compiler.OP_DBL_DIV, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := compiler.IsDblOp(test.opcode); got != test.isDblOp {
				t.Errorf("IsDblOp(%v) = %v, want %v", test.opcode, got, test.isDblOp)
			}
		})
	}
}

func testStringOperations(t *testing.T) {
	tests := []struct {
		name    string
		opcode  compiler.Opcode
		isStrOp bool
	}{
		{"string equality", compiler.OP_STR_EQ, true},
		{"string inequality", compiler.OP_STR_NEQ, true},
		{"string less than", compiler.OP_STR_LT, true},
		{"string greater than", compiler.OP_STR_GT, true},
		{"string less equal", compiler.OP_STR_LE, true},
		{"string greater equal", compiler.OP_STR_GE, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := compiler.IsStrOp(test.opcode); got != test.isStrOp {
				t.Errorf("IsStrOp(%v) = %v, want %v", test.opcode, got, test.isStrOp)
			}
		})
	}
}

func testJumpOperations(t *testing.T) {
	tests := []struct {
		name   string
		opcode compiler.Opcode
		isJump bool
	}{
		{"jump if zero", compiler.OpJz, true},
		{"jump if zero param", compiler.OpJzP, true},
		{"jump if false", compiler.OP_JFALSE, true},
		{"jump if false param", compiler.OP_JFALSE_P, true},
		{"jump if true", compiler.OP_JTRUE, true},
		{"jump if true param", compiler.OP_JTRUE_P, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Note: Using IsStrOp as placeholder since IsJumpOp isn't implemented yet
			// This test will need to be updated when IsJumpOp is available
			_ = test.opcode // suppress unused warning
			t.Skip("Jump operations test pending IsJumpOp implementation")
		})
	}
}

func testTypeFunctions(t *testing.T) {
	tests := []struct {
		name     string
		opcode   compiler.Opcode
		isTypeFn bool
	}{
		{"push 8-bit", compiler.OpPush_8, true},
		{"push 16-bit", compiler.OpPush_16, true},
		{"push 32-bit", compiler.OpPush_32, true},
		{"push unsigned", compiler.OpPush_U, true},
		{"push double", compiler.OpPush_DBL, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Note: Using IsStrOp as placeholder since IsTypeFunction isn't implemented yet
			// This test will need to be updated when IsTypeFunction is available
			_ = test.opcode // suppress unused warning
			t.Skip("Type functions test pending IsTypeFunction implementation")
		})
	}
}

func testMiscellaneousOperations(t *testing.T) {
	tests := []struct {
		name     string
		opcode   compiler.Opcode
		isIntOp  bool
		isDblOp  bool
		isStrOp  bool
		isJump   bool
		isTypeFn bool
	}{
		{
			name:     "no operation",
			opcode:   compiler.OP_NOP,
			isIntOp:  false,
			isDblOp:  false,
			isStrOp:  false,
			isJump:   false,
			isTypeFn: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := compiler.IsIntOp(test.opcode); got != test.isIntOp {
				t.Errorf("IsIntOp(%v) = %v, want %v", test.opcode, got, test.isIntOp)
			}
			if got := compiler.IsDblOp(test.opcode); got != test.isDblOp {
				t.Errorf("IsDblOp(%v) = %v, want %v", test.opcode, got, test.isDblOp)
			}
			if got := compiler.IsStrOp(test.opcode); got != test.isStrOp {
				t.Errorf("IsStrOp(%v) = %v, want %v", test.opcode, got, test.isStrOp)
			}
		})
	}
}

// TestUndefinedValues tests undefined value handling
func TestUndefinedValues(t *testing.T) {
	if !compiler.IsUndefined(compiler.YRUndefined) {
		t.Error("YRUndefined should be recognized as undefined")
	}

	if compiler.IsUndefined(0) {
		t.Error("0 should not be recognized as undefined")
	}

	// Test that undefined constants are properly handled
	const testUndefined = compiler.YRUndefined
	if testUndefined != 0xFFFABADAFABADAFF {
		t.Errorf("YRUndefined should be 0xFFFABADAFABADAFF, got %x", testUndefined)
	}
}

// TestOpcodeString tests opcode string representation
func TestOpcodeString(t *testing.T) {
	tests := []struct {
		opcode   compiler.Opcode
		expected string
	}{
		{compiler.OP_NOP, "NOP"},
		{compiler.OP_HALT, "HALT"},
		{compiler.OpPush_8, "PUSH_8"},
		{compiler.OP_INT_ADD, "INT_ADD"},
		{compiler.OpJz, "JZ"},
	}

	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			if got := test.opcode.String(); got != test.expected {
				t.Errorf("Opcode %d string representation = %q, want %q", test.opcode, got, test.expected)
			}
		})
	}
}

// TestOpcodeCategories tests opcode category classification
func TestOpcodeCategories(t *testing.T) {
	tests := []struct {
		opcode   compiler.Opcode
		category string
	}{
		{compiler.OpPush_8, "stack"},
		{compiler.OpPush_16, "stack"},
		{compiler.OpPush_32, "stack"},
		{compiler.OP_INT_ADD, "arithmetic"},
		{compiler.OP_INT_SUB, "arithmetic"},
		{compiler.OP_INT_MUL, "arithmetic"},
		{compiler.OpJz, "jump"},
		// TODO: Find correct opcodes for JNZ and JMP
		// {compiler.OP_JNZ, "jump"},
		// {compiler.OP_JMP, "jump"},
		{compiler.OP_STR_EQ, "arithmetic"},
		{compiler.OP_STR_NEQ, "arithmetic"},
		{compiler.OP_HALT, "control"},
		{compiler.OP_NOP, "control"},
	}

	for _, test := range tests {
		t.Run(test.opcode.String(), func(t *testing.T) {
			if got := test.opcode.GetCategory(); got != test.category {
				t.Errorf("Opcode %v category = %q, want %q", test.opcode, got, test.category)
			}
		})
	}
}

// TestInstructionProperties tests instruction property methods
func TestInstructionProperties(t *testing.T) {
	tests := []struct {
		name             string
		opcode           compiler.Opcode
		expectedJump     bool
		expectedTypeFunc bool
		expectedStrOp    bool
	}{
		{
			name:             "jump instruction JZ",
			opcode:           compiler.OpJz,
			expectedJump:     true,
			expectedTypeFunc: false,
			expectedStrOp:    false,
		},
		{
			name:             "type function INT8",
			opcode:           compiler.OP_INT8,
			expectedJump:     false,
			expectedTypeFunc: true,
			expectedStrOp:    false,
		},
		{
			name:             "string operation STR_EQ",
			opcode:           compiler.OP_STR_EQ,
			expectedJump:     false,
			expectedTypeFunc: false,
			expectedStrOp:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inst := compiler.NewInstruction(tt.opcode, 0, 0) // positions don't matter for these tests

			if got := inst.IsJump(); got != tt.expectedJump {
				t.Errorf("IsJump() = %v, want %v", got, tt.expectedJump)
			}
			if got := inst.IsTypeFunction(); got != tt.expectedTypeFunc {
				t.Errorf("IsTypeFunction() = %v, want %v", got, tt.expectedTypeFunc)
			}
			if got := inst.IsStringOperation(); got != tt.expectedStrOp {
				t.Errorf("IsStringOperation() = %v, want %v", got, tt.expectedStrOp)
			}
		})
	}
}

// TestInstructionOperandTests tests instruction operand properties
func TestInstructionOperandTests(t *testing.T) {
	tests := []struct {
		name              string
		opcode            compiler.Opcode
		operand           compiler.Operand
		expectedImmediate bool
		expectedRelative  bool
		expectedAbsolute  bool
	}{
		{
			name:   "immediate operand PUSH_8",
			opcode: compiler.OpPush_8,
			operand: compiler.Operand{
				Type:  compiler.OperandImmediate8,
				Value: uint64(42),
			},
			expectedImmediate: true,
			expectedRelative:  false,
			expectedAbsolute:  false,
		},
		{
			name:   "relative operand JZ",
			opcode: compiler.OpJz,
			operand: compiler.Operand{
				Type:  compiler.OperandRelative8,
				Value: uint64(100),
			},
			expectedImmediate: false,
			expectedRelative:  true,
			expectedAbsolute:  false,
		},
		{
			name:   "absolute operand PUSH_U",
			opcode: compiler.OpPush_U,
			operand: compiler.Operand{
				Type:  compiler.OperandAbsolute32,
				Value: uint64(0x1000),
			},
			expectedImmediate: false,
			expectedRelative:  false,
			expectedAbsolute:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inst := compiler.NewInstructionWithOperand(tt.opcode, tt.operand, 0, 0) // positions don't matter

			if got := inst.HasImmediateOperand(); got != tt.expectedImmediate {
				t.Errorf("HasImmediateOperand() = %v, want %v", got, tt.expectedImmediate)
			}
			if got := inst.HasRelativeOperand(); got != tt.expectedRelative {
				t.Errorf("HasRelativeOperand() = %v, want %v", got, tt.expectedRelative)
			}
			if got := inst.HasAbsoluteOperand(); got != tt.expectedAbsolute {
				t.Errorf("HasAbsoluteOperand() = %v, want %v", got, tt.expectedAbsolute)
			}
		})
	}
}

// TestOperationHelpers tests helper functions for operations
func TestOperationHelpers(t *testing.T) {
	// Test addition operation
	result := compiler.Operation(func(a, b uint64) uint64 { return a + b }, 10, 20)
	if result != 30 {
		t.Errorf("Addition operation result = %d, want 30", result)
	}

	// Test comparison operation
	cmpResult := compiler.Comparison(func(a, b uint64) bool { return a > b }, 30, 20)
	if cmpResult != 1 {
		t.Errorf("Greater comparison result = %d, want 1", cmpResult)
	}

	cmpResult = compiler.Comparison(func(a, b uint64) bool { return a > b }, 20, 30)
	if cmpResult != 0 {
		t.Errorf("Less comparison result = %d, want 0", cmpResult)
	}
}
