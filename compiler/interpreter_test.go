package compiler

import (
	"fmt"
	"testing"

	"github.com/cawalch/go-yara/regex"
)

// assertInterpreterResult is a helper function that executes bytecode and asserts the expected result
func assertInterpreterResult(t *testing.T, bytecode []byte, expected int64) {
	t.Helper()
	interp := NewInterpreter(bytecode)
	err := interp.Execute()
	if err != nil {
		t.Errorf("Execute() error = %v", err)
		return
	}
	if len(interp.GetStack()) != 1 {
		t.Errorf("stack length = %d, want 1", len(interp.GetStack()))
		return
	}
	if interp.GetStack()[0].IntVal != expected {
		t.Errorf("stack[0] = %d, want %d", interp.GetStack()[0].IntVal, expected)
	}
}

// TestInterpreterBasicStack tests basic stack operations
func TestInterpreterBasicStack(t *testing.T) {
	tests := []struct {
		name     string
		bytecode []byte
		expected int64
	}{
		{
			name: "push_8_and_halt",
			bytecode: []byte{
				byte(OpPush8), 42,
				byte(OpHalt),
			},
			expected: 42,
		},
		{
			name: "push_16_and_halt",
			bytecode: func() []byte {
				b := []byte{byte(OpPush16)}
				b = append(b, 0x00, 0x01, byte(OpHalt)) // 256 in little-endian + halt
				return b
			}(),
			expected: 256,
		},
		{
			name: "push_32_and_halt",
			bytecode: func() []byte {
				b := []byte{byte(OpPush32)}
				b = append(b, 0x00, 0x00, 0x01, 0x00, byte(OpHalt)) // 65536 in little-endian + halt
				return b
			}(),
			expected: 65536,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interp := NewInterpreter(tt.bytecode)
			err := interp.Execute()
			if err != nil {
				t.Errorf("Execute() error = %v", err)
			}
			if len(interp.GetStack()) != 1 {
				t.Errorf("stack length = %d, want 1", len(interp.GetStack()))
			}
			if interp.GetStack()[0].IntVal != tt.expected {
				t.Errorf("stack[0] = %d, want %d", interp.GetStack()[0].IntVal, tt.expected)
			}
		})
	}
}

func TestInterpreterIntegerOnlyMixedDoubleDoesNotPanic(t *testing.T) {
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("Execute() panicked: %v", recovered)
		}
	}()

	interp := NewInterpreter([]byte("D00000000@0\n"))
	interp.SetCurrentRule("test")
	interp.SetRuleResults(make(map[string]bool))

	err := interp.Execute()
	if err == nil {
		t.Fatal("Execute() error = nil, want type mismatch")
	}
	if _, ok := err.(*InterpreterError); !ok {
		t.Fatalf("Execute() error = %T %v, want *InterpreterError", err, err)
	}
}

func TestInterpreterRejectsBackwardConditionalJump(t *testing.T) {
	interp := NewInterpreter([]byte("A002\xfb\xff\xff\xff"))
	interp.SetCurrentRule("test")
	interp.SetRuleResults(make(map[string]bool))

	err := interp.Execute()
	if err == nil {
		t.Fatal("Execute() error = nil, want invalid bytecode")
	}

	interpErr, ok := err.(*InterpreterError)
	if !ok {
		t.Fatalf("Execute() error = %T %v, want *InterpreterError", err, err)
	}
	if interpErr.Type != ErrorInvalidBytecode {
		t.Fatalf("Execute() error type = %v, want %v", interpErr.Type, ErrorInvalidBytecode)
	}
}

// TestInterpreterArithmetic tests arithmetic operations
func TestInterpreterArithmetic(t *testing.T) {
	tests := []struct {
		name     string
		opcode   Opcode
		left     int64
		right    int64
		expected int64
	}{
		{"add_two_numbers", OpIntAdd, 10, 20, 30},
		{"subtract_two_numbers", OpIntSub, 50, 20, 30},
		{"multiply_two_numbers", OpIntMul, 5, 6, 30},
		{"divide_two_numbers", OpIntDiv, 60, 2, 30},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bytecode := []byte{
				byte(OpPush8), byte(tt.left),
				byte(OpPush8), byte(tt.right),
				byte(tt.opcode),
				byte(OpHalt),
			}
			assertInterpreterResult(t, bytecode, tt.expected)
		})
	}
}

// TestInterpreterComparison tests comparison operations
func TestInterpreterComparison(t *testing.T) {
	tests := []struct {
		name     string
		opcode   Opcode
		left     int64
		right    int64
		expected int64
	}{
		{"equal_true", OpIntEq, 10, 10, 1},
		{"equal_false", OpIntEq, 10, 20, 0},
		{"less_than_true", OpIntLt, 10, 20, 1},
		{"greater_than_true", OpIntGt, 20, 10, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bytecode := []byte{
				byte(OpPush8), byte(tt.left),
				byte(OpPush8), byte(tt.right),
				byte(tt.opcode),
				byte(OpHalt),
			}
			assertInterpreterResult(t, bytecode, tt.expected)
		})
	}
}

// TestInterpreterLengthOf tests OpLengthOf ("length of ($a)" / "length of them").
func TestInterpreterLengthOf(t *testing.T) {
	tests := []struct {
		name     string
		set      []string
		matches  map[string][]Match // pattern -> matches with lengths
		expected int64
	}{
		{
			"single string single match",
			[]string{"$a"},
			map[string][]Match{"$a": {{Pattern: "$a", Offset: 0, Length: 5}}},
			5,
		},
		{
			"single string multiple matches",
			[]string{"$a"},
			map[string][]Match{
				"$a": {
					{Pattern: "$a", Offset: 0, Length: 3},
					{Pattern: "$a", Offset: 10, Length: 7},
				},
			},
			10,
		},
		{
			"multiple strings mixed matches",
			[]string{"$a", "$b", "$c"},
			map[string][]Match{
				"$a": {{Pattern: "$a", Offset: 0, Length: 4}},
				"$c": {{Pattern: "$c", Offset: 20, Length: 6}},
			},
			10,
		},
		{
			"no matches",
			[]string{"$a", "$b"},
			map[string][]Match{},
			0,
		},
		{
			"empty set",
			[]string{},
			map[string][]Match{"$a": {{Pattern: "$a", Offset: 0, Length: 5}}},
			0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			emitter := NewEmitter()
			emitter.EmitPush(0, 1, 1) // setIndex = 0
			emitter.EmitOpcode(OpLengthOf, 1, 1)
			emitter.EmitOpcode(OpHalt, 1, 1)

			bytecode, err := emitter.GetBytecode()
			if err != nil {
				t.Fatalf("GetBytecode() error = %v", err)
			}
			interp := NewInterpreter(bytecode)

			interp.stringSets = [][]string{tt.set}
			mc := &MatchContext{Matches: tt.matches}
			interp.matchContext = mc

			if err := interp.Execute(); err != nil {
				t.Fatalf("Execute() error = %v", err)
			}

			stack := interp.GetStack()
			if len(stack) == 0 {
				t.Fatalf("expected value on stack, got empty stack")
			}
			if stack[0].IntVal != tt.expected {
				t.Errorf("got %d, want %d", stack[0].IntVal, tt.expected)
			}
		})
	}
}

// TestInterpreterDebugMode tests debug mode functionality.
func TestInterpreterLogical(t *testing.T) {
	tests := []struct {
		name     string
		opcode   Opcode
		left     int64
		right    int64
		expected int64
	}{
		{"and_true", OpAnd, 1, 1, 1},
		{"and_false", OpAnd, 1, 0, 0},
		{"or_true", OpOr, 1, 0, 1},
		{"or_false", OpOr, 0, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bytecode := []byte{
				byte(OpPush8), byte(tt.left),
				byte(OpPush8), byte(tt.right),
				byte(tt.opcode),
				byte(OpHalt),
			}
			assertInterpreterResult(t, bytecode, tt.expected)
		})
	}
}

// TestInterpreterMemory tests memory operations
func TestInterpreterMemory(t *testing.T) {
	tests := []struct {
		name     string
		bytecode []byte
		memAddr  int
		expected int64
	}{
		{
			name: "clear_memory",
			bytecode: func() []byte {
				b := []byte{byte(OpClearM)}
				b = append(b, 0, 0, 0, 0, 0, 0, 0, 0, byte(OpHalt)) // addr 0 + halt
				return b
			}(),
			memAddr:  0,
			expected: 0,
		},
		{
			name: "push_and_pop_memory",
			bytecode: func() []byte {
				b := []byte{byte(OpPush8), 42}
				b = append(b, byte(OpPopM), 0, 0, 0, 0, 0, 0, 0, 0, byte(OpPushM), 0, 0, 0, 0, 0, 0, 0, 0, byte(OpHalt)) // addr 0 + halt
				return b
			}(),
			memAddr:  0,
			expected: 42,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interp := NewInterpreter(tt.bytecode)
			err := interp.Execute()
			if err != nil {
				t.Errorf("Execute() error = %v", err)
			}
			mem := interp.GetMemoryAt(tt.memAddr)
			if mem.IntVal != tt.expected {
				t.Errorf("memory[%d] = %d, want %d", tt.memAddr, mem.IntVal, tt.expected)
			}
		})
	}
}

// TestInterpreterJumps tests jump operations
func TestInterpreterJumps(t *testing.T) {
	tests := []struct {
		name     string
		bytecode []byte
		expected int64
	}{
		{
			name: "jfalse_taken",
			bytecode: func() []byte {
				b := []byte{byte(OpPush8), 0}
				b = append(b, byte(OpJfalse), 2, 0, 0, 0, byte(OpPush8), 10, byte(OpPush8), 20, byte(OpHalt))
				return b
			}(),
			expected: 20,
		},
		{
			name: "jtrue_taken",
			bytecode: func() []byte {
				b := []byte{byte(OpPush8), 1}
				b = append(b, byte(OpJtrue), 2, 0, 0, 0, byte(OpPush8), 10, byte(OpPush8), 20, byte(OpHalt))
				return b
			}(),
			expected: 20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interp := NewInterpreter(tt.bytecode)
			err := interp.Execute()
			if err != nil {
				t.Errorf("Execute() error = %v", err)
			}
			if len(interp.GetStack()) < 1 {
				t.Errorf("stack length = %d, want >= 1", len(interp.GetStack()))
			}
		})
	}
}

// TestInterpreterBitwise tests bitwise operations
func TestInterpreterBitwise(t *testing.T) {
	tests := []struct {
		name     string
		bytecode []byte
		expected int64
	}{
		{
			name: "bitwise_and",
			bytecode: []byte{
				byte(OpPush8), 0xFF,
				byte(OpPush8), 0x0F,
				byte(OpBitwiseAnd),
				byte(OpHalt),
			},
			expected: 0x0F,
		},
		{
			name: "bitwise_or",
			bytecode: []byte{
				byte(OpPush8), 0xF0,
				byte(OpPush8), 0x0F,
				byte(OpBitwiseOr),
				byte(OpHalt),
			},
			expected: 0xFF,
		},
		{
			name: "bitwise_xor",
			bytecode: []byte{
				byte(OpPush8), 0xFF,
				byte(OpPush8), 0xFF,
				byte(OpBitwiseXor),
				byte(OpHalt),
			},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interp := NewInterpreter(tt.bytecode)
			err := interp.Execute()
			if err != nil {
				t.Errorf("Execute() error = %v", err)
			}
			if len(interp.GetStack()) != 1 {
				t.Errorf("stack length = %d, want 1", len(interp.GetStack()))
			}
			if interp.GetStack()[0].IntVal != tt.expected {
				t.Errorf("stack[0] = %d, want %d", interp.GetStack()[0].IntVal, tt.expected)
			}
		})
	}
}

// TestInterpreterMiscOps tests miscellaneous operations
func TestInterpreterMiscOps(t *testing.T) {
	tests := []struct {
		name     string
		bytecode []byte
		setup    func(*Interpreter)
		validate func(*testing.T, *Interpreter)
	}{
		{
			name:     "undefined",
			bytecode: []byte{byte(OpPushU), byte(OpHalt)},
			validate: func(t *testing.T, i *Interpreter) {
				if len(i.stack) != 1 {
					t.Errorf("stack length = %d, want 1", len(i.stack))
				} else if i.stack[0].Type != ValueTypeUndefined {
					t.Errorf("stack[0].Type = %v, want ValueTypeUndefined", i.stack[0].Type)
				}
			},
		},
		{
			name:     "filesize",
			bytecode: []byte{byte(OpFilesize), byte(OpHalt)},
			setup: func(i *Interpreter) {
				i.matchContext.FileSize = 1024
			},
			validate: func(t *testing.T, i *Interpreter) {
				if len(i.stack) != 1 {
					t.Errorf("stack length = %d, want 1", len(i.stack))
				} else if i.stack[0].IntVal != 1024 {
					t.Errorf("stack[0] = %d, want 1024", i.stack[0].IntVal)
				}
			},
		},
		{
			name: "increment_memory",
			bytecode: func() []byte {
				b := []byte{byte(OpIncrM)}
				b = append(b, 0, 0, 0, 0, 0, 0, 0, 0, // addr 0
					byte(OpIncrM), 0, 0, 0, 0, 0, 0, 0, 0, // addr 0
					byte(OpPushM), 0, 0, 0, 0, 0, 0, 0, 0, // addr 0
					byte(OpHalt))
				return b
			}(),
			validate: func(t *testing.T, i *Interpreter) {
				if len(i.stack) != 1 {
					t.Errorf("stack length = %d, want 1", len(i.stack))
				} else if i.stack[0].IntVal != 2 {
					t.Errorf("stack[0] = %d, want 2", i.stack[0].IntVal)
				}
			},
		},
		{
			name: "complex_arithmetic",
			bytecode: []byte{
				byte(OpPush8), 10,
				byte(OpPush8), 20,
				byte(OpIntAdd),
				byte(OpPush8), 2,
				byte(OpIntMul),
				byte(OpHalt),
			},
			validate: func(t *testing.T, i *Interpreter) {
				if len(i.stack) != 1 {
					t.Errorf("stack length = %d, want 1", len(i.stack))
				} else if i.stack[0].IntVal != 60 {
					t.Errorf("result = %d, want 60", i.stack[0].IntVal)
				}
			},
		},
		{
			name: "type_conversion",
			bytecode: []byte{
				byte(OpPush8), 1,
				byte(OpIntToDbl),
				byte(OpHalt),
			},
			validate: func(t *testing.T, i *Interpreter) {
				if len(i.stack) != 1 {
					t.Errorf("stack length = %d, want 1", len(i.stack))
				} else if i.stack[0].Type != ValueTypeDouble {
					t.Errorf("stack[0].Type = %v, want ValueTypeDouble", i.stack[0].Type)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interp := NewInterpreter(tt.bytecode)
			if tt.setup != nil {
				tt.setup(interp)
			}
			err := interp.Execute()
			if err != nil {
				t.Errorf("Execute() error = %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, interp)
			}
		})
	}
}

// TestInterpreterStringOps tests string comparison operations via opcodes
func TestInterpreterStringOps(t *testing.T) {
	tests := []struct {
		name     string
		opcode   Opcode
		left     string
		right    string
		expected int64
	}{
		{"eq_true", OpStrEq, "foo", "foo", 1},
		{"eq_false", OpStrEq, "foo", "bar", 0},
		{"neq_true", OpStrNeq, "foo", "bar", 1},
		{"neq_false", OpStrNeq, "foo", "foo", 0},
		{"lt_true", OpStrLt, "bar", "foo", 1},
		{"gt_true", OpStrGt, "foo", "bar", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interp := NewInterpreter([]byte{byte(OpHalt)})
			_ = interp.PushString(tt.left)
			_ = interp.PushString(tt.right)

			err := interp.executeOpcode(tt.opcode)
			if err != nil {
				t.Errorf("executeOpcode() error = %v", err)
			}
			if len(interp.GetStack()) != 1 {
				t.Errorf("stack length = %d, want 1", len(interp.GetStack()))
			}
			if interp.GetStack()[0].IntVal != tt.expected {
				t.Errorf("result = %d, want %d", interp.GetStack()[0].IntVal, tt.expected)
			}
		})
	}
}

// TestInterpreterReadInt tests reading integers from data
func TestInterpreterReadInt(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		offset   int64
		size     int
		unsigned bool
		expected int64
	}{
		{
			name:     "read_uint8",
			data:     []byte{0xFF},
			offset:   0,
			size:     1,
			unsigned: true,
			expected: 255,
		},
		{
			name:     "read_int8_negative",
			data:     []byte{0xFF},
			offset:   0,
			size:     1,
			unsigned: false,
			expected: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interp := NewInterpreter([]byte{byte(OpHalt)})
			interp.matchContext.Data = tt.data

			result, err := interp.executeReadInt(tt.offset, tt.size, tt.unsigned)
			if err != nil {
				t.Errorf("executeReadInt() error = %v", err)
			}

			// Push the result onto the stack to match the test expectations
			_ = interp.push(Value{Type: ValueTypeInt, IntVal: result})
			if len(interp.GetStack()) != 1 {
				t.Errorf("stack length = %d, want 1", len(interp.GetStack()))
			}
			if interp.GetStack()[0].IntVal != tt.expected {
				t.Errorf("read value = %d, want %d", interp.GetStack()[0].IntVal, tt.expected)
			}
		})
	}
}

func TestInterpreterReadIntOpcodes64Bit(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	tests := []struct {
		name     string
		opcode   Opcode
		expected int64
	}{
		{name: "int64_little_endian", opcode: OpInt64, expected: 0x0807060504030201},
		{name: "uint64_little_endian", opcode: OpUint64, expected: 0x0807060504030201},
		{name: "int64_big_endian", opcode: OpInt64be, expected: 0x0102030405060708},
		{name: "uint64_big_endian", opcode: OpUint64be, expected: 0x0102030405060708},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interp := NewInterpreter([]byte{byte(OpPush8), 0, byte(tt.opcode), byte(OpHalt)})
			interp.matchContext.Data = data
			if err := interp.Execute(); err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			stack := interp.GetStack()
			if len(stack) != 1 {
				t.Fatalf("stack length = %d, want 1", len(stack))
			}
			if stack[0].IntVal != tt.expected {
				t.Fatalf("read value = %#x, want %#x", stack[0].IntVal, tt.expected)
			}
		})
	}
}

// TestInterpreterNegation tests negation operations
func TestInterpreterNegation(t *testing.T) {
	tests := []struct {
		name     string
		bytecode []byte
		expected int64
	}{
		{
			name: "int_negation",
			bytecode: []byte{
				byte(OpPush8), 42,
				byte(OpIntMinus),
				byte(OpHalt),
			},
			expected: -42,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interp := NewInterpreter(tt.bytecode)
			err := interp.Execute()
			if err != nil {
				t.Errorf("Execute() error = %v", err)
			}
			if len(interp.GetStack()) != 1 {
				t.Errorf("stack length = %d, want 1", len(interp.GetStack()))
			}
			if interp.GetStack()[0].IntVal != tt.expected {
				t.Errorf("stack[0] = %d, want %d", interp.GetStack()[0].IntVal, tt.expected)
			}
		})
	}
}

// TestInterpreterOffsetOperation tests OpOffset operation
func TestInterpreterOffsetOperation(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		index    int64
		matches  map[string][]Match
		expected int64
	}{
		{
			name:    "offset_first_match",
			pattern: "test",
			index:   1,
			matches: map[string][]Match{
				"test": {
					{Pattern: "test", Offset: 10, Length: 5},
					{Pattern: "test", Offset: 20, Length: 5},
				},
			},
			expected: 10,
		},
		{
			name:    "offset_second_match",
			pattern: "test",
			index:   2,
			matches: map[string][]Match{
				"test": {
					{Pattern: "test", Offset: 10, Length: 5},
					{Pattern: "test", Offset: 20, Length: 5},
				},
			},
			expected: 20,
		},
		{
			name:    "offset_invalid_index",
			pattern: "test",
			index:   5,
			matches: map[string][]Match{
				"test": {{Pattern: "test", Offset: 10, Length: 5}},
			},
			expected: 0, // Undefined
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interp := NewInterpreter([]byte{byte(OpHalt)})
			interp.matchContext.Matches = tt.matches
			_ = interp.PushString(tt.pattern)
			_ = interp.push(Value{Type: ValueTypeInt, IntVal: tt.index})

			err := interp.executeOpcode(OpOffset)
			if err != nil {
				t.Errorf("executeOpcode(OpOffset) error = %v", err)
			}
			if len(interp.GetStack()) != 1 {
				t.Errorf("stack length = %d, want 1", len(interp.GetStack()))
			}
			if tt.expected == 0 && interp.GetStack()[0].Type != ValueTypeUndefined {
				t.Errorf("expected undefined, got %v", interp.GetStack()[0])
			} else if tt.expected != 0 && interp.GetStack()[0].IntVal != tt.expected {
				t.Errorf("offset = %d, want %d", interp.GetStack()[0].IntVal, tt.expected)
			}
		})
	}
}

// TestInterpreterLengthOperation tests OpLength operation
func TestInterpreterLengthOperation(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		index    int64
		matches  map[string][]Match
		expected int64
	}{
		{
			name:    "length_first_match",
			pattern: "test",
			index:   1,
			matches: map[string][]Match{
				"test": {{Pattern: "test", Offset: 0, Length: 7}},
			},
			expected: 7,
		},
		{
			name:    "length_multiple_matches",
			pattern: "test",
			index:   2,
			matches: map[string][]Match{
				"test": {
					{Pattern: "test", Offset: 0, Length: 5},
					{Pattern: "test", Offset: 10, Length: 8},
				},
			},
			expected: 8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interp := NewInterpreter([]byte{byte(OpHalt)})
			interp.matchContext.Matches = tt.matches
			_ = interp.PushString(tt.pattern)
			_ = interp.push(Value{Type: ValueTypeInt, IntVal: tt.index})

			err := interp.executeOpcode(OpLength)
			if err != nil {
				t.Errorf("executeOpcode(OpLength) error = %v", err)
			}
			if len(interp.GetStack()) != 1 {
				t.Errorf("stack length = %d, want 1", len(interp.GetStack()))
			}
			if interp.GetStack()[0].IntVal != tt.expected {
				t.Errorf("length = %d, want %d", interp.GetStack()[0].IntVal, tt.expected)
			}
		})
	}
}

// TestInterpreterFound tests OpFound operation
func TestInterpreterFound(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		matches  map[string][]Match
		expected int64
	}{
		{
			name:    "found_pattern_exists",
			pattern: "test",
			matches: map[string][]Match{
				"test": {{Pattern: "test", Offset: 0, Length: 4}},
			},
			expected: 1,
		},
		{
			name:    "found_pattern_not_exists",
			pattern: "notfound",
			matches: map[string][]Match{
				"test": {{Pattern: "test", Offset: 0, Length: 4}},
			},
			expected: 0,
		},
		{
			name:     "found_empty_matches",
			pattern:  "test",
			matches:  map[string][]Match{},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interp := NewInterpreter([]byte{byte(OpHalt)})
			interp.matchContext.Matches = tt.matches
			_ = interp.PushString(tt.pattern)

			err := interp.executeOpcode(OpFound)
			if err != nil {
				t.Errorf("executeOpcode(OpFound) error = %v", err)
			}
			if len(interp.GetStack()) != 1 {
				t.Errorf("stack length = %d, want 1", len(interp.GetStack()))
			}
			if interp.GetStack()[0].IntVal != tt.expected {
				t.Errorf("result = %d, want %d", interp.GetStack()[0].IntVal, tt.expected)
			}
		})
	}
}

// TestInterpreterCount tests OpCount operation
func TestInterpreterCount(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		matches  map[string][]Match
		expected int64
	}{
		{
			name:    "count_single_match",
			pattern: "test",
			matches: map[string][]Match{
				"test": {{Pattern: "test", Offset: 0, Length: 4}},
			},
			expected: 1,
		},
		{
			name:    "count_multiple_matches",
			pattern: "test",
			matches: map[string][]Match{
				"test": {
					{Pattern: "test", Offset: 0, Length: 4},
					{Pattern: "test", Offset: 10, Length: 4},
					{Pattern: "test", Offset: 20, Length: 4},
				},
			},
			expected: 3,
		},
		{
			name:     "count_no_matches",
			pattern:  "test",
			matches:  map[string][]Match{},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interp := NewInterpreter([]byte{byte(OpHalt)})
			interp.matchContext.Matches = tt.matches
			_ = interp.PushString(tt.pattern)

			err := interp.executeOpcode(OpCount)
			if err != nil {
				t.Errorf("executeOpcode(OpCount) error = %v", err)
			}
			if len(interp.GetStack()) != 1 {
				t.Errorf("stack length = %d, want 1", len(interp.GetStack()))
			}
			if interp.GetStack()[0].IntVal != tt.expected {
				t.Errorf("result = %d, want %d", interp.GetStack()[0].IntVal, tt.expected)
			}
		})
	}
}

// TestInterpreterFoundAt tests OpFoundAt operation
func TestInterpreterFoundAt(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		offset   int64
		matches  map[string][]Match
		expected int64
	}{
		{
			name:    "found_at_match_exists",
			pattern: "test",
			offset:  10,
			matches: map[string][]Match{
				"test": {
					{Pattern: "test", Offset: 10, Length: 5},
					{Pattern: "test", Offset: 20, Length: 5},
				},
			},
			expected: 1,
		},
		{
			name:    "found_at_match_not_exists",
			pattern: "test",
			offset:  15,
			matches: map[string][]Match{
				"test": {
					{Pattern: "test", Offset: 10, Length: 5},
					{Pattern: "test", Offset: 20, Length: 5},
				},
			},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interp := NewInterpreter([]byte{byte(OpHalt)})
			interp.matchContext.Matches = tt.matches
			_ = interp.PushString(tt.pattern)
			_ = interp.push(Value{Type: ValueTypeInt, IntVal: tt.offset})

			err := interp.executeOpcode(OpFoundAt)
			if err != nil {
				t.Errorf("executeOpcode(OpFoundAt) error = %v", err)
			}
			if len(interp.GetStack()) != 1 {
				t.Errorf("stack length = %d, want 1", len(interp.GetStack()))
			}
			if interp.GetStack()[0].IntVal != tt.expected {
				t.Errorf("result = %d, want %d", interp.GetStack()[0].IntVal, tt.expected)
			}
		})
	}
}

// TestInterpreterFoundIn tests OpFoundIn operation
func TestInterpreterFoundIn(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		startOff int64
		endOff   int64
		matches  map[string][]Match
		expected int64
	}{
		{
			name:     "found_in_match_in_range",
			pattern:  "test",
			startOff: 5,
			endOff:   25,
			matches: map[string][]Match{
				"test": {
					{Pattern: "test", Offset: 10, Length: 5},
					{Pattern: "test", Offset: 30, Length: 5},
				},
			},
			expected: 1,
		},
		{
			name:     "found_in_match_out_of_range",
			pattern:  "test",
			startOff: 5,
			endOff:   15,
			matches: map[string][]Match{
				"test": {
					{Pattern: "test", Offset: 20, Length: 5},
				},
			},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interp := NewInterpreter([]byte{byte(OpHalt)})
			interp.matchContext.Matches = tt.matches
			_ = interp.PushString(tt.pattern)
			_ = interp.push(Value{Type: ValueTypeInt, IntVal: tt.startOff})
			_ = interp.push(Value{Type: ValueTypeInt, IntVal: tt.endOff})

			err := interp.executeOpcode(OpFoundIn)
			if err != nil {
				t.Errorf("executeOpcode(OpFoundIn) error = %v", err)
			}
			if len(interp.GetStack()) != 1 {
				t.Errorf("stack length = %d, want 1", len(interp.GetStack()))
			}
			if interp.GetStack()[0].IntVal != tt.expected {
				t.Errorf("result = %d, want %d", interp.GetStack()[0].IntVal, tt.expected)
			}
		})
	}
}

// TestInterpreterMatches tests OpMatches operation
func TestInterpreterMatches(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		regex    string
		expected int64
	}{
		{
			name:     "matches_found",
			value:    "test",
			regex:    `/te.t/`,
			expected: 1,
		},
		{
			name:     "matches_not_found",
			value:    "notfound",
			regex:    `/te.t/`,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interp := NewInterpreter([]byte{byte(OpHalt)})
			_ = interp.PushString(tt.value)
			_ = interp.PushString(tt.regex)

			err := interp.executeOpcode(OpMatches)
			if err != nil {
				t.Errorf("executeOpcode(OpMatches) error = %v", err)
			}
			if len(interp.GetStack()) != 1 {
				t.Errorf("stack length = %d, want 1", len(interp.GetStack()))
			}
			if interp.GetStack()[0].IntVal != tt.expected {
				t.Errorf("result = %d, want %d", interp.GetStack()[0].IntVal, tt.expected)
			}
		})
	}
}

// TestInterpreterStackUnderflow tests stack underflow handling
func TestInterpreterStackUnderflow(t *testing.T) {
	bytecode := []byte{
		byte(OpIntAdd), // Try to add with empty stack
		byte(OpHalt),
	}

	interp := NewInterpreter(bytecode)
	err := interp.Execute()
	if err == nil {
		t.Errorf("Execute() should return error on stack underflow")
	}
}

// TestInterpreterRegexFoundOps_FOUND tests FOUND operation
func TestInterpreterRegexFoundOps_FOUND(t *testing.T) {
	interp := setupRegexInterpreter(t)

	// FOUND($a) -> true
	_ = interp.PushString("$a")
	if execErr := interp.executeOpcode(OpFound); execErr != nil {
		t.Fatalf("executeOpcode(OpFound) error = %v", execErr)
	}
	if len(interp.GetStack()) != 1 || interp.GetStack()[0].IntVal != 1 {
		t.Fatalf("FOUND($a) expected 1, got %+v", interp.GetStack()[0])
	}
}

// TestInterpreterRegexFoundOps_FOUND_AT tests FOUND_AT operation
func TestInterpreterRegexFoundOps_FOUND_AT(t *testing.T) {
	interp := setupRegexInterpreter(t)
	matches := interp.matchContext.Matches["$a"]
	hitOff := matches[0].Offset
	missOff := hitOff + 99

	tests := []struct {
		name     string
		offset   int64
		expected int64
	}{
		{"FOUND_AT hit", hitOff, 1},
		{"FOUND_AT miss", missOff, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear stack before each test
			interp.stack = interp.stack[:0]

			_ = interp.PushString("$a")
			_ = interp.push(Value{Type: ValueTypeInt, IntVal: tt.offset})
			if execErr := interp.executeOpcode(OpFoundAt); execErr != nil {
				t.Fatalf("executeOpcode(OpFoundAt) error = %v", execErr)
			}
			if len(interp.GetStack()) != 1 || interp.GetStack()[0].IntVal != tt.expected {
				t.Fatalf("FOUND_AT($a, %d) expected %d, got %+v", tt.offset, tt.expected, interp.GetStack()[0])
			}
		})
	}
}

// TestInterpreterRegexFoundOps_FOUND_IN tests FOUND_IN operation
func TestInterpreterRegexFoundOps_FOUND_IN(t *testing.T) {
	interp := setupRegexInterpreter(t)
	matches := interp.matchContext.Matches["$a"]
	hitOff := matches[0].Offset

	tests := []struct {
		name     string
		start    int64
		end      int64
		expected int64
	}{
		{"FOUND_IN covering hit", max(hitOff-1, 0), hitOff + 10, 1},
		{"FOUND_IN before hit", 0, hitOff - 1, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear stack before each test
			interp.stack = interp.stack[:0]

			_ = interp.PushString("$a")
			_ = interp.push(Value{Type: ValueTypeInt, IntVal: tt.start})
			_ = interp.push(Value{Type: ValueTypeInt, IntVal: tt.end})
			if execErr := interp.executeOpcode(OpFoundIn); execErr != nil {
				t.Fatalf("executeOpcode(OpFoundIn) error = %v", execErr)
			}
			if len(interp.GetStack()) != 1 || interp.GetStack()[0].IntVal != tt.expected {
				t.Fatalf("FOUND_IN($a, %d, %d) expected %d, got %+v", tt.start, tt.end, tt.expected, interp.GetStack()[0])
			}
		})
	}
}

// setupRegexInterpreter creates an interpreter with regex matches for testing
func setupRegexInterpreter(t *testing.T) *Interpreter {
	// Compile a simple regex via the internal compiler path
	sc := NewStringCompiler(NewEmitter())
	code, err := sc.compileRegex(`/ab+/`, nil)
	if err != nil {
		t.Fatalf("compileRegex error: %v", err)
	}

	// Generate matches using the regex VM (scan semantics like execution pipeline)
	data := []byte("zabbb zab ab")
	flags := regex.FlagsScan

	type M = Match
	var matches []M
	searchStart := 0
	for searchStart <= len(data) {
		ok, start, end := regex.ExecMatch(code, data[searchStart:], flags)
		if !ok {
			break
		}
		absStart := searchStart + start
		absEnd := searchStart + end
		matches = append(matches, M{
			Pattern: "$a",
			Offset:  int64(absStart),
			Length:  absEnd - absStart,
			Base:    0,
		})
		// Advance by one to allow overlapping matches (mirrors cmd/main.go)
		if absStart+1 > searchStart {
			searchStart = absStart + 1
		} else {
			searchStart++
		}
	}

	if len(matches) == 0 {
		t.Fatalf("expected at least one regex-derived match, got 0")
	}

	// Interpreter with only HALT; we'll invoke opcodes directly
	interp := NewInterpreter([]byte{byte(OpHalt)})
	interp.matchContext.Matches = map[string][]Match{
		"$a": matches,
	}

	return interp
}

// TestInterpreterCountInRange tests OpCountIn operation
func TestInterpreterCountInRange(t *testing.T) {
	tests := []struct {
		name     string
		count    int64
		min      int64
		max      int64
		expected int64
	}{
		{"count within range", 5, 3, 10, 1},
		{"count at min boundary", 3, 3, 10, 1},
		{"count at max boundary", 10, 3, 10, 1},
		{"count below range", 2, 3, 10, 0},
		{"count above range", 11, 3, 10, 0},
		{"zero count in range", 0, 0, 5, 1},
		{"zero count below range", 0, 1, 5, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			emitter := NewEmitter()
			emitter.EmitPush(uint64(tt.count), 1, 1)
			emitter.EmitPush(uint64(tt.min), 1, 1)
			emitter.EmitPush(uint64(tt.max), 1, 1)
			emitter.EmitOpcode(OpCountIn, 1, 1)
			emitter.EmitOpcode(OpHalt, 1, 1)

			bytecode, err := emitter.GetBytecode()
			if err != nil {
				t.Fatalf("GetBytecode() error = %v", err)
			}
			interp := NewInterpreter(bytecode)
			err = interp.Execute()
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}

			if len(interp.GetStack()) != 1 {
				t.Fatalf("stack length = %d, want 1", len(interp.GetStack()))
			}

			got := interp.GetStack()[0].IntVal
			if got != tt.expected {
				t.Errorf("count=%d in (%d..%d) = %d, want %d", tt.count, tt.min, tt.max, got, tt.expected)
			}
		})
	}
}

// TestInterpreterOfPercent tests OpOfPercent operation
func TestInterpreterOfPercent(t *testing.T) {
	tests := []struct {
		name     string
		matched  int // number of matched strings out of total
		total    int // total strings in set
		percent  int64
		expected int64
	}{
		{"50_percent_2_of_3", 2, 3, 50, 1},   // 66.7% >= 50% => true
		{"75_percent_2_of_3", 2, 3, 75, 0},   // 66.7% < 75% => false
		{"100_percent_2_of_2", 2, 2, 100, 1}, // 100% >= 100% => true
		{"33_percent_1_of_3", 1, 3, 33, 1},   // 33.3% >= 33% => true
		{"34_percent_1_of_3", 1, 3, 34, 0},   // 33.3% < 34% => false
		{"0_percent_0_of_3", 0, 3, 1, 0},     // 0% < 1% => false
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			emitter := NewEmitter()

			// Push the percentage (bottom of stack)
			emitter.EmitPush(uint64(tt.percent), 1, 1)

			// Push the string set ID (top of stack)
			emitter.EmitPush(stringSetAll, 1, 1)

			// Emit OpOfPercent
			emitter.EmitOpcode(OpOfPercent, 1, 1)

			// Emit OpHalt
			emitter.EmitOpcode(OpHalt, 1, 1)

			bytecode, err := emitter.GetBytecode()
			if err != nil {
				t.Fatalf("GetBytecode() error = %v", err)
			}

			interp := NewInterpreter(bytecode)

			// Set up match context with the right number of matched strings
			mc := &MatchContext{
				Matches: make(map[string][]Match),
			}
			for i := 0; i < tt.total; i++ {
				id := fmt.Sprintf("$s%d", i)
				if i < tt.matched {
					mc.Matches[id] = []Match{{Offset: 0, Length: 1}}
				}
			}
			interp.matchContext = mc
			interp.allStrings = make([]string, tt.total)
			for i := 0; i < tt.total; i++ {
				interp.allStrings[i] = fmt.Sprintf("$s%d", i)
			}

			err = interp.Execute()
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}

			if len(interp.GetStack()) != 1 {
				t.Fatalf("stack length = %d, want 1", len(interp.GetStack()))
			}

			got := interp.GetStack()[0].IntVal
			if got != tt.expected {
				t.Errorf("%d%% of %d (matched=%d) = %d, want %d", tt.percent, tt.total, tt.matched, got, tt.expected)
			}
		})
	}
}

// TestInterpreterOfFoundIn tests OpOfFoundIn (N of strings in range)
func TestInterpreterOfFoundIn(t *testing.T) {
	tests := []struct {
		name     string
		count    int64
		min      int64
		max      int64
		matched  int // strings with matches in range
		total    int
		expected int64
	}{
		{"2 of 3 in range", 2, 0, 100, 2, 3, 1},
		{"1 of 3 in range", 1, 0, 100, 2, 3, 1},
		{"3 of 3 in range not enough", 3, 0, 100, 2, 3, 0},
		{"any of 3 in range", 1, 0, 100, 1, 3, 1},
		{"none in range", 1, 0, 100, 0, 3, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Stack layout: [count, stringSetIndex, min, max]
			emitter := NewEmitter()
			emitter.EmitPush(uint64(tt.count), 1, 1)
			emitter.EmitPush(0, 1, 1) // string set index 0
			emitter.EmitPush(uint64(tt.min), 1, 1)
			emitter.EmitPush(uint64(tt.max), 1, 1)
			emitter.EmitOpcode(OpOfFoundIn, 1, 1)
			emitter.EmitOpcode(OpHalt, 1, 1)

			bytecode, err := emitter.GetBytecode()
			if err != nil {
				t.Fatalf("GetBytecode() error = %v", err)
			}
			interp := NewInterpreter(bytecode)

			// Set up string set
			interp.stringSets = [][]string{{}}
			mc := &MatchContext{Matches: make(map[string][]Match)}
			for i := 0; i < tt.total; i++ {
				id := fmt.Sprintf("$s%d", i)
				interp.stringSets[0] = append(interp.stringSets[0], id)
				if i < tt.matched {
					mc.Matches[id] = []Match{{Offset: 10, Length: 1}}
				} else {
					mc.Matches[id] = []Match{{Offset: 500, Length: 1}}
				}
			}
			interp.matchContext = mc

			err = interp.Execute()
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}

			if len(interp.GetStack()) != 1 {
				t.Fatalf("stack length = %d, want 1", len(interp.GetStack()))
			}

			got := interp.GetStack()[0].IntVal
			if got != tt.expected {
				t.Errorf("%d of %d in (%d..%d) = %d, want %d", tt.count, tt.matched, tt.min, tt.max, got, tt.expected)
			}
		})
	}
}

// TestInterpreterOfFoundAt tests OpOfFoundAt (N of strings at offset)
func TestInterpreterOfFoundAt(t *testing.T) {
	tests := []struct {
		name     string
		count    int64
		offset   int64
		matched  int // strings with match at exact offset
		total    int
		expected int64
	}{
		{"1 at offset 0", 1, 0, 1, 3, 1},
		{"2 at offset 0 not enough", 2, 0, 1, 3, 0},
		{"1 at offset 42 none", 1, 42, 0, 3, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Stack layout: [count, stringSetIndex, offset]
			emitter := NewEmitter()
			emitter.EmitPush(uint64(tt.count), 1, 1)
			emitter.EmitPush(0, 1, 1) // string set index 0
			emitter.EmitPush(uint64(tt.offset), 1, 1)
			emitter.EmitOpcode(OpOfFoundAt, 1, 1)
			emitter.EmitOpcode(OpHalt, 1, 1)

			bytecode, err := emitter.GetBytecode()
			if err != nil {
				t.Fatalf("GetBytecode() error = %v", err)
			}
			interp := NewInterpreter(bytecode)

			interp.stringSets = [][]string{{}}
			mc := &MatchContext{Matches: make(map[string][]Match)}
			for i := 0; i < tt.total; i++ {
				id := fmt.Sprintf("$s%d", i)
				interp.stringSets[0] = append(interp.stringSets[0], id)
				if i < tt.matched {
					mc.Matches[id] = []Match{{Offset: tt.offset, Length: 1}}
				} else {
					mc.Matches[id] = []Match{{Offset: 999, Length: 1}}
				}
			}
			interp.matchContext = mc

			err = interp.Execute()
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}

			if len(interp.GetStack()) != 1 {
				t.Fatalf("stack length = %d, want 1", len(interp.GetStack()))
			}

			got := interp.GetStack()[0].IntVal
			if got != tt.expected {
				t.Errorf("%d of %d at %d = %d, want %d", tt.count, tt.matched, tt.offset, got, tt.expected)
			}
		})
	}
}

// TestInterpreterCountInOf tests OpCountInOf ("#a in (min..max) of ($str*)").
func TestInterpreterCountInOf(t *testing.T) {
	tests := []struct {
		name     string
		set      []string
		matched  map[string]int // pattern -> number of matches
		min      int64
		max      int64
		expected bool
	}{
		{"2 of 3 matched, range 1..3", []string{"$a", "$b", "$c"}, map[string]int{"$a": 1, "$b": 1}, 1, 3, true},
		{"2 of 3 matched, range 3..5", []string{"$a", "$b", "$c"}, map[string]int{"$a": 1, "$b": 1}, 3, 5, false},
		{"0 of 3 matched, range 0..0", []string{"$a", "$b", "$c"}, map[string]int{}, 0, 0, true},
		{"0 of 3 matched, range 1..3", []string{"$a", "$b", "$c"}, map[string]int{}, 1, 3, false},
		{"3 of 3 matched, range 3..3", []string{"$a", "$b", "$c"}, map[string]int{"$a": 2, "$b": 1, "$c": 1}, 3, 3, true},
		{"empty set, range 0..0", []string{}, map[string]int{}, 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			emitter := NewEmitter()
			emitter.EmitPush(0, 1, 1) // setIndex = 0
			emitter.EmitPush(uint64(tt.min), 1, 1)
			emitter.EmitPush(uint64(tt.max), 1, 1)
			emitter.EmitOpcode(OpCountInOf, 1, 1)
			emitter.EmitOpcode(OpHalt, 1, 1)

			bytecode, err := emitter.GetBytecode()
			if err != nil {
				t.Fatalf("GetBytecode() error = %v", err)
			}
			interp := NewInterpreter(bytecode)

			interp.stringSets = [][]string{tt.set}
			mc := &MatchContext{Matches: make(map[string][]Match)}
			for pattern, count := range tt.matched {
				mc.Matches[pattern] = make([]Match, count)
			}
			interp.matchContext = mc

			if err := interp.Execute(); err != nil {
				t.Fatalf("Execute() error = %v", err)
			}

			stack := interp.GetStack()
			got := len(stack) > 0 && stack[0].IntVal == 1
			if got != tt.expected {
				t.Errorf("got %v, want %v (matched=%d, range=[%d,%d])", got, tt.expected, len(tt.matched), tt.min, tt.max)
			}
		})
	}
}
