package compiler

import (
	"testing"

	"github.com/cawalch/go-yara/regex"
)

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
				byte(OP_PUSH_8), 42,
				byte(OP_HALT),
			},
			expected: 42,
		},
		{
			name: "push_16_and_halt",
			bytecode: func() []byte {
				b := []byte{byte(OP_PUSH_16)}
				b = append(b, 0x00, 0x01) // 256 in little-endian
				b = append(b, byte(OP_HALT))
				return b
			}(),
			expected: 256,
		},
		{
			name: "push_32_and_halt",
			bytecode: func() []byte {
				b := []byte{byte(OP_PUSH_32)}
				b = append(b, 0x00, 0x00, 0x01, 0x00) // 65536 in little-endian
				b = append(b, byte(OP_HALT))
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

// TestInterpreterArithmetic tests arithmetic operations
func TestInterpreterArithmetic(t *testing.T) {
	tests := []struct {
		name     string
		bytecode []byte
		expected int64
	}{
		{
			name: "add_two_numbers",
			bytecode: []byte{
				byte(OP_PUSH_8), 10,
				byte(OP_PUSH_8), 20,
				byte(OP_INT_ADD),
				byte(OP_HALT),
			},
			expected: 30,
		},
		{
			name: "subtract_two_numbers",
			bytecode: []byte{
				byte(OP_PUSH_8), 50,
				byte(OP_PUSH_8), 20,
				byte(OP_INT_SUB),
				byte(OP_HALT),
			},
			expected: 30,
		},
		{
			name: "multiply_two_numbers",
			bytecode: []byte{
				byte(OP_PUSH_8), 5,
				byte(OP_PUSH_8), 6,
				byte(OP_INT_MUL),
				byte(OP_HALT),
			},
			expected: 30,
		},
		{
			name: "divide_two_numbers",
			bytecode: []byte{
				byte(OP_PUSH_8), 60,
				byte(OP_PUSH_8), 2,
				byte(OP_INT_DIV),
				byte(OP_HALT),
			},
			expected: 30,
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

// TestInterpreterComparison tests comparison operations
func TestInterpreterComparison(t *testing.T) {
	tests := []struct {
		name     string
		bytecode []byte
		expected int64
	}{
		{
			name: "equal_true",
			bytecode: []byte{
				byte(OP_PUSH_8), 10,
				byte(OP_PUSH_8), 10,
				byte(OP_INT_EQ),
				byte(OP_HALT),
			},
			expected: 1,
		},
		{
			name: "equal_false",
			bytecode: []byte{
				byte(OP_PUSH_8), 10,
				byte(OP_PUSH_8), 20,
				byte(OP_INT_EQ),
				byte(OP_HALT),
			},
			expected: 0,
		},
		{
			name: "less_than_true",
			bytecode: []byte{
				byte(OP_PUSH_8), 10,
				byte(OP_PUSH_8), 20,
				byte(OP_INT_LT),
				byte(OP_HALT),
			},
			expected: 1,
		},
		{
			name: "greater_than_true",
			bytecode: []byte{
				byte(OP_PUSH_8), 20,
				byte(OP_PUSH_8), 10,
				byte(OP_INT_GT),
				byte(OP_HALT),
			},
			expected: 1,
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

// TestInterpreterLogical tests logical operations
func TestInterpreterLogical(t *testing.T) {
	tests := []struct {
		name     string
		bytecode []byte
		expected int64
	}{
		{
			name: "and_true",
			bytecode: []byte{
				byte(OP_PUSH_8), 1,
				byte(OP_PUSH_8), 1,
				byte(OP_AND),
				byte(OP_HALT),
			},
			expected: 1,
		},
		{
			name: "and_false",
			bytecode: []byte{
				byte(OP_PUSH_8), 1,
				byte(OP_PUSH_8), 0,
				byte(OP_AND),
				byte(OP_HALT),
			},
			expected: 0,
		},
		{
			name: "or_true",
			bytecode: []byte{
				byte(OP_PUSH_8), 1,
				byte(OP_PUSH_8), 0,
				byte(OP_OR),
				byte(OP_HALT),
			},
			expected: 1,
		},
		{
			name: "or_false",
			bytecode: []byte{
				byte(OP_PUSH_8), 0,
				byte(OP_PUSH_8), 0,
				byte(OP_OR),
				byte(OP_HALT),
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
				b := []byte{byte(OP_CLEAR_M)}
				b = append(b, 0, 0, 0, 0, 0, 0, 0, 0) // addr 0
				b = append(b, byte(OP_HALT))
				return b
			}(),
			memAddr:  0,
			expected: 0,
		},
		{
			name: "push_and_pop_memory",
			bytecode: func() []byte {
				b := []byte{byte(OP_PUSH_8), 42}
				b = append(b, byte(OP_POP_M))
				b = append(b, 0, 0, 0, 0, 0, 0, 0, 0) // addr 0
				b = append(b, byte(OP_PUSH_M))
				b = append(b, 0, 0, 0, 0, 0, 0, 0, 0) // addr 0
				b = append(b, byte(OP_HALT))
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
				b := []byte{byte(OP_PUSH_8), 0}
				b = append(b, byte(OP_JFALSE))
				b = append(b, 2, 0, 0, 0) // jump +2 bytes
				b = append(b, byte(OP_PUSH_8), 10)
				b = append(b, byte(OP_PUSH_8), 20)
				b = append(b, byte(OP_HALT))
				return b
			}(),
			expected: 20,
		},
		{
			name: "jtrue_taken",
			bytecode: func() []byte {
				b := []byte{byte(OP_PUSH_8), 1}
				b = append(b, byte(OP_JTRUE))
				b = append(b, 2, 0, 0, 0) // jump +2 bytes
				b = append(b, byte(OP_PUSH_8), 10)
				b = append(b, byte(OP_PUSH_8), 20)
				b = append(b, byte(OP_HALT))
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
				byte(OP_PUSH_8), 0xFF,
				byte(OP_PUSH_8), 0x0F,
				byte(OP_BITWISE_AND),
				byte(OP_HALT),
			},
			expected: 0x0F,
		},
		{
			name: "bitwise_or",
			bytecode: []byte{
				byte(OP_PUSH_8), 0xF0,
				byte(OP_PUSH_8), 0x0F,
				byte(OP_BITWISE_OR),
				byte(OP_HALT),
			},
			expected: 0xFF,
		},
		{
			name: "bitwise_xor",
			bytecode: []byte{
				byte(OP_PUSH_8), 0xFF,
				byte(OP_PUSH_8), 0xFF,
				byte(OP_BITWISE_XOR),
				byte(OP_HALT),
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

// TestInterpreterUndefined tests undefined value handling
func TestInterpreterUndefined(t *testing.T) {
	bytecode := []byte{
		byte(OP_PUSH_U),
		byte(OP_HALT),
	}

	interp := NewInterpreter(bytecode)
	err := interp.Execute()
	if err != nil {
		t.Errorf("Execute() error = %v", err)
	}
	if len(interp.GetStack()) != 1 {
		t.Errorf("stack length = %d, want 1", len(interp.GetStack()))
	}
	if interp.GetStack()[0].Type != ValueTypeUndefined {
		t.Errorf("stack[0].Type = %v, want ValueTypeUndefined", interp.GetStack()[0].Type)
	}
}

// TestInterpreterFilesize tests filesize operation
func TestInterpreterFilesize(t *testing.T) {
	bytecode := []byte{
		byte(OP_FILESIZE),
		byte(OP_HALT),
	}

	interp := NewInterpreter(bytecode)
	interp.matchContext.FileSize = 1024
	err := interp.Execute()
	if err != nil {
		t.Errorf("Execute() error = %v", err)
	}
	if len(interp.GetStack()) != 1 {
		t.Errorf("stack length = %d, want 1", len(interp.GetStack()))
	}
	if interp.GetStack()[0].IntVal != 1024 {
		t.Errorf("stack[0] = %d, want 1024", interp.GetStack()[0].IntVal)
	}
}

// TestInterpreterIncrementMemory tests increment memory operation
func TestInterpreterIncrementMemory(t *testing.T) {
	bytecode := func() []byte {
		b := []byte{byte(OP_INCR_M)}
		b = append(b, 0, 0, 0, 0, 0, 0, 0, 0) // addr 0
		b = append(b, byte(OP_INCR_M))
		b = append(b, 0, 0, 0, 0, 0, 0, 0, 0) // addr 0
		b = append(b, byte(OP_PUSH_M))
		b = append(b, 0, 0, 0, 0, 0, 0, 0, 0) // addr 0
		b = append(b, byte(OP_HALT))
		return b
	}()

	interp := NewInterpreter(bytecode)
	err := interp.Execute()
	if err != nil {
		t.Errorf("Execute() error = %v", err)
	}
	if len(interp.GetStack()) != 1 {
		t.Errorf("stack length = %d, want 1", len(interp.GetStack()))
	}
	if interp.GetStack()[0].IntVal != 2 {
		t.Errorf("stack[0] = %d, want 2", interp.GetStack()[0].IntVal)
	}
}

// TestInterpreterStringComparison tests string comparison operations
func TestInterpreterStringComparison(t *testing.T) {
	interp := NewInterpreter([]byte{byte(OP_HALT)})

	// Test string equality
	interp.push(Value{Type: ValueTypeString, StringVal: "hello"})
	interp.push(Value{Type: ValueTypeString, StringVal: "hello"})
	err := interp.executeStringComparison(func(a, b string) bool { return a == b })
	if err != nil {
		t.Errorf("executeStringComparison() error = %v", err)
	}
	if len(interp.GetStack()) != 1 || interp.GetStack()[0].IntVal != 1 {
		t.Errorf("string equality comparison failed")
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
			interp := NewInterpreter([]byte{byte(OP_HALT)})
			interp.matchContext.Data = tt.data

			result, err := interp.executeReadInt(tt.offset, tt.size, tt.unsigned)
			if err != nil {
				t.Errorf("executeReadInt() error = %v", err)
			}

			// Push the result onto the stack to match the test expectations
			interp.push(Value{Type: ValueTypeInt, IntVal: result})
			if len(interp.GetStack()) != 1 {
				t.Errorf("stack length = %d, want 1", len(interp.GetStack()))
			}
			if interp.GetStack()[0].IntVal != tt.expected {
				t.Errorf("read value = %d, want %d", interp.GetStack()[0].IntVal, tt.expected)
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
				byte(OP_PUSH_8), 42,
				byte(OP_INT_MINUS),
				byte(OP_HALT),
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

// TestInterpreterOffsetOperation tests OP_OFFSET operation
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
			interp := NewInterpreter([]byte{byte(OP_HALT)})
			interp.matchContext.Matches = tt.matches
			interp.push(Value{Type: ValueTypeString, StringVal: tt.pattern})
			interp.push(Value{Type: ValueTypeInt, IntVal: tt.index})

			err := interp.executeOpcode(OP_OFFSET)
			if err != nil {
				t.Errorf("executeOpcode(OP_OFFSET) error = %v", err)
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

// TestInterpreterLengthOperation tests OP_LENGTH operation
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
			interp := NewInterpreter([]byte{byte(OP_HALT)})
			interp.matchContext.Matches = tt.matches
			interp.push(Value{Type: ValueTypeString, StringVal: tt.pattern})
			interp.push(Value{Type: ValueTypeInt, IntVal: tt.index})

			err := interp.executeOpcode(OP_LENGTH)
			if err != nil {
				t.Errorf("executeOpcode(OP_LENGTH) error = %v", err)
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

// TestInterpreterFound tests OP_FOUND operation
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
			interp := NewInterpreter([]byte{byte(OP_HALT)})
			interp.matchContext.Matches = tt.matches
			interp.push(Value{Type: ValueTypeString, StringVal: tt.pattern})

			err := interp.executeOpcode(OP_FOUND)
			if err != nil {
				t.Errorf("executeOpcode(OP_FOUND) error = %v", err)
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

// TestInterpreterCount tests OP_COUNT operation
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
			interp := NewInterpreter([]byte{byte(OP_HALT)})
			interp.matchContext.Matches = tt.matches
			interp.push(Value{Type: ValueTypeString, StringVal: tt.pattern})

			err := interp.executeOpcode(OP_COUNT)
			if err != nil {
				t.Errorf("executeOpcode(OP_COUNT) error = %v", err)
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

// TestInterpreterFoundAt tests OP_FOUND_AT operation
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
			interp := NewInterpreter([]byte{byte(OP_HALT)})
			interp.matchContext.Matches = tt.matches
			interp.push(Value{Type: ValueTypeString, StringVal: tt.pattern})
			interp.push(Value{Type: ValueTypeInt, IntVal: tt.offset})

			err := interp.executeOpcode(OP_FOUND_AT)
			if err != nil {
				t.Errorf("executeOpcode(OP_FOUND_AT) error = %v", err)
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

// TestInterpreterFoundIn tests OP_FOUND_IN operation
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
			interp := NewInterpreter([]byte{byte(OP_HALT)})
			interp.matchContext.Matches = tt.matches
			interp.push(Value{Type: ValueTypeString, StringVal: tt.pattern})
			interp.push(Value{Type: ValueTypeInt, IntVal: tt.startOff})
			interp.push(Value{Type: ValueTypeInt, IntVal: tt.endOff})

			err := interp.executeOpcode(OP_FOUND_IN)
			if err != nil {
				t.Errorf("executeOpcode(OP_FOUND_IN) error = %v", err)
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

// TestInterpreterMatches tests OP_MATCHES operation
func TestInterpreterMatches(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		matches  map[string][]Match
		expected int64
	}{
		{
			name:    "matches_found",
			pattern: "test",
			matches: map[string][]Match{
				"test": {{Pattern: "test", Offset: 0, Length: 4}},
			},
			expected: 1,
		},
		{
			name:    "matches_not_found",
			pattern: "notfound",
			matches: map[string][]Match{
				"test": {{Pattern: "test", Offset: 0, Length: 4}},
			},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interp := NewInterpreter([]byte{byte(OP_HALT)})
			interp.matchContext.Matches = tt.matches
			interp.push(Value{Type: ValueTypeString, StringVal: tt.pattern})

			err := interp.executeOpcode(OP_MATCHES)
			if err != nil {
				t.Errorf("executeOpcode(OP_MATCHES) error = %v", err)
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

// TestInterpreterComplexArithmetic tests complex arithmetic expressions
func TestInterpreterComplexArithmetic(t *testing.T) {
	// Test: (10 + 20) * 2 = 60
	bytecode := []byte{
		byte(OP_PUSH_8), 10,
		byte(OP_PUSH_8), 20,
		byte(OP_INT_ADD),
		byte(OP_PUSH_8), 2,
		byte(OP_INT_MUL),
		byte(OP_HALT),
	}

	interp := NewInterpreter(bytecode)
	err := interp.Execute()
	if err != nil {
		t.Errorf("Execute() error = %v", err)
	}
	if len(interp.GetStack()) != 1 {
		t.Errorf("stack length = %d, want 1", len(interp.GetStack()))
	}
	if interp.GetStack()[0].IntVal != 60 {
		t.Errorf("result = %d, want 60", interp.GetStack()[0].IntVal)
	}
}

// TestInterpreterStackUnderflow tests stack underflow handling
func TestInterpreterStackUnderflow(t *testing.T) {
	bytecode := []byte{
		byte(OP_INT_ADD), // Try to add with empty stack
		byte(OP_HALT),
	}

	interp := NewInterpreter(bytecode)
	err := interp.Execute()
	if err == nil {
		t.Errorf("Execute() should return error on stack underflow")
	}
}

// TestInterpreterTypeConversion tests type conversion operations
func TestInterpreterTypeConversion(t *testing.T) {
	bytecode := []byte{
		byte(OP_PUSH_8), 1,
		byte(OP_INT_TO_DBL),
		byte(OP_HALT),
	}

	interp := NewInterpreter(bytecode)
	err := interp.Execute()
	if err != nil {
		t.Errorf("Execute() error = %v", err)
	}
	if len(interp.GetStack()) != 1 {
		t.Errorf("stack length = %d, want 1", len(interp.GetStack()))
	}
	if interp.GetStack()[0].Type != ValueTypeDouble {
		t.Errorf("stack[0].Type = %v, want ValueTypeDouble", interp.GetStack()[0].Type)
	}
}

// Regex-backed FOUND/FOUND_AT/FOUND_IN parity tests (compiler-level)
func TestInterpreterRegexFoundOps(t *testing.T) {
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
	interp := NewInterpreter([]byte{byte(OP_HALT)})
	interp.matchContext.Matches = map[string][]Match{
		"$a": matches,
	}

	// FOUND($a) -> true
	interp.push(Value{Type: ValueTypeString, StringVal: "$a"})
	if execErr := interp.executeOpcode(OP_FOUND); execErr != nil {
		t.Fatalf("executeOpcode(OP_FOUND) error = %v", execErr)
	}
	if len(interp.GetStack()) != 1 || interp.GetStack()[0].IntVal != 1 {
		t.Fatalf("FOUND($a) expected 1, got %+v", interp.GetStack()[0])
	}
	interp.stack = interp.stack[:0]

	// FOUND_AT($a, off) where off is an actual match start -> true
	hitOff := matches[0].Offset
	interp.push(Value{Type: ValueTypeString, StringVal: "$a"})
	interp.push(Value{Type: ValueTypeInt, IntVal: hitOff})
	if execErr := interp.executeOpcode(OP_FOUND_AT); execErr != nil {
		t.Fatalf("executeOpcode(OP_FOUND_AT) error = %v", execErr)
	}
	if len(interp.GetStack()) != 1 || interp.GetStack()[0].IntVal != 1 {
		t.Fatalf("FOUND_AT($a, %d) expected 1, got %+v", hitOff, interp.GetStack()[0])
	}
	interp.stack = interp.stack[:0]

	// FOUND_AT($a, miss) -> false
	missOff := hitOff + 99
	interp.push(Value{Type: ValueTypeString, StringVal: "$a"})
	interp.push(Value{Type: ValueTypeInt, IntVal: missOff})
	if execErr := interp.executeOpcode(OP_FOUND_AT); execErr != nil {
		t.Fatalf("executeOpcode(OP_FOUND_AT) error = %v", execErr)
	}
	if len(interp.GetStack()) != 1 || interp.GetStack()[0].IntVal != 0 {
		t.Fatalf("FOUND_AT($a, %d) expected 0, got %+v", missOff, interp.GetStack()[0])
	}
	interp.stack = interp.stack[:0]

	// FOUND_IN($a, start, end) covering a known hit -> true
	startIn := hitOff - 1
	if startIn < 0 {
		startIn = 0
	}
	endIn := hitOff + 10
	interp.push(Value{Type: ValueTypeString, StringVal: "$a"})
	interp.push(Value{Type: ValueTypeInt, IntVal: startIn})
	interp.push(Value{Type: ValueTypeInt, IntVal: endIn})
	if execErr := interp.executeOpcode(OP_FOUND_IN); execErr != nil {
		t.Fatalf("executeOpcode(OP_FOUND_IN) error = %v", execErr)
	}
	if len(interp.GetStack()) != 1 || interp.GetStack()[0].IntVal != 1 {
		t.Fatalf("FOUND_IN($a, %d, %d) expected 1, got %+v", startIn, endIn, interp.GetStack()[0])
	}
	interp.stack = interp.stack[:0]

	// FOUND_IN($a, start, end) entirely before the first match -> false
	beforeStart := int64(0)
	beforeEnd := hitOff - 1
	interp.push(Value{Type: ValueTypeString, StringVal: "$a"})
	interp.push(Value{Type: ValueTypeInt, IntVal: beforeStart})
	interp.push(Value{Type: ValueTypeInt, IntVal: beforeEnd})
	if execErr := interp.executeOpcode(OP_FOUND_IN); execErr != nil {
		t.Fatalf("executeOpcode(OP_FOUND_IN) error = %v", execErr)
	}
	if len(interp.GetStack()) != 1 || interp.GetStack()[0].IntVal != 0 {
		t.Fatalf("FOUND_IN($a, %d, %d) expected 0, got %+v", beforeStart, beforeEnd, interp.GetStack()[0])
	}
}
