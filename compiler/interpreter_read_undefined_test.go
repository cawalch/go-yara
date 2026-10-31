package compiler

import (
	"errors"
	"math"
	"testing"
)

func TestIntegerReadUndefined(t *testing.T) {
	opcodes := []Opcode{OpInt8, OpUint8, OpInt16, OpUint16, OpInt32, OpUint32, OpInt64, OpUint64,
		OpInt8be, OpUint8be, OpInt16be, OpUint16be, OpInt32be, OpUint32be, OpInt64be, OpUint64be}
	for _, opcode := range opcodes {
		t.Run(opcode.String(), func(t *testing.T) {
			for _, tc := range []struct {
				name   string
				offset Value
				ctx    *MatchContext
				want   ValueType
			}{
				{"negative", Value{Type: ValueTypeInt, IntVal: -1}, &MatchContext{Data: make([]byte, 8)}, ValueTypeUndefined},
				{"eof", Value{Type: ValueTypeInt, IntVal: 8}, &MatchContext{Data: make([]byte, 8)}, ValueTypeUndefined},
				{"overflow", Value{Type: ValueTypeInt, IntVal: math.MaxInt64}, &MatchContext{Data: make([]byte, 8)}, ValueTypeUndefined},
				{"undefined_offset", Value{Type: ValueTypeUndefined}, &MatchContext{Data: make([]byte, 8)}, ValueTypeUndefined},
				{"block_gap", Value{Type: ValueTypeInt, IntVal: 8}, &MatchContext{Blocks: []MemoryBlock{{Base: 16, Data: make([]byte, 8)}}}, ValueTypeUndefined},
				{"valid_zero", Value{Type: ValueTypeInt}, &MatchContext{Data: make([]byte, 8)}, ValueTypeInt},
				{"valid_block", Value{Type: ValueTypeInt, IntVal: 16}, &MatchContext{Blocks: []MemoryBlock{{Base: 16, Data: make([]byte, 8)}}}, ValueTypeInt},
			} {
				t.Run(tc.name, func(t *testing.T) {
					interp := NewInterpreter(nil)
					interp.matchContext = tc.ctx
					if err := interp.push(tc.offset); err != nil {
						t.Fatal(err)
					}
					if err := interp.executeOpcode(opcode); err != nil {
						t.Fatal(err)
					}
					stack := interp.GetStack()
					if len(stack) != 1 || stack[0].Type != tc.want || stack[0].IntVal != 0 {
						t.Fatalf("stack=%v, want one %v value", stack, tc.want)
					}
				})
			}
		})
	}
}

func TestIntegerReadPreservesExecutionErrors(t *testing.T) {
	for _, opcode := range []Opcode{OpUint16, OpUint16be} {
		t.Run(opcode.String(), func(t *testing.T) {
			for _, tc := range []struct {
				name  string
				stack []Value
				ctx   *MatchContext
			}{
				{"underflow", nil, &MatchContext{}},
				{"invalid_type", []Value{{Type: ValueTypeDouble, DoubleVal: 1}}, &MatchContext{}},
				{"missing_context", []Value{{Type: ValueTypeInt}}, nil},
				{"undefined_without_context", []Value{{Type: ValueTypeUndefined}}, nil},
			} {
				t.Run(tc.name, func(t *testing.T) {
					interp := NewInterpreter(nil)
					interp.stack = tc.stack
					interp.matchContext = tc.ctx
					var failure *InterpreterError
					if err := interp.executeOpcode(opcode); !errors.As(err, &failure) {
						t.Fatalf("got %v, want interpreter error", err)
					}
				})
			}
		})
	}
}

func TestIntegerReadAssertionMissingContext(t *testing.T) {
	for _, opcode := range []Opcode{OpAssertUint16Eq, OpAssertUint32Eq} {
		t.Run(opcode.String(), func(t *testing.T) {
			interp := NewInterpreter(nil)
			interp.matchContext = nil
			interp.currentCompiledRule = &CompiledRule{assertions: []conditionAssertion{{Opcode: opcode}}}
			if _, err := interp.evaluateAssertion(0); err == nil {
				t.Fatal("missing match context must remain an error")
			}
		})
	}
}
