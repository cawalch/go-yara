package compiler

import (
	"testing"
)

// buildDispatchBytecode creates a bytecode program that exercises the dispatch
// path by executing a sequence of push8+pop pairs.
// This isolates the dispatch overhead from pattern matching.
func buildDispatchBytecode(iterations int) []byte {
	// Each iteration: OpPush8 + operand + OpPop = 3 bytes
	// Final: OpHalt = 1 byte
	code := make([]byte, 0, iterations*3+1)
	for i := 0; i < iterations; i++ {
		code = append(code, byte(OpPush8), 42, byte(OpPop))
	}
	code = append(code, byte(OpHalt))
	return code
}

// BenchmarkDispatchPushPop measures the dispatch overhead per instruction pair
// (push8 + pop) in a single run.
func BenchmarkDispatchPushPop(b *testing.B) {
	bytecode := buildDispatchBytecode(b.N)
	interp := NewInterpreter(bytecode)

	b.ResetTimer()
	if err := interp.Execute(); err != nil {
		b.Fatal(err)
	}
}

// BenchmarkDispatchPushPopRepeated runs the dispatch loop N times with a small
// bytecode program to measure per-instruction overhead with fresh interpreters.
func BenchmarkDispatchPushPopRepeated(b *testing.B) {
	const iterationsPerRun = 500
	bytecode := buildDispatchBytecode(iterationsPerRun)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		interp := NewInterpreter(bytecode)
		if err := interp.Execute(); err != nil {
			b.Fatal(err)
		}
	}
}

// buildMixedDispatchBytecode creates a bytecode with a variety of opcodes
// to test branch prediction with a realistic mix.
func buildMixedDispatchBytecode(iterations int) []byte {
	// Sequence: Push8(2), Push8(2), IntAdd(0), Pop(0) = 5 bytes
	code := make([]byte, 0, iterations*5+1)
	for i := 0; i < iterations; i++ {
		code = append(code,
			byte(OpPush8), 1,
			byte(OpPush8), 2,
			byte(OpIntAdd),
			byte(OpPop),
		)
	}
	code = append(code, byte(OpHalt))
	return code
}

func BenchmarkDispatchMixedOpcodes(b *testing.B) {
	bytecode := buildMixedDispatchBytecode(b.N)
	interp := NewInterpreter(bytecode)

	b.ResetTimer()
	if err := interp.Execute(); err != nil {
		b.Fatal(err)
	}
}
