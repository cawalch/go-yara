package compiler

import "testing"

func TestInterpreterOfOperation(t *testing.T) {
	emitter := NewEmitter()
	// count = 2
	emitter.EmitPush(2, 1, 1)
	// string set index 0
	emitter.EmitPush(0, 1, 1)
	emitter.EmitOpcode(OpOf, 1, 1)
	emitter.EmitHalt(1, 1)
	bytecode, err := emitter.GetBytecode()
	if err != nil {
		t.Fatalf("bytecode: %v", err)
	}

	interp := NewInterpreter(bytecode)
	interp.SetStringSets([][]string{{"$a", "$b", "$c"}})
	interp.SetMatchContext(&MatchContext{
		Matches: map[string][]Match{
			"$a": {{Pattern: "$a", Offset: 0, Length: 1}},
			"$b": {{Pattern: "$b", Offset: 1, Length: 1}},
		},
	})
	if err := interp.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	stack := interp.GetStack()
	if len(stack) != 1 {
		t.Fatalf("stack length %d, want 1", len(stack))
	}
	if stack[0].IntVal != 1 {
		t.Fatalf("result %d, want 1", stack[0].IntVal)
	}
}
