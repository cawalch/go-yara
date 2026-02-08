package compiler

import "testing"

func TestInterpreterStringOpsExtended(t *testing.T) {
	tests := []struct {
		name   string
		op     Opcode
		left   string
		right  string
		expect int64
	}{
		{"contains_true", OpContains, "hello world", "world", 1},
		{"contains_false", OpContains, "hello", "world", 0},
		{"startswith_true", OpStartswith, "hello world", "hello", 1},
		{"endswith_true", OpEndswith, "hello world", "world", 1},
		{"icontains_true", OpIcontains, "Hello World", "world", 1},
		{"iendswith_true", OpIendswith, "Hello World", "WORLD", 1},
		{"iequals_true", OpIequals, "Hello", "hello", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			emitter := NewEmitter()
			emitter.EmitPushString(tt.left, 1, 1)
			emitter.EmitPushString(tt.right, 1, 1)
			emitter.EmitOpcode(tt.op, 1, 1)
			emitter.EmitHalt(1, 1)
			bytecode, err := emitter.GetBytecode()
			if err != nil {
				t.Fatalf("bytecode: %v", err)
			}
			interp := NewInterpreter(bytecode)
			interp.SetStringLiterals(emitter.GetStringLiterals())
			if err := interp.Execute(); err != nil {
				t.Fatalf("execute: %v", err)
			}
			stack := interp.GetStack()
			if len(stack) != 1 {
				t.Fatalf("stack length %d, want 1", len(stack))
			}
			if stack[0].IntVal != tt.expect {
				t.Fatalf("result %d, want %d", stack[0].IntVal, tt.expect)
			}
		})
	}
}

func TestInterpreterMatchesOp(t *testing.T) {
	emitter := NewEmitter()
	emitter.EmitPushString("hello world", 1, 1)
	emitter.EmitPushString(`/world/`, 1, 1)
	emitter.EmitOpcode(OpMatches, 1, 1)
	emitter.EmitHalt(1, 1)
	bytecode, err := emitter.GetBytecode()
	if err != nil {
		t.Fatalf("bytecode: %v", err)
	}
	interp := NewInterpreter(bytecode)
	interp.SetStringLiterals(emitter.GetStringLiterals())
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
