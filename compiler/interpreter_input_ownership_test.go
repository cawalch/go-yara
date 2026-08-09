package compiler

import "testing"

func TestNewInterpreterCopiesBytecode(t *testing.T) {
	emitter := NewEmitter()
	emitter.EmitPush(7, 1, 1)
	emitter.EmitHalt(1, 1)
	bytecode, err := emitter.GetBytecode()
	if err != nil {
		t.Fatalf("GetBytecode() error = %v", err)
	}

	interpreter := NewInterpreter(bytecode)
	defer interpreter.Release()
	bytecode[0] = byte(OpHalt)

	if err := interpreter.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	stack := interpreter.GetStack()
	if len(stack) != 1 || stack[0].IntVal != 7 {
		t.Fatalf("caller mutation changed bytecode execution: %+v", stack)
	}
}

func TestInterpreterCopiesStringLiteralInput(t *testing.T) {
	emitter := NewEmitter()
	emitter.EmitPushString("owned", 1, 1)
	emitter.EmitHalt(1, 1)
	bytecode, err := emitter.GetBytecode()
	if err != nil {
		t.Fatalf("GetBytecode() error = %v", err)
	}
	literals := emitter.GetStringLiterals()

	interpreter := NewInterpreter(bytecode)
	defer interpreter.Release()
	interpreter.SetStringLiterals(literals)
	literals[0] = "mutated"

	if err := interpreter.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	stack := interpreter.GetStack()
	if len(stack) != 1 || interpreter.GetString(stack[0]) != "owned" {
		t.Fatalf("caller mutation changed string literal execution: %+v", stack)
	}
}

func TestInterpreterCopiesNestedStringSetInputs(t *testing.T) {
	emitter := NewEmitter()
	emitter.EmitPush(1, 1, 1)
	emitter.EmitPush(0, 1, 1)
	emitter.EmitOpcode(OpOf, 1, 1)
	emitter.EmitHalt(1, 1)
	bytecode, err := emitter.GetBytecode()
	if err != nil {
		t.Fatalf("GetBytecode() error = %v", err)
	}

	interpreter := NewInterpreter(bytecode)
	defer interpreter.Release()
	stringSets := [][]string{{"$owned"}}
	textStringSets := [][]string{{"owned"}}
	interpreter.SetStringSets(stringSets)
	interpreter.SetTextStringSets(textStringSets)
	interpreter.SetMatchContext(&MatchContext{Matches: map[string][]Match{
		"$owned": {{Pattern: "$owned", Offset: 0, Length: 5}},
	}})
	stringSets[0][0] = "$mutated"
	textStringSets[0][0] = "mutated"

	if err := interpreter.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	stack := interpreter.GetStack()
	if len(stack) != 1 || stack[0].IntVal != 1 {
		t.Fatalf("caller mutation changed string-set execution: %+v", stack)
	}
	if got := interpreter.textStringSets[0][0]; got != "owned" {
		t.Fatalf("SetTextStringSets retained caller data: got %q", got)
	}
}

func TestInterpreterCopiesCompiledRuleSlice(t *testing.T) {
	emitter := NewEmitter()
	emitter.EmitOpcodeWithOperand(
		OpPushRule,
		Operand{Type: OperandImmediate8, Value: 0},
		1,
		1,
	)
	emitter.EmitHalt(1, 1)
	bytecode, err := emitter.GetBytecode()
	if err != nil {
		t.Fatalf("GetBytecode() error = %v", err)
	}

	interpreter := NewInterpreter(bytecode)
	defer interpreter.Release()
	rules := []*CompiledRule{{Name: "owned"}}
	interpreter.SetCompiledRules(rules)
	interpreter.SetRuleResults(map[string]bool{"owned": true})
	interpreter.PreserveRuleResults = true
	rules[0] = &CompiledRule{Name: "mutated"}

	if err := interpreter.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	stack := interpreter.GetStack()
	if len(stack) != 1 || stack[0].IntVal != 1 {
		t.Fatalf("caller mutation changed rule reference execution: %+v", stack)
	}
}
