package compiler

import (
	"errors"
	"fmt"
	"testing"
)

func TestMatchQueryOperandTypes(t *testing.T) {
	for _, opcode := range []Opcode{OpFoundAt, OpFoundIn, OpOfFoundAt, OpOfFoundIn} {
		t.Run(opcode.String(), func(t *testing.T) {
			inRange := opcode == OpFoundIn || opcode == OpOfFoundIn
			for _, left := range []ValueType{ValueTypeInt, ValueTypeUndefined, ValueTypeDouble, ValueTypeString} {
				for _, right := range []ValueType{ValueTypeInt, ValueTypeUndefined, ValueTypeDouble, ValueTypeString} {
					if !inRange && right != ValueTypeInt {
						continue
					}
					t.Run(fmt.Sprintf("%v/%v", left, right), func(t *testing.T) {
						interp := NewInterpreter(nil)
						interp.matchContext.Matches = map[string][]Match{"$a": {{Offset: 0, Length: 1}}}
						if opcode == OpFoundAt || opcode == OpFoundIn {
							if err := interp.PushString("$a"); err != nil {
								t.Fatal(err)
							}
						} else {
							interp.stringSets = [][]string{{"$a"}}
							interp.stack = []Value{{Type: ValueTypeInt, IntVal: 1}, {Type: ValueTypeInt}}
						}
						interp.stack = append(interp.stack, Value{Type: left})
						if inRange {
							interp.stack = append(interp.stack, Value{Type: right})
						}
						err := interp.executeOpcode(opcode)
						invalid := (left != ValueTypeInt && left != ValueTypeUndefined) ||
							(right != ValueTypeInt && right != ValueTypeUndefined)
						if invalid {
							var failure *InterpreterError
							if !errors.As(err, &failure) || failure.Type != ErrorTypeMismatch {
								t.Fatalf("got %v, want type mismatch", err)
							}
							return
						}
						if err != nil {
							t.Fatal(err)
						}
						want := Value{Type: ValueTypeInt, IntVal: 1}
						if left == ValueTypeUndefined || right == ValueTypeUndefined {
							want = Value{Type: ValueTypeUndefined}
						}
						if len(interp.stack) != 1 || interp.stack[0] != want {
							t.Fatalf("stack=%v, want [%v]", interp.stack, want)
						}
					})
				}
			}
			var failure *InterpreterError
			if err := NewInterpreter(nil).executeOpcode(opcode); !errors.As(err, &failure) || failure.Type != ErrorStackUnderflow {
				t.Fatalf("got %v, want stack underflow", err)
			}
		})
	}
}

func TestUndefinedMatchQueryAssertions(t *testing.T) {
	for _, query := range []string{
		`#a >= 2 and $a at @a[2]`,
		`uint16(0) == 0 and not ($a in (0..@a[2]))`,
		`not defined ($a at @a[2]) or $a at 0`,
		`not (any of them in (@a[2]..filesize))`,
	} {
		t.Run(query, func(t *testing.T) {
			source := `rule query { strings: $a = "a" condition: ` + query + ` } rule healthy { condition: true }`
			pair := [2]*CompiledProgram{compileAssertionVariant(t, source, false), compileAssertionVariant(t, source, true)}
			for _, data := range [][]byte{nil, []byte("b"), []byte("a"), []byte("aa"), {0, 0, 'a'}} {
				for _, program := range pair {
					if _, err := program.Scan(data); err != nil {
						t.Fatal(err)
					}
				}
				assertEquivalentAssertionScan(t, pair, data)
			}
		})
	}
}
