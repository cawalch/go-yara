package compiler

import (
	"fmt"
	"math"
	"testing"
)

func TestInterpreterNotScalarOperands(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value Value
		want  Value
	}{
		{"zero", Value{Type: ValueTypeInt}, Value{Type: ValueTypeInt, IntVal: 1}},
		{"integer", Value{Type: ValueTypeInt, IntVal: -2}, Value{Type: ValueTypeInt}},
		{"float_zero", Value{Type: ValueTypeDouble}, Value{Type: ValueTypeInt, IntVal: 1}},
		{"negative_zero", Value{Type: ValueTypeDouble, DoubleVal: math.Copysign(0, -1)}, Value{Type: ValueTypeInt}},
		{"float", Value{Type: ValueTypeDouble, DoubleVal: 0.5}, Value{Type: ValueTypeInt}},
		{"undefined", Value{Type: ValueTypeUndefined}, Value{Type: ValueTypeUndefined}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			interp := NewInterpreter(nil)
			interp.stack = []Value{tc.value}
			if err := interp.executeOpcode(OpNot); err != nil {
				t.Fatal(err)
			}
			if len(interp.stack) != 1 || interp.stack[0] != tc.want {
				t.Fatalf("stack=%v, want %v", interp.stack, tc.want)
			}
		})
	}
	for _, str := range []string{"", "a", "\x00", "\x00a"} {
		interp := NewInterpreter(nil)
		if err := interp.PushString(str); err != nil {
			t.Fatal(err)
		}
		if err := interp.executeOpcode(OpNot); err != nil {
			t.Fatal(err)
		}
		if len(interp.stack) != 1 || interp.stack[0].Type != ValueTypeInt || interp.stack[0].IntVal != boolToInt(str == "") {
			t.Fatalf("not %q: stack=%v", str, interp.stack)
		}
	}
}

func TestModuleFloatNaNIsUndefined(t *testing.T) {
	for _, value := range []float64{math.NaN(), 0, math.Copysign(0, -1), 0.5, math.Inf(1)} {
		interp := NewInterpreter(nil)
		if err := interp.pushModuleValue(FloatValue(value)); err != nil {
			t.Fatal(err)
		}
		if err := interp.executeOpcode(OpDefined); err != nil {
			t.Fatal(err)
		}
		if interp.stack[0].Type != ValueTypeInt || interp.stack[0].IntVal != boolToInt(!math.IsNaN(value)) {
			t.Fatalf("defined module float %v: stack=%v", value, interp.stack)
		}
	}
}

func TestNotScalarConditionVariants(t *testing.T) {
	for _, tc := range []struct {
		condition string
		want      bool
	}{
		{`not 0.0`, true}, {`not -0.0`, false}, {`not not -0.0`, true},
		{`not (false or -0.0)`, false}, {`not (true and -0.0)`, false},
		{`not ""`, true}, {`not "\x00"`, false}, {`not not "a"`, true},
		{`not (uint8(0) * -0.5)`, false}, {`not defined (not (uint8(filesize) * 0.5))`, true},
		{`not (filesize < 0)`, true},
	} {
		t.Run(tc.condition, func(t *testing.T) {
			for _, fused := range []bool{false, true} {
				p := compileAssertionVariant(t, fmt.Sprintf(`rule r { strings: $a="a" condition: #a >= 0 and (%s) }`, tc.condition), fused)
				for _, input := range [][]byte{nil, {0}, {1}, []byte("a"), nil} {
					result, err := p.Scan(input)
					if err != nil {
						t.Fatal(err)
					}
					if (len(result.MatchedRules) != 0) != tc.want {
						t.Fatalf("fused=%v input=%q: matches=%v, want %v", fused, input, result.MatchedRules, tc.want)
					}
				}
			}
		})
	}
}
