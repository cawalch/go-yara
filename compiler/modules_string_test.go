package compiler

import "testing"

func TestStringToIntPortablePrefixes(t *testing.T) {
	convert := stringModule().Functions["to_int"].Evaluate
	cases := []struct {
		name string
		args []ModuleValue
		want ModuleValue
	}{
		{"binary_auto", []ModuleValue{StringValue("0b10")}, ModuleValue{}},
		{"binary_zero_base", []ModuleValue{StringValue("0b10"), IntegerValue(0)}, ModuleValue{}},
		{"binary_explicit_prefix", []ModuleValue{StringValue("0b10"), IntegerValue(2)}, ModuleValue{}},
		{"binary_upper_signed", []ModuleValue{StringValue(" -0B10")}, ModuleValue{}},
		{"binary_explicit_digits", []ModuleValue{StringValue("10"), IntegerValue(2)}, IntegerValue(2)},
		{"binary_explicit_negative", []ModuleValue{StringValue("-10"), IntegerValue(2)}, IntegerValue(-2)},
		{"decimal_auto", []ModuleValue{StringValue("10")}, IntegerValue(10)},
		{"octal_auto", []ModuleValue{StringValue("010")}, IntegerValue(8)},
		{"hex_auto", []ModuleValue{StringValue("0x10")}, IntegerValue(16)},
		{"hex_digits_containing_b", []ModuleValue{StringValue("0b10"), IntegerValue(16)}, IntegerValue(2832)},
		{"go_octal_prefix", []ModuleValue{StringValue("0o10")}, ModuleValue{}},
		{"underscore", []ModuleValue{StringValue("1_0")}, ModuleValue{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := convert(ModuleContext{}, tc.args)
			if err != nil || got != tc.want {
				t.Fatalf("got %+v, %v; want %+v", got, err, tc.want)
			}
		})
	}
}
