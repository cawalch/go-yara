package tests

import (
	"testing"

	"github.com/cawalch/go-yara/compiler"
)

func TestValueTypes(t *testing.T) {
	interp := compiler.NewInterpreter(nil)

	tests := []struct {
		name     string
		setup    func() compiler.Value
		expected compiler.ValueType
	}{
		{
			"integer",
			func() compiler.Value { return compiler.Value{Type: compiler.ValueTypeInt, IntVal: 42} },
			compiler.ValueTypeInt,
		},
		{
			"double",
			func() compiler.Value { return compiler.Value{Type: compiler.ValueTypeDouble, DoubleVal: 3.14} },
			compiler.ValueTypeDouble,
		},
		{
			"string",
			func() compiler.Value {
				_ = interp.PushString("test")
				return interp.GetStack()[0]
			},
			compiler.ValueTypeString,
		},
		{
			"undefined",
			func() compiler.Value { return compiler.Value{Type: compiler.ValueTypeUndefined} },
			compiler.ValueTypeUndefined,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// specific setup might need clean stack
			// simplified
			val := tt.setup()
			if val.Type != tt.expected {
				t.Errorf("Expected value type %v, got %v", tt.expected, val.Type)
			}
		})
	}
}

func TestStringValueContent(t *testing.T) {
	interp := compiler.NewInterpreter(nil)

	tests := []struct {
		input    string
		expected string
	}{
		{"hello", "hello"},
		{"", ""},
		{"test\n", "test\n"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			_ = interp.PushString(tt.input)
			val := interp.GetStack()[len(interp.GetStack())-1]

			if val.Type != compiler.ValueTypeString {
				t.Fatalf("Expected ValueTypeString, got %v", val.Type)
			}

			actual := interp.GetString(val)
			if actual != tt.expected {
				t.Errorf("Expected string '%s', got '%s'", tt.expected, actual)
			}
		})
	}
}

func TestNumericStringRepresentation(t *testing.T) {
	// Integers and Doubles should still String() correctly without context
	intVal := compiler.Value{Type: compiler.ValueTypeInt, IntVal: 42}
	if intVal.String() != "42" {
		t.Errorf("Expected '42', got '%s'", intVal.String())
	}

	dblVal := compiler.Value{Type: compiler.ValueTypeDouble, DoubleVal: 3.14}
	if dblVal.String() != "3.140000" {
		t.Errorf("Expected '3.140000', got '%s'", dblVal.String())
	}
}
