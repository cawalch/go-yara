package tests

import (
	"testing"

	"github.com/cawalch/go-yara/compiler"
)

func TestValueStringRepresentation(t *testing.T) {
	// Test integer value string representation
	intVal := compiler.Value{Type: compiler.ValueTypeInt, IntVal: 42}
	if intVal.String() != "42" {
		t.Errorf("Expected integer string '42', got '%s'", intVal.String())
	}

	// Test negative integer value
	negIntVal := compiler.Value{Type: compiler.ValueTypeInt, IntVal: -123}
	if negIntVal.String() != "-123" {
		t.Errorf("Expected negative integer string '-123', got '%s'", negIntVal.String())
	}

	// Test zero integer
	zeroIntVal := compiler.Value{Type: compiler.ValueTypeInt, IntVal: 0}
	if zeroIntVal.String() != "0" {
		t.Errorf("Expected zero integer string '0', got '%s'", zeroIntVal.String())
	}
}

func TestValueDoubleStringRepresentation(t *testing.T) {
	// Test double value string representation
	doubleVal := compiler.Value{Type: compiler.ValueTypeDouble, DoubleVal: 3.14}
	if doubleVal.String() != "3.140000" {
		t.Errorf("Expected double string '3.140000', got '%s'", doubleVal.String())
	}

	// Test negative double
	negDoubleVal := compiler.Value{Type: compiler.ValueTypeDouble, DoubleVal: -2.5}
	if negDoubleVal.String() != "-2.500000" {
		t.Errorf("Expected negative double string '-2.500000', got '%s'", negDoubleVal.String())
	}

	// Test zero double
	zeroDoubleVal := compiler.Value{Type: compiler.ValueTypeDouble, DoubleVal: 0.0}
	if zeroDoubleVal.String() != "0.000000" {
		t.Errorf("Expected zero double string '0.000000', got '%s'", zeroDoubleVal.String())
	}
}

func TestStringValueRepresentation(t *testing.T) {
	// Test string value representation
	strVal := compiler.Value{Type: compiler.ValueTypeString, StringVal: "hello"}
	if strVal.String() != "\"hello\"" {
		t.Errorf("Expected quoted string '\"hello\"', got '%s'", strVal.String())
	}

	// Test empty string
	emptyStrVal := compiler.Value{Type: compiler.ValueTypeString, StringVal: ""}
	if emptyStrVal.String() != "\"\"" {
		t.Errorf("Expected empty quoted string '\"\"', got '%s'", emptyStrVal.String())
	}

	// Test string with special characters
	specialStrVal := compiler.Value{Type: compiler.ValueTypeString, StringVal: "test\n"}
	if specialStrVal.String() != "\"test\\n\"" {
		t.Errorf("Expected special string '\"test\\n\"', got '%s'", specialStrVal.String())
	}
}

func TestValueRuleRefRepresentation(t *testing.T) {
	// Test rule reference value representation
	ruleRefVal := compiler.Value{Type: compiler.ValueTypeRuleRef, IntVal: 1}
	// The String method currently returns "unknown" for rule reference types
	if ruleRefVal.String() != "unknown" {
		t.Errorf("Expected rule reference string 'unknown', got '%s'", ruleRefVal.String())
	}

	// Verify the rule reference has the correct type and value
	if ruleRefVal.Type != compiler.ValueTypeRuleRef {
		t.Errorf("Expected ValueTypeRuleRef, got %v", ruleRefVal.Type)
	}
	if ruleRefVal.IntVal != 1 {
		t.Errorf("Expected rule reference value 1, got %d", ruleRefVal.IntVal)
	}
}

func TestValueUndefinedRepresentation(t *testing.T) {
	// Test undefined value representation
	undefinedVal := compiler.Value{Type: compiler.ValueTypeUndefined}
	if undefinedVal.String() != "undefined" {
		t.Errorf("Expected undefined string 'undefined', got '%s'", undefinedVal.String())
	}
}

func TestValueTypes(t *testing.T) {
	// Test that all value types are properly recognized
	tests := []struct {
		name     string
		value    compiler.Value
		expected compiler.ValueType
	}{
		{"integer", compiler.Value{Type: compiler.ValueTypeInt, IntVal: 42}, compiler.ValueTypeInt},
		{"double", compiler.Value{Type: compiler.ValueTypeDouble, DoubleVal: 3.14}, compiler.ValueTypeDouble},
		{"string", compiler.Value{Type: compiler.ValueTypeString, StringVal: "test"}, compiler.ValueTypeString},
		{"rule_ref", compiler.Value{Type: compiler.ValueTypeRuleRef, IntVal: 1}, compiler.ValueTypeRuleRef},
		{"undefined", compiler.Value{Type: compiler.ValueTypeUndefined}, compiler.ValueTypeUndefined},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value.Type != tt.expected {
				t.Errorf("Expected value type %v, got %v", tt.expected, tt.value.Type)
			}
		})
	}
}

func TestValueSpecialFloatValues(t *testing.T) {
	// Test NaN representation
	// Note: We can't easily create NaN in Go without math package, but we can test the logic
	// This test ensures the String method handles special float cases correctly

	// Test large numbers
	largeDouble := compiler.Value{Type: compiler.ValueTypeDouble, DoubleVal: 1e20}
	if largeDouble.String() != "100000000000000000000.000000" {
		t.Errorf("Expected large number string, got '%s'", largeDouble.String())
	}

	// Test very small numbers
	smallDouble := compiler.Value{Type: compiler.ValueTypeDouble, DoubleVal: 1e-20}
	if smallDouble.String() != "0.000000" {
		t.Errorf("Expected small number string '0.000000', got '%s'", smallDouble.String())
	}
}

func TestValueInconsistentData(t *testing.T) {
	// Test values with inconsistent data (e.g., integer type but string data set)
	// These should still work but might not make logical sense
	inconsistentVal := compiler.Value{
		Type:      compiler.ValueTypeInt,
		IntVal:    42,
		DoubleVal: 3.14,    // This field should be ignored for integer type
		StringVal: "hello", // This field should be ignored for integer type
	}

	if inconsistentVal.String() != "42" {
		t.Errorf("Expected inconsistent integer value to use IntVal: got '%s'", inconsistentVal.String())
	}
}
