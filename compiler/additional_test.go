// Package compiler provides additional tests for comprehensive coverage.
package compiler

import (
	"testing"
)

// TestComparison tests the Comparison function for comprehensive coverage
func TestComparison(t *testing.T) {
	// Test with undefined values
	t.Run("undefined_values", func(t *testing.T) {
		result := Comparison(func(a, b uint64) bool { return a == b }, YRUndefined, 10)
		if result != 0 {
			t.Errorf("Comparison with undefined first operand should return 0, got %d", result)
		}

		result = Comparison(func(a, b uint64) bool { return a == b }, 10, YRUndefined)
		if result != 0 {
			t.Errorf("Comparison with undefined second operand should return 0, got %d", result)
		}

		result = Comparison(func(a, b uint64) bool { return a == b }, YRUndefined, YRUndefined)
		if result != 0 {
			t.Errorf("Comparison with both undefined operands should return 0, got %d", result)
		}
	})

	// Test with defined values
	t.Run("defined_values", func(t *testing.T) {
		// Test equality operator
		result := Comparison(func(a, b uint64) bool { return a == b }, 10, 10)
		if result != 1 {
			t.Errorf("Comparison(10, 10) with equality should return 1, got %d", result)
		}

		result = Comparison(func(a, b uint64) bool { return a == b }, 10, 20)
		if result != 0 {
			t.Errorf("Comparison(10, 20) with equality should return 0, got %d", result)
		}

		// Test less than operator
		result = Comparison(func(a, b uint64) bool { return a < b }, 10, 20)
		if result != 1 {
			t.Errorf("Comparison(10, 20) with less than should return 1, got %d", result)
		}

		result = Comparison(func(a, b uint64) bool { return a < b }, 20, 10)
		if result != 0 {
			t.Errorf("Comparison(20, 10) with less than should return 0, got %d", result)
		}

		// Test greater than operator
		result = Comparison(func(a, b uint64) bool { return a > b }, 20, 10)
		if result != 1 {
			t.Errorf("Comparison(20, 10) with greater than should return 1, got %d", result)
		}

		result = Comparison(func(a, b uint64) bool { return a > b }, 10, 20)
		if result != 0 {
			t.Errorf("Comparison(10, 20) with greater than should return 0, got %d", result)
		}
	})
}

// TestOperation tests the Operation function for comprehensive coverage
func TestOperation(t *testing.T) {
	// Test with undefined values
	t.Run("undefined_values", func(t *testing.T) {
		result := Operation(func(a, b uint64) uint64 { return a + b }, YRUndefined, 10)
		if result != YRUndefined {
			t.Errorf("Operation with undefined first operand should return YRUndefined, got %d", result)
		}

		result = Operation(func(a, b uint64) uint64 { return a + b }, 10, YRUndefined)
		if result != YRUndefined {
			t.Errorf("Operation with undefined second operand should return YRUndefined, got %d", result)
		}

		result = Operation(func(a, b uint64) uint64 { return a + b }, YRUndefined, YRUndefined)
		if result != YRUndefined {
			t.Errorf("Operation with both undefined operands should return YRUndefined, got %d", result)
		}
	})

	// Test with defined values
	t.Run("defined_values", func(t *testing.T) {
		// Test addition
		result := Operation(func(a, b uint64) uint64 { return a + b }, 10, 20)
		if result != 30 {
			t.Errorf("Operation(10, 20) with addition should return 30, got %d", result)
		}

		// Test multiplication
		result = Operation(func(a, b uint64) uint64 { return a * b }, 5, 6)
		if result != 30 {
			t.Errorf("Operation(5, 6) with multiplication should return 30, got %d", result)
		}

		// Test subtraction
		result = Operation(func(a, b uint64) uint64 { return a - b }, 20, 10)
		if result != 10 {
			t.Errorf("Operation(20, 10) with subtraction should return 10, got %d", result)
		}
	})
}

// TestIsUndefined tests the IsUndefined function
func TestIsUndefined(t *testing.T) {
	tests := []struct {
		name     string
		value    uint64
		expected bool
	}{
		{
			name:     "undefined_value",
			value:    YRUndefined,
			expected: true,
		},
		{
			name:     "zero_value",
			value:    0,
			expected: false,
		},
		{
			name:     "normal_value",
			value:    42,
			expected: false,
		},
		{
			name:     "max_value",
			value:    ^uint64(0),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsUndefined(tt.value)
			if result != tt.expected {
				t.Errorf("IsUndefined(%d) = %v, want %v", tt.value, result, tt.expected)
			}
		})
	}
}
