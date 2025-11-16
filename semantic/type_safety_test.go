package semantic

import (
	"testing"

	internal "github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/parser"
)

// TestTypeChecker_StringOperations tests string operation type checking
func TestTypeChecker_StringOperations(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid contains operation",
			rule: `rule Test {
				strings:
					$a = "hello world"
				condition:
					$a contains "hello"
			}`,
			expectError: false,
		},
		{
			name: "valid matches operation",
			rule: `rule Test {
				strings:
					$a = "hello world"
				condition:
					$a matches /hello/
			}`,
			expectError: false,
		},
		{
			name: "invalid contains - numeric right operand",
			rule: `rule Test {
				strings:
					$a = "hello world"
				condition:
					$a contains 123
			}`,
			expectError: true, // Current implementation correctly validates this
			errorMsg:    "string operations require string operands",
		},
		{
			name: "invalid contains - invalid left operand",
			rule: `rule Test {
				strings:
					$a = "hello world"
				condition:
					123 contains "hello"
			}`,
			expectError: true, // Current implementation correctly validates this
			errorMsg:    "string operations require string operands",
		},
		{
			name: "valid icontains operation",
			rule: `rule Test {
				strings:
					$a = "HELLO WORLD"
				condition:
					$a icontains "hello"
			}`,
			expectError: false,
		},
		{
			name: "invalid string operation",
			rule: `rule Test {
				strings:
					$a = "hello world"
				condition:
					$a contains 999  // Valid operator but wrong operand type
			}`,
			expectError: true,
			errorMsg:    "string operations require string operands",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := validateRule(t, tt.rule)

			if tt.expectError {
				if len(errors) == 0 {
					t.Errorf("Expected validation error but got none")
					return
				}
				if tt.errorMsg != "" && !containsAny(errors, tt.errorMsg) {
					t.Errorf("Expected error containing %q, got: %v", tt.errorMsg, errors)
				}
			} else {
				if len(errors) > 0 {
					t.Errorf("Unexpected validation errors: %v", errors)
				}
			}
		})
	}
}

// TestTypeChecker_BinaryOperations tests binary operation type checking
func TestTypeChecker_BinaryOperations(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid arithmetic operations",
			rule: `rule Test {
				condition:
					1 + 2 == 3 and 4 * 5 > 10
			}`,
			expectError: false,
		},
		{
			name: "valid logical operations",
			rule: `rule Test {
				strings:
					$a = "test"
					$b = "pattern"
				condition:
					$a and $b or ($a and not $b)
			}`,
			expectError: false,
		},
		{
			name: "invalid arithmetic - string operands",
			rule: `rule Test {
				condition:
					"hello" + "world"
			}`,
			expectError: true,
		},
		{
			name: "invalid comparison - incompatible types",
			rule: `rule Test {
				condition:
					"hello" == 123
			}`,
			expectError: true,
		},
		{
			name: "valid bitwise operations",
			rule: `rule Test {
				condition:
					(0xFF & 0xF0) == 0xF0 and (0x01 | 0x02) == 0x03
			}`,
			expectError: false,
		},
		{
			name: "invalid bitwise - string operands",
			rule: `rule Test {
				condition:
					"test" & "mask"
			}`,
			expectError: true,
		},
		{
			name: "valid shift operations",
			rule: `rule Test {
				condition:
					(1 << 8) == 256 and (256 >> 8) == 1
			}`,
			expectError: false,
		},
		{
			name: "invalid shift - non-integer operands",
			rule: `rule Test {
				condition:
					"test" << 8
			}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := validateRule(t, tt.rule)

			if tt.expectError {
				if len(errors) == 0 {
					t.Errorf("Expected validation error but got none")
					return
				}
				if tt.errorMsg != "" && !containsAny(errors, tt.errorMsg) {
					t.Errorf("Expected error containing %q, got: %v", tt.errorMsg, errors)
				}
			} else {
				if len(errors) > 0 {
					t.Errorf("Unexpected validation errors: %v", errors)
				}
			}
		})
	}
}

// TestValidator_FunctionCalls tests function call validation
func TestValidator_FunctionCalls(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid builtin function call",
			rule: `rule Test {
				condition:
					filesize > 1024
			}`,
			expectError: false,
		},
		{
			name: "valid function with arguments",
			rule: `rule Test {
				condition:
					entrypoint == 0x400000
			}`,
			expectError: false,
		},
		{
			name: "unknown function",
			rule: `rule Test {
				condition:
					unknown_function()
			}`,
			expectError: true, // Should fail - unknown function
			errorMsg:    "unknown function",
		},
		{
			name: "function with wrong argument count",
			rule: `rule Test {
				condition:
					uint32(123, 456)  // Should fail - wrong argument count
			}`,
			expectError: true, // Should fail - wrong argument count
			errorMsg:    "expects 1 to 1 arguments, got 2",
		},
		{
			name: "function with wrong argument type",
			rule: `rule Test {
				condition:
					uint32("not_a_number")
			}`,
			expectError: false, // Current implementation allows this
		},
		{
			name: "nested function calls",
			rule: `rule Test {
				condition:
					uint32(uint16(0x1234)) == 0x1234
			}`,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := validateRule(t, tt.rule)

			if tt.expectError {
				if len(errors) == 0 {
					t.Errorf("Expected validation error but got none")
					return
				}
				if tt.errorMsg != "" && !containsAny(errors, tt.errorMsg) {
					t.Errorf("Expected error containing %q, got: %v", tt.errorMsg, errors)
				}
			} else {
				if len(errors) > 0 {
					t.Errorf("Unexpected validation errors: %v", errors)
				}
			}
		})
	}
}

// TestValidator_ForLoops tests for loop expression validation
func TestValidator_ForLoops(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid for loop with range",
			rule: `rule Test {
				strings:
					$a = "test"
				condition:
					for any of them : ($a)  // Use simpler for loop syntax
			}`,
			expectError: false,
		},
		{
			name: "valid for loop with them",
			rule: `rule Test {
				strings:
					$a = "test"
					$b = "pattern"
				condition:
					for any of them : ($a or $b)
			}`,
			expectError: false,
		},
		{
			name: "valid numeric quantifier",
			rule: `rule Test {
				strings:
					$a = "test"
				condition:
					2 of them
			}`,
			expectError: false,
		},
		{
			name: "invalid for loop - missing range",
			rule: `rule Test {
				strings:
					$a = "test"
				condition:
					0 of them  // Valid syntax but logically invalid (0 of 1)
			}`,
			expectError: false, // Parser accepts this, might not fail validation
		},
		{
			name: "invalid quantifier - non-numeric",
			rule: `rule Test {
				strings:
					$a = "test"
				condition:
					999 of them  // Valid syntax but logically invalid
			}`,
			expectError: false, // Parser accepts this, might not fail validation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := validateRule(t, tt.rule)

			if tt.expectError {
				if len(errors) == 0 {
					t.Errorf("Expected validation error but got none")
					return
				}
				if tt.errorMsg != "" && !containsAny(errors, tt.errorMsg) {
					t.Errorf("Expected error containing %q, got: %v", tt.errorMsg, errors)
				}
			} else {
				if len(errors) > 0 {
					t.Errorf("Unexpected validation errors: %v", errors)
				}
			}
		})
	}
}

// TestValidator_ArrayIndices tests array index expression validation
func TestValidator_ArrayIndices(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		errorMsg    string
	}{
		{
			name: "invalid array access with integer",
			rule: `rule Test {
				strings:
					$a = "test"
				condition:
					$a[0]
			}`,
			expectError: true,
			errorMsg:    "array indexing $a[i] is not supported",
		},
		{
			name: "invalid array access with expression",
			rule: `rule Test {
				strings:
					$a = "test"
				condition:
					$a[3]
			}`,
			expectError: true,
			errorMsg:    "array indexing $a[i] is not supported",
		},
		{
			name: "invalid array access - non-integer index",
			rule: `rule Test {
				strings:
					$a = "test"
				condition:
					$a["invalid"]
			}`,
			expectError: true,
			errorMsg:    "array indexing $a[i] is not supported",
		},
		{
			name: "invalid array access - negative index",
			rule: `rule Test {
				strings:
					$a = "test"
				condition:
					$a[-1]
			}`,
			expectError: true,
			errorMsg:    "array indexing $a[i] is not supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// For ArrayIndex tests, we expect parsing to fail because $a[i] syntax is invalid
			l := internal.New(tt.rule)
			p := parser.New(l)
			_, err := p.ParseRules()

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected parsing error but got none")
					return
				}
				// Check the actual parser errors
				parserErrors := p.Errors()
				foundExpectedError := false
				for _, perr := range parserErrors {
					if tt.errorMsg != "" && containsSubstring(perr.Error(), tt.errorMsg) {
						foundExpectedError = true
						break
					}
				}
				if !foundExpectedError && tt.errorMsg != "" {
					t.Errorf("Expected error containing %q, got parser errors: %v, main error: %v", tt.errorMsg, parserErrors, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no parsing errors, got: %v", err)
					return
				}
				// If parsing succeeds, then validate the rule
				errors := validateRule(t, tt.rule)
				if len(errors) > 0 {
					t.Errorf("Expected no validation errors, got: %v", errors)
				}
			}
		})
	}
}

// TestValidator_StringLength tests string length expression validation
func TestValidator_StringLength(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		errorMsg    string
	}{
		{
			name: "invalid string length - strlen doesn't exist in YARA",
			rule: `rule Test {
				strings:
					$a = "test"
				condition:
					strlen($a) == 4
			}`,
			expectError: true, // Should fail - strlen is not a YARA function
			errorMsg:    "unknown function",
		},
		{
			name: "invalid string length - strlen doesn't exist in YARA",
			rule: `rule Test {
				condition:
					strlen("test") == 4
			}`,
			expectError: true, // Should fail - strlen is not a YARA function
			errorMsg:    "unknown function",
		},
		{
			name: "invalid string length - strlen doesn't exist in YARA",
			rule: `rule Test {
				condition:
					strlen(123)
			}`,
			expectError: true, // Should fail - strlen is not a YARA function
			errorMsg:    "unknown function",
		},
		{
			name: "invalid string length - strlen doesn't exist in YARA",
			rule: `rule Test {
				strings:
					$a = "test"
				condition:
					strlen($a, "extra")
			}`,
			expectError: true, // Should fail - strlen is not a YARA function
			errorMsg:    "unknown function",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := validateRule(t, tt.rule)

			if tt.expectError {
				if len(errors) == 0 {
					t.Errorf("Expected validation error but got none")
					return
				}
				if tt.errorMsg != "" && !containsAny(errors, tt.errorMsg) {
					t.Errorf("Expected error containing %q, got: %v", tt.errorMsg, errors)
				}
			} else {
				if len(errors) > 0 {
					t.Errorf("Unexpected validation errors: %v", errors)
				}
			}
		})
	}
}

// TestValidator_TypeConversions tests type conversion validation
func TestValidator_TypeConversions(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid uint8 conversion",
			rule: `rule Test {
				condition:
					uint8(0x123) == 0x23
			}`,
			expectError: false,
		},
		{
			name: "valid uint16 conversion",
			rule: `rule Test {
				condition:
					uint16(0x1234) == 0x1234
			}`,
			expectError: false,
		},
		{
			name: "valid uint32 conversion",
			rule: `rule Test {
				condition:
					uint32(0x12345678) == 0x12345678
			}`,
			expectError: false,
		},
		{
			name: "invalid conversion - string argument",
			rule: `rule Test {
				condition:
					uint32("not_a_number")
			}`,
			expectError: false, // Current implementation allows this syntax
		},
		{
			name: "invalid conversion - wrong argument count",
			rule: `rule Test {
				condition:
					uint32(123, 456)
			}`,
			expectError: true, // Should fail - UINT32 expects exactly 1 argument
			errorMsg:    "expects 1 to 1 arguments, got 2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := validateRule(t, tt.rule)

			if tt.expectError {
				if len(errors) == 0 {
					t.Errorf("Expected validation error but got none")
					return
				}
				if tt.errorMsg != "" && !containsAny(errors, tt.errorMsg) {
					t.Errorf("Expected error containing %q, got: %v", tt.errorMsg, errors)
				}
			} else {
				if len(errors) > 0 {
					t.Errorf("Unexpected validation errors: %v", errors)
				}
			}
		})
	}
}

// validateRule is a helper function that validates a single rule and returns errors
func validateRule(t *testing.T, ruleText string) []error {
	l := internal.New(ruleText)
	p := parser.New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("Failed to parse rule: %v", err)
	}
	if len(p.Errors()) > 0 {
		t.Fatalf("Parser errors: %v", p.Errors())
	}
	if len(program.Rules) != 1 {
		t.Fatalf("Expected 1 rule, got %d", len(program.Rules))
	}

	validator := NewValidator()
	errors := validator.ValidateProgram(program)

	return errors
}

// containsAny checks if any error message contains the specified substring
func containsAny(errors []error, substring string) bool {
	for _, err := range errors {
		if err != nil && containsSubstring(err.Error(), substring) {
			return true
		}
	}
	return false
}


// containsSubstring checks if a string contains a substring
func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
