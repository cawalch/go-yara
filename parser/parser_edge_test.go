package parser

import (
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
)

// TestParseBitwiseOperators tests bitwise operator parsing
func TestParseBitwiseOperators(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name: "bitwise_and",
			input: `rule bitwise_and {
				condition:
					1 & 2
			}`,
		},
		{
			name: "bitwise_or",
			input: `rule bitwise_or {
				condition:
					1 | 2
			}`,
		},
		{
			name: "bitwise_xor",
			input: `rule bitwise_xor {
				condition:
					1 ^ 2
			}`,
		},
		{
			name: "bitwise_not",
			input: `rule bitwise_not {
				condition:
					~1
			}`,
		},
		{
			name: "left_shift",
			input: `rule left_shift {
				condition:
					1 << 2
			}`,
		},
		{
			name: "right_shift",
			input: `rule right_shift {
				condition:
					8 >> 2
			}`,
		},
		{
			name: "bitwise_combination",
			input: `rule bitwise_combo {
				condition:
					(1 & 2) | (3 ^ 4)
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)
			p := New(l)

			program, err := p.ParseRules()
			if err != nil {
				t.Fatalf("parsing failed: %v", err)
			}

			if len(program.Rules) != 1 {
				t.Errorf("expected 1 rule, got %d", len(program.Rules))
			}

			rule := program.Rules[0]
			if rule.Condition == nil {
				t.Error("condition is nil")
			}
		})
	}
}

// TestParseUnaryOperators tests unary operator parsing
func TestParseUnaryOperators(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name: "logical_not",
			input: `rule not_op {
				condition:
					not true
			}`,
		},
		{
			name: "bitwise_not",
			input: `rule bitwise_not {
				condition:
					~42
			}`,
		},
		{
			name: "unary_minus",
			input: `rule unary_minus {
				condition:
					-42
			}`,
		},
		{
			name: "defined_operator",
			input: `rule defined_op {
				strings:
					$s1 = "test"
				condition:
					defined $s1
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)
			p := New(l)

			program, err := p.ParseRules()
			if err != nil {
				t.Fatalf("parsing failed: %v", err)
			}

			if len(program.Rules) != 1 {
				t.Errorf("expected 1 rule, got %d", len(program.Rules))
			}
		})
	}
}

// TestParseFunctionCalls tests data type function parsing
func TestParseFunctionCalls(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name: "int8_function",
			input: `rule int8_fn {
				condition:
					int8(0x1000) == 1
			}`,
		},
		{
			name: "int16_function",
			input: `rule int16_fn {
				condition:
					int16(0x1000) == 1
			}`,
		},
		{
			name: "int32_function",
			input: `rule int32_fn {
				condition:
					int32(0x1000) == 1
			}`,
		},
		{
			name: "uint8_function",
			input: `rule uint8_fn {
				condition:
					uint8(0x1000) == 1
			}`,
		},
		{
			name: "uint16_function",
			input: `rule uint16_fn {
				condition:
					uint16(0x1000) == 1
			}`,
		},
		{
			name: "uint32_function",
			input: `rule uint32_fn {
				condition:
					uint32(0x1000) == 1
			}`,
		},
		{
			name: "uint8be_function",
			input: `rule uint8be_fn {
				condition:
					uint8be(0x1000) == 1
			}`,
		},
		{
			name: "uint16be_function",
			input: `rule uint16be_fn {
				condition:
					uint16be(0x1000) == 1
			}`,
		},
		{
			name: "uint32be_function",
			input: `rule uint32be_fn {
				condition:
					uint32be(0x1000) == 1
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)
			p := New(l)

			program, err := p.ParseRules()
			if err != nil {
				t.Fatalf("parsing failed: %v", err)
			}

			if len(program.Rules) != 1 {
				t.Errorf("expected 1 rule, got %d", len(program.Rules))
			}
		})
	}
}

// TestParseQuantifierVariations tests quantifier expression variations
func TestParseQuantifierVariations(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name: "all_of_them",
			input: `rule all_them {
				strings:
					$s1 = "test"
				condition:
					all of them
			}`,
		},
		{
			name: "any_of_them",
			input: `rule any_them {
				strings:
					$s1 = "test"
				condition:
					any of them
			}`,
		},
		{
			name: "none_of_them",
			input: `rule none_them {
				strings:
					$s1 = "test"
				condition:
					none of them
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)
			p := New(l)

			program, err := p.ParseRules()
			if err != nil {
				t.Fatalf("parsing failed: %v", err)
			}

			if len(program.Rules) != 1 {
				t.Errorf("expected 1 rule, got %d", len(program.Rules))
			}
		})
	}
}

// TestParseStringModifiers tests string modifier parsing
func TestParseStringModifiers(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name: "nocase_modifier",
			input: `rule nocase_mod {
				strings:
					$s1 = "test" nocase
				condition:
					$s1
			}`,
		},
		{
			name: "wide_modifier",
			input: `rule wide_mod {
				strings:
					$s1 = "test" wide
				condition:
					$s1
			}`,
		},
		{
			name: "ascii_modifier",
			input: `rule ascii_mod {
				strings:
					$s1 = "test" ascii
				condition:
					$s1
			}`,
		},
		{
			name: "fullword_modifier",
			input: `rule fullword_mod {
				strings:
					$s1 = "test" fullword
				condition:
					$s1
			}`,
		},
		{
			name: "multiple_modifiers",
			input: `rule multi_mods {
				strings:
					$s1 = "test" nocase wide
				condition:
					$s1
			}`,
		},
		{
			name: "three_modifiers",
			input: `rule three_mods {
				strings:
					$s1 = "test" nocase wide fullword
				condition:
					$s1
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)
			p := New(l)

			program, err := p.ParseRules()
			if err != nil {
				t.Fatalf("parsing failed: %v", err)
			}

			if len(program.Rules) != 1 {
				t.Errorf("expected 1 rule, got %d", len(program.Rules))
			}

			rule := program.Rules[0]
			if len(rule.Strings) != 1 {
				t.Errorf("expected 1 string, got %d", len(rule.Strings))
			}
		})
	}
}

// TestParseHexLiterals tests hex literal parsing
func TestParseHexLiterals(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name: "hex_literal_uppercase",
			input: `rule hex_upper {
				condition:
					0xDEADBEEF == 0xDEADBEEF
			}`,
		},
		{
			name: "hex_literal_lowercase",
			input: `rule hex_lower {
				condition:
					0xdeadbeef == 0xdeadbeef
			}`,
		},
		{
			name: "hex_literal_mixed",
			input: `rule hex_mixed {
				condition:
					0xDeAdBeEf == 0xDeAdBeEf
			}`,
		},
		{
			name: "hex_in_comparison",
			input: `rule hex_comp {
				condition:
					0xFF > 0x10
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)
			p := New(l)

			program, err := p.ParseRules()
			if err != nil {
				t.Fatalf("parsing failed: %v", err)
			}

			if len(program.Rules) != 1 {
				t.Errorf("expected 1 rule, got %d", len(program.Rules))
			}
		})
	}
}

// TestParseIntegerLiterals tests integer literal parsing edge cases
func TestParseIntegerLiterals(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name: "small_integer",
			input: `rule small_int {
				condition:
					0 == 0
			}`,
		},
		{
			name: "large_integer",
			input: `rule large_int {
				condition:
					9223372036854775807 > 0
			}`,
		},
		{
			name: "negative_integer",
			input: `rule neg_int {
				condition:
					-42 < 0
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)
			p := New(l)

			program, err := p.ParseRules()
			if err != nil {
				t.Fatalf("parsing failed: %v", err)
			}

			if len(program.Rules) != 1 {
				t.Errorf("expected 1 rule, got %d", len(program.Rules))
			}
		})
	}
}

// TestParseComplexBitwiseExpressions tests complex bitwise expressions
func TestParseComplexBitwiseExpressions(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name: "multiple_bitwise_ops",
			input: `rule multi_bitwise {
				condition:
					(1 & 2) | (3 ^ 4)
			}`,
		},
		{
			name: "bitwise_with_shifts",
			input: `rule bitwise_shifts {
				condition:
					(1 << 2) & (8 >> 1)
			}`,
		},
		{
			name: "complex_bitwise_chain",
			input: `rule bitwise_chain {
				condition:
					1 & 2 | 3 ^ 4 & 5
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)
			p := New(l)

			program, err := p.ParseRules()
			if err != nil {
				t.Fatalf("parsing failed: %v", err)
			}

			if len(program.Rules) != 1 {
				t.Errorf("expected 1 rule, got %d", len(program.Rules))
			}
		})
	}
}

// TestParseUnaryMinusOperator tests unary minus operator parsing
func TestParseUnaryMinusOperator(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name: "unary_minus_integer",
			input: `rule unary_minus {
				condition:
					-42 < 0
			}`,
		},
		{
			name: "unary_minus_in_expression",
			input: `rule unary_minus_expr {
				condition:
					-42 + 10
			}`,
		},
		{
			name: "double_unary_minus",
			input: `rule double_minus {
				condition:
					--42
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)
			p := New(l)

			program, err := p.ParseRules()
			if err != nil {
				t.Fatalf("parsing failed: %v", err)
			}

			if len(program.Rules) != 1 {
				t.Errorf("expected 1 rule, got %d", len(program.Rules))
			}
		})
	}
}

// TestParseFunctionCallsExtended tests function call parsing with arguments
func TestParseFunctionCallsExtended(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name: "int8_with_arg",
			input: `rule int8_arg {
				condition:
					int8(0x1000) == 1
			}`,
		},
		{
			name: "int16_with_arg",
			input: `rule int16_arg {
				condition:
					int16(0x1000) == 1
			}`,
		},
		{
			name: "int32_with_arg",
			input: `rule int32_arg {
				condition:
					int32(0x1000) == 1
			}`,
		},
		{
			name: "uint8_with_arg",
			input: `rule uint8_arg {
				condition:
					uint8(0x1000) == 1
			}`,
		},
		{
			name: "uint16_with_arg",
			input: `rule uint16_arg {
				condition:
					uint16(0x1000) == 1
			}`,
		},
		{
			name: "uint32_with_arg",
			input: `rule uint32_arg {
				condition:
					uint32(0x1000) == 1
			}`,
		},
		{
			name: "int8be_with_arg",
			input: `rule int8be_arg {
				condition:
					int8be(0x1000) == 1
			}`,
		},
		{
			name: "int16be_with_arg",
			input: `rule int16be_arg {
				condition:
					int16be(0x1000) == 1
			}`,
		},
		{
			name: "int32be_with_arg",
			input: `rule int32be_arg {
				condition:
					int32be(0x1000) == 1
			}`,
		},
		{
			name: "uint8be_with_arg",
			input: `rule uint8be_arg {
				condition:
					uint8be(0x1000) == 1
			}`,
		},
		{
			name: "uint16be_with_arg",
			input: `rule uint16be_arg {
				condition:
					uint16be(0x1000) == 1
			}`,
		},
		{
			name: "uint32be_with_arg",
			input: `rule uint32be_arg {
				condition:
					uint32be(0x1000) == 1
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)
			p := New(l)

			program, err := p.ParseRules()
			if err != nil {
				t.Fatalf("parsing failed: %v", err)
			}

			if len(program.Rules) != 1 {
				t.Errorf("expected 1 rule, got %d", len(program.Rules))
			}
		})
	}
}

// TestParseComplexQuantifiers tests complex quantifier expressions
func TestParseComplexQuantifiers(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name: "all_of_them",
			input: `rule all_them {
				strings:
					$s1 = "test"
					$s2 = "test2"
				condition:
					all of them
			}`,
		},
		{
			name: "any_of_them",
			input: `rule any_them {
				strings:
					$s1 = "test"
					$s2 = "test2"
				condition:
					any of them
			}`,
		},
		{
			name: "none_of_them",
			input: `rule none_them {
				strings:
					$s1 = "test"
					$s2 = "test2"
				condition:
					none of them
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)
			p := New(l)

			program, err := p.ParseRules()
			if err != nil {
				t.Fatalf("parsing failed: %v", err)
			}

			if len(program.Rules) != 1 {
				t.Errorf("expected 1 rule, got %d", len(program.Rules))
			}
		})
	}
}

// TestParseStringOperations tests string operation parsing
// Note: These may not be fully implemented yet, so we test basic syntax
func TestParseStringOperations(t *testing.T) {
	// Test that basic comparisons work
	input := `rule string_comp {
		strings:
			$s1 = "test"
		condition:
			$s1
	}`

	l := lexer.New(input)
	p := New(l)

	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	if len(program.Rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(program.Rules))
	}
}

// TestParsePrimaryExpressions tests various primary expression types
func TestParsePrimaryExpressions(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name: "true_literal",
			input: `rule true_lit {
				condition:
					true
			}`,
		},
		{
			name: "false_literal",
			input: `rule false_lit {
				condition:
					false
			}`,
		},
		{
			name: "integer_literal",
			input: `rule int_lit {
				condition:
					42
			}`,
		},
		{
			name: "hex_integer_literal",
			input: `rule hex_lit {
				condition:
					0x2A
			}`,
		},
		{
			name: "string_literal",
			input: `rule str_lit {
				condition:
					"test" == "test"
			}`,
		},
		{
			name: "parenthesized_expr",
			input: `rule paren_expr {
				condition:
					(true and false)
			}`,
		},
		{
			name: "filesize_keyword",
			input: `rule filesize_kw {
				condition:
					filesize > 0
			}`,
		},
		{
			name: "entrypoint_keyword",
			input: `rule entrypoint_kw {
				condition:
					entrypoint == 0x400000
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)
			p := New(l)

			program, err := p.ParseRules()
			if err != nil {
				t.Fatalf("parsing failed: %v", err)
			}

			if len(program.Rules) != 1 {
				t.Errorf("expected 1 rule, got %d", len(program.Rules))
			}
		})
	}
}

// TestParseComplexNestedExpressions tests deeply nested expressions
func TestParseComplexNestedExpressions(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name: "deeply_nested_parentheses",
			input: `rule deep_nest {
				condition:
					(((true and false) or true) and (true or false))
			}`,
		},
		{
			name: "mixed_operators_nested",
			input: `rule mixed_nest {
				condition:
					((1 + 2) * (3 - 4)) / (5 % 6)
			}`,
		},
		{
			name: "logical_and_arithmetic",
			input: `rule logical_arith {
				condition:
					(1 + 2 == 3) and (4 * 5 == 20)
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)
			p := New(l)

			program, err := p.ParseRules()
			if err != nil {
				t.Fatalf("parsing failed: %v", err)
			}

			if len(program.Rules) != 1 {
				t.Errorf("expected 1 rule, got %d", len(program.Rules))
			}
		})
	}
}

// TestParseErrorRecovery tests parser error recovery
func TestParseErrorRecovery(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
	}{
		{
			name: "missing_colon_in_meta",
			input: `rule test {
				meta:
					key = "value"
					invalid syntax here
				condition:
					true
			}`,
			expectError: true,
		},
		{
			name: "missing_assignment_in_strings",
			input: `rule test {
				strings:
					$s1 "test"
				condition:
					true
			}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)
			p := New(l)

			_, err := p.ParseRules()
			if tt.expectError && err == nil {
				t.Error("expected parsing error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected parsing error: %v", err)
			}
		})
	}
}

// TestParseQuantifierExpressionsExtended tests more quantifier variations
func TestParseQuantifierExpressionsExtended(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name: "all_of_them",
			input: `rule all_them {
				strings:
					$a1 = "test1"
					$a2 = "test2"
				condition:
					all of them
			}`,
		},
		{
			name: "any_of_them",
			input: `rule any_them {
				strings:
					$b1 = "test1"
					$b2 = "test2"
				condition:
					any of them
			}`,
		},
		{
			name: "none_of_them",
			input: `rule none_them {
				strings:
					$s1 = "test"
					$s2 = "test2"
				condition:
					none of them
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)
			p := New(l)

			program, err := p.ParseRules()
			if err != nil {
				t.Fatalf("parsing failed: %v", err)
			}

			if len(program.Rules) != 1 {
				t.Errorf("expected 1 rule, got %d", len(program.Rules))
			}
		})
	}
}

// TestParseMultiplicativeOperators tests division and modulo
func TestParseMultiplicativeOperators(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name: "division",
			input: `rule division {
				condition:
					10 / 2
			}`,
		},
		{
			name: "modulo",
			input: `rule modulo {
				condition:
					10 % 3
			}`,
		},
		{
			name: "multiplication",
			input: `rule multiply {
				condition:
					3 * 4
			}`,
		},
		{
			name: "complex_multiplicative",
			input: `rule complex_mult {
				condition:
					10 / 2 * 3 % 4
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)
			p := New(l)

			program, err := p.ParseRules()
			if err != nil {
				t.Fatalf("parsing failed: %v", err)
			}

			if len(program.Rules) != 1 {
				t.Errorf("expected 1 rule, got %d", len(program.Rules))
			}
		})
	}
}

// TestParseShiftOperators tests left and right shift operators
func TestParseShiftOperators(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name: "left_shift_simple",
			input: `rule lshift {
				condition:
					1 << 4
			}`,
		},
		{
			name: "right_shift_simple",
			input: `rule rshift {
				condition:
					16 >> 2
			}`,
		},
		{
			name: "shift_in_expression",
			input: `rule shift_expr {
				condition:
					(1 << 8) == 256
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)
			p := New(l)

			program, err := p.ParseRules()
			if err != nil {
				t.Fatalf("parsing failed: %v", err)
			}

			if len(program.Rules) != 1 {
				t.Errorf("expected 1 rule, got %d", len(program.Rules))
			}
		})
	}
}
