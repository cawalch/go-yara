package parser

import (
	"fmt"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/internal/lexer"
)

// assertRuleParsesWithCondition is a helper function that parses a rule and asserts it has a condition
func assertRuleParsesWithCondition(t *testing.T, input string) {
	t.Helper()
	l := lexer.New(input)
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
}

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
			assertRuleParsesWithCondition(t, tt.input)
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
			assertRuleParses(t, tt.input)
		})
	}
}

// assertRuleParses is a helper function that parses a rule and asserts basic structure
func assertRuleParses(t *testing.T, input string) {
	t.Helper()
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

// TestParseFunctionCalls tests data type function parsing
func TestParseFunctionCalls(t *testing.T) {
	t.Run("IntegerFunctions", testIntegerFunctions)
	t.Run("UnsignedFunctions", testUnsignedFunctions)
	t.Run("BigEndianFunctions", testBigEndianFunctions)
}

func testIntegerFunctions(t *testing.T) {
	integerFuncs := []string{"int8", "int16", "int32"}

	for _, funcName := range integerFuncs {
		t.Run(funcName+"_function", func(t *testing.T) {
			input := fmt.Sprintf(`rule %s_fn {
				condition:
					%s(0x1000) == 1
			}`, funcName, funcName)

			assertRuleParses(t, input)
		})
	}
}

func testUnsignedFunctions(t *testing.T) {
	unsignedFuncs := []string{"uint8", "uint16", "uint32"}

	for _, funcName := range unsignedFuncs {
		t.Run(funcName+"_function", func(t *testing.T) {
			input := fmt.Sprintf(`rule %s_fn {
				condition:
					%s(0x1000) == 1
			}`, funcName, funcName)

			assertRuleParses(t, input)
		})
	}
}

func testBigEndianFunctions(t *testing.T) {
	bigEndianFuncs := []string{"uint8be", "uint16be", "uint32be"}

	for _, funcName := range bigEndianFuncs {
		t.Run(funcName+"_function", func(t *testing.T) {
			input := fmt.Sprintf(`rule %s_fn {
				condition:
					%s(0x1000) == 1
			}`, funcName, funcName)

			assertRuleParses(t, input)
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
	t.Run("SingleModifiers", testSingleStringModifiers)
	t.Run("MultipleModifiers", testMultipleStringModifiers)
}

func TestParseInvalidStringModifierCombos(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantSubstr string
	}{
		{
			name: "base64_with_wide",
			input: `
rule bad1 {
	strings:
		$s = "test" base64 wide
	condition:
		$s
}`,
			wantSubstr: "base64 modifiers are incompatible with 'wide' or 'ascii'",
		},
		{
			name: "base64_with_xor",
			input: `
rule bad2 {
	strings:
		$s = "test" base64 xor(1)
	condition:
		$s
}`,
			wantSubstr: "base64 modifiers are incompatible with 'xor', 'nocase', or 'fullword'",
		},
		{
			name: "xor_range_out_of_bounds",
			input: `
rule bad3 {
	strings:
		$s = "test" xor(1-300)
	condition:
		$s
}`,
			wantSubstr: "xor range must be within 0..255",
		},
		{
			name: "xor_range_inverted",
			input: `
rule bad4 {
	strings:
		$s = "test" xor(5-3)
	condition:
		$s
}`,
			wantSubstr: "xor range max must be >= min",
		},
		{
			name: "base64_duplicate_alphabet",
			input: `
rule bad5 {
	strings:
		$s = "test" base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	condition:
		$s
}`,
			wantSubstr: "invalid base64 alphabet: duplicate characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)
			p := New(l)
			_, err := p.ParseRules()
			if err == nil {
				t.Fatalf("expected parse error for %s", tt.name)
			}
			if tt.wantSubstr == "" {
				return
			}
			found := false
			for _, parseErr := range p.Errors() {
				if strings.Contains(parseErr.Error(), tt.wantSubstr) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected error containing %q, got %v", tt.wantSubstr, p.Errors())
			}
		})
	}
}

func TestParseExtendedStringModifiers(t *testing.T) {
	input := `rule mod_ext {
		strings:
			$xor1 = "test" xor
			$xor2 = "test" xor(1-3)
			$xor3 = "test" xor(0x42)
			$xor4 = "test" xor()
			$b64 = "test" base64("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
			$b64w = "test" base64wide("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
		condition:
			all of them
	}`

	l := lexer.New(input)
	p := New(l)
	program, err := p.ParseRules()
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}
	if len(program.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(program.Rules))
	}
	rule := program.Rules[0]
	if len(rule.Strings) != 6 {
		t.Fatalf("expected 6 strings, got %d", len(rule.Strings))
	}

	byID := make(map[string]*ast.String, len(rule.Strings))
	for _, s := range rule.Strings {
		byID[s.Identifier] = s
	}

	checkXorRange := func(id string, min, max int64) {
		s := byID[id]
		if s == nil || len(s.Modifiers) != 1 || s.Modifiers[0].Type != ast.StringModifierXor {
			t.Fatalf("expected xor modifier for %s", id)
		}
		r, ok := s.Modifiers[0].Value.(ast.XorRange)
		if !ok {
			t.Fatalf("expected xor range for %s", id)
		}
		if r.Min != min || r.Max != max {
			t.Fatalf("xor range for %s = %d-%d, want %d-%d", id, r.Min, r.Max, min, max)
		}
	}

	checkXorRange("$xor1", 0, 255)
	checkXorRange("$xor2", 1, 3)
	checkXorRange("$xor3", 0x42, 0x42)
	checkXorRange("$xor4", 0, 255)

	for _, id := range []string{"$b64", "$b64w"} {
		s := byID[id]
		if s == nil || len(s.Modifiers) != 1 {
			t.Fatalf("expected base64 modifier for %s", id)
		}
		if s.Modifiers[0].Value != "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" {
			t.Fatalf("unexpected base64 alphabet for %s", id)
		}
	}
}

func testSingleStringModifiers(t *testing.T) {
	modifiers := []string{"nocase", "wide", "ascii", "fullword"}

	for _, modifier := range modifiers {
		t.Run(modifier+"_modifier", func(t *testing.T) {
			input := fmt.Sprintf(`rule %s_mod {
				strings:
					$s1 = "test" %s
				condition:
					$s1
			}`, modifier, modifier)

			assertRuleWithSingleStringParses(t, input)
		})
	}
}

func testMultipleStringModifiers(t *testing.T) {
	tests := []struct {
		name      string
		modifiers []string
	}{
		{"two_modifiers", []string{"nocase", "wide"}},
		{"three_modifiers", []string{"nocase", "wide", "fullword"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modifierStr := " " + strings.Join(test.modifiers, " ")
			input := fmt.Sprintf(`rule %s {
				strings:
					$s1 = "test"%s
				condition:
					$s1
			}`, test.name, modifierStr)

			assertRuleWithSingleStringParses(t, input)
		})
	}
}

// assertRuleWithSingleStringParses tests if a YARA rule with one string parses successfully
func assertRuleWithSingleStringParses(t *testing.T, input string) {
	l := lexer.New(input)
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
	// Helper to create a rule with the given function call
	createFunctionRule := func(funcName, ruleName string) string {
		return fmt.Sprintf(`rule %s {
				condition:
					%s(0x1000) == 1
			}`, ruleName, funcName)
	}

	// Test function names using a concise array
	functionNames := []string{
		"int8", "int16", "int32",
		"uint8", "uint16", "uint32",
		"int8be", "int16be", "int32be",
		"uint8be", "uint16be", "uint32be",
	}

	for _, funcName := range functionNames {
		t.Run(funcName+"_with_arg", func(t *testing.T) {
			ruleInput := createFunctionRule(funcName, funcName+"_arg")

			l := lexer.New(ruleInput)
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
