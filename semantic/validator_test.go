package semantic

import (
	"context"
	"fmt"
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/parser"
	"github.com/cawalch/go-yara/token"
)

// validatorTestCase represents a single validator test case
type validatorTestCase struct {
	name        string
	input       string
	wantErr     bool
	minErrCount int // Minimum errors expected (allows for cascading errors)
}

// parseAndValidateProgram parses input and validates it, returning validation errors
func parseAndValidateProgram(_ *testing.T, input string) ([]error, error) {
	lex := lexer.New(input)
	p := parser.New(lex)
	program, err := p.ParseRulesWithContext(context.Background())
	if err != nil {
		return nil, fmt.Errorf("parse rules failed: %w", err)
	}

	validator := NewValidator()
	return validator.ValidateProgram(program), nil
}

// assertValidationResults validates program validation results against expectations
func assertValidationResults(t *testing.T, errors []error, wantErr bool, minErrCount int) {
	if wantErr && len(errors) == 0 {
		t.Errorf("ValidateProgram() expected errors, got none")
		return
	}

	if !wantErr && len(errors) > 0 {
		t.Errorf("ValidateProgram() unexpected errors: %v", errors)
		return
	}

	if minErrCount > 0 && len(errors) < minErrCount {
		t.Errorf("ValidateProgram() expected at least %d errors, got %d: %v", minErrCount, len(errors), errors)
	}
}

// TestValidator tests the semantic validator functionality
func TestValidator(t *testing.T) {
	t.Run("ValidRules", testValidatorValidRules)
	t.Run("InvalidRules", testValidatorInvalidRules)
	t.Run("Quantifiers", testValidatorQuantifiers)
}

// testValidatorValidRules tests validation of correct YARA rules
func testValidatorValidRules(t *testing.T) {
	t.Run("BasicRuleStructures", testValidatorBasicRuleStructures)
	t.Run("KeywordValidations", testValidatorKeywordValidations)
	t.Run("StringOperations", testValidatorStringOperations)
}

// testValidatorBasicRuleStructures tests validation of basic YARA rule structures
func testValidatorBasicRuleStructures(t *testing.T) {
	tests := []struct {
		name string
		rule string
	}{
		{
			name: "complete_rule_with_meta_strings_condition",
			rule: `rule test_rule {
    meta:
        author = "test"
    strings:
        $s1 = "malware"
        $s2 = "virus"
    condition:
        $s1 and $s2
}`,
		},
		{
			name: "simple_condition_only",
			rule: `rule test_rule {
    strings:
        $s1 = "malware"
    condition:
        $s1
}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			errors, err := parseAndValidateProgram(t, tt.rule)
			if err != nil {
				t.Fatalf("ParseRules() error = %v", err)
			}
			assertValidationResults(t, errors, false, 0)
		})
	}
}

// testValidatorKeywordValidations tests validation of YARA keywords in conditions
func testValidatorKeywordValidations(t *testing.T) {
	tests := []struct {
		name string
		rule string
	}{
		{
			name: "integer_comparison",
			rule: `rule test_rule {
    condition:
        1 > 0
}`,
		},
		{
			name: "filesize_keyword",
			rule: `rule test_rule {
    condition:
        filesize > 1024
}`,
		},
		{
			name: "entrypoint_keyword",
			rule: `rule test_rule {
    condition:
        entrypoint == 0x400000
}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			errors, err := parseAndValidateProgram(t, tt.rule)
			if err != nil {
				t.Fatalf("ParseRules() error = %v", err)
			}
			assertValidationResults(t, errors, false, 0)
		})
	}
}

// testValidatorStringOperations tests validation of string operations in conditions
func testValidatorStringOperations(t *testing.T) {
	tests := []struct {
		name string
		rule string
	}{
		{
			name: "string_contains",
			rule: `rule test_rule {
    strings:
        $s1 = "malware"
    condition:
        $s1 contains "mal"
}`,
		},
		{
			name: "string_matches",
			rule: `rule test_rule {
    strings:
        $s1 = "malware"
    condition:
        $s1 matches /mal/
}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			errors, err := parseAndValidateProgram(t, tt.rule)
			if err != nil {
				t.Fatalf("ParseRules() error = %v", err)
			}
			assertValidationResults(t, errors, false, 0)
		})
	}
}

// testValidatorInvalidRules tests validation of incorrect YARA rules
func testValidatorInvalidRules(t *testing.T) {
	tests := []validatorTestCase{
		{
			name: "undefined_string_reference",
			input: `
rule test_rule {
    strings:
        $s1 = "malware"
    condition:
        $s1 and $s2
}`,
			wantErr:     true,
			minErrCount: 1, // At least undefined $s2 error
		},
		{
			name: "type_mismatch_in_comparison",
			input: `
rule test_rule {
    strings:
        $s1 = "malware"
    condition:
        $s1 == "string"
}`,
			wantErr:     true,
			minErrCount: 1, // At least type mismatch error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			errors, err := parseAndValidateProgram(t, tt.input)
			if err != nil {
				t.Fatalf("ParseRules() error = %v", err)
			}
			assertValidationResults(t, errors, tt.wantErr, tt.minErrCount)
		})
	}
}

// testValidatorQuantifiers tests validation of quantifier expressions
func testValidatorQuantifiers(t *testing.T) {
	tests := []validatorTestCase{
		{
			name: "for_any_of_them",
			input: `
rule test_rule {
    strings:
        $s1 = "test"
        $s2 = "malware"
    condition:
        for any of them : ($)
}`,
			wantErr: false,
		},
		{
			name: "all_of_them",
			input: `
rule test_rule {
    strings:
        $s1 = "test"
    condition:
        all of them
}`,
			wantErr: false,
		},
		{
			name: "any_of_them",
			input: `
rule test_rule {
    strings:
        $s1 = "test"
        $s2 = "malware"
    condition:
        any of them
}`,
			wantErr: false,
		},
		{
			name: "none_of_them",
			input: `
rule test_rule {
    strings:
        $s1 = "test"
    condition:
        none of them
}`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			errors, err := parseAndValidateProgram(t, tt.input)
			if err != nil {
				t.Fatalf("ParseRules() error = %v", err)
			}
			assertValidationResults(t, errors, tt.wantErr, tt.minErrCount)
		})
	}
}

// TestSymbolTable tests the symbol table functionality
// TestSymbolTableBasicOperations tests core symbol table functionality
func TestSymbolTableBasicOperations(t *testing.T) {
	st := NewSymbolTable()
	st.EnterScope("test_rule")

	pos := token.Position{Line: 1, Column: 1}

	// Define a rule and string for testing
	rule := &ast.Rule{Name: "test_rule", Pos: pos}
	str := &ast.String{Identifier: "$s1", Pos: pos}

	// Test rule definition
	if err := st.DefineRule("test_rule", pos, rule); err != nil {
		t.Fatalf("DefineRule() error = %v", err)
	}

	// Test string definition
	if err := st.DefineString("$s1", pos, str); err != nil {
		t.Fatalf("DefineString() error = %v", err)
	}

	// Test lookup functionality
	symbol, exists := st.Lookup("$s1")
	if !exists {
		t.Fatalf("Lookup() string not found")
	}
	if symbol.Type != SymbolString {
		t.Errorf("Lookup() wrong symbol type, got %v, want %v", symbol.Type, SymbolString)
	}

	// Test symbol usage tracking
	st.MarkUsed("$s1")
	if !symbol.Used {
		t.Errorf("MarkUsed() did not mark symbol as used")
	}

	// Test scope isolation - symbol should not be found after exiting scope
	st.ExitScope()
	_, exists = st.Lookup("$s1")
	if exists {
		t.Errorf("Lookup() should not find string after exiting scope")
	}
}

// TestSymbolTableAdvancedOperations tests complex symbol table scenarios
func TestSymbolTableAdvancedOperations(t *testing.T) {
	operationTests := []struct {
		name      string
		setupFunc func(*SymbolTable)
		testFunc  func(*SymbolTable) bool
		expected  bool
	}{
		{
			name: "scope_stack_management",
			setupFunc: func(st *SymbolTable) {
				st.EnterScope("inner")
			},
			testFunc: func(st *SymbolTable) bool {
				// Test that we can define symbols in inner scope
				pos := token.Position{Line: 1, Column: 1}
				str := &ast.String{Identifier: "$inner", Pos: pos}
				return st.DefineString("$inner", pos, str) == nil
			},
			expected: true,
		},
		{
			name:      "undefined_lookup",
			setupFunc: func(_ *SymbolTable) {},
			testFunc: func(st *SymbolTable) bool {
				_, exists := st.Lookup("$undefined")
				return !exists
			},
			expected: true,
		},
	}

	for _, tt := range operationTests {
		t.Run(tt.name, func(_ *testing.T) {
			testST := NewSymbolTable()
			testST.EnterScope("test")

			tt.setupFunc(testST)
			result := tt.testFunc(testST)

			if result != tt.expected {
				t.Errorf("Test operation %s: got %v, want %v", tt.name, result, tt.expected)
			}
		})
	}
}

// TestTypeSystem tests the type system functionality
func TestTypeSystem(t *testing.T) {
	t.Run("IntegerTypeProperties", testIntegerTypeProperties)
	t.Run("TypeInferenceFromLiterals", testTypeInferenceFromLiterals)
	t.Run("TypeCompatibility", testTypeCompatibility)
}

// testIntegerTypeProperties tests integer type property functionality
func testIntegerTypeProperties(t *testing.T) {
	intTypeTests := []struct {
		name       string
		intType    *IntegerType
		wantSize   int
		wantSigned bool
		wantStr    string
	}{
		{
			name:       "Int32Type_properties",
			intType:    Int32Type,
			wantSize:   4,
			wantSigned: true,
			wantStr:    "int32",
		},
		{
			name:       "Uint64Type_properties",
			intType:    Uint64Type,
			wantSize:   8,
			wantSigned: false,
			wantStr:    "uint64",
		},
	}

	for _, tt := range intTypeTests {
		t.Run(tt.name, func(_ *testing.T) {
			if tt.intType.Size != tt.wantSize {
				t.Errorf("Size: got %d, want %d", tt.intType.Size, tt.wantSize)
			}
			if tt.intType.Signed != tt.wantSigned {
				t.Errorf("Signed: got %v, want %v", tt.intType.Signed, tt.wantSigned)
			}
			if tt.intType.String() != tt.wantStr {
				t.Errorf("String(): got %s, want %s", tt.intType.String(), tt.wantStr)
			}
		})
	}
}

// typeInferenceTestCase represents a test case for type inference
type typeInferenceTestCase struct {
	name         string
	tokenType    token.Type
	value        any
	expectedType DataType
}

// testTypeInferenceFromLiterals tests type inference from literals
func testTypeInferenceFromLiterals(t *testing.T) {
	literalTests := []typeInferenceTestCase{
		{
			name:         "boolean_literal",
			tokenType:    token.TRUE,
			value:        true,
			expectedType: TypeBoolean,
		},
		{
			name:         "integer_literal",
			tokenType:    token.IntegerLit,
			value:        42,
			expectedType: TypeInteger,
		},
		{
			name:         "hex_integer_literal",
			tokenType:    token.HexIntegerLit,
			value:        0xFF,
			expectedType: TypeInteger,
		},
		{
			name:         "string_literal",
			tokenType:    token.StringLit,
			value:        "test",
			expectedType: TypeString,
		},
	}

	for _, tt := range literalTests {
		t.Run(tt.name, func(_ *testing.T) {
			result := InferTypeFromLiteral(tt.tokenType, tt.value)
			if result.DataType != tt.expectedType {
				t.Errorf("InferTypeFromLiteral() got type %v, want %v",
					result.DataType, tt.expectedType)
			}
		})
	}
}

// typeCompatibilityTestCase represents a test case for type compatibility
type typeCompatibilityTestCase struct {
	name          string
	left          *TypeInfo
	right         *TypeInfo
	canCompare    bool
	canArithmetic bool
}

// testTypeCompatibility tests type compatibility and operations
func testTypeCompatibility(t *testing.T) {
	compatibilityTests := []typeCompatibilityTestCase{
		{
			name:          "int32_vs_uint64",
			left:          &TypeInfo{DataType: TypeInteger, IntegerType: Int32Type},
			right:         &TypeInfo{DataType: TypeInteger, IntegerType: Uint64Type},
			canCompare:    true,
			canArithmetic: true,
		},
		{
			name:          "int_vs_bool",
			left:          &TypeInfo{DataType: TypeInteger, IntegerType: Int32Type},
			right:         &TypeInfo{DataType: TypeBoolean},
			canCompare:    false,
			canArithmetic: false,
		},
		{
			name:          "string_vs_string",
			left:          &TypeInfo{DataType: TypeString},
			right:         &TypeInfo{DataType: TypeString},
			canCompare:    true,
			canArithmetic: false,
		},
	}

	for _, tt := range compatibilityTests {
		t.Run(tt.name, func(_ *testing.T) {
			if got := tt.left.CanCompare(tt.right); got != tt.canCompare {
				t.Errorf("CanCompare(): got %v, want %v", got, tt.canCompare)
			}
			if got := tt.left.CanPerformArithmetic(tt.right); got != tt.canArithmetic {
				t.Errorf("CanPerformArithmetic(): got %v, want %v", got, tt.canArithmetic)
			}
		})
	}
}

// TestTypeChecker tests type checking functionality
func TestTypeChecker(t *testing.T) {
	st := NewSymbolTable()
	st.EnterScope("test_rule")

	// Define a string for testing
	pos := token.Position{Line: 1, Column: 1}
	str := &ast.String{Identifier: "$s1", Pos: pos}
	_ = st.DefineString("$s1", pos, str)

	checker := NewTypeChecker(st)

	// Test literal type checking
	literal := &ast.Literal{Type: token.TRUE, Value: true, Pos: pos}
	typeInfo, errors := checker.CheckExpressionTypes(literal)

	if len(errors) > 0 {
		t.Errorf("CheckExpressionTypes() unexpected errors for literal: %v", errors)
	}

	if typeInfo.DataType != TypeBoolean {
		t.Errorf("CheckExpressionTypes() wrong type for boolean literal")
	}

	// Test identifier type checking
	identifier := &ast.Identifier{Name: "$s1", Pos: pos}
	typeInfo, errors = checker.CheckExpressionTypes(identifier)

	if len(errors) > 0 {
		t.Errorf("CheckExpressionTypes() unexpected errors for identifier: %v", errors)
	}

	if typeInfo.DataType != TypeBoolean {
		t.Errorf("CheckExpressionTypes() wrong type for string identifier")
	}
}

// BenchmarkValidator benchmarks the semantic validator
func BenchmarkValidator(b *testing.B) {
	input := `
rule benchmark_rule {
    meta:
        author = "test"
        version = "1.0"
    strings:
        $s1 = "malware"
        $s2 = "virus"
    condition:
        $s1 and $s2
}`

	lex := lexer.New(input)
	p := parser.New(lex)
	program, err := p.ParseRulesWithContext(context.Background())

	if err != nil || program == nil {
		b.Fatalf("ParseRules() failed: %v", err)
	}

	validator := NewValidator()

	for b.Loop() {
		validator.ValidateProgram(program)
	}
}

// TestValidatorStructureVisitors tests core structure visitor methods
func TestValidatorStructureVisitors(t *testing.T) {
	tests := []struct {
		name      string
		visitFunc func(*Validator, ast.Node)
		setupFunc func() ast.Node
	}{
		{
			name: "VisitProgram",
			setupFunc: func() ast.Node {
				return createValidatorTestProgram()
			},
			visitFunc: func(v *Validator, node ast.Node) {
				result := v.VisitProgram(node.(*ast.Program))
				if result == nil {
					t.Error("VisitProgram should return errors slice")
				}
			},
		},
		{
			name: "VisitRule",
			setupFunc: func() ast.Node {
				return createValidatorTestRule()
			},
			visitFunc: func(v *Validator, node ast.Node) {
				v.VisitRule(node.(*ast.Rule))
			},
		},
		{
			name: "VisitCondition",
			setupFunc: func() ast.Node {
				return createValidatorTestCondition()
			},
			visitFunc: func(v *Validator, node ast.Node) {
				v.VisitCondition(node.(*ast.Condition))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			v := NewValidator()
			node := tt.setupFunc()
			tt.visitFunc(v, node)
		})
	}
}

// TestValidatorElementVisitors tests element visitor methods (strings, meta)
func TestValidatorElementVisitors(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func() ast.Node
		visitFunc func(*Validator, ast.Node)
	}{
		{
			name: "VisitString",
			setupFunc: func() ast.Node {
				return createValidatorTestString()
			},
			visitFunc: func(v *Validator, node ast.Node) {
				v.VisitString(node.(*ast.String))
			},
		},
		{
			name: "VisitMeta",
			setupFunc: func() ast.Node {
				return createValidatorTestMeta()
			},
			visitFunc: func(v *Validator, node ast.Node) {
				v.VisitMeta(node.(*ast.Meta))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			v := NewValidator()
			node := tt.setupFunc()
			tt.visitFunc(v, node)
		})
	}
}

// TestValidatorExpressionVisitors tests expression visitor methods
func TestValidatorExpressionVisitors(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func() ast.Node
		visitFunc func(*Validator, ast.Node)
	}{
		{
			name: "VisitBinaryOp",
			setupFunc: func() ast.Node {
				return createValidatorTestBinaryOp()
			},
			visitFunc: func(v *Validator, node ast.Node) {
				v.VisitBinaryOp(node.(*ast.BinaryOp))
			},
		},
		{
			name: "VisitUnaryOp",
			setupFunc: func() ast.Node {
				return createValidatorTestUnaryOp()
			},
			visitFunc: func(v *Validator, node ast.Node) {
				v.VisitUnaryOp(node.(*ast.UnaryOp))
			},
		},
		{
			name: "VisitIdentifier",
			setupFunc: func() ast.Node {
				return createValidatorTestIdentifier()
			},
			visitFunc: func(v *Validator, node ast.Node) {
				v.VisitIdentifier(node.(*ast.Identifier))
			},
		},
		{
			name: "VisitLiteral",
			setupFunc: func() ast.Node {
				return createValidatorTestLiteral()
			},
			visitFunc: func(v *Validator, node ast.Node) {
				v.VisitLiteral(node.(*ast.Literal))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			v := NewValidator()
			node := tt.setupFunc()
			tt.visitFunc(v, node)
		})
	}
}

// TestValidatorErrorHandling tests error handling
func TestValidatorErrorHandling(t *testing.T) {
	validator := NewValidator()

	// Test with invalid rule (undefined string reference)
	program := &ast.Program{
		Rules: []*ast.Rule{
			{
				Name: "test_rule",
				Condition: &ast.Identifier{
					Name: "$undefined",
				},
			},
		},
	}

	errors := validator.ValidateProgram(program)
	if len(errors) == 0 {
		t.Error("Expected errors for undefined string reference")
	}
}

// TestValidatorMetaValidation tests meta validation
func TestValidatorMetaValidation(t *testing.T) {
	validator := NewValidator()

	rule := &ast.Rule{
		Name: "test_rule",
		Meta: []*ast.Meta{
			{
				Key:   "author",
				Value: ast.MetaString("test"),
			},
			{
				Key:   "version",
				Value: ast.MetaInt(1),
			},
		},
		Condition: &ast.Literal{
			Type:  token.TRUE,
			Value: true,
		},
	}

	validator.validateRule(rule)

	// Check that meta keys are defined as variables
	if validator.GetSymbolTable().HasErrors() {
		t.Error("Should not have errors for valid meta")
	}
}

// TestValidatorStringValidation tests string validation
func TestValidatorStringValidation(t *testing.T) {
	validator := NewValidator()

	rule := &ast.Rule{
		Name: "test_rule",
		Strings: []*ast.String{
			{
				Identifier: "$s1",
				Pattern: &ast.TextString{
					Value: "test",
				},
			},
			{
				Identifier: "$s2",
				Pattern: &ast.TextString{
					Value: "malware",
				},
			},
		},
		Condition: &ast.Literal{
			Type:  token.TRUE,
			Value: true,
		},
	}

	validator.validateRule(rule)

	// Check that strings are marked as used
	symbolTable := validator.GetSymbolTable()
	if symbol, exists := symbolTable.Lookup("$s1"); exists {
		if !symbol.Used {
			t.Error("String $s1 should be marked as used")
		}
	}
}

// TestValidatorConditionValidation tests condition validation
func TestValidatorConditionValidation(t *testing.T) {
	validator := NewValidator()

	// Test valid condition
	condition := &ast.Literal{
		Type:  token.TRUE,
		Value: true,
	}

	validator.validateCondition(condition)

	// Test invalid condition (non-boolean)
	invalidCondition := &ast.Literal{
		Type:  token.StringLit,
		Value: "invalid",
	}

	validator.validateCondition(invalidCondition)

	// Should have errors
	if !validator.HasErrors() {
		t.Error("Expected errors for invalid condition type")
	}
}

// TestValidatorValidateExpression tests validateExpression method
func TestValidatorValidateExpression(t *testing.T) {
	validator := NewValidator()
	st := validator.GetSymbolTable()
	st.EnterScope("test")
	pos := token.Position{Line: 1, Column: 1}

	// Define a string
	str := &ast.String{Identifier: "$s1", Pos: pos}
	_ = st.DefineString("$s1", pos, str)

	tests := []struct {
		name         string
		expr         ast.Expression
		expectedType DataType
		wantErr      bool
	}{
		{
			name: "literal_true",
			expr: &ast.Literal{
				Type:  token.TRUE,
				Value: true,
			},
			expectedType: TypeBoolean,
			wantErr:      false,
		},
		{
			name: "literal_integer",
			expr: &ast.Literal{
				Type:  token.IntegerLit,
				Value: int64(42),
			},
			expectedType: TypeInteger,
			wantErr:      false,
		},
		{
			name: "identifier_string",
			expr: &ast.Identifier{
				Name: "$s1",
			},
			expectedType: TypeBoolean,
			wantErr:      false,
		},
		{
			name: "identifier_filesize",
			expr: &ast.Identifier{
				Name: "filesize",
			},
			expectedType: TypeInteger,
			wantErr:      false,
		},
		{
			name: "undefined_identifier",
			expr: &ast.Identifier{
				Name: "undefined",
			},
			expectedType: TypeUnknown,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			typeInfo, errors := validator.validateExpression(tt.expr)
			if (len(errors) > 0) != tt.wantErr {
				t.Errorf("validateExpression() error = %v, wantErr %v", len(errors) > 0, tt.wantErr)
			}
			if typeInfo.DataType != tt.expectedType {
				t.Errorf("validateExpression() got %v, want %v", typeInfo.DataType, tt.expectedType)
			}
		})
	}
}

// TestValidatorValidateMeta tests validateMeta method
func TestValidatorValidateMeta(t *testing.T) {
	validator := NewValidator()

	meta := []*ast.Meta{
		{
			Key:   "author",
			Value: ast.MetaString("test"),
		},
		{
			Key:   "version",
			Value: ast.MetaInt(1),
		},
	}

	validator.validateMeta(meta)

	// Should not have errors for valid meta
	if validator.HasErrors() {
		t.Errorf("validateMeta() unexpected errors: %v", validator.GetErrors())
	}
}

// TestValidatorValidateStrings tests validateStrings method
func TestValidatorValidateStrings(t *testing.T) {
	validator := NewValidator()

	strings := []*ast.String{
		{
			Identifier: "$s1",
			Pattern: &ast.TextString{
				Value: "test",
			},
		},
		{
			Identifier: "$s2",
			Pattern: &ast.TextString{
				Value: "malware",
			},
		},
	}

	validator.validateStrings(strings)

	// Should not have errors for valid strings
	if validator.HasErrors() {
		t.Errorf("validateStrings() unexpected errors: %v", validator.GetErrors())
	}
}

// Helper functions for creating test AST nodes for validator tests

// createValidatorTestProgram creates a basic test program for validator testing
func createValidatorTestProgram() *ast.Program {
	return &ast.Program{
		Rules: []*ast.Rule{
			createValidatorTestRule(),
		},
	}
}

// createValidatorTestRule creates a basic test rule for validator testing
func createValidatorTestRule() *ast.Rule {
	return &ast.Rule{
		Name:      "test_rule",
		Condition: createValidatorTestLiteral(),
	}
}

// createValidatorTestMeta creates a test meta entry for validator testing
func createValidatorTestMeta() *ast.Meta {
	return &ast.Meta{
		Key:   "author",
		Value: ast.MetaString("test"),
	}
}

// createValidatorTestString creates a test string for validator testing
func createValidatorTestString() *ast.String {
	return &ast.String{
		Identifier: "$test",
		Pattern: &ast.TextString{
			Value: "test",
		},
	}
}

// createValidatorTestCondition creates a test condition for validator testing
func createValidatorTestCondition() *ast.Condition {
	return &ast.Condition{
		Expression: createValidatorTestLiteral(),
	}
}

// createValidatorTestBinaryOp creates a test binary operation for validator testing
func createValidatorTestBinaryOp() *ast.BinaryOp {
	return &ast.BinaryOp{
		Op: token.AND,
		Left: &ast.Literal{
			Type:  token.TRUE,
			Value: true,
		},
		Right: &ast.Literal{
			Type:  token.FALSE,
			Value: false,
		},
	}
}

// createValidatorTestUnaryOp creates a test unary operation for validator testing
func createValidatorTestUnaryOp() *ast.UnaryOp {
	return &ast.UnaryOp{
		Op: token.NOT,
		Right: &ast.Literal{
			Type:  token.TRUE,
			Value: true,
		},
	}
}

// createValidatorTestIdentifier creates a test identifier for validator testing
func createValidatorTestIdentifier() *ast.Identifier {
	return &ast.Identifier{
		Name: "test",
	}
}

// createValidatorTestLiteral creates a test literal for validator testing
func createValidatorTestLiteral() *ast.Literal {
	return &ast.Literal{
		Type:  token.TRUE,
		Value: true,
	}
}
