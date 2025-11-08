package semantic

import (
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/parser"
	"github.com/cawalch/go-yara/token"
)

// TestValidator tests the semantic validator functionality
func TestValidator(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantErr     bool
		minErrCount int // Minimum errors expected (allows for cascading errors)
	}{
		{
			name: "valid rule with strings and condition",
			input: `
rule test_rule {
    meta:
        author = "test"
    strings:
        $s1 = "malware"
        $s2 = "virus"
    condition:
        $s1 and $s2
}`,
			wantErr:     false,
			minErrCount: 0,
		},
		{
			name: "undefined string reference",
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
			name: "type mismatch in comparison",
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
		{
			name: "valid simple condition",
			input: `
rule test_rule {
    strings:
        $s1 = "malware"
    condition:
        $s1
}`,
			wantErr:     false,
			minErrCount: 0,
		},
		{
			name: "valid integer comparison",
			input: `
rule test_rule {
    condition:
        1 > 0
}`,
			wantErr:     false,
			minErrCount: 0,
		},
		{
			name: "valid filesize keyword",
			input: `
rule test_rule {
    condition:
        filesize > 1024
}`,
			wantErr:     false,
			minErrCount: 0,
		},
		{
			name: "valid entrypoint keyword",
			input: `
rule test_rule {
		  condition:
		      entrypoint == 0x400000
}`,
			wantErr:     false,
			minErrCount: 0,
		},
		{
			name: "valid string contains",
			input: `
rule test_rule {
		  strings:
		      $s1 = "malware"
		  condition:
		      $s1 contains "mal"
}`,
			wantErr:     false,
			minErrCount: 0,
		},
		{
			name: "valid string matches",
			input: `
rule test_rule {
		  strings:
		      $s1 = "malware"
		  condition:
		      $s1 matches /mal/
}`,
			wantErr:     false,
			minErrCount: 0,
		},
		{
			name: "valid quantifier for",
			input: `
rule test_rule {
		  strings:
		      $s1 = "test"
		      $s2 = "malware"
		  condition:
		      for any of them : ($)
}`,
			wantErr:     false,
			minErrCount: 0,
		},
		{
			name: "valid quantifier all of them",
			input: `
rule test_rule {
    strings:
        $s1 = "test"
    condition:
        all of them
}`,
			wantErr:     false,
			minErrCount: 0,
		},
		{
			name: "valid quantifier any of them",
			input: `
rule test_rule {
    strings:
        $s1 = "test"
        $s2 = "malware"
    condition:
        any of them
}`,
			wantErr:     false,
			minErrCount: 0,
		},
		{
			name: "valid quantifier none of them",
			input: `
rule test_rule {
    strings:
        $s1 = "test"
    condition:
        none of them
}`,
			wantErr:     false,
			minErrCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the input
			lex := lexer.New(tt.input)
			p := parser.New(lex)
			program, err := p.ParseRules()

			if err != nil {
				t.Fatalf("ParseRules() error = %v", err)
			}

			// Validate semantically
			validator := NewValidator()
			errors := validator.ValidateProgram(program)

			if tt.wantErr && len(errors) == 0 {
				t.Errorf("ValidateProgram() expected errors, got none")
			}

			if !tt.wantErr && len(errors) > 0 {
				t.Errorf("ValidateProgram() unexpected errors: %v", errors)
			}

			if tt.minErrCount > 0 && len(errors) < tt.minErrCount {
				t.Errorf("ValidateProgram() expected at least %d errors, got %d: %v", tt.minErrCount, len(errors), errors)
			}
		})
	}
}

// TestSymbolTable tests the symbol table functionality
func TestSymbolTable(t *testing.T) {
	st := NewSymbolTable()

	// Test scope management
	st.EnterScope("test_rule")

	// Test rule definition
	pos := token.Position{Line: 1, Column: 1}
	rule := &ast.Rule{Name: "test_rule", Pos: pos}
	err := st.DefineRule("test_rule", pos, rule)
	if err != nil {
		t.Errorf("DefineRule() error = %v", err)
	}

	// Test string definition
	str := &ast.String{Identifier: "$s1", Pos: pos}
	err = st.DefineString("$s1", pos, str)
	if err != nil {
		t.Errorf("DefineString() error = %v", err)
	}

	// Test lookup
	symbol, exists := st.Lookup("$s1")
	if !exists {
		t.Errorf("Lookup() string not found")
	}
	if symbol.Type != SymbolString {
		t.Errorf("Lookup() wrong symbol type")
	}

	// Test mark used
	st.MarkUsed("$s1")
	if !symbol.Used {
		t.Errorf("MarkUsed() did not mark symbol as used")
	}

	// Test exit scope
	st.ExitScope()
	_, exists = st.Lookup("$s1")
	if exists {
		t.Errorf("Lookup() should not find string after exiting scope")
	}
}

// TestTypeSystem tests the type system functionality
func TestTypeSystem(t *testing.T) {
	// Test integer type creation
	int32Type := Int32Type
	if int32Type.Size != 4 || int32Type.Signed != true {
		t.Errorf("Int32Type has wrong properties")
	}

	// Test type string representation
	if int32Type.String() != "int32" {
		t.Errorf("Int32Type.String() = %s, want int32", int32Type.String())
	}

	// Test type inference from literals
	boolType := InferTypeFromLiteral(token.TRUE, true)
	if boolType.DataType != TypeBoolean {
		t.Errorf("InferTypeFromLiteral() boolean type inference failed")
	}

	intType := InferTypeFromLiteral(token.INTEGER_LIT, 42)
	if intType.DataType != TypeInteger {
		t.Errorf("InferTypeFromLiteral() integer type inference failed")
	}

	// Test type compatibility
	left := &TypeInfo{DataType: TypeInteger, IntegerType: Int32Type}
	right := &TypeInfo{DataType: TypeInteger, IntegerType: Uint64Type}

	if !left.CanCompare(right) {
		t.Errorf("CanCompare() should allow integer comparison")
	}

	if !left.CanPerformArithmetic(right) {
		t.Errorf("CanPerformArithmetic() should allow integer arithmetic")
	}
}

// TestStringValidator tests string reference validation
func TestStringValidator(t *testing.T) {
	st := NewSymbolTable()
	st.EnterScope("test_rule")

	// Define some strings
	pos := token.Position{Line: 1, Column: 1}
	str1 := &ast.String{Identifier: "$s1", Pos: pos}
	str2 := &ast.String{Identifier: "$s2", Pos: pos}

	_ = st.DefineString("$s1", pos, str1)
	_ = st.DefineString("$s2", pos, str2)

	validator := NewStringValidator(st)

	// Test valid string reference
	identifier := &ast.Identifier{Name: "$s1", Pos: pos}
	errors := validator.ValidateStringReferences(identifier)

	if len(errors) > 0 {
		t.Errorf("ValidateStringReferences() unexpected errors for valid reference: %v", errors)
	}

	// Test invalid string reference
	invalidIdentifier := &ast.Identifier{Name: "$s3", Pos: pos}
	errors = validator.ValidateStringReferences(invalidIdentifier)

	if len(errors) == 0 {
		t.Errorf("ValidateStringReferences() expected errors for invalid reference")
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

// TestModuleValidator tests module function validation
func TestModuleValidator(t *testing.T) {
	st := NewSymbolTable()
	validator := NewModuleValidator(st)

	// Test filesize validation
	funcName := "filesize"
	args := make([]ast.Expression, 0)
	pos := token.Position{Line: 1, Column: 1}

	typeInfo, errors := validator.ValidateFunctionCall(funcName, args, pos)

	if len(errors) > 0 {
		t.Errorf("ValidateFunctionCall() unexpected errors for filesize: %v", errors)
	}

	if typeInfo.DataType != TypeInteger {
		t.Errorf("ValidateFunctionCall() wrong return type for filesize")
	}

	// Test invalid function
	invalidFuncName := "unknown_function"
	_, errors = validator.ValidateFunctionCall(invalidFuncName, args, pos)

	if len(errors) == 0 {
		t.Errorf("ValidateFunctionCall() expected errors for unknown function")
	}
}

// TestFileValidator tests file operation validation
func TestFileValidator(t *testing.T) {
	st := NewSymbolTable()
	validator := NewFileValidator(st)

	// Test filesize operation validation
	identifier := &ast.Identifier{Name: "filesize", Pos: token.Position{Line: 1, Column: 1}}
	errors := validator.ValidateFileOperations(identifier)

	if len(errors) > 0 {
		t.Errorf("ValidateFileOperations() unexpected errors for filesize: %v", errors)
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
	program, err := p.ParseRules()

	if err != nil || program == nil {
		b.Fatalf("ParseRules() failed: %v", err)
	}

	validator := NewValidator()

	for b.Loop() {
		validator.ValidateProgram(program)
	}
}

// TestValidatorVisitorMethodsExtended tests additional visitor methods
func TestValidatorVisitorMethodsExtended(t *testing.T) {
	validator := NewValidator()

	// Test VisitProgram
	program := &ast.Program{
		Rules: []*ast.Rule{
			{
				Name: "test_rule",
				Condition: &ast.Literal{
					Type:  token.TRUE,
					Value: true,
				},
			},
		},
	}
	result := validator.VisitProgram(program)
	if result == nil {
		t.Error("VisitProgram should return errors slice")
	}

	// Test VisitRule
	rule := &ast.Rule{
		Name: "test_rule",
		Condition: &ast.Literal{
			Type:  token.TRUE,
			Value: true,
		},
	}
	validator.VisitRule(rule)

	// Test VisitMeta
	meta := &ast.Meta{
		Key:   "author",
		Value: ast.MetaString("test"),
	}
	validator.VisitMeta(meta)

	// Test VisitString
	str := &ast.String{
		Identifier: "$test",
		Pattern: &ast.TextString{
			Value: "test",
		},
	}
	validator.VisitString(str)

	// Test VisitCondition
	condition := &ast.Condition{
		Expression: &ast.Literal{
			Type:  token.TRUE,
			Value: true,
		},
	}
	validator.VisitCondition(condition)

	// Test VisitBinaryOp
	binOp := &ast.BinaryOp{
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
	validator.VisitBinaryOp(binOp)

	// Test VisitUnaryOp
	unaryOp := &ast.UnaryOp{
		Op: token.NOT,
		Right: &ast.Literal{
			Type:  token.TRUE,
			Value: true,
		},
	}
	validator.VisitUnaryOp(unaryOp)

	// Test VisitIdentifier
	ident := &ast.Identifier{
		Name: "test",
	}
	validator.VisitIdentifier(ident)

	// Test VisitLiteral
	literal := &ast.Literal{
		Type:  token.TRUE,
		Value: true,
	}
	validator.VisitLiteral(literal)
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
		Type:  token.STRING_LIT,
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
				Type:  token.INTEGER_LIT,
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
		t.Run(tt.name, func(t *testing.T) {
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
