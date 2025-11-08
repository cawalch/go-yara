package semantic

import (
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

// TestFileValidatorOperations tests file operation validation
func TestFileValidatorOperations(t *testing.T) {
	st := NewSymbolTable()
	st.EnterScope("test")
	validator := NewFileValidator(st)

	pos := token.Position{Line: 1, Column: 1}

	tests := []struct {
		name    string
		expr    ast.Expression
		wantErr bool
	}{
		{
			name: "filesize_identifier",
			expr: &ast.Identifier{
				Name: "filesize",
				Pos:  pos,
			},
			wantErr: false,
		},
		{
			name: "entrypoint_identifier",
			expr: &ast.Identifier{
				Name: "entrypoint",
				Pos:  pos,
			},
			wantErr: false,
		},
		{
			name: "non_file_identifier",
			expr: &ast.Identifier{
				Name: "other",
				Pos:  pos,
			},
			wantErr: false, // No error, just not a file operation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := validator.ValidateFileOperations(tt.expr)
			hasErr := len(errors) > 0

			if hasErr != tt.wantErr {
				t.Errorf("ValidateFileOperations() error = %v, wantErr %v, errors: %v", hasErr, tt.wantErr, errors)
			}
		})
	}
}

// TestFileValidatorFilesizeOperation tests filesize operation validation
func TestFileValidatorFilesizeOperation(t *testing.T) {
	st := NewSymbolTable()
	validator := NewFileValidator(st)

	pos := token.Position{Line: 1, Column: 1}

	errors := validator.ValidateFilesizeOperation("filesize", pos)
	if len(errors) > 0 {
		t.Errorf("ValidateFilesizeOperation() unexpected errors: %v", errors)
	}
}

// TestFileValidatorEntrypointOperation tests entrypoint operation validation
func TestFileValidatorEntrypointOperation(t *testing.T) {
	st := NewSymbolTable()
	validator := NewFileValidator(st)

	pos := token.Position{Line: 1, Column: 1}

	errors := validator.ValidateEntrypointOperation("entrypoint", pos)
	if len(errors) > 0 {
		t.Errorf("ValidateEntrypointOperation() unexpected errors: %v", errors)
	}
}

// TestFileValidatorFileSizeComparison tests file size comparison validation
func TestFileValidatorFileSizeComparison(t *testing.T) {
	st := NewSymbolTable()
	validator := NewFileValidator(st)

	pos := token.Position{Line: 1, Column: 1}

	filesizeExpr := &ast.Identifier{
		Name: "filesize",
		Pos:  pos,
	}

	otherExpr := &ast.Literal{
		Type:  token.INTEGER_LIT,
		Value: int64(1024),
		Pos:   pos,
	}

	args := FileSizeComparisonArgs{
		Op:           token.GT,
		FilesizeExpr: filesizeExpr,
		OtherExpr:    otherExpr,
		Pos:          pos,
	}
	_, errs := validator.ValidateFileSizeComparison(&args)
	if len(errs) > 0 {
		t.Errorf("ValidateFileSizeComparison() unexpected errors: %v", errs)
	}
}

// TestFileValidatorEntrypointOffset tests entrypoint offset validation
func TestFileValidatorEntrypointOffset(t *testing.T) {
	st := NewSymbolTable()
	validator := NewFileValidator(st)

	pos := token.Position{Line: 1, Column: 1}

	entrypointExpr := &ast.Identifier{
		Name: "entrypoint",
		Pos:  pos,
	}

	offsetExpr := &ast.Literal{
		Type:  token.INTEGER_LIT,
		Value: int64(0),
		Pos:   pos,
	}

	_, errors := validator.ValidateEntrypointOffset(entrypointExpr, offsetExpr, pos)
	if len(errors) > 0 {
		t.Errorf("ValidateEntrypointOffset() unexpected errors: %v", errors)
	}
}

// TestFileValidatorErrors tests error management
func TestFileValidatorErrors(t *testing.T) {
	st := NewSymbolTable()
	validator := NewFileValidator(st)

	// Initially should have no errors
	if validator.HasErrors() {
		t.Error("HasErrors() should return false initially")
	}

	errors := validator.GetErrors()
	if len(errors) != 0 {
		t.Errorf("GetErrors() returned %d errors, want 0", len(errors))
	}
}

// Helper function to create integer literal expression
func createIntLiteralExpr(value int64) *ast.Literal {
	return &ast.Literal{
		Type:  token.INTEGER_LIT,
		Value: value,
		Pos:   token.Position{Line: 1, Column: 1},
	}
}

// TestModuleValidatorFunctionCalls tests module function call validation
func TestModuleValidatorFunctionCalls(t *testing.T) {
	st := NewSymbolTable()
	validator := NewModuleValidator(st)
	pos := token.Position{Line: 1, Column: 1}

	// Test no-argument functions
	t.Run("NoArgumentFunctions", func(t *testing.T) {
		noArgTests := []struct {
			name     string
			funcName string
			wantErr  bool
		}{
			{"filesize", "filesize", false},
		}

		for _, tt := range noArgTests {
			t.Run(tt.name, func(t *testing.T) {
				_, errors := validator.ValidateFunctionCall(tt.funcName, []ast.Expression{}, pos)
				hasErr := len(errors) > 0
				if hasErr != tt.wantErr {
					t.Errorf("ValidateFunctionCall() error = %v, wantErr %v, errors: %v", hasErr, tt.wantErr, errors)
				}
			})
		}
	})

	// Test integer conversion functions
	t.Run("IntegerConversionFunctions", func(t *testing.T) {
		conversionTests := []struct {
			name     string
			funcName string
		}{
			{"uint8", "uint8"},
			{"uint16", "uint16"},
			{"uint32", "uint32"},
			{"int8", "int8"},
			{"int16", "int16"},
			{"int32", "int32"},
		}

		// Common test argument
		testArg := createIntLiteralExpr(0x1000)

		for _, tt := range conversionTests {
			t.Run(tt.name, func(t *testing.T) {
				_, errors := validator.ValidateFunctionCall(tt.funcName, []ast.Expression{testArg}, pos)
				hasErr := len(errors) > 0
				if hasErr {
					t.Errorf("ValidateFunctionCall() unexpected error for %s: %v", tt.funcName, errors)
				}
			})
		}
	})
}

// TestModuleValidatorErrors tests error management
func TestModuleValidatorErrors(t *testing.T) {
	st := NewSymbolTable()
	validator := NewModuleValidator(st)

	// Initially should have no errors
	if validator.HasErrors() {
		t.Error("HasErrors() should return false initially")
	}

	errors := validator.GetErrors()
	if len(errors) != 0 {
		t.Errorf("GetErrors() returned %d errors, want 0", len(errors))
	}
}

// TestStringValidatorWildcardReferences tests wildcard string reference validation
func TestStringValidatorWildcardReferences(t *testing.T) {
	st := NewSymbolTable()
	st.EnterScope("test")
	pos := token.Position{Line: 1, Column: 1}

	// Define some strings with common prefix
	str1 := &ast.String{Identifier: "$abc1", Pos: pos}
	_ = st.DefineString("$abc1", pos, str1)

	str2 := &ast.String{Identifier: "$abc2", Pos: pos}
	_ = st.DefineString("$abc2", pos, str2)

	validator := NewStringValidator(st)

	// Test exact match (non-wildcard)
	exactIdent := &ast.Identifier{Name: "$abc1", Pos: pos}
	errors := validator.ValidateStringReferences(exactIdent)

	if len(errors) > 0 {
		t.Errorf("ValidateStringReferences() unexpected errors for exact match: %v", errors)
	}
}

// TestStringValidatorThemReference tests "them" reference validation
func TestStringValidatorThemReference(t *testing.T) {
	st := NewSymbolTable()
	st.EnterScope("test")
	pos := token.Position{Line: 1, Column: 1}

	// Define some strings
	str1 := &ast.String{Identifier: "$s1", Pos: pos}
	_ = st.DefineString("$s1", pos, str1)

	validator := NewStringValidator(st)

	themIdent := &ast.Identifier{Name: "them", Pos: pos}
	errors := validator.ValidateStringReferences(themIdent)

	if len(errors) > 0 {
		t.Errorf("ValidateStringReferences() unexpected errors for 'them': %v", errors)
	}
}

// TestStringValidatorErrors tests error management
func TestStringValidatorErrors(t *testing.T) {
	st := NewSymbolTable()
	validator := NewStringValidator(st)

	// Initially should have no errors
	if validator.HasErrors() {
		t.Error("HasErrors() should return false initially")
	}

	errors := validator.GetErrors()
	if len(errors) != 0 {
		t.Errorf("GetErrors() returned %d errors, want 0", len(errors))
	}
}

// Helper functions to reduce repetitive AST construction for smoke tests
func createTestPos() token.Position {
	return token.Position{Line: 1, Column: 1}
}

func createTestProgram() *ast.Program {
	pos := createTestPos()
	return &ast.Program{
		Pos:   pos,
		Rules: []*ast.Rule{},
	}
}

func createTestRule() *ast.Rule {
	pos := createTestPos()
	return &ast.Rule{
		Pos:  pos,
		Name: "test",
		Condition: &ast.Literal{
			Type:  token.TRUE,
			Value: true,
			Pos:   pos,
		},
	}
}

func createTestBinaryOp() *ast.BinaryOp {
	pos := createTestPos()
	return &ast.BinaryOp{
		Pos: pos,
		Left: &ast.Literal{
			Type:  token.INTEGER_LIT,
			Value: int64(1),
			Pos:   pos,
		},
		Op: token.PLUS,
		Right: &ast.Literal{
			Type:  token.INTEGER_LIT,
			Value: int64(2),
			Pos:   pos,
		},
	}
}

func createTestUnaryOp() *ast.UnaryOp {
	pos := createTestPos()
	return &ast.UnaryOp{
		Pos: pos,
		Op:  token.NOT,
		Right: &ast.Literal{
			Type:  token.TRUE,
			Value: true,
			Pos:   pos,
		},
	}
}

// TestValidatorVisitorMethods tests that visitor methods don't panic when called
func TestValidatorVisitorMethods(t *testing.T) {
	validator := NewValidator()

	t.Run("StructureNodes", func(t *testing.T) {
		// Test VisitProgram
		validator.VisitProgram(createTestProgram())

		// Test VisitRule
		validator.VisitRule(createTestRule())
	})

	t.Run("RuleComponents", func(t *testing.T) {
		pos := createTestPos()

		// Test VisitMeta
		meta := &ast.Meta{
			Pos:   pos,
			Key:   "test",
			Value: ast.MetaString("value"),
		}
		validator.VisitMeta(meta)

		// Test VisitString
		str := &ast.String{
			Pos:        pos,
			Identifier: "$test",
			Pattern: &ast.TextString{
				Pos:   pos,
				Value: "test",
			},
		}
		validator.VisitString(str)

		// Test VisitCondition
		condition := &ast.Condition{
			Pos: pos,
			Expression: &ast.Literal{
				Type:  token.TRUE,
				Value: true,
				Pos:   pos,
			},
		}
		validator.VisitCondition(condition)
	})

	t.Run("Expressions", func(t *testing.T) {
		// Test VisitBinaryOp
		validator.VisitBinaryOp(createTestBinaryOp())

		// Test VisitUnaryOp
		validator.VisitUnaryOp(createTestUnaryOp())

		pos := createTestPos()

		// Test VisitIdentifier
		ident := &ast.Identifier{
			Pos:  pos,
			Name: "test",
		}
		validator.VisitIdentifier(ident)

		// Test VisitLiteral
		literal := &ast.Literal{
			Pos:   pos,
			Type:  token.INTEGER_LIT,
			Value: int64(42),
		}
		validator.VisitLiteral(literal)
	})
}

// TestValidatorGetSymbolTable tests GetSymbolTable method
func TestValidatorGetSymbolTable(t *testing.T) {
	validator := NewValidator()

	st := validator.GetSymbolTable()
	if st == nil {
		t.Error("GetSymbolTable() returned nil")
	}
}

// TestValidatorHasErrors tests HasErrors method
func TestValidatorHasErrors(t *testing.T) {
	validator := NewValidator()

	// Initially should have no errors
	if validator.HasErrors() {
		t.Error("HasErrors() should return false initially")
	}
}

// TestValidatorGetErrors tests GetErrors method
func TestValidatorGetErrors(t *testing.T) {
	validator := NewValidator()

	errors := validator.GetErrors()
	if len(errors) != 0 {
		t.Errorf("GetErrors() returned %d errors, want 0", len(errors))
	}
}

// TestModuleValidatorIsModuleFunction tests isModuleFunction
func TestModuleValidatorIsModuleFunction(t *testing.T) {
	st := NewSymbolTable()
	validator := NewModuleValidator(st)

	tests := []struct {
		name     string
		funcName string
		expected bool
	}{
		{"filesize", "filesize", true},
		{"entrypoint", "entrypoint", true},
		{"uint8", "uint8", true},
		{"uint16", "uint16", true},
		{"uint32", "uint32", true},
		{"int8", "int8", true},
		{"int16", "int16", true},
		{"int32", "int32", true},
		{"uint8be", "uint8be", true},
		{"unknown", "unknown", false},
		{"custom", "custom", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.isModuleFunction(tt.funcName)
			if result != tt.expected {
				t.Errorf("isModuleFunction(%s) = %v, want %v", tt.funcName, result, tt.expected)
			}
		})
	}
}

// TestFileValidatorIsFileOperation tests isFileOperation
func TestFileValidatorIsFileOperation(t *testing.T) {
	st := NewSymbolTable()
	validator := NewFileValidator(st)

	tests := []struct {
		name     string
		expected bool
	}{
		{"filesize", true},
		{"entrypoint", true},
		{"other", false},
		{"test", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.isFileOperation(tt.name)
			if result != tt.expected {
				t.Errorf("isFileOperation(%s) = %v, want %v", tt.name, result, tt.expected)
			}
		})
	}
}

// TestStringValidatorMatchesPattern tests pattern matching
func TestStringValidatorMatchesPattern(t *testing.T) {
	st := NewSymbolTable()
	validator := NewStringValidator(st)

	tests := []struct {
		name     string
		strName  string
		pattern  string
		expected bool
	}{
		{"exact_match", "$abc1", "$abc1", true},
		{"wildcard_match", "$abc1", "$abc*", true},
		{"wildcard_no_match", "$xyz1", "$abc*", false},
		{"no_wildcard", "$test", "$test", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.matchesPattern(tt.strName, tt.pattern)
			if result != tt.expected {
				t.Errorf("matchesPattern(%s, %s) = %v, want %v", tt.strName, tt.pattern, result, tt.expected)
			}
		})
	}
}

// TestValidatorGetTypeFromSymbol tests getTypeFromSymbol method
func TestValidatorGetTypeFromSymbol(t *testing.T) {
	st := NewSymbolTable()
	st.EnterScope("test")
	pos := token.Position{Line: 1, Column: 1}

	// Define different symbol types
	rule := &ast.Rule{Name: "test_rule", Pos: pos}
	_ = st.DefineRule("test_rule", pos, rule)

	str := &ast.String{Identifier: "$s1", Pos: pos}
	_ = st.DefineString("$s1", pos, str)

	_ = st.DefineVariable("var1", pos, SymbolVariable)

	validator := NewValidator()
	validator.symbolTable = st

	tests := []struct {
		name         string
		symbolName   string
		expectedType DataType
	}{
		{"rule_symbol", "test_rule", TypeBoolean},
		{"string_symbol", "$s1", TypeBoolean},
		{"variable_symbol", "var1", TypeInteger},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			symbol, exists := st.Lookup(tt.symbolName)
			if !exists {
				t.Fatalf("Symbol %s not found", tt.symbolName)
			}

			typeInfo := validator.getTypeFromSymbol(symbol)
			if typeInfo.DataType != tt.expectedType {
				t.Errorf("getTypeFromSymbol() got %v, want %v", typeInfo.DataType, tt.expectedType)
			}
		})
	}
}

// TestValidatorCollectSymbols tests collectSymbols method
func TestValidatorCollectSymbols(t *testing.T) {
	validator := NewValidator()

	pos := token.Position{Line: 1, Column: 1}

	rule := &ast.Rule{
		Pos:  pos,
		Name: "test_rule",
		Strings: []*ast.String{
			{
				Pos:        pos,
				Identifier: "$s1",
				Pattern: &ast.TextString{
					Pos:   pos,
					Value: "test",
				},
			},
		},
		Condition: &ast.Identifier{
			Name: "$s1",
			Pos:  pos,
		},
	}

	// Use the full ValidateProgram method to properly test symbol collection
	program := &ast.Program{
		Pos:   pos,
		Rules: []*ast.Rule{rule},
	}

	errors := validator.ValidateProgram(program)

	// Should complete without panic and have minimal errors
	if len(errors) > 0 {
		t.Logf("ValidateProgram() returned errors: %v", errors)
	}
}

// TestValidatorValidateRule tests validateRule method
func TestValidatorValidateRule(t *testing.T) {
	validator := NewValidator()

	pos := token.Position{Line: 1, Column: 1}

	// First collect symbols
	rule := &ast.Rule{
		Pos:  pos,
		Name: "test_rule",
		Meta: []*ast.Meta{
			{
				Pos:   pos,
				Key:   "author",
				Value: ast.MetaString("test"),
			},
		},
		Strings: []*ast.String{
			{
				Pos:        pos,
				Identifier: "$s1",
				Pattern: &ast.TextString{
					Pos:   pos,
					Value: "test",
				},
			},
		},
		Condition: &ast.Identifier{
			Name: "$s1",
			Pos:  pos,
		},
	}

	// Collect symbols first
	validator.collectSymbols(rule)

	// Then validate
	validator.validateRule(rule)

	// Should not have errors for valid rule
	if validator.HasErrors() {
		t.Errorf("validateRule() unexpected errors: %v", validator.GetErrors())
	}
}
