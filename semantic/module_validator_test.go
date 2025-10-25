package semantic

import (
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

func TestModuleValidatorCreation(t *testing.T) {
	symbolTable := NewSymbolTable()
	validator := NewModuleValidator(symbolTable)

	if validator == nil {
		t.Fatal("NewModuleValidator returned nil")
	}

	if validator.symbolTable == nil {
		t.Error("symbolTable is nil")
	}

	if validator.errors == nil {
		t.Error("errors slice is not initialized")
	}
}

func TestValidateModuleFunctions(t *testing.T) {
	symbolTable := NewSymbolTable()
	validator := NewModuleValidator(symbolTable)

	// Test with a simple identifier expression
	pos := token.Position{Line: 1, Column: 1}
	ident := &ast.Identifier{Pos: pos, Name: "filesize"}

	errors := validator.ValidateModuleFunctions(ident)
	if len(errors) != 0 {
		t.Errorf("expected no errors, got %d", len(errors))
	}

	// Test with a binary operation containing module functions
	left := &ast.Identifier{Pos: pos, Name: "filesize"}
	right := &ast.Identifier{Pos: pos, Name: "entrypoint"}
	binOp := &ast.BinaryOp{Pos: pos, Left: left, Op: token.PLUS, Right: right}

	errors = validator.ValidateModuleFunctions(binOp)
	if len(errors) != 0 {
		t.Errorf("expected no errors for binary op, got %d", len(errors))
	}

	// Test with a unary operation containing a module function
	unary := &ast.UnaryOp{Pos: pos, Op: token.NOT, Right: ident}

	errors = validator.ValidateModuleFunctions(unary)
	if len(errors) != 0 {
		t.Errorf("expected no errors for unary op, got %d", len(errors))
	}
}

func TestIsModuleFunction(t *testing.T) {
	symbolTable := NewSymbolTable()
	validator := NewModuleValidator(symbolTable)

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
		{"uint64", "uint64", true},
		{"int8", "int8", true},
		{"int16", "int16", true},
		{"int32", "int32", true},
		{"int64", "int64", true},
		{"uint8be", "uint8be", true},
		{"uint16be", "uint16be", true},
		{"uint32be", "uint32be", true},
		{"uint64be", "uint64be", true},
		{"int8be", "int8be", true},
		{"int16be", "int16be", true},
		{"int32be", "int32be", true},
		{"int64be", "int64be", true},
		{"not_a_module_func", "not_a_module_func", false},
		{"empty", "", false},
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

func TestValidateFilesizeCall(t *testing.T) {
	symbolTable := NewSymbolTable()
	validator := NewModuleValidator(symbolTable)
	pos := token.Position{Line: 1, Column: 1}

	// Test with no arguments (valid)
	typeInfo, errors := validator.validateFilesizeCall([]ast.Expression{}, pos)
	if len(errors) != 0 {
		t.Errorf("expected no errors for filesize with no args, got %d", len(errors))
	}
	if typeInfo.DataType != TypeInteger || typeInfo.IntegerType != Uint64Type {
		t.Errorf("expected uint64 return type, got %v/%v", typeInfo.DataType, typeInfo.IntegerType)
	}

	// Test with arguments (invalid)
	arg := &ast.Identifier{Pos: pos, Name: "test"}
	typeInfo, errors = validator.validateFilesizeCall([]ast.Expression{arg}, pos)
	if len(errors) == 0 {
		t.Error("expected errors for filesize with args, got none")
	}
	if typeInfo.DataType != TypeUnknown {
		t.Errorf("expected unknown type on error, got %v", typeInfo.DataType)
	}
}

func TestValidateEntrypointCall(t *testing.T) {
	symbolTable := NewSymbolTable()
	validator := NewModuleValidator(symbolTable)
	pos := token.Position{Line: 1, Column: 1}

	// Test with no arguments (valid)
	typeInfo, errors := validator.validateEntrypointCall([]ast.Expression{}, pos)
	if len(errors) != 0 {
		t.Errorf("expected no errors for entrypoint with no args, got %d", len(errors))
	}
	if typeInfo.DataType != TypeInteger || typeInfo.IntegerType != Uint64Type {
		t.Errorf("expected uint64 return type, got %v/%v", typeInfo.DataType, typeInfo.IntegerType)
	}

	// Test with arguments (invalid)
	arg := &ast.Identifier{Pos: pos, Name: "test"}
	typeInfo, errors = validator.validateEntrypointCall([]ast.Expression{arg}, pos)
	if len(errors) == 0 {
		t.Error("expected errors for entrypoint with args, got none")
	}
	if typeInfo.DataType != TypeUnknown {
		t.Errorf("expected unknown type on error, got %v", typeInfo.DataType)
	}
}

func TestValidateDataTypeFunctionCall(t *testing.T) {
	symbolTable := NewSymbolTable()
	validator := NewModuleValidator(symbolTable)
	pos := token.Position{Line: 1, Column: 1}

	// Test with valid function and argument
	arg := &ast.Literal{Pos: pos, Type: token.INTEGER_LIT, Value: int64(10)}
	typeInfo, errors := validator.validateDataTypeFunctionCall("uint32", []ast.Expression{arg}, pos)
	if len(errors) != 0 {
		t.Errorf("expected no errors for uint32 with int arg, got %d", len(errors))
	}
	if typeInfo.DataType != TypeInteger {
		t.Errorf("expected integer return type, got %v", typeInfo.DataType)
	}

	// Test with no arguments (invalid)
	typeInfo, errors = validator.validateDataTypeFunctionCall("uint32", []ast.Expression{}, pos)
	if len(errors) == 0 {
		t.Error("expected errors for uint32 with no args, got none")
	}
	if typeInfo.DataType != TypeUnknown {
		t.Errorf("expected unknown type on error, got %v", typeInfo.DataType)
	}

	// Test with too many arguments (invalid)
	args := []ast.Expression{arg, arg}
	typeInfo, errors = validator.validateDataTypeFunctionCall("uint32", args, pos)
	if len(errors) == 0 {
		t.Error("expected errors for uint32 with too many args, got none")
	}
	if typeInfo.DataType != TypeUnknown {
		t.Errorf("expected unknown type on error, got %v", typeInfo.DataType)
	}

	// Test with invalid function name
	typeInfo, errors = validator.validateDataTypeFunctionCall("invalid_func", []ast.Expression{arg}, pos)
	if len(errors) == 0 {
		t.Error("expected errors for invalid function name, got none")
	}
	if typeInfo.DataType != TypeUnknown {
		t.Errorf("expected unknown type on error, got %v", typeInfo.DataType)
	}
}

func TestValidateFunctionCall(t *testing.T) {
	symbolTable := NewSymbolTable()
	validator := NewModuleValidator(symbolTable)
	pos := token.Position{Line: 1, Column: 1}

	// Test filesize
	typeInfo, errors := validator.ValidateFunctionCall("filesize", []ast.Expression{}, pos)
	if len(errors) != 0 {
		t.Errorf("expected no errors for filesize, got %d", len(errors))
	}
	if typeInfo.DataType != TypeInteger || typeInfo.IntegerType != Uint64Type {
		t.Errorf("expected uint64 return type for filesize, got %v/%v", typeInfo.DataType, typeInfo.IntegerType)
	}

	// Test entrypoint
	typeInfo, errors = validator.ValidateFunctionCall("entrypoint", []ast.Expression{}, pos)
	if len(errors) != 0 {
		t.Errorf("expected no errors for entrypoint, got %d", len(errors))
	}
	if typeInfo.DataType != TypeInteger || typeInfo.IntegerType != Uint64Type {
		t.Errorf("expected uint64 return type for entrypoint, got %v/%v", typeInfo.DataType, typeInfo.IntegerType)
	}

	// Test data type function
	arg := &ast.Literal{Pos: pos, Type: token.INTEGER_LIT, Value: int64(10)}
	typeInfo, errors = validator.ValidateFunctionCall("uint32", []ast.Expression{arg}, pos)
	if len(errors) != 0 {
		t.Errorf("expected no errors for uint32, got %d", len(errors))
	}
	if typeInfo.DataType != TypeInteger {
		t.Errorf("expected integer return type for uint32, got %v", typeInfo.DataType)
	}
}

func TestModuleValidatorErrorManagement(t *testing.T) {
	symbolTable := NewSymbolTable()
	validator := NewModuleValidator(symbolTable)

	// Initially should have no errors
	if validator.HasErrors() {
		t.Error("expected no errors initially")
	}

	if len(validator.GetErrors()) != 0 {
		t.Errorf("expected 0 errors initially, got %d", len(validator.GetErrors()))
	}

	// Add an error
	pos := token.Position{Line: 1, Column: 1}
	err := &SemanticError{Message: "test error", Position: pos}
	validator.addError(err)

	if !validator.HasErrors() {
		t.Error("expected to have errors after adding one")
	}

	errors := validator.GetErrors()
	if len(errors) != 1 {
		t.Errorf("expected 1 error after adding, got %d", len(errors))
	}

	if errors[0] != err {
		t.Error("retrieved error doesn't match added error")
	}
}
