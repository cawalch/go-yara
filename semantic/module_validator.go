// Package semantic implements semantic analysis and validation for YARA rules.
package semantic

import (
	"fmt"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

// ModuleValidator handles validation of module functions and file operations
type ModuleValidator struct {
	symbolTable *SymbolTable
	errors      []error
}

// NewModuleValidator creates a new module validator
func NewModuleValidator(symbolTable *SymbolTable) *ModuleValidator {
	return &ModuleValidator{
		symbolTable: symbolTable,
		errors:      make([]error, 0),
	}
}

// ValidateModuleFunctions validates all module function calls in expressions
func (mv *ModuleValidator) ValidateModuleFunctions(expr ast.Expression) []error {
	mv.errors = mv.errors[:0] // Clear previous errors
	mv.collectModuleFunctions(expr)
	return mv.errors
}

// collectModuleFunctions recursively collects module function calls
func (mv *ModuleValidator) collectModuleFunctions(expr ast.Expression) {
	switch e := expr.(type) {
	case *ast.BinaryOp:
		mv.collectModuleFunctions(e.Left)
		mv.collectModuleFunctions(e.Right)

	case *ast.UnaryOp:
		mv.collectModuleFunctions(e.Right)

	case *ast.Identifier:
		// Check if this is a module function call
		if mv.isModuleFunction(e.Name) {
			mv.validateModuleFunction(e.Name, e.Position())
		}

	default:
		// For other expression types, no module functions to collect
	}
}

// isModuleFunction checks if an identifier is a module function
func (mv *ModuleValidator) isModuleFunction(name string) bool {
	// List of known module functions that need validation
	moduleFunctions := []string{
		// Data type functions
		"uint8", "uint16", "uint32", "uint64",
		"int8", "int16", "int32", "int64",
		"uint8be", "uint16be", "uint32be", "uint64be",
		"int8be", "int16be", "int32be", "int64be",

		// File operations
		"filesize", "entrypoint",
	}

	for _, funcName := range moduleFunctions {
		if name == funcName {
			return true
		}
	}

	return false
}

// validateModuleFunction validates a module function call
func (mv *ModuleValidator) validateModuleFunction(funcName string, pos token.Position) {
	switch funcName {
	case filesizeKeyword:
		mv.validateFilesize(pos)
	case entrypointKeyword:
		mv.validateEntrypoint(pos)
	default:
		// Data type functions (uint32, int16be, etc.)
		mv.validateDataTypeFunction(funcName, pos)
	}
}

// validateFilesize validates the filesize function
func (mv *ModuleValidator) validateFilesize(pos token.Position) {
	// filesize is always available and returns uint64
	// No special validation needed beyond type checking
}

// validateEntrypoint validates the entrypoint function
func (mv *ModuleValidator) validateEntrypoint(pos token.Position) {
	// entrypoint is always available and returns uint64
	// No special validation needed beyond type checking
}

// validateDataTypeFunction validates data type function calls
func (mv *ModuleValidator) validateDataTypeFunction(funcName string, pos token.Position) {
	// Check if the function exists and is valid
	expectedType, err := GetIntegerTypeFromFunction(funcName)
	if err != nil {
		mv.addError(&SemanticError{
			Message:  fmt.Sprintf("unknown data type function: %s", funcName),
			Position: pos,
		})
		return
	}

	// In a full implementation, we would validate:
	// 1. Function arguments (if any)
	// 2. Context where the function is called
	// 3. Return type compatibility

	// For now, just validate that the function is known
	_ = expectedType // Avoid unused variable error
}

// ValidateFunctionCall validates a function call expression
func (mv *ModuleValidator) ValidateFunctionCall(funcName string, args []ast.Expression, pos token.Position) (*TypeInfo, []error) {
	switch funcName {
	case filesizeKeyword:
		return mv.validateFilesizeCall(args, pos)
	case entrypointKeyword:
		return mv.validateEntrypointCall(args, pos)
	default:
		// Data type functions
		return mv.validateDataTypeFunctionCall(funcName, args, pos)
	}
}

// validateFilesizeCall validates a filesize function call
func (mv *ModuleValidator) validateFilesizeCall(args []ast.Expression, pos token.Position) (*TypeInfo, []error) {
	var errors []error

	// filesize takes no arguments
	if len(args) != 0 {
		errors = append(errors, &SemanticError{
			Message:  "filesize function takes no arguments",
			Position: pos,
		})
		return &TypeInfo{DataType: TypeUnknown}, errors
	}

	return &TypeInfo{DataType: TypeInteger, IntegerType: Uint64Type}, errors
}

// validateEntrypointCall validates an entrypoint function call
func (mv *ModuleValidator) validateEntrypointCall(args []ast.Expression, pos token.Position) (*TypeInfo, []error) {
	var errors []error

	// entrypoint takes no arguments
	if len(args) != 0 {
		errors = append(errors, &SemanticError{
			Message:  "entrypoint function takes no arguments",
			Position: pos,
		})
		return &TypeInfo{DataType: TypeUnknown}, errors
	}

	return &TypeInfo{DataType: TypeInteger, IntegerType: Uint64Type}, errors
}

// validateDataTypeFunctionCall validates a data type function call
func (mv *ModuleValidator) validateDataTypeFunctionCall(funcName string, args []ast.Expression, pos token.Position) (*TypeInfo, []error) {
	var errors []error

	// Most data type functions take exactly one argument (offset)
	if len(args) != 1 {
		errors = append(errors, &SemanticError{
			Message:  fmt.Sprintf("%s function requires exactly one argument", funcName),
			Position: pos,
		})
		return &TypeInfo{DataType: TypeUnknown}, errors
	}

	// Validate the argument type
	argType, argErrors := mv.validateFunctionArgument(args[0])
	errors = append(errors, argErrors...)

	if argType != nil && !argType.IsInteger() {
		errors = append(errors, &SemanticError{
			Message:  fmt.Sprintf("%s function requires integer argument", funcName),
			Position: pos,
		})
		return &TypeInfo{DataType: TypeUnknown}, errors
	}

	// Get the return type for this function
	returnType, err := GetIntegerTypeFromFunction(funcName)
	if err != nil {
		errors = append(errors, &SemanticError{
			Message:  err.Error(),
			Position: pos,
		})
		return &TypeInfo{DataType: TypeUnknown}, errors
	}

	return &TypeInfo{DataType: TypeInteger, IntegerType: returnType}, errors
}

// validateFunctionArgument validates a function argument expression
func (mv *ModuleValidator) validateFunctionArgument(expr ast.Expression) (*TypeInfo, []error) {
	// Create a temporary type checker for this
	checker := NewTypeChecker(mv.symbolTable)
	return checker.CheckExpressionTypes(expr)
}

// addError adds a validation error
func (mv *ModuleValidator) addError(err error) {
	mv.errors = append(mv.errors, err)
}

// GetErrors returns all validation errors
func (mv *ModuleValidator) GetErrors() []error {
	return mv.errors
}

// HasErrors returns true if there are validation errors
func (mv *ModuleValidator) HasErrors() bool {
	return len(mv.errors) > 0
}
