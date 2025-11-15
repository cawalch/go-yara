package semantic

import (
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

func TestFileValidatorValidateFilesizeOperation(t *testing.T) {
	st := NewSymbolTable()
	fv := NewFileValidator(st)

	pos := token.Position{Line: 1, Column: 1}

	// Test valid filesize operation
	errors := fv.ValidateFilesizeOperation("filesize", pos)
	if len(errors) > 0 {
		t.Errorf("ValidateFilesizeOperation() unexpected errors: %v", errors)
	}

	// Test invalid operation
	errors = fv.ValidateFilesizeOperation("invalid", pos)
	if len(errors) == 0 {
		t.Error("ValidateFilesizeOperation() expected errors for invalid operation")
	}
}

func TestFileValidatorValidateEntrypointOperation(t *testing.T) {
	st := NewSymbolTable()
	fv := NewFileValidator(st)

	pos := token.Position{Line: 1, Column: 1}

	// Test valid entrypoint operation
	errors := fv.ValidateEntrypointOperation("entrypoint", pos)
	if len(errors) > 0 {
		t.Errorf("ValidateEntrypointOperation() unexpected errors: %v", errors)
	}

	// Test invalid operation
	errors = fv.ValidateEntrypointOperation("invalid", pos)
	if len(errors) == 0 {
		t.Error("ValidateEntrypointOperation() expected errors for invalid operation")
	}
}

func TestFileValidatorValidateFileSizeComparison(t *testing.T) {
	st := NewSymbolTable()
	fv := NewFileValidator(st)

	pos := token.Position{Line: 1, Column: 1}

	// Test valid comparison
	filesizeExpr := &ast.Identifier{Name: "filesize", Pos: pos}
	otherExpr := &ast.Literal{Type: token.IntegerLit, Value: int64(1024), Pos: pos}

	args := FileSizeComparisonArgs{
		Op:           token.GT,
		FilesizeExpr: filesizeExpr,
		OtherExpr:    otherExpr,
		Pos:          pos,
	}
	typeInfo, errors := fv.ValidateFileSizeComparison(&args)
	if len(errors) > 0 {
		t.Errorf("ValidateFileSizeComparison() unexpected errors: %v", errors)
	}
	if typeInfo.DataType != TypeBoolean {
		t.Errorf("ValidateFileSizeComparison() wrong return type")
	}

	// Test invalid left operand
	invalidExpr := &ast.Literal{Type: token.StringLit, Value: "invalid", Pos: pos}
	invalidArgs := FileSizeComparisonArgs{
		Op:           token.GT,
		FilesizeExpr: invalidExpr,
		OtherExpr:    otherExpr,
		Pos:          pos,
	}
	_, errors = fv.ValidateFileSizeComparison(&invalidArgs)
	if len(errors) == 0 {
		t.Error("ValidateFileSizeComparison() expected errors for invalid left operand")
	}
}

func TestFileValidatorValidateEntrypointOffset(t *testing.T) {
	st := NewSymbolTable()
	fv := NewFileValidator(st)

	pos := token.Position{Line: 1, Column: 1}

	// Test valid offset
	entrypointExpr := &ast.Identifier{Name: "entrypoint", Pos: pos}
	offsetExpr := &ast.Literal{Type: token.IntegerLit, Value: int64(0x1000), Pos: pos}

	typeInfo, errors := fv.ValidateEntrypointOffset(entrypointExpr, offsetExpr, pos)
	if len(errors) > 0 {
		t.Errorf("ValidateEntrypointOffset() unexpected errors: %v", errors)
	}
	if typeInfo.DataType != TypeInteger {
		t.Errorf("ValidateEntrypointOffset() wrong return type")
	}

	// Test invalid offset type
	invalidOffset := &ast.Literal{Type: token.StringLit, Value: "invalid", Pos: pos}
	_, errors = fv.ValidateEntrypointOffset(entrypointExpr, invalidOffset, pos)
	if len(errors) == 0 {
		t.Error("ValidateEntrypointOffset() expected errors for invalid offset type")
	}
}

func TestFileValidatorValidateFileOperations(t *testing.T) {
	st := NewSymbolTable()
	fv := NewFileValidator(st)

	pos := token.Position{Line: 1, Column: 1}

	// Test with filesize
	expr := &ast.Identifier{Name: "filesize", Pos: pos}
	errors := fv.ValidateFileOperations(expr)
	if len(errors) > 0 {
		t.Errorf("ValidateFileOperations() unexpected errors: %v", errors)
	}

	// Test with entrypoint
	expr = &ast.Identifier{Name: "entrypoint", Pos: pos}
	errors = fv.ValidateFileOperations(expr)
	if len(errors) > 0 {
		t.Errorf("ValidateFileOperations() unexpected errors: %v", errors)
	}

	// Test with binary op containing filesize
	binOp := &ast.BinaryOp{
		Op:    token.GT,
		Left:  &ast.Identifier{Name: "filesize", Pos: pos},
		Right: &ast.Literal{Type: token.IntegerLit, Value: int64(1024), Pos: pos},
	}
	errors = fv.ValidateFileOperations(binOp)
	if len(errors) > 0 {
		t.Errorf("ValidateFileOperations() unexpected errors: %v", errors)
	}
}
