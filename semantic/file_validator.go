package semantic

import (
	"fmt"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

// FileValidator handles validation of file operation keywords
type FileValidator struct {
	symbolTable *SymbolTable
	errors      []error
}

const (
	filesizeKeyword   = "filesize"
	entrypointKeyword = "entrypoint"
	flagsKeyword      = "flags"
)

// NewFileValidator creates a new file validator
func NewFileValidator(symbolTable *SymbolTable) *FileValidator {
	return &FileValidator{
		symbolTable: symbolTable,
		errors:      make([]error, 0),
	}
}

// ValidateFileOperations validates all file operation keywords in expressions
func (fv *FileValidator) ValidateFileOperations(expr ast.Expression) []error {
	fv.errors = fv.errors[:0] // Clear previous errors
	fv.collectFileOperations(expr)
	return fv.errors
}

// collectFileOperations recursively collects file operation keywords
func (fv *FileValidator) collectFileOperations(expr ast.Expression) {
	switch e := expr.(type) {
	case *ast.Identifier:
		// Check if this is a file operation keyword
		if fv.isFileOperation(e.Name) {
			fv.validateFileOperation(e.Name, e.Position())
		}

	case *ast.BinaryOp:
		fv.collectFileOperations(e.Left)
		fv.collectFileOperations(e.Right)

	case *ast.UnaryOp:
		fv.collectFileOperations(e.Right)

	default:
		// For other expression types, no file operations to collect
	}
}

// isFileOperation checks if an identifier is a file operation keyword
func (fv *FileValidator) isFileOperation(name string) bool {
	return name == filesizeKeyword || name == entrypointKeyword
}

// validateFileOperation validates a file operation keyword
func (fv *FileValidator) validateFileOperation(opName string, pos token.Position) {
	switch opName {
	case filesizeKeyword:
		fv.validateFilesizeUsage(pos)
	case entrypointKeyword:
		fv.validateEntrypointUsage(pos)
	default:
		fv.addError(&Error{
			Message:  "unknown file operation: " + opName,
			Position: pos,
		})
	}
}

// validateFilesizeUsage validates the usage of the filesize keyword
func (fv *FileValidator) validateFilesizeUsage(_ token.Position) {
	// filesize is always available in any rule context
	// No special validation needed beyond type checking
}

// validateEntrypointUsage validates the usage of the entrypoint keyword
func (fv *FileValidator) validateEntrypointUsage(_ token.Position) {
	// entrypoint is always available in any rule context
	// No special validation needed beyond type checking
}

// ValidateFilesizeOperation validates a filesize operation in context
func (fv *FileValidator) ValidateFilesizeOperation(operation string, pos token.Position) []error {
	var errors []error

	switch operation {
	case filesizeKeyword:
		// filesize is a simple keyword reference
		// Validation is handled by type checking
		return errors

	default:
		errors = append(errors, &Error{
			Message:  "invalid filesize operation: " + operation,
			Position: pos,
		})
		return errors
	}
}

// ValidateEntrypointOperation validates an entrypoint operation in context
func (fv *FileValidator) ValidateEntrypointOperation(operation string, pos token.Position) []error {
	var errors []error

	switch operation {
	case entrypointKeyword:
		// entrypoint is a simple keyword reference
		// Validation is handled by type checking
		return errors

	default:
		errors = append(errors, &Error{
			Message:  "invalid entrypoint operation: " + operation,
			Position: pos,
		})
		return errors
	}
}

// FileSizeComparisonArgs contains arguments for filesize comparison validation
type FileSizeComparisonArgs struct {
	Op           token.TokenType
	FilesizeExpr ast.Expression
	OtherExpr    ast.Expression
	Pos          token.Position
}

// ValidateFileSizeComparison validates filesize comparison operations
func (fv *FileValidator) ValidateFileSizeComparison(args *FileSizeComparisonArgs) (*TypeInfo, []error) {
	var errors []error

	// Validate that the left side is filesize
	filesizeType := fv.getFilesizeType(args.FilesizeExpr)
	if filesizeType == nil {
		errors = append(errors, &Error{
			Message:  "left operand must be filesize",
			Position: args.Pos,
		})
		return &TypeInfo{DataType: TypeUnknown}, errors
	}

	// Validate that the right side is a compatible type
	otherType, otherErrors := fv.validateComparisonOperand(args.OtherExpr)
	errors = append(errors, otherErrors...)

	if otherType != nil {
		// Check type compatibility
		if !filesizeType.CanCompare(otherType) {
			errors = append(errors, &Error{
				Message:  fmt.Sprintf("cannot compare filesize (%s) with %s", filesizeType.String(), otherType.String()),
				Position: args.Pos,
			})
			return &TypeInfo{DataType: TypeUnknown}, errors
		}
	}

	return &TypeInfo{DataType: TypeBoolean}, errors
}

// ValidateEntrypointOffset validates entrypoint offset operations
func (fv *FileValidator) ValidateEntrypointOffset(entrypointExpr, offsetExpr ast.Expression, pos token.Position) (*TypeInfo, []error) {
	var errors []error

	// Validate that the left side is entrypoint
	entrypointType := fv.getEntrypointType(entrypointExpr)
	if entrypointType == nil {
		errors = append(errors, &Error{
			Message:  "left operand must be entrypoint",
			Position: pos,
		})
		return &TypeInfo{DataType: TypeUnknown}, errors
	}

	// Validate that the offset is an integer
	offsetType, offsetErrors := fv.validateOffsetOperand(offsetExpr)
	errors = append(errors, offsetErrors...)

	if offsetType != nil && !offsetType.IsInteger() {
		errors = append(errors, &Error{
			Message:  "entrypoint offset must be an integer",
			Position: pos,
		})
		return &TypeInfo{DataType: TypeUnknown}, errors
	}

	// Result is still an integer (entrypoint + offset)
	return &TypeInfo{DataType: TypeInteger, IntegerType: Uint64Type}, errors
}

// getFilesizeType checks if an expression refers to filesize
func (fv *FileValidator) getFilesizeType(expr ast.Expression) *TypeInfo {
	ident, ok := expr.(*ast.Identifier)
	if ok && ident.Name == filesizeKeyword {
		return &TypeInfo{DataType: TypeInteger, IntegerType: Uint64Type}
	}
	return nil
}

// getEntrypointType checks if an expression refers to entrypoint
func (fv *FileValidator) getEntrypointType(expr ast.Expression) *TypeInfo {
	ident, ok := expr.(*ast.Identifier)
	if ok && ident.Name == entrypointKeyword {
		return &TypeInfo{DataType: TypeInteger, IntegerType: Uint64Type}
	}
	return nil
}

// validateComparisonOperand validates an operand in a comparison
func (fv *FileValidator) validateComparisonOperand(expr ast.Expression) (*TypeInfo, []error) {
	// Create a temporary type checker for this
	checker := NewTypeChecker(fv.symbolTable)
	return checker.CheckExpressionTypes(expr)
}

// validateOffsetOperand validates an offset operand
func (fv *FileValidator) validateOffsetOperand(expr ast.Expression) (*TypeInfo, []error) {
	// Create a temporary type checker for this
	checker := NewTypeChecker(fv.symbolTable)
	return checker.CheckExpressionTypes(expr)
}

// addError adds a validation error
func (fv *FileValidator) addError(err error) {
	fv.errors = append(fv.errors, err)
}

// GetErrors returns all validation errors
func (fv *FileValidator) GetErrors() []error {
	return fv.errors
}

// HasErrors returns true if there are validation errors
func (fv *FileValidator) HasErrors() bool {
	return len(fv.errors) > 0
}
