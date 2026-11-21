// Package opcoderef provides shared AST/types helpers for compiler opcode analyzers.
package opcoderef

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// Ref identifies an opcode constant referenced in AST.
type Ref struct {
	Name  string
	Value uint64
	Expr  ast.Expr
}

// FindNamedType returns the named type with the given name in pass.Pkg, or nil.
func FindNamedType(pass *analysis.Pass, name string) *types.Named {
	typeName, ok := pass.Pkg.Scope().Lookup(name).(*types.TypeName)
	if !ok {
		return nil
	}
	named, _ := typeName.Type().(*types.Named)
	return named
}

// Constant resolves expression to an opcode constant reference when applicable.
func Constant(pass *analysis.Pass, opcodeType *types.Named, expression ast.Expr) (Ref, bool) {
	identifier, ok := expression.(*ast.Ident)
	if !ok {
		return Ref{}, false
	}
	object, ok := pass.TypesInfo.Uses[identifier].(*types.Const)
	if !ok || !IsConstant(opcodeType, object) {
		return Ref{}, false
	}
	value, ok := constant.Uint64Val(constant.ToInt(object.Val()))
	if !ok {
		return Ref{}, false
	}
	return Ref{Name: object.Name(), Value: value, Expr: expression}, true
}

// IsConstant reports whether object is an Opcode constant or untyped Op* integer constant.
func IsConstant(opcodeType *types.Named, object *types.Const) bool {
	if types.Identical(object.Type(), opcodeType) {
		return true
	}
	basic, ok := object.Type().(*types.Basic)
	return ok &&
		basic.Info()&types.IsInteger != 0 &&
		basic.Info()&types.IsUntyped != 0 &&
		strings.HasPrefix(object.Name(), "Op") &&
		object.Pkg() == opcodeType.Obj().Pkg()
}

// Dereference unwraps a pointer type if present.
func Dereference(valueType types.Type) types.Type {
	if pointer, ok := valueType.(*types.Pointer); ok {
		return pointer.Elem()
	}
	return valueType
}

// IsIdentifier reports whether expression is an *ast.Ident with the given name.
func IsIdentifier(expression ast.Expr, name string) bool {
	identifier, ok := expression.(*ast.Ident)
	return ok && identifier.Name == name
}

// IsTestFile reports whether position belongs to a *_test.go file.
func IsTestFile(pass *analysis.Pass, position token.Pos) bool {
	filename := pass.Fset.PositionFor(position, false).Filename
	return strings.HasSuffix(filepath.Base(filename), "_test.go")
}
