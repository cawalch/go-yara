// Package opcodecontract defines an analyzer for compiler opcode invariants.
package opcodecontract

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

// Analyzer verifies that emitted opcodes have dispatch handlers and that every
// dispatched opcode has a stable name.
var Analyzer = &analysis.Analyzer{
	Name:     "opcodecontract",
	Doc:      "checks compiler opcode dispatch and naming contracts",
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

type opcodeRef struct {
	name  string
	value uint64
	expr  ast.Expr
}

type contractChecker struct {
	pass          *analysis.Pass
	inspectResult *inspector.Inspector
	opcodeType    *types.Named
}

func run(pass *analysis.Pass) (any, error) {
	opcodeType := findOpcodeType(pass)
	if opcodeType == nil {
		return nil, nil
	}

	checker := contractChecker{
		pass:          pass,
		inspectResult: pass.ResultOf[inspect.Analyzer].(*inspector.Inspector),
		opcodeType:    opcodeType,
	}
	names := checker.collectOpcodeNames()
	handlers := checker.collectOpcodeHandlers()

	for value, handler := range handlers {
		if _, ok := names[value]; !ok {
			checker.pass.Reportf(
				handler.expr.Pos(),
				"dispatched opcode %s has no opcodeNames entry",
				handler.name,
			)
		}
	}

	checker.checkEmittedOpcodes(handlers)
	return nil, nil
}

func findOpcodeType(pass *analysis.Pass) *types.Named {
	typeName, ok := pass.Pkg.Scope().Lookup("Opcode").(*types.TypeName)
	if !ok {
		return nil
	}
	opcodeType, _ := typeName.Type().(*types.Named)
	return opcodeType
}

func (checker *contractChecker) collectOpcodeNames() map[uint64]opcodeRef {
	names := make(map[uint64]opcodeRef)
	checker.inspectResult.Preorder([]ast.Node{(*ast.GenDecl)(nil)}, func(node ast.Node) {
		decl := node.(*ast.GenDecl)
		for _, spec := range decl.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for index, name := range valueSpec.Names {
				if name.Name != "opcodeNames" || index >= len(valueSpec.Values) {
					if index < len(valueSpec.Values) {
						checker.addRangeOpcodeNames(names, name.Name, valueSpec.Values[index])
					}
					continue
				}
				literal, ok := valueSpec.Values[index].(*ast.CompositeLit)
				if !ok {
					continue
				}
				for _, element := range literal.Elts {
					entry, ok := element.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if ref, ok := checker.opcodeConstant(entry.Key); ok {
						names[ref.value] = ref
					}
				}
			}
		}
	})
	return names
}

func (checker *contractChecker) addRangeOpcodeNames(
	names map[uint64]opcodeRef,
	tableName string,
	expression ast.Expr,
) {
	rangeStarts := map[string]string{
		"intOpNames":    "OpIntBegin",
		"dblOpNames":    "OpDblBegin",
		"strOpNames":    "OpStrBegin",
		"dataTypeNames": "OpReadInt",
	}
	startName, ok := rangeStarts[tableName]
	if !ok {
		return
	}
	start, ok := checker.pass.Pkg.Scope().Lookup(startName).(*types.Const)
	if !ok {
		return
	}
	startValue, ok := constant.Uint64Val(constant.ToInt(start.Val()))
	if !ok {
		return
	}
	literal, ok := expression.(*ast.CompositeLit)
	if !ok {
		return
	}
	for offset, element := range literal.Elts {
		value := startValue + uint64(offset)
		names[value] = opcodeRef{name: tableName, value: value, expr: element}
	}
}

func (checker *contractChecker) collectOpcodeHandlers() map[uint64]opcodeRef {
	handlers := make(map[uint64]opcodeRef)
	checker.inspectResult.Preorder([]ast.Node{(*ast.AssignStmt)(nil)}, func(node ast.Node) {
		assignment := node.(*ast.AssignStmt)
		for _, left := range assignment.Lhs {
			index, ok := left.(*ast.IndexExpr)
			if !ok || !isIdentifier(index.X, "opcodeTable") {
				continue
			}

			ref, ok := checker.opcodeConstant(index.Index)
			if !ok {
				checker.pass.Reportf(index.Index.Pos(), "opcodeTable index must be an Opcode constant")
				continue
			}
			if previous, exists := handlers[ref.value]; exists {
				checker.pass.Report(analysis.Diagnostic{
					Pos:     ref.expr.Pos(),
					End:     ref.expr.End(),
					Message: "opcode value assigned more than once in opcodeTable",
					Related: []analysis.RelatedInformation{{
						Pos:     previous.expr.Pos(),
						End:     previous.expr.End(),
						Message: "first assignment is here",
					}},
				})
				continue
			}
			handlers[ref.value] = ref
		}
	})
	return handlers
}

func (checker *contractChecker) checkEmittedOpcodes(handlers map[uint64]opcodeRef) {
	reported := make(map[uint64]bool)
	checker.inspectResult.Preorder([]ast.Node{(*ast.CallExpr)(nil)}, func(node ast.Node) {
		call := node.(*ast.CallExpr)
		if checker.isTestFile(call.Pos()) {
			return
		}
		signature, ok := checker.emitterCallSignature(call)
		if !ok {
			return
		}
		for _, ref := range checker.emittedOpcodeConstants(signature, call) {
			if _, ok := handlers[ref.value]; ok || reported[ref.value] {
				continue
			}
			reported[ref.value] = true
			checker.pass.Reportf(
				ref.expr.Pos(),
				"emitted opcode %s has no opcodeTable dispatch handler",
				ref.name,
			)
		}
	})
}

func (checker *contractChecker) emitterCallSignature(call *ast.CallExpr) (*types.Signature, bool) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil, false
	}
	selection := checker.pass.TypesInfo.Selections[selector]
	if selection == nil {
		return nil, false
	}
	method, ok := selection.Obj().(*types.Func)
	if !ok || !strings.HasPrefix(method.Name(), "Emit") {
		return nil, false
	}
	signature, ok := method.Type().(*types.Signature)
	if !ok || signature.Recv() == nil {
		return nil, false
	}
	receiver := dereference(signature.Recv().Type())
	named, ok := receiver.(*types.Named)
	if !ok || named.Obj().Pkg() != checker.pass.Pkg || named.Obj().Name() != "Emitter" {
		return nil, false
	}
	return signature, true
}

func (checker *contractChecker) emittedOpcodeConstants(
	signature *types.Signature,
	call *ast.CallExpr,
) []opcodeRef {
	var refs []opcodeRef
	if len(call.Args) > 0 &&
		signature.Params().Len() > 0 &&
		types.Identical(signature.Params().At(0).Type(), checker.opcodeType) {
		if ref, ok := checker.opcodeConstant(call.Args[0]); ok {
			refs = append(refs, ref)
		}
	}

	for _, argument := range call.Args {
		ast.Inspect(argument, func(node ast.Node) bool {
			entry, ok := node.(*ast.KeyValueExpr)
			if !ok || !isIdentifier(entry.Key, "Opcode") {
				return true
			}
			if ref, ok := checker.opcodeConstant(entry.Value); ok {
				refs = append(refs, ref)
			}
			return true
		})
	}
	return refs
}

func (checker *contractChecker) opcodeConstant(expression ast.Expr) (opcodeRef, bool) {
	identifier, ok := expression.(*ast.Ident)
	if !ok {
		return opcodeRef{}, false
	}
	object, ok := checker.pass.TypesInfo.Uses[identifier].(*types.Const)
	if !ok || !checker.isOpcodeConstant(object) {
		return opcodeRef{}, false
	}
	value, ok := constant.Uint64Val(constant.ToInt(object.Val()))
	if !ok {
		return opcodeRef{}, false
	}
	return opcodeRef{name: object.Name(), value: value, expr: expression}, true
}

func (checker *contractChecker) isOpcodeConstant(object *types.Const) bool {
	if types.Identical(object.Type(), checker.opcodeType) {
		return true
	}
	basic, ok := object.Type().(*types.Basic)
	return ok &&
		basic.Info()&types.IsInteger != 0 &&
		basic.Info()&types.IsUntyped != 0 &&
		strings.HasPrefix(object.Name(), "Op") &&
		object.Pkg() == checker.opcodeType.Obj().Pkg()
}

func dereference(valueType types.Type) types.Type {
	if pointer, ok := valueType.(*types.Pointer); ok {
		return pointer.Elem()
	}
	return valueType
}

func isIdentifier(expression ast.Expr, name string) bool {
	identifier, ok := expression.(*ast.Ident)
	return ok && identifier.Name == name
}

func (checker *contractChecker) isTestFile(position token.Pos) bool {
	filename := checker.pass.Fset.PositionFor(position, false).Filename
	return strings.HasSuffix(filepath.Base(filename), "_test.go")
}
