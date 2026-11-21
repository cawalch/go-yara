// Package opcodecontract defines an analyzer for compiler opcode invariants.
package opcodecontract

import (
	"go/ast"
	"go/constant"
	"go/types"
	"strings"

	"github.com/cawalch/go-yara/internal/analyzers/opcoderef"

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

type contractChecker struct {
	pass          *analysis.Pass
	inspectResult *inspector.Inspector
	opcodeType    *types.Named
}

func run(pass *analysis.Pass) (any, error) {
	opcodeType := opcoderef.FindNamedType(pass, "Opcode")
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
				handler.Expr.Pos(),
				"dispatched opcode %s has no opcodeNames entry",
				handler.Name,
			)
		}
	}

	checker.checkEmittedOpcodes(handlers)
	return nil, nil
}

func (checker *contractChecker) collectOpcodeNames() map[uint64]opcoderef.Ref {
	names := make(map[uint64]opcoderef.Ref)
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
					if ref, ok := opcoderef.Constant(checker.pass, checker.opcodeType, entry.Key); ok {
						names[ref.Value] = ref
					}
				}
			}
		}
	})
	return names
}

func (checker *contractChecker) addRangeOpcodeNames(
	names map[uint64]opcoderef.Ref,
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
		names[value] = opcoderef.Ref{Name: tableName, Value: value, Expr: element}
	}
}

func (checker *contractChecker) collectOpcodeHandlers() map[uint64]opcoderef.Ref {
	handlers := make(map[uint64]opcoderef.Ref)
	checker.inspectResult.Preorder([]ast.Node{(*ast.AssignStmt)(nil)}, func(node ast.Node) {
		assignment := node.(*ast.AssignStmt)
		for _, left := range assignment.Lhs {
			index, ok := left.(*ast.IndexExpr)
			if !ok || !opcoderef.IsIdentifier(index.X, "opcodeTable") {
				continue
			}

			ref, ok := opcoderef.Constant(checker.pass, checker.opcodeType, index.Index)
			if !ok {
				checker.pass.Reportf(index.Index.Pos(), "opcodeTable index must be an Opcode constant")
				continue
			}
			if previous, exists := handlers[ref.Value]; exists {
				checker.pass.Report(analysis.Diagnostic{
					Pos:     ref.Expr.Pos(),
					End:     ref.Expr.End(),
					Message: "opcode value assigned more than once in opcodeTable",
					Related: []analysis.RelatedInformation{{
						Pos:     previous.Expr.Pos(),
						End:     previous.Expr.End(),
						Message: "first assignment is here",
					}},
				})
				continue
			}
			handlers[ref.Value] = ref
		}
	})
	return handlers
}

func (checker *contractChecker) checkEmittedOpcodes(handlers map[uint64]opcoderef.Ref) {
	reported := make(map[uint64]bool)
	checker.inspectResult.Preorder([]ast.Node{(*ast.CallExpr)(nil)}, func(node ast.Node) {
		call := node.(*ast.CallExpr)
		if opcoderef.IsTestFile(checker.pass, call.Pos()) {
			return
		}
		signature, ok := checker.emitterCallSignature(call)
		if !ok {
			return
		}
		for _, ref := range checker.emittedOpcodeConstants(signature, call) {
			if _, ok := handlers[ref.Value]; ok || reported[ref.Value] {
				continue
			}
			reported[ref.Value] = true
			checker.pass.Reportf(
				ref.Expr.Pos(),
				"emitted opcode %s has no opcodeTable dispatch handler",
				ref.Name,
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
	receiver := opcoderef.Dereference(signature.Recv().Type())
	named, ok := receiver.(*types.Named)
	if !ok || named.Obj().Pkg() != checker.pass.Pkg || named.Obj().Name() != "Emitter" {
		return nil, false
	}
	return signature, true
}

func (checker *contractChecker) emittedOpcodeConstants(
	signature *types.Signature,
	call *ast.CallExpr,
) []opcoderef.Ref {
	var refs []opcoderef.Ref
	if len(call.Args) > 0 &&
		signature.Params().Len() > 0 &&
		types.Identical(signature.Params().At(0).Type(), checker.opcodeType) {
		if ref, ok := opcoderef.Constant(checker.pass, checker.opcodeType, call.Args[0]); ok {
			refs = append(refs, ref)
		}
	}

	for _, argument := range call.Args {
		ast.Inspect(argument, func(node ast.Node) bool {
			entry, ok := node.(*ast.KeyValueExpr)
			if !ok || !opcoderef.IsIdentifier(entry.Key, "Opcode") {
				return true
			}
			if ref, ok := opcoderef.Constant(checker.pass, checker.opcodeType, entry.Value); ok {
				refs = append(refs, ref)
			}
			return true
		})
	}
	return refs
}
