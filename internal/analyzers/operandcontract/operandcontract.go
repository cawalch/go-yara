// Package operandcontract defines an analyzer for compiler bytecode operands.
package operandcontract

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

// Analyzer verifies that emitted operand kinds and interpreter byte
// consumption agree with the bytecode contract for each opcode.
var Analyzer = &analysis.Analyzer{
	Name:     "operandcontract",
	Doc:      "checks compiler opcode operand kinds and consumed byte widths",
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

type operandSpec struct {
	kind  string
	bytes int
}

var contractSpecs = map[string]operandSpec{
	"OpCall":                   {kind: "OperandImmediate32", bytes: 4},
	"OpPush8":                  {kind: "OperandImmediate8", bytes: 1},
	"OpPush16":                 {kind: "OperandImmediate16", bytes: 2},
	"OpPush32":                 {kind: "OperandImmediate32", bytes: 4},
	"OpPush64":                 {kind: "OperandImmediate64", bytes: 8},
	"OpPushDbl":                {kind: "OperandImmediate64", bytes: 8},
	"OpPushRuleRef":            {kind: "OperandImmediate8", bytes: 1},
	"OpPushStr":                {kind: "OperandImmediate32", bytes: 4},
	"OpLoadVar":                {kind: "OperandImmediate32", bytes: 4},
	"OpPushRule":               {kind: "OperandImmediate8", bytes: 1},
	"OpInitRule":               {kind: "OperandImmediate8", bytes: 1},
	"OpPushM":                  {kind: "OperandImmediate32", bytes: 4},
	"OpPopM":                   {kind: "OperandImmediate32", bytes: 4},
	"OpClearM":                 {kind: "OperandImmediate32", bytes: 4},
	"OpIncrM":                  {kind: "OperandImmediate32", bytes: 4},
	"OpIterStartIntRange":      {kind: "OperandImmediate32", bytes: 4},
	"OpIterStartStringSet":     {kind: "OperandImmediate32", bytes: 4},
	"OpIterStartTextStringSet": {kind: "OperandImmediate32", bytes: 4},
	"OpJz":                     {kind: "OperandRelative32", bytes: 4},
	"OpJzP":                    {kind: "OperandRelative32", bytes: 4},
	"OpJtrue":                  {kind: "OperandRelative32", bytes: 4},
	"OpJfalse":                 {kind: "OperandRelative32", bytes: 4},
}

type opcodeRef struct {
	name  string
	value uint64
	expr  ast.Expr
}

type resolvedContract struct {
	ref  opcodeRef
	spec operandSpec
}

type contractChecker struct {
	pass          *analysis.Pass
	inspectResult *inspector.Inspector
	opcodeType    *types.Named
	contracts     map[uint64]resolvedContract
	consumed      map[uint64]bool
	helpers       map[string]int
}

func run(pass *analysis.Pass) (any, error) {
	if pass.Pkg.Name() != "compiler" {
		return nil, nil
	}
	opcodeType := findNamedType(pass, "Opcode")
	if opcodeType == nil {
		return nil, nil
	}
	checker := contractChecker{
		pass:          pass,
		inspectResult: pass.ResultOf[inspect.Analyzer].(*inspector.Inspector),
		opcodeType:    opcodeType,
		contracts:     resolveContracts(pass),
		consumed:      make(map[uint64]bool),
	}
	checker.helpers = checker.collectFixedWidthHelpers()
	checker.checkEmissions()
	checker.checkConsumption()
	checker.checkMissingConsumption()
	return nil, nil
}

func resolveContracts(pass *analysis.Pass) map[uint64]resolvedContract {
	contracts := make(map[uint64]resolvedContract)
	for name, spec := range contractSpecs {
		object, ok := pass.Pkg.Scope().Lookup(name).(*types.Const)
		if !ok {
			continue
		}
		value, ok := constant.Uint64Val(constant.ToInt(object.Val()))
		if !ok {
			continue
		}
		contracts[value] = resolvedContract{
			ref: opcodeRef{
				name:  name,
				value: value,
				expr:  identifierAt(object.Pos(), name),
			},
			spec: spec,
		}
	}
	return contracts
}

func identifierAt(position token.Pos, name string) *ast.Ident {
	return &ast.Ident{NamePos: position, Name: name}
}

func (checker *contractChecker) checkEmissions() {
	checker.inspectResult.Preorder([]ast.Node{(*ast.CallExpr)(nil)}, func(node ast.Node) {
		call := node.(*ast.CallExpr)
		if checker.isTestFile(call.Pos()) {
			return
		}
		name, ok := checker.emitterCallName(call)
		if !ok || len(call.Args) == 0 {
			return
		}
		ref, ok := checker.opcodeConstant(call.Args[0])
		if !ok {
			return
		}
		contract, hasOperand := checker.contracts[ref.value]
		switch name {
		case "EmitOpcode", "NewInstruction":
			if hasOperand {
				checker.pass.Reportf(
					ref.expr.Pos(),
					"opcode %s requires %s, not %s",
					ref.name,
					contract.spec.kind,
					name,
				)
			}
		case "EmitOpcodeWithOperand", "NewInstructionWithOperand":
			checker.checkOperandEmission(ref, call)
		}
	})
}

func (checker *contractChecker) checkOperandEmission(
	ref opcodeRef,
	call *ast.CallExpr,
) {
	contract, hasOperand := checker.contracts[ref.value]
	if !hasOperand {
		checker.pass.Reportf(ref.expr.Pos(), "opcode %s does not accept an operand", ref.name)
		return
	}
	if len(call.Args) < 2 {
		return
	}
	kind, ok := checker.operandKind(call.Args[1])
	if !ok {
		checker.pass.Reportf(
			call.Args[1].Pos(),
			"operand kind for opcode %s is not statically known; want %s",
			ref.name,
			contract.spec.kind,
		)
		return
	}
	if kind != contract.spec.kind {
		checker.pass.Reportf(
			call.Args[1].Pos(),
			"opcode %s requires %s, got %s",
			ref.name,
			contract.spec.kind,
			kind,
		)
	}
}

func (checker *contractChecker) emitterCallName(call *ast.CallExpr) (string, bool) {
	switch function := call.Fun.(type) {
	case *ast.SelectorExpr:
		selection := checker.pass.TypesInfo.Selections[function]
		if selection == nil {
			return "", false
		}
		method, ok := selection.Obj().(*types.Func)
		if !ok {
			return "", false
		}
		receiver := dereference(selection.Recv())
		named, ok := receiver.(*types.Named)
		if !ok || named.Obj().Pkg() != checker.pass.Pkg || named.Obj().Name() != "Emitter" {
			return "", false
		}
		return method.Name(), true
	case *ast.Ident:
		functionObject, ok := checker.pass.TypesInfo.Uses[function].(*types.Func)
		if !ok || functionObject.Pkg() != checker.pass.Pkg {
			return "", false
		}
		switch functionObject.Name() {
		case "NewInstruction", "NewInstructionWithOperand":
			return functionObject.Name(), true
		default:
			return "", false
		}
	default:
		return "", false
	}
}

func (checker *contractChecker) operandKind(expression ast.Expr) (string, bool) {
	literal, ok := expression.(*ast.CompositeLit)
	if !ok || !isNamedType(checker.pass.TypesInfo.TypeOf(literal), checker.pass.Pkg, "Operand") {
		return "", false
	}
	for _, element := range literal.Elts {
		entry, ok := element.(*ast.KeyValueExpr)
		if !ok || !isIdentifier(entry.Key, "Type") {
			continue
		}
		identifier, ok := entry.Value.(*ast.Ident)
		if !ok {
			return "", false
		}
		object, ok := checker.pass.TypesInfo.Uses[identifier].(*types.Const)
		if !ok || !isNamedType(object.Type(), checker.pass.Pkg, "OperandType") {
			return "", false
		}
		return object.Name(), true
	}
	return "OperandNone", true
}

func (checker *contractChecker) collectFixedWidthHelpers() map[string]int {
	helpers := make(map[string]int)
	checker.inspectResult.Preorder([]ast.Node{(*ast.FuncDecl)(nil)}, func(node ast.Node) {
		declaration := node.(*ast.FuncDecl)
		if declaration.Body == nil {
			return
		}
		opcodeParameters := checker.opcodeParameterNames(declaration)
		if len(opcodeParameters) == 0 {
			return
		}
		width := 0
		ambiguous := false
		ast.Inspect(declaration.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || calledName(call.Fun) != "validateBytecodeBounds" || len(call.Args) < 2 {
				return true
			}
			identifier, ok := call.Args[0].(*ast.Ident)
			if !ok || !opcodeParameters[identifier.Name] {
				return true
			}
			callWidth, ok := integerLiteral(call.Args[1])
			if !ok || callWidth <= 0 {
				return true
			}
			if width != 0 && width != callWidth {
				ambiguous = true
			}
			width = callWidth
			return true
		})
		if width > 0 && !ambiguous {
			helpers[declaration.Name.Name] = width
		}
	})
	return helpers
}

func (checker *contractChecker) opcodeParameterNames(
	declaration *ast.FuncDecl,
) map[string]bool {
	names := make(map[string]bool)
	if declaration.Type.Params == nil {
		return names
	}
	for _, field := range declaration.Type.Params.List {
		if !types.Identical(checker.pass.TypesInfo.TypeOf(field.Type), checker.opcodeType) {
			continue
		}
		for _, name := range field.Names {
			names[name.Name] = true
		}
	}
	return names
}

func (checker *contractChecker) checkConsumption() {
	checker.inspectResult.Preorder([]ast.Node{(*ast.CallExpr)(nil)}, func(node ast.Node) {
		call := node.(*ast.CallExpr)
		if checker.isTestFile(call.Pos()) || len(call.Args) == 0 {
			return
		}
		name := calledName(call.Fun)
		if name == "validateBytecodeBounds" {
			checker.checkDirectConsumption(call)
			return
		}
		width, ok := checker.helpers[name]
		if !ok {
			return
		}
		ref, ok := checker.opcodeConstant(call.Args[0])
		if ok {
			checker.checkConsumedWidth(ref, width, call.Args[0].Pos())
		}
	})
}

func (checker *contractChecker) checkDirectConsumption(call *ast.CallExpr) {
	if len(call.Args) < 2 {
		return
	}
	ref, ok := checker.opcodeConstant(call.Args[0])
	if !ok {
		return
	}
	width, ok := integerLiteral(call.Args[1])
	if ok {
		checker.checkConsumedWidth(ref, width, call.Args[1].Pos())
	}
}

func (checker *contractChecker) checkConsumedWidth(
	ref opcodeRef,
	width int,
	position token.Pos,
) {
	contract, ok := checker.contracts[ref.value]
	if !ok {
		checker.pass.Reportf(
			position,
			"opcode %s consumes %d operand bytes but has no operand contract",
			ref.name,
			width,
		)
		return
	}
	checker.consumed[ref.value] = true
	if width != contract.spec.bytes {
		checker.pass.Reportf(
			position,
			"opcode %s consumes %d operand bytes; contract requires %d",
			ref.name,
			width,
			contract.spec.bytes,
		)
	}
}

func (checker *contractChecker) checkMissingConsumption() {
	for value, contract := range checker.contracts {
		if checker.consumed[value] {
			continue
		}
		checker.pass.Reportf(
			contract.ref.expr.Pos(),
			"opcode %s requires a %d-byte operand but no interpreter consumption was found",
			contract.ref.name,
			contract.spec.bytes,
		)
	}
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

func findNamedType(pass *analysis.Pass, name string) *types.Named {
	typeName, ok := pass.Pkg.Scope().Lookup(name).(*types.TypeName)
	if !ok {
		return nil
	}
	named, _ := typeName.Type().(*types.Named)
	return named
}

func calledName(function ast.Expr) string {
	switch function := function.(type) {
	case *ast.SelectorExpr:
		return function.Sel.Name
	case *ast.Ident:
		return function.Name
	default:
		return ""
	}
}

func integerLiteral(expression ast.Expr) (int, bool) {
	value, ok := expression.(*ast.BasicLit)
	if !ok || value.Kind != token.INT {
		return 0, false
	}
	exact := constant.MakeFromLiteral(value.Value, token.INT, 0)
	result, ok := constant.Int64Val(exact)
	return int(result), ok
}

func dereference(valueType types.Type) types.Type {
	if pointer, ok := valueType.(*types.Pointer); ok {
		return pointer.Elem()
	}
	return valueType
}

func isNamedType(valueType types.Type, pkg *types.Package, name string) bool {
	named, ok := dereference(valueType).(*types.Named)
	return ok && named.Obj().Pkg() == pkg && named.Obj().Name() == name
}

func isIdentifier(expression ast.Expr, name string) bool {
	identifier, ok := expression.(*ast.Ident)
	return ok && identifier.Name == name
}

func (checker *contractChecker) isTestFile(position token.Pos) bool {
	filename := checker.pass.Fset.PositionFor(position, false).Filename
	return strings.HasSuffix(filepath.Base(filename), "_test.go")
}
