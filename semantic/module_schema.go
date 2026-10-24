package semantic

import (
	"fmt"
	"maps"

	"github.com/cawalch/go-yara/ast"
)

// NewValidatorWithModuleSchemas accepts structured namespaces alongside flat functions.
func NewValidatorWithModuleSchemas(functions ModuleFunctions, schemas map[string]*TypeInfo) *Validator {
	v := NewValidatorWithModules(functions)
	v.moduleSchemas = maps.Clone(schemas)
	v.moduleVariables = map[string]*TypeInfo{}
	return v
}

func (v *Validator) moduleAccessError(expr ast.Expression, message string) (*TypeInfo, []error) {
	return &TypeInfo{DataType: TypeUnknown}, []error{&Error{Code: ErrCodeTypeMismatch, Message: message, Position: expr.Position(), Rule: v.currentRule}}
}

func (v *Validator) validateMemberAccess(expr *ast.MemberAccess) (*TypeInfo, []error) {
	if id, ok := expr.Object.(*ast.Identifier); ok && v.moduleSchemas[id.Name] == nil && v.moduleVariables[id.Name] == nil {
		return &TypeInfo{DataType: TypeUnknown}, []error{v.unsupportedModuleError(id.Name, id.Pos)}
	}
	object, errs := v.validateExpression(expr.Object)
	if len(errs) > 0 {
		return object, errs
	}
	if object.DataType != TypeStruct {
		return v.moduleAccessError(expr, "member access requires a structure, got "+object.String())
	}
	field := object.Fields[expr.Member]
	if field == nil {
		return v.moduleAccessError(expr, "unknown module attribute: "+expr.Member)
	}
	return field, nil
}

func (v *Validator) validateIndexAccess(expr *ast.IndexAccess) (*TypeInfo, []error) {
	object, errs := v.validateExpression(expr.Object)
	index, indexErrs := v.validateExpression(expr.Index)
	errs = append(errs, indexErrs...)
	if len(errs) > 0 {
		return &TypeInfo{DataType: TypeUnknown}, errs
	}
	if object.DataType != TypeArray && object.DataType != TypeDictionary {
		return v.moduleAccessError(expr, "indexing requires an array or dictionary")
	}
	want := TypeInteger
	if object.DataType == TypeDictionary {
		want = TypeString
	}
	if index.DataType != want {
		return v.moduleAccessError(expr.Index, "invalid collection index type: got "+index.String())
	}
	return object.Element, nil
}

func (v *Validator) isModuleCollectionExpression(expr ast.Expression) bool {
	switch e := expr.(type) {
	case *ast.MemberAccess, *ast.IndexAccess:
		return true
	case *ast.Identifier:
		return v.moduleSchemas[e.Name] != nil || v.moduleVariables[e.Name] != nil
	default:
		return false
	}
}

func (v *Validator) validateModuleLoop(loop *ast.ForLoop) (*TypeInfo, []error) {
	collection, errs := v.validateExpression(loop.Range)
	if len(errs) > 0 {
		return &TypeInfo{DataType: TypeBoolean}, errs
	}
	if collection.DataType != TypeArray && collection.DataType != TypeDictionary {
		return v.moduleAccessError(loop.Range, "module loop requires an array or dictionary")
	}
	count := 1
	if collection.DataType == TypeDictionary {
		count = 2
	}
	if len(loop.Variables) != count {
		return v.moduleAccessError(loop, fmt.Sprintf("module collection loop requires %d variable(s)", count))
	}
	outer := v.moduleVariables
	v.moduleVariables = maps.Clone(outer)
	if v.moduleVariables == nil {
		v.moduleVariables = map[string]*TypeInfo{}
	}
	defer func() { v.moduleVariables = outer }()
	v.symbolTable.EnterScope("module_loop")
	defer v.symbolTable.ExitScope()
	for index, name := range loop.Variables {
		if name == "$" || name == "" {
			return v.moduleAccessError(loop, "invalid module loop variable")
		}
		if err := v.symbolTable.DefineVariable(name, loop.Pos, SymbolVariable); err != nil {
			return v.moduleAccessError(loop, err.Error())
		}
		typ := collection.Element
		if count == 2 && index == 0 {
			typ = &TypeInfo{DataType: TypeString}
		}
		v.moduleVariables[name] = typ
	}
	conditionType, conditionErrs := v.validateExpression(loop.Condition)
	if conditionType != nil && conditionType.isStructured() {
		return v.moduleAccessError(loop.Condition, "loop condition requires a scalar value")
	}
	return &TypeInfo{DataType: TypeBoolean}, conditionErrs
}

// ModuleExpressionType resolves already-validated member/index expressions.
// roots includes module namespaces and any scoped collection loop variables.
func ModuleExpressionType(expr ast.Expression, roots map[string]*TypeInfo) *TypeInfo {
	switch e := expr.(type) {
	case *ast.Identifier:
		return roots[e.Name]
	case *ast.MemberAccess:
		if object := ModuleExpressionType(e.Object, roots); object != nil {
			return object.Fields[e.Member]
		}
	case *ast.IndexAccess:
		if object := ModuleExpressionType(e.Object, roots); object != nil {
			return object.Element
		}
	}
	return nil
}
