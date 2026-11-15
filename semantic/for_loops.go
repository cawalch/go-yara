package semantic

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

// validateOfExpression validates of expressions
func (v *Validator) validateOfExpression(ofExpr *ast.OfExpression) (*TypeInfo, []error) {
	errors := v.validateQuantifierExpr(ofExpr.Count, true)

	// Validate the strings expression
	_, stringsErrs := v.validateExpression(ofExpr.Strings)
	errors = append(errors, stringsErrs...)
	if v.strictLibyaraCompatibility && len(v.currentRuleStrings) == 0 {
		if ident, ok := ofExpr.Strings.(*ast.Identifier); ok && ident.Name == themKeyword {
			errors = append(errors, &Error{
				Code:     ErrCodeUndefinedIdentifier,
				Message:  `undefined string "$*"`,
				Position: ofExpr.Strings.Position(),
				Rule:     v.currentRule,
			})
		}
	}
	if ofExpr.InRange != nil {
		_, inErrs := v.validateExpression(ofExpr.InRange)
		errors = append(errors, inErrs...)
	}
	if ofExpr.AtOffset != nil {
		_, atErrs := v.validateExpression(ofExpr.AtOffset)
		errors = append(errors, atErrs...)
	}
	if containsAnonymousPlaceholder(ofExpr.Strings) {
		errors = append(errors, &Error{
			Code:     ErrCodeInvalidLoop,
			Message:  "anonymous string placeholder cannot be used in explicit string lists; use them",
			Position: ofExpr.Strings.Position(),
			Rule:     v.currentRule,
		})
	}

	// Of expressions always return boolean
	return &TypeInfo{DataType: TypeBoolean}, errors
}

func containsAnonymousPlaceholder(expr ast.Expression) bool {
	switch e := expr.(type) {
	case nil:
		return false
	case *ast.Identifier:
		return e.Name == "$"
	case *ast.StringTuple:
		if slices.ContainsFunc(e.Elements, containsAnonymousPlaceholder) {
			return true
		}
	case *ast.BinaryOp:
		return containsAnonymousPlaceholder(e.Left) || containsAnonymousPlaceholder(e.Right)
	case *ast.UnaryOp:
		return containsAnonymousPlaceholder(e.Right)
	case *ast.MemberAccess:
		return containsAnonymousPlaceholder(e.Object)
	case *ast.IndexAccess:
		return containsAnonymousPlaceholder(e.Object) || containsAnonymousPlaceholder(e.Index)
	case *ast.FunctionCall:
		if slices.ContainsFunc(e.Args, containsAnonymousPlaceholder) {
			return true
		}
	case *ast.ForLoop:
		return containsAnonymousPlaceholder(e.QuantifierExpr) ||
			containsAnonymousPlaceholder(e.Range) ||
			containsAnonymousPlaceholder(e.Condition) ||
			containsAnonymousPlaceholder(e.InRange) ||
			containsAnonymousPlaceholder(e.AtOffset)
	case *ast.OfExpression:
		return containsAnonymousPlaceholder(e.Count) ||
			containsAnonymousPlaceholder(e.Strings) ||
			containsAnonymousPlaceholder(e.InRange) ||
			containsAnonymousPlaceholder(e.AtOffset)
	case *ast.StringLength:
		return containsAnonymousPlaceholder(e.String) || containsAnonymousPlaceholder(e.Index)
	case *ast.StringOffset:
		return containsAnonymousPlaceholder(e.String) || containsAnonymousPlaceholder(e.Index)
	case *ast.StringCount:
		return containsAnonymousPlaceholder(e.String) || containsAnonymousPlaceholder(e.Index)
	case *ast.LengthOf:
		return containsAnonymousPlaceholder(e.Target)
	case *ast.PercentExpression:
		return containsAnonymousPlaceholder(e.Value)
	}
	return false
}

func isAnonymousPlaceholder(expr ast.Expression) bool {
	ident, ok := expr.(*ast.Identifier)
	return ok && ident.Name == "$"
}

func isStringSetExpression(expr ast.Expression) bool {
	switch e := expr.(type) {
	case nil:
		return false
	case *ast.Identifier:
		return e.Name == "them" || (strings.HasPrefix(e.Name, "$") && e.Name != "$")
	case *ast.StringTuple:
		for _, element := range e.Elements {
			if !isStringSetExpression(element) {
				return false
			}
		}
		return true
	case *ast.BinaryOp:
		return e.Op == token.COMMA && isStringSetExpression(e.Left) && isStringSetExpression(e.Right)
	default:
		return false
	}
}

func (v *Validator) isIntegerTuple(tuple *ast.StringTuple) bool {
	if len(tuple.Elements) == 0 {
		return false
	}
	for _, elem := range tuple.Elements {
		switch e := elem.(type) {
		case *ast.Literal:
			if e.Type == token.IntegerLit {
				return true
			}
			if e.Type == token.StringLit {
				return false
			}
		case *ast.Identifier:
			if strings.HasPrefix(e.Name, "$") || e.Name == "them" {
				return false
			}
			if sym, exists := v.symbolTable.Lookup(e.Name); exists {
				info := v.getTypeFromSymbol(sym)
				if info.DataType == TypeInteger {
					return true
				}
			}
		default:
			info, _ := v.validateExpression(elem)
			if info != nil && info.DataType == TypeInteger {
				return true
			}
		}
	}
	return false
}

func (v *Validator) validateTupleElementTypes(tuple *ast.StringTuple, loopVarType string) []error {
	if isStringSetExpression(tuple) {
		return nil
	}
	var errs []error
	for _, elem := range tuple.Elements {
		elemType, elemErrs := v.validateExpression(elem)
		errs = append(errs, elemErrs...)
		if elemType == nil || elemType.DataType == TypeUnknown {
			continue
		}
		if loopVarType == "integer" && elemType.DataType != TypeInteger {
			errs = append(errs, &Error{
				Code:     ErrCodeTypeMismatch,
				Message:  "for-loop integer enumeration element must be integer, got " + elemType.String(),
				Position: elem.Position(),
				Rule:     v.currentRule,
			})
		} else if loopVarType == "string" && elemType.DataType != TypeString {
			errs = append(errs, &Error{
				Code:     ErrCodeTypeMismatch,
				Message:  "for-loop string tuple element must be string, got " + elemType.String(),
				Position: elem.Position(),
				Rule:     v.currentRule,
			})
		}
	}
	return errs
}

// validateForLoopExpression validates for loop expressions
func (v *Validator) validateForLoopExpression(forLoop *ast.ForLoop) (*TypeInfo, []error) {
	if v.isModuleCollectionExpression(forLoop.Range) {
		return v.validateModuleLoop(forLoop)
	}
	errors := v.validateQuantifierExpr(forLoop.QuantifierExpr, false)
	outerModuleVariables := v.moduleVariables
	v.moduleVariables = maps.Clone(outerModuleVariables)
	defer func() { v.moduleVariables = outerModuleVariables }()
	outerVariables := v.loopVariables
	v.loopVariables = maps.Clone(outerVariables)
	defer func() { v.loopVariables = outerVariables }()

	// Determine loop variable type from range expression
	loopVarType := ""
	switch r := forLoop.Range.(type) {
	case *ast.StringTuple:
		switch {
		case isStringSetExpression(r):
			loopVarType = "string"
		case v.isIntegerTuple(r):
			loopVarType = "integer"
		default:
			loopVarType = "string"
		}
	case *ast.Literal:
		switch r.Type {
		case token.StringLit:
			loopVarType = "string"
		case token.IntegerLit:
			loopVarType = "integer"
		}
	case *ast.BinaryOp:
		// Integer range (min..max)
		if r.Op == token.DOT {
			loopVarType = "integer"
		}
	case *ast.Identifier:
		// String set iteration: for any s in ($*), for any s in (them)
		if strings.HasPrefix(r.Name, "$") || r.Name == "them" {
			loopVarType = "string"
		} else if sym, exists := v.symbolTable.Lookup(r.Name); exists {
			info := v.getTypeFromSymbol(sym)
			if info.DataType == TypeInteger {
				loopVarType = "integer"
			}
		}
	}
	if loopVarType == "" && isStringSetExpression(forLoop.Range) {
		loopVarType = "string"
	}
	if containsAnonymousPlaceholder(forLoop.Range) {
		errors = append(errors, &Error{
			Code:     ErrCodeInvalidLoop,
			Message:  "anonymous string placeholder cannot be used in explicit string lists; use them",
			Position: forLoop.Range.Position(),
			Rule:     v.currentRule,
		})
	}

	// Create a scope for the loop variables so it is visible in the condition.
	v.symbolTable.EnterScope("for_loop")
	for _, variable := range forLoop.Variables {
		if variable != "" {
			if variable == "$" {
				errors = append(errors, &Error{
					Code:     ErrCodeInvalidLoop,
					Message:  "for-loop variable cannot be anonymous string placeholder $",
					Position: forLoop.Pos,
					Rule:     v.currentRule,
				})
				continue
			}
			if err := v.symbolTable.DefineVariable(variable, forLoop.Pos, SymbolVariable); err != nil {
				errors = append(errors, &Error{
					Code:     ErrCodeDuplicateVariable,
					Message:  err.Error(),
					Position: forLoop.Pos,
					Rule:     v.currentRule,
				})
			}
			if loopVarType != "" {
				v.loopVariables[variable] = loopVarType
			}
		}
	}

	// Validate the range expression
	_, rangeErrs := v.validateExpression(forLoop.Range)
	errors = append(errors, rangeErrs...)
	if v.strictLibyaraCompatibility && len(v.currentRuleStrings) == 0 {
		if ident, ok := forLoop.Range.(*ast.Identifier); ok && ident.Name == themKeyword {
			errors = append(errors, &Error{
				Code:     ErrCodeUndefinedIdentifier,
				Message:  `undefined string "$*"`,
				Position: forLoop.Range.Position(),
				Rule:     v.currentRule,
			})
		}
	}
	if forLoop.InRange != nil {
		_, inErrs := v.validateExpression(forLoop.InRange)
		errors = append(errors, inErrs...)
	}
	if forLoop.AtOffset != nil {
		_, atErrs := v.validateExpression(forLoop.AtOffset)
		errors = append(errors, atErrs...)
	}

	if tuple, ok := forLoop.Range.(*ast.StringTuple); ok {
		errors = append(errors, v.validateTupleElementTypes(tuple, loopVarType)...)
	}

	// Ordinary loop variables shadow structured outer variables in the body.
	for _, name := range forLoop.Variables {
		delete(v.moduleVariables, name)
	}
	// Validate the condition expression
	if loopVarType == "string" {
		v.stringLoopDepth++
	}
	conditionType, conditionErrs := v.validateExpression(forLoop.Condition)
	if conditionType != nil && conditionType.isStructured() {
		_, structuredErrs := v.moduleAccessError(forLoop.Condition, "loop condition requires a scalar value")
		conditionErrs = append(conditionErrs, structuredErrs...)
	}
	if loopVarType == "string" {
		v.stringLoopDepth--
	}
	errors = append(errors, conditionErrs...)

	v.symbolTable.ExitScope()

	// For loops always return boolean
	return &TypeInfo{DataType: TypeBoolean}, errors
}

// validateQuantifierExpr validates an expression-form quantifier for `of` and
// `for` expressions, allowing quantifier keywords when allowKeywords is true.
func (v *Validator) validateQuantifierExpr(expr ast.Expression, allowKeywords bool) []error {
	if expr == nil {
		return nil
	}
	if allowKeywords {
		if ident, ok := expr.(*ast.Identifier); ok {
			switch ident.Name {
			case "all", "any", "none":
				return nil
			}
		}
	}
	typ, errs := v.validateExpression(expr)
	if typ != nil && typ.DataType != TypeInteger && typ.DataType != TypeUnknown {
		errs = append(errs, &Error{
			Code:     ErrCodeTypeMismatch,
			Message:  "quantifier expression must evaluate to an integer, got " + typ.String(),
			Position: expr.Position(),
			Rule:     v.currentRule,
		})
	} else if val, ok := evalConstantInt(expr); ok && val < 0 {
		errs = append(errs, &Error{
			Code:     ErrCodeInvalidOperation,
			Message:  fmt.Sprintf("invalid value in condition: \"%d\"", val),
			Position: expr.Position(),
			Rule:     v.currentRule,
		})
	}
	return errs
}
