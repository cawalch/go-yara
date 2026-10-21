package semantic

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

// Validator performs semantic analysis on YARA rules
type Validator struct {
	symbolTable        *SymbolTable
	errors             []error
	loopVariables      map[string]string // loop variable name -> "string" or "integer"
	stringLoopDepth    int
	currentRule        string
	currentRuleStrings []string
	allRuleNames       []string
	globalVarNames     []string
	moduleFunctions    ModuleFunctions
	importedModules    map[string]bool
}

// Special identifier keywords
const (
	filesizeKeyword   = "filesize"
	entrypointKeyword = "entrypoint"
	themKeyword       = "them"
)

// NewValidator creates a new semantic validator
func NewValidator() *Validator {
	return NewValidatorWithModules(nil)
}

// NewValidatorWithModules creates a validator that accepts the supplied
// module function signatures.
func NewValidatorWithModules(moduleFunctions ModuleFunctions) *Validator {
	return &Validator{
		symbolTable:     NewSymbolTable(),
		errors:          make([]error, 0),
		loopVariables:   make(map[string]string),
		moduleFunctions: moduleFunctions,
		importedModules: make(map[string]bool),
	}
}

// ValidateProgram performs semantic analysis on a complete program
func (v *Validator) ValidateProgram(program *ast.Program) []error {
	v.errors = v.errors[:0] // Clear previous errors
	v.symbolTable.ResetWithCapacity(len(program.Rules))
	v.currentRule = ""
	v.currentRuleStrings = nil
	v.allRuleNames = v.allRuleNames[:0]
	v.globalVarNames = v.globalVarNames[:0]
	clear(v.importedModules)

	// First: validate module imports and remember the namespaces available to
	// dotted calls in rule conditions.
	for _, importStmt := range program.Imports {
		if !v.moduleFunctions.hasModule(importStmt.Module) {
			v.addError(v.unsupportedModuleError(importStmt.Module, importStmt.Pos))
			continue
		}
		v.importedModules[importStmt.Module] = true
	}

	// Second: collect global variables and external variables
	for _, globalVar := range program.GlobalVariables {
		v.collectGlobalVariable(globalVar)
	}
	for _, extVar := range program.ExternalVariables {
		v.collectExternalVariable(extVar)
	}

	// Third pass: collect all rule and string definitions
	for _, rule := range program.Rules {
		v.collectSymbols(rule)
	}

	// Fourth pass: reject circular rule dependencies before code generation.
	v.validateRuleDependencyCycles(program)

	// Fifth pass: validate all rules
	for _, rule := range program.Rules {
		v.validateRule(rule)
	}

	return v.errors
}

// collectSymbols collects all symbols from a rule
func (v *Validator) collectSymbols(rule *ast.Rule) {
	v.allRuleNames = append(v.allRuleNames, rule.Name)
	// Define the rule itself in the global scope (rules should be globally accessible)
	if err := v.symbolTable.DefineRule(rule.Name, rule.Pos, rule); err != nil {
		v.addError(&Error{
			Code:     ErrCodeDuplicateRule,
			Message:  err.Error(),
			Position: rule.Pos,
			Rule:     rule.Name,
		})
	}
}

// collectGlobalVariable collects a global variable symbol.
func (v *Validator) collectGlobalVariable(globalVar *ast.GlobalVariable) {
	v.globalVarNames = append(v.globalVarNames, globalVar.Name)
	typeInfo := &TypeInfo{DataType: TypeUnknown}
	if globalVar.Value != nil {
		var errs []error
		typeInfo, errs = v.validateExpression(globalVar.Value)
		v.addErrors(errs)
	}
	if typeInfo == nil || typeInfo.DataType == TypeUnknown {
		v.addError(&Error{
			Code:     ErrCodeInvalidVariable,
			Message:  "global variable " + globalVar.Name + " must have a literal integer, string, or boolean value",
			Position: globalVar.Pos,
		})
		return
	}

	def := globalVariableDefinition{
		name:     globalVar.Name,
		pos:      globalVar.Pos,
		global:   globalVar,
		typeInfo: typeInfo,
	}
	if err := v.symbolTable.defineGlobalVariable(def); err != nil {
		v.addError(&Error{
			Code:     ErrCodeDuplicateVariable,
			Message:  err.Error(),
			Position: globalVar.Pos,
		})
	}
}

// collectExternalVariable collects an external variable symbol
func (v *Validator) collectExternalVariable(extVar *ast.ExternalVariable) {
	v.globalVarNames = append(v.globalVarNames, extVar.Name)
	if err := v.symbolTable.DefineVariable(extVar.Name, extVar.Pos, SymbolExternal); err != nil {
		v.addError(&Error{
			Code:     ErrCodeDuplicateVariable,
			Message:  err.Error(),
			Position: extVar.Pos,
		})
	}
}

// validateRule performs semantic validation on a single rule
func (v *Validator) validateRule(rule *ast.Rule) {
	previousRule := v.currentRule
	v.currentRule = rule.Name
	prevStrings := v.currentRuleStrings
	v.currentRuleStrings = make([]string, 0, len(rule.Strings))
	for _, str := range rule.Strings {
		if str != nil {
			v.currentRuleStrings = append(v.currentRuleStrings, str.Identifier)
		}
	}

	// Enter rule scope for validation
	v.symbolTable.EnterScopeWithCapacity(rule.Name, len(rule.Strings))

	// Re-define strings in the new scope for validation
	for _, str := range rule.Strings {
		if err := v.symbolTable.DefineString(str.Identifier, str.Pos, str); err != nil {
			v.addError(&Error{
				Code:     ErrCodeDuplicateString,
				Message:  err.Error(),
				Position: str.Pos,
				Rule:     rule.Name,
			})
		}
	}

	// Validate meta section
	v.validateMeta(rule.Meta)

	// Validate strings section
	v.validateStrings(rule.Strings)
	v.validateEvidence(rule)
	v.validateStringModifiers(rule)

	// Validate condition
	v.validateCondition(rule.Condition)

	// Exit rule scope
	v.symbolTable.ExitScope()
	v.currentRule = previousRule
	v.currentRuleStrings = prevStrings
}

// validateMeta validates the meta section
func (v *Validator) validateMeta(meta []*ast.Meta) {
	for _, m := range meta {
		// Check for duplicate meta keys (already handled by parser, but double-check)
		if existing, exists := v.symbolTable.LookupInCurrentScope(m.Key); exists {
			if existing.Type == SymbolVariable {
				v.addError(&Error{
					Code:     ErrCodeDuplicateMeta,
					Message:  "duplicate meta key: " + m.Key,
					Position: m.Pos,
					Rule:     v.currentRule,
				})
			}
		}

		// Define meta as variable for potential use in conditions
		if err := v.symbolTable.DefineVariable(m.Key, m.Pos, SymbolVariable); err != nil {
			v.addError(&Error{
				Code:     ErrCodeDuplicateMeta,
				Message:  err.Error(),
				Position: m.Pos,
				Rule:     v.currentRule,
			})
		}
	}
}

// validateStrings validates the strings section
func (v *Validator) validateStrings(stringsSlice []*ast.String) {
	for _, str := range stringsSlice {
		// Mark string as used when referenced in condition
		// This will be checked later during condition validation
		v.symbolTable.MarkUsed(str.Identifier)
	}
}

// validateCondition validates the condition expression
func (v *Validator) validateCondition(condition ast.Expression) {
	if condition != nil {
		conditionType, errs := v.validateExpression(condition)
		v.addErrors(errs)

		// Condition should evaluate to boolean or numeric (integers/floats are truthy/falsy)
		if conditionType != nil && conditionType.DataType != TypeUnknown && conditionType.DataType != TypeBoolean && !conditionType.IsNumeric() {
			v.addError(&Error{
				Code:     ErrCodeInvalidCondition,
				Message:  "condition must evaluate to boolean or numeric",
				Position: condition.Position(),
				Rule:     v.currentRule,
			})
		}
	}
}

// validateExpression validates an expression and returns its type
func (v *Validator) validateExpression(expr ast.Expression) (*TypeInfo, []error) {
	switch {
	case v.isSimpleExpression(expr):
		return v.validateSimpleExpression(expr)
	case v.isOperationExpression(expr):
		return v.validateOperationExpression(expr)
	case v.isSpecialExpression(expr):
		return v.validateSpecialExpression(expr)
	default:
		return v.validateUnknownExpression()
	}
}

// isSimpleExpression checks if expression is a simple type (literal, identifier)
func (v *Validator) isSimpleExpression(expr ast.Expression) bool {
	switch expr.(type) {
	case *ast.Literal, *ast.Identifier:
		return true
	default:
		return false
	}
}

// isOperationExpression checks if expression is an operation (binary, unary)
func (v *Validator) isOperationExpression(expr ast.Expression) bool {
	switch expr.(type) {
	case *ast.BinaryOp, *ast.UnaryOp:
		return true
	default:
		return false
	}
}

// isSpecialExpression checks if expression is a special type (function call, for loop, etc.)
func (v *Validator) isSpecialExpression(expr ast.Expression) bool {
	switch expr.(type) {
	case *ast.OfExpression, *ast.FunctionCall, *ast.ForLoop, *ast.PercentExpression:
		return true
	case *ast.StringLength, *ast.StringOffset, *ast.StringCount, *ast.LengthOf:
		return true
	default:
		return false
	}
}

// validateSimpleExpression validates simple expressions (literals, identifiers)
func (v *Validator) validateSimpleExpression(expr ast.Expression) (*TypeInfo, []error) {
	switch e := expr.(type) {
	case *ast.Literal:
		return v.validateLiteralExpression(e)
	case *ast.Identifier:
		return v.validateIdentifierExpression(e)
	default:
		return v.validateUnknownExpression()
	}
}

// validateOperationExpression validates operation expressions (binary, unary)
func (v *Validator) validateOperationExpression(expr ast.Expression) (*TypeInfo, []error) {
	switch e := expr.(type) {
	case *ast.BinaryOp:
		return v.validateBinaryOpExpression(e)
	case *ast.UnaryOp:
		return v.validateUnaryOpExpression(e)
	default:
		return v.validateUnknownExpression()
	}
}

// validateSpecialExpression validates special expressions (function calls, for loops, etc.)
func (v *Validator) validateSpecialExpression(expr ast.Expression) (*TypeInfo, []error) {
	switch e := expr.(type) {
	case *ast.OfExpression:
		return v.validateOfExpression(e)
	case *ast.FunctionCall:
		return v.validateFunctionCallExpression(e)
	case *ast.ForLoop:
		return v.validateForLoopExpression(e)
	case *ast.StringLength:
		return v.validateStringLengthExpression(e)
	case *ast.StringOffset:
		return v.validateStringOffsetExpression(e)
	case *ast.StringCount:
		return v.validateStringCountExpression(e)
	case *ast.LengthOf:
		return v.validateLengthOfExpression(e)
	case *ast.PercentExpression:
		return v.validatePercentExpression(e)
	default:
		return v.validateUnknownExpression()
	}
}

// validateUnknownExpression handles unknown expression types
func (v *Validator) validateUnknownExpression() (*TypeInfo, []error) {
	// Unrecognized expression nodes carry an unknown type.
	return &TypeInfo{DataType: TypeUnknown}, nil
}

// validateLiteralExpression validates literal expressions
func (v *Validator) validateLiteralExpression(lit *ast.Literal) (*TypeInfo, []error) {
	return InferTypeFromLiteral(lit.Type, lit.Value), nil
}

// validateIdentifierExpression validates identifier expressions
func (v *Validator) validateIdentifierExpression(ident *ast.Identifier) (*TypeInfo, []error) {
	var errors []error

	// Check for special keywords first
	switch ident.Name {
	case "filesize", "entrypoint", "flags":
		return &TypeInfo{DataType: TypeInteger, IntegerType: Uint64Type}, nil
	case "them":
		return &TypeInfo{DataType: TypeBoolean}, nil
	case "$":
		return v.validateQuantifierSymbol(ident)
	case "all", "any", "none":
		// Quantifier keywords - these are used in "all of them" expressions
		// They will be handled by the BinaryOp case with OF operator
		return &TypeInfo{DataType: TypeUnknown}, nil
	// Data type functions
	case "uint8", "uint16", "uint32", "uint8be", "uint16be", "uint32be":
		return &TypeInfo{DataType: TypeInteger, IntegerType: Uint64Type}, nil
	case "int8", "int16", "int32", "int8be", "int16be", "int32be":
		return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}, nil
	}

	// Look up the identifier in symbol table
	if symbol, exists := v.symbolTable.Lookup(ident.Name); exists {
		symbol.Used = true
		info := v.getTypeFromSymbol(symbol)
		// If symbol is a loop variable, use the loopVariables map for type info
		if info.DataType == TypeUnknown || symbol.Type == SymbolVariable {
			if typ, ok := v.loopVariables[ident.Name]; ok {
				switch typ {
				case "string":
					return &TypeInfo{DataType: TypeString}, nil
				case "integer":
					return &TypeInfo{DataType: TypeInteger, IntegerType: Uint64Type}, nil
				}
			}
		}
		return info, nil
	}

	// Try alternative lookups for special cases
	return v.tryAlternativeIdentifierLookups(ident, errors)
}

// validateQuantifierSymbol handles the special $ symbol in quantifiers
func (v *Validator) validateQuantifierSymbol(ident *ast.Identifier) (*TypeInfo, []error) {
	if v.stringLoopDepth == 0 {
		return &TypeInfo{DataType: TypeUnknown}, []error{&Error{
			Code:     ErrCodeInvalidLoop,
			Message:  "anonymous string placeholder cannot be used directly; use a string-set expression such as them",
			Position: ident.Position(),
			Rule:     v.currentRule,
		}}
	}
	// "$" refers to the current string in a for-loop body (for any of them : ($)).
	// In that context it evaluates to boolean (whether the string matched), so
	// it must be typed as SymbolString, not SymbolVariable.
	if symbol, exists := v.symbolTable.LookupInCurrentScope("$"); exists {
		return v.getTypeFromSymbol(symbol), nil
	}
	if err := v.symbolTable.DefineVariable("$", ident.Position(), SymbolString); err != nil {
		return &TypeInfo{DataType: TypeUnknown}, []error{&Error{
			Code:     ErrCodeInvalidLoop,
			Message:  err.Error(),
			Position: ident.Position(),
			Rule:     v.currentRule,
		}}
	}
	if symbol, exists := v.symbolTable.Lookup("$"); exists {
		return v.getTypeFromSymbol(symbol), nil
	}
	return &TypeInfo{DataType: TypeBoolean}, nil
}

// tryAlternativeIdentifierLookups attempts to find identifier in alternative contexts
func (v *Validator) tryAlternativeIdentifierLookups(ident *ast.Identifier, errors []error) (*TypeInfo, []error) {
	// Check if this is a wildcard string set identifier (e.g., $a*, $str*)
	// These are valid in quantifier expressions like "any of ($a*)" or "#a in (1..3) of ($a*)"
	// The compiler handles expansion at compile time; we just need to allow the identifier.
	if strings.HasPrefix(ident.Name, "$") && strings.HasSuffix(ident.Name, "*") {
		return &TypeInfo{DataType: TypeBoolean}, nil
	}
	// Check if this might be a string reference without the $ prefix
	// This happens when using #, @, or ! operators in conditions or matches operands
	if stringSymbol, hasStringSymbol := v.symbolTable.Lookup("$" + ident.Name); hasStringSymbol {
		stringSymbol.Used = true
		return v.getTypeFromSymbol(stringSymbol), nil
	}

	// Bare dotted identifiers are structured module/member references. The
	// current module registry exposes typed function calls, not object fields,
	// so fail explicitly instead of guessing a placeholder type.
	if moduleName, ok := moduleNameFromDottedName(ident.Name); ok {
		errors = append(errors, v.unsupportedModuleError(moduleName, ident.Position()))
		return &TypeInfo{DataType: TypeUnknown}, errors
	}

	// Check if this might be a rule reference from an included file
	// Rules are globally accessible, so check the global scope
	if globalSymbol, hasGlobalSymbol := v.symbolTable.LookupInGlobalScope(ident.Name); hasGlobalSymbol {
		globalSymbol.Used = true
		return v.getTypeFromSymbol(globalSymbol), nil
	}

	err := &Error{
		Code:     ErrCodeUndefinedIdentifier,
		Message:  "undefined identifier: " + ident.Name,
		Position: ident.Position(),
		Rule:     v.currentRule,
	}
	if sugg := v.suggestIdentifier(ident.Name); sugg != "" {
		err.Suggestion = sugg
	}
	errors = append(errors, err)
	return &TypeInfo{DataType: TypeUnknown}, errors
}

// validateBinaryOpExpression validates binary operation expressions
func (v *Validator) validateBinaryOpExpression(binOp *ast.BinaryOp) (*TypeInfo, []error) {
	var errors []error

	// Special handling for module access (dot notation)
	if binOp.Op == token.DOT {
		if moduleName, handled := moduleNameFromMemberAccess(binOp); handled {
			errors = append(errors, v.unsupportedModuleError(moduleName, binOp.Position()))
			return &TypeInfo{DataType: TypeUnknown}, errors
		}
	}

	leftType, leftErrs := v.validateExpression(binOp.Left)
	rightType, rightErrs := v.validateExpression(binOp.Right)

	errors = append(errors, leftErrs...)
	errors = append(errors, rightErrs...)

	if leftType == nil || rightType == nil {
		return &TypeInfo{DataType: TypeUnknown}, errors
	}

	if (binOp.Op == token.DIVIDE || binOp.Op == token.IntDivide || binOp.Op == token.MODULO) && isZeroIntegerLiteral(binOp.Right) {
		semErr := &Error{
			Code:     ErrCodeDivisionByZero,
			Message:  "division by zero",
			Position: binOp.Position(),
			Rule:     v.currentRule,
		}
		errors = append(errors, semErr)
		return &TypeInfo{DataType: TypeUnknown}, errors
	}

	resultType, err := InferTypeFromBinaryOp(leftType, binOp.Op, rightType)
	if err != nil {
		semErr := &Error{
			Code:       ErrCodeTypeMismatch,
			Message:    err.Error(),
			Position:   binOp.Position(),
			Rule:       v.currentRule,
			Suggestion: bitwiseSuggestion(binOp.Op, leftType, rightType),
		}
		errors = append(errors, semErr)
		return &TypeInfo{DataType: TypeUnknown}, errors
	}
	return resultType, errors
}

func isZeroIntegerLiteral(expr ast.Expression) bool {
	if un, ok := expr.(*ast.UnaryOp); ok && (un.Op == token.MINUS || un.Op == token.PLUS) {
		return isZeroIntegerLiteral(un.Right)
	}
	lit, ok := expr.(*ast.Literal)
	if !ok {
		return false
	}
	switch v := lit.Value.(type) {
	case string:
		if n, err := strconv.ParseInt(v, 0, 64); err == nil {
			return n == 0
		}
		return false
	case int64:
		return v == 0
	case int:
		return v == 0
	case uint64:
		return v == 0
	case uint:
		return v == 0
	default:
		return false
	}
}

// validateUnaryOpExpression validates unary operation expressions
func (v *Validator) validateUnaryOpExpression(unaryOp *ast.UnaryOp) (*TypeInfo, []error) {
	var errors []error

	// Special handling for string operators before validating the operand
	// This is needed because we need to check if the operand is a string identifier
	if unaryOp.Op == token.NOT || unaryOp.Op == token.HASH || unaryOp.Op == token.AT {
		if resultType, handled := v.handleStringOperators(unaryOp, errors); handled {
			return resultType, errors
		}
	}

	operandType, operandErrs := v.validateExpression(unaryOp.Right)
	errors = append(errors, operandErrs...)

	if operandType != nil {
		resultType, err := InferTypeFromUnaryOp(unaryOp.Op, operandType)
		if err != nil {
			errors = append(errors, &Error{
				Code:     ErrCodeTypeMismatch,
				Message:  err.Error(),
				Position: unaryOp.Position(),
				Rule:     v.currentRule,
			})
			return &TypeInfo{DataType: TypeUnknown}, errors
		}
		return resultType, errors
	}

	return &TypeInfo{DataType: TypeUnknown}, errors
}

// handleStringOperators handles string-specific unary operators
func (v *Validator) handleStringOperators(unaryOp *ast.UnaryOp, _ []error) (*TypeInfo, bool) {
	if ident, ok := unaryOp.Right.(*ast.Identifier); ok {
		// Check if this is a string reference (with or without $ prefix)
		var stringName string
		if strings.HasPrefix(ident.Name, "$") {
			stringName = ident.Name
		} else {
			// Try with $ prefix for string references in conditions
			stringName = "$" + ident.Name
		}

		if symbol, exists := v.symbolTable.Lookup(stringName); exists && symbol.Type == SymbolString {
			// All string operators (#, @, !) return integer
			return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}, true
		}
	}
	return nil, false
}

// getTypeFromSymbol returns the type information for a symbol
func (v *Validator) getTypeFromSymbol(symbol *Symbol) *TypeInfo {
	switch symbol.Type {
	case SymbolRule:
		return &TypeInfo{DataType: TypeBoolean}
	case SymbolString:
		// String identifiers in conditions evaluate to boolean (whether the string is found)
		return &TypeInfo{DataType: TypeBoolean}
	case SymbolVariable:
		// Variables without explicit type metadata default to int64.
		return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}
	case SymbolExternal:
		// Runtime external variables are dynamically typed by the caller.
		return &TypeInfo{DataType: TypeUnknown}
	case SymbolGlobal:
		if symbol.TypeInfo != nil {
			return symbol.TypeInfo
		}
		return &TypeInfo{DataType: TypeUnknown}
	default:
		return &TypeInfo{DataType: TypeUnknown}
	}
}

// addError adds a semantic error
func (v *Validator) addError(err error) {
	var semanticErr *Error
	if errors.As(err, &semanticErr) && semanticErr.Rule == "" {
		semanticErr.Rule = v.currentRule
	}
	v.errors = append(v.errors, err)
}

func (v *Validator) addErrors(errs []error) {
	for _, err := range errs {
		v.addError(err)
	}
}

// GetErrors returns all semantic errors
func (v *Validator) GetErrors() []error {
	return v.errors
}

// HasErrors returns true if there are semantic errors
func (v *Validator) HasErrors() bool {
	return len(v.errors) > 0
}

// GetSymbolTable returns the symbol table
func (v *Validator) GetSymbolTable() *SymbolTable {
	return v.symbolTable
}

// validatePercentExpression validates a percent expression ("N %")
func (v *Validator) validatePercentExpression(expr *ast.PercentExpression) (*TypeInfo, []error) {
	// The inner value should be an integer (1-100)
	valType, errs := v.validateExpression(expr.Value)
	if valType.DataType != TypeInteger {
		errs = append(errs, fmt.Errorf("percentage must be an integer, got %v", valType.DataType))
	}
	// PercentExpression itself is an integer (used as count in OfExpression)
	return &TypeInfo{DataType: TypeInteger}, errs
}

// validateStringLengthExpression validates string length expressions (!a or !a[i])
func (v *Validator) validateStringLengthExpression(stringLength *ast.StringLength) (*TypeInfo, []error) {
	return v.validateStringIndexExpression(stringLength.String, stringLength.Index, "length")
}

// validateStringOffsetExpression validates string offset expressions (@a or @a[i])
func (v *Validator) validateStringOffsetExpression(stringOffset *ast.StringOffset) (*TypeInfo, []error) {
	return v.validateStringIndexExpression(stringOffset.String, stringOffset.Index, "offset")
}

// validateStringCountExpression validates string count expressions (#a or #a[i])
func (v *Validator) validateStringCountExpression(stringCount *ast.StringCount) (*TypeInfo, []error) {
	return v.validateStringIndexExpression(stringCount.String, stringCount.Index, "count")
}

// validateStringIndexExpression is the shared body for the string length / offset /
// count validators. The three AST node types (StringLength, StringOffset,
// StringCount) carry the same String and Index fields with the same semantics,
// so their validation differs only in the operator name used in the index-type
// error message. Returns TypeInteger, matching the YARA semantics of !a / @a / #a.
func (v *Validator) validateStringIndexExpression(str ast.Expression, index ast.Expression, opName string) (*TypeInfo, []error) {
	var errors []error

	if isAnonymousPlaceholder(str) && v.stringLoopDepth == 0 {
		errors = append(errors, &Error{
			Code:     ErrCodeInvalidStringOp,
			Message:  "anonymous string placeholder cannot be used with string " + opName + " outside a string loop",
			Position: str.Position(),
			Rule:     v.currentRule,
		})
	} else if err := v.validateStringIdentifier(str); err != nil {
		errors = append(errors, err)
	}

	if index != nil {
		indexType, indexErrs := v.validateExpression(index)
		errors = append(errors, indexErrs...)

		if indexType != nil && indexType.DataType != TypeInteger {
			errors = append(errors, &Error{
				Code:     ErrCodeInvalidArgumentType,
				Message:  "string " + opName + " index must be integer",
				Position: index.Position(),
				Rule:     v.currentRule,
			})
		}
	}

	return &TypeInfo{DataType: TypeInteger, IntegerType: Uint64Type}, errors
}

// validateLengthOfExpression validates "length of" expressions
func (v *Validator) validateLengthOfExpression(lengthOf *ast.LengthOf) (*TypeInfo, []error) {
	var errors []error

	// Validate the target expression
	targetType, targetErrs := v.validateExpression(lengthOf.Target)
	errors = append(errors, targetErrs...)

	// The target should be a string identifier, quantified string, or special identifier (them/all)
	// String identifiers in conditions evaluate to boolean (found/not found), which is valid for length of
	if targetType != nil && targetType.DataType != TypeBoolean && targetType.DataType != TypeString && targetType.DataType != TypeUnknown {
		errors = append(errors, &Error{
			Code:     ErrCodeInvalidStringOp,
			Message:  "length of target must be a string identifier",
			Position: lengthOf.Target.Position(),
			Rule:     v.currentRule,
		})
	}

	// Length of expressions return integers
	return &TypeInfo{DataType: TypeInteger, IntegerType: Uint64Type}, errors
}

// validateStringIdentifier validates that an expression can be a string identifier
func (v *Validator) validateStringIdentifier(expr ast.Expression) error {
	ident, ok := expr.(*ast.Identifier)
	if !ok {
		return &Error{
			Code:     ErrCodeInvalidStringOp,
			Message:  "string operations require string identifier",
			Position: expr.Position(),
			Rule:     v.currentRule,
		}
	}

	// Check if this identifier could be a string reference
	var stringName string
	if strings.HasPrefix(ident.Name, "$") {
		stringName = ident.Name
	} else {
		// Try with $ prefix for string references in conditions
		stringName = "$" + ident.Name
	}

	if symbol, exists := v.symbolTable.Lookup(stringName); exists && symbol.Type == SymbolString {
		symbol.Used = true
	}

	// We accept the syntax even if string doesn't exist yet
	// This matches the lenient behavior of YARA validation
	return nil
}

func (v *Validator) suggestIdentifier(name string) string {
	var candidates []string
	if strings.HasPrefix(name, "$") {
		candidates = v.currentRuleStrings
	} else {
		candidates = append(candidates, v.currentRuleStrings...)
		candidates = append(candidates, v.allRuleNames...)
		candidates = append(candidates, v.globalVarNames...)
		candidates = append(candidates, filesizeKeyword, entrypointKeyword, themKeyword)
		for mod := range v.importedModules {
			candidates = append(candidates, mod)
		}
		for loopVar := range v.loopVariables {
			candidates = append(candidates, loopVar)
		}
	}
	if suggestion, ok := findSimilarIdentifier(name, candidates); ok {
		return suggestion
	}
	return ""
}
