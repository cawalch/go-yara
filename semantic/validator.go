package semantic

import (
	"fmt"
	"slices"
	"strings"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

// Error represents a semantic analysis error
type Error struct {
	Message  string
	Position token.Position
}

func (e *Error) Error() string {
	return fmt.Sprintf("semantic error at %d:%d: %s",
		e.Position.Line, e.Position.Column, e.Message)
}

// Validator performs semantic analysis on YARA rules
type Validator struct {
	symbolTable *SymbolTable
	errors      []error
}

// Ensure Validator implements the focused visitor interfaces it needs
var _ ast.RuleVisitor = (*Validator)(nil)
var _ ast.ExpressionVisitor = (*Validator)(nil)
var _ ast.ControlFlowVisitor = (*Validator)(nil)

// NewValidator creates a new semantic validator
func NewValidator() *Validator {
	return &Validator{
		symbolTable: NewSymbolTable(),
		errors:      make([]error, 0),
	}
}

// ValidateProgram performs semantic analysis on a complete program
func (v *Validator) ValidateProgram(program *ast.Program) []error {
	v.errors = v.errors[:0] // Clear previous errors
	v.symbolTable.Reset()

	// First: collect external variables
	for _, extVar := range program.ExternalVariables {
		v.collectExternalVariable(extVar)
	}

	// Second pass: collect all rule and string definitions
	for _, rule := range program.Rules {
		v.collectSymbols(rule)
	}

	// Third pass: validate all rules
	for _, rule := range program.Rules {
		v.validateRule(rule)
	}

	return v.errors
}

// collectSymbols collects all symbols from a rule
func (v *Validator) collectSymbols(rule *ast.Rule) {
	// Define the rule itself in the global scope (rules should be globally accessible)
	if err := v.symbolTable.DefineRule(rule.Name, rule.Pos, rule); err != nil {
		v.addError(&Error{
			Message:  err.Error(),
			Position: rule.Pos,
		})
	}

	// Define strings in the global scope as well
	for _, str := range rule.Strings {
		if err := v.symbolTable.DefineString(str.Identifier, str.Pos, str); err != nil {
			v.addError(&Error{
				Message:  err.Error(),
				Position: str.Pos,
			})
		}
	}
}

// collectExternalVariable collects an external variable symbol
func (v *Validator) collectExternalVariable(extVar *ast.ExternalVariable) {
	if err := v.symbolTable.DefineVariable(extVar.Name, extVar.Pos, SymbolExternal); err != nil {
		v.addError(&Error{
			Message:  err.Error(),
			Position: extVar.Pos,
		})
	}
}

// validateRule performs semantic validation on a single rule
func (v *Validator) validateRule(rule *ast.Rule) {
	// Enter rule scope for validation
	v.symbolTable.EnterScope("rule_" + rule.Name)

	// Re-define strings in the new scope for validation
	for _, str := range rule.Strings {
		if err := v.symbolTable.DefineString(str.Identifier, str.Pos, str); err != nil {
			v.addError(&Error{
				Message:  err.Error(),
				Position: str.Pos,
			})
		}
	}

	// Validate meta section
	v.validateMeta(rule.Meta)

	// Validate strings section
	v.validateStrings(rule.Strings)

	// Validate condition
	v.validateCondition(rule.Condition)

	// Exit rule scope
	v.symbolTable.ExitScope()
}

// validateMeta validates the meta section
func (v *Validator) validateMeta(meta []*ast.Meta) {
	for _, m := range meta {
		// Check for duplicate meta keys (already handled by parser, but double-check)
		if existing, exists := v.symbolTable.LookupInCurrentScope(m.Key); exists {
			if existing.Type == SymbolVariable {
				v.addError(&Error{
					Message:  "duplicate meta key: " + m.Key,
					Position: m.Pos,
				})
			}
		}

		// Define meta as variable for potential use in conditions
		if err := v.symbolTable.DefineVariable(m.Key, m.Pos, SymbolVariable); err != nil {
			v.addError(&Error{
				Message:  err.Error(),
				Position: m.Pos,
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
		v.errors = append(v.errors, errs...)

		// Condition should evaluate to boolean or numeric (integers/floats are truthy/falsy)
		if conditionType != nil && conditionType.DataType != TypeBoolean && !conditionType.IsNumeric() {
			v.addError(&Error{
				Message:  "condition must evaluate to boolean or numeric",
				Position: condition.Position(),
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
	case *ast.OfExpression, *ast.FunctionCall, *ast.ForLoop, *ast.StringLength, *ast.ArrayIndex:
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
	case *ast.ArrayIndex:
		return v.validateArrayIndexExpression(e)
	default:
		return v.validateUnknownExpression()
	}
}

// validateUnknownExpression handles unknown expression types
func (v *Validator) validateUnknownExpression() (*TypeInfo, []error) {
	// For other expression types, return unknown for now
	// These will be implemented as more AST nodes are added
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
		return v.getTypeFromSymbol(symbol), nil
	}

	// Try alternative lookups for special cases
	return v.tryAlternativeIdentifierLookups(ident, errors)
}

// validateQuantifierSymbol handles the special $ symbol in quantifiers
func (v *Validator) validateQuantifierSymbol(ident *ast.Identifier) (*TypeInfo, []error) {
	// Special case for $ in quantifiers like "for any of them : ($)"
	// Create a synthetic symbol for this special case to maintain consistency
	if symbol, exists := v.symbolTable.LookupInCurrentScope("$"); exists {
		return v.getTypeFromSymbol(symbol), nil
	}
	// Define a synthetic symbol for the quantifier context
	if err := v.symbolTable.DefineVariable("$", ident.Position(), SymbolVariable); err != nil {
		return &TypeInfo{DataType: TypeUnknown}, []error{&Error{
			Message:  err.Error(),
			Position: ident.Position(),
		}}
	}
	if symbol, exists := v.symbolTable.Lookup("$"); exists {
		return v.getTypeFromSymbol(symbol), nil
	}
	return &TypeInfo{DataType: TypeBoolean}, nil
}

// tryAlternativeIdentifierLookups attempts to find identifier in alternative contexts
func (v *Validator) tryAlternativeIdentifierLookups(ident *ast.Identifier, errors []error) (*TypeInfo, []error) {
	// Check if this might be a string reference without the $ prefix
	// This happens when using #, @, or ! operators in conditions
	if stringSymbol, hasStringSymbol := v.symbolTable.Lookup("$" + ident.Name); hasStringSymbol {
		stringSymbol.Used = true
		return v.getTypeFromSymbol(stringSymbol), nil
	}

	// Check if this might be a module function (e.g., pe.is_pe)
	if strings.Contains(ident.Name, ".") {
		// This is likely a module function, return integer type
		return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}, nil
	}

	// Check if this might be a rule reference from an included file
	// Rules are globally accessible, so check the global scope
	if globalSymbol, hasGlobalSymbol := v.symbolTable.LookupInGlobalScope(ident.Name); hasGlobalSymbol {
		globalSymbol.Used = true
		return v.getTypeFromSymbol(globalSymbol), nil
	}

	errors = append(errors, &Error{
		Message:  "undefined identifier: " + ident.Name,
		Position: ident.Position(),
	})
	return &TypeInfo{DataType: TypeUnknown}, errors
}

// validateBinaryOpExpression validates binary operation expressions
func (v *Validator) validateBinaryOpExpression(binOp *ast.BinaryOp) (*TypeInfo, []error) {
	var errors []error

	// Special handling for module access (dot notation)
	if binOp.Op == token.DOT {
		if resultType, handled := v.handleModuleAccess(binOp, errors); handled {
			return resultType, errors
		}
	}

	leftType, leftErrs := v.validateExpression(binOp.Left)
	rightType, rightErrs := v.validateExpression(binOp.Right)

	errors = append(errors, leftErrs...)
	errors = append(errors, rightErrs...)

	if leftType != nil && rightType != nil {
		resultType, err := InferTypeFromBinaryOp(leftType, binOp.Op, rightType)
		if err != nil {
			errors = append(errors, &Error{
				Message:  err.Error(),
				Position: binOp.Position(),
			})
			return &TypeInfo{DataType: TypeUnknown}, errors
		}
		return resultType, errors
	}

	return &TypeInfo{DataType: TypeUnknown}, errors
}

// handleModuleAccess handles module access expressions (e.g., pe.is_pe)
func (v *Validator) handleModuleAccess(binOp *ast.BinaryOp, _ []error) (*TypeInfo, bool) {
	if leftIdent, ok := binOp.Left.(*ast.Identifier); ok {
		if rightIdent, isRightIdent := binOp.Right.(*ast.Identifier); isRightIdent {
			// Check if this is a module function (e.g., pe.is_pe)
			if v.isModuleFunction(leftIdent.Name) {
				// Module functions return integer or boolean depending on the function
				// For now, we'll assume they return integer for most functions
				// and boolean for is_* functions
				if strings.HasPrefix(rightIdent.Name, "is_") {
					return &TypeInfo{DataType: TypeBoolean}, true
				}
				return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}, true
			}
		}
	}
	return nil, false
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
				Message:  err.Error(),
				Position: unaryOp.Position(),
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

// validateOfExpression validates of expressions
func (v *Validator) validateOfExpression(ofExpr *ast.OfExpression) (*TypeInfo, []error) {
	var errors []error

	// Validate the count expression
	_, countErrs := v.validateExpression(ofExpr.Count)
	errors = append(errors, countErrs...)

	// Validate the strings expression
	_, stringsErrs := v.validateExpression(ofExpr.Strings)
	errors = append(errors, stringsErrs...)

	// Of expressions always return boolean
	return &TypeInfo{DataType: TypeBoolean}, errors
}

// validateFunctionCallExpression validates function call expressions
func (v *Validator) validateFunctionCallExpression(funcCall *ast.FunctionCall) (*TypeInfo, []error) {
	var errors []error

	// Validate function arguments
	for _, arg := range funcCall.Args {
		_, argErrs := v.validateExpression(arg)
		errors = append(errors, argErrs...)
	}

	// Data type functions return integers
	return &TypeInfo{DataType: TypeInteger, IntegerType: Uint64Type}, errors
}

// validateForLoopExpression validates for loop expressions
func (v *Validator) validateForLoopExpression(forLoop *ast.ForLoop) (*TypeInfo, []error) {
	var errors []error

	// Validate the range expression
	_, rangeErrs := v.validateExpression(forLoop.Range)
	errors = append(errors, rangeErrs...)

	// Validate the condition expression
	_, conditionErrs := v.validateExpression(forLoop.Condition)
	errors = append(errors, conditionErrs...)

	// For loops always return boolean
	return &TypeInfo{DataType: TypeBoolean}, errors
}

// validateStringLengthExpression validates string length expressions
func (v *Validator) validateStringLengthExpression(strLen *ast.StringLength) (*TypeInfo, []error) {
	var errors []error

	// StringLength is created by the parser for !string operator
	// The string expression should be an identifier
	fmt.Printf("DEBUG: StringLength node with string: %T\n", strLen.String)
	if ident, ok := strLen.String.(*ast.Identifier); ok {
		if resultType, found := v.checkStringLengthIdentifier(ident, errors); found {
			return resultType, errors
		}
	}

	// Validate the string expression
	_, stringErrs := v.validateExpression(strLen.String)
	errors = append(errors, stringErrs...)

	// String length returns integer
	return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}, errors
}

// checkStringLengthIdentifier checks if a string length identifier is valid
func (v *Validator) checkStringLengthIdentifier(ident *ast.Identifier, _ []error) (*TypeInfo, bool) {
	// Check if this is a string reference (with or without $ prefix)
	var stringName string
	if strings.HasPrefix(ident.Name, "$") {
		stringName = ident.Name
	} else {
		// Try with $ prefix for string references in conditions
		stringName = "$" + ident.Name
	}

	fmt.Printf("DEBUG: Looking up string symbol: %s\n", stringName)
	if symbol, exists := v.symbolTable.Lookup(stringName); exists && symbol.Type == SymbolString {
		// String length returns integer
		fmt.Printf("DEBUG: Found string symbol, returning integer type\n")
		return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}, true
	}
	return nil, false
}

// validateArrayIndexExpression validates array index expressions
func (v *Validator) validateArrayIndexExpression(arrayIndex *ast.ArrayIndex) (*TypeInfo, []error) {
	var errors []error

	// Validate the array expression
	arrayType, arrayErrs := v.validateExpression(arrayIndex.Array)
	errors = append(errors, arrayErrs...)

	// Validate the index expression
	_, indexErrs := v.validateExpression(arrayIndex.Index)
	errors = append(errors, indexErrs...)

	// Array indexing returns the type of the array elements
	// For now, assume it returns the same type as the array
	return arrayType, errors
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
		// For now, assume variables are integers
		// This will be refined as we add more type information
		return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}
	case SymbolExternal:
		// External variables could be string, integer, or boolean
		// For now, assume integer type (will be refined with type hints)
		return &TypeInfo{DataType: TypeInteger, IntegerType: Int64Type}
	default:
		return &TypeInfo{DataType: TypeUnknown}
	}
}

// addError adds a semantic error
func (v *Validator) addError(err error) {
	v.errors = append(v.errors, err)
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

// ============================================================================
// Visitor Pattern Implementation - Focused Interface Methods
// ============================================================================

// RuleVisitor implementations

// VisitProgram visits and validates a program node
func (v *Validator) VisitProgram(program *ast.Program) any {
	return v.ValidateProgram(program)
}

// VisitRule visits and validates a rule node
func (v *Validator) VisitRule(rule *ast.Rule) any {
	v.validateRule(rule)
	return nil
}

// VisitMeta visits and validates a meta node
func (v *Validator) VisitMeta(_ *ast.Meta) any {
	// Meta validation is handled in validateMeta
	return nil
}

// VisitString visits and validates a string node
func (v *Validator) VisitString(_ *ast.String) any {
	// String validation is handled in validateStrings
	return nil
}

// VisitCondition visits and validates a condition node
func (v *Validator) VisitCondition(condition *ast.Condition) any {
	if condition.Expression != nil {
		v.validateCondition(condition.Expression)
	}
	return nil
}

// ExpressionVisitor implementations

// VisitBinaryOp visits and validates a binary operation node
func (v *Validator) VisitBinaryOp(_ *ast.BinaryOp) any {
	// Binary operation validation is handled in validateExpression
	return nil
}

// VisitUnaryOp visits and validates a unary operation node
func (v *Validator) VisitUnaryOp(_ *ast.UnaryOp) any {
	// Unary operation validation is handled in validateExpression
	return nil
}

// VisitIdentifier visits and validates an identifier node
func (v *Validator) VisitIdentifier(_ *ast.Identifier) any {
	// Identifier validation is handled in validateExpression
	return nil
}

// VisitLiteral visits and validates a literal node
func (v *Validator) VisitLiteral(_ *ast.Literal) any {
	// Literal validation is handled in validateExpression
	return nil
}

// VisitFunctionCall visits and validates a function call node
func (v *Validator) VisitFunctionCall(_ *ast.FunctionCall) any {
	// FunctionCall validation is handled in validateExpression
	return nil
}

// ControlFlowVisitor implementations

// VisitForLoop visits and validates a for loop node
func (v *Validator) VisitForLoop(_ *ast.ForLoop) any {
	// ForLoop validation is handled in validateExpression
	return nil
}

// VisitOfExpression visits and validates an of expression node
func (v *Validator) VisitOfExpression(_ *ast.OfExpression) any {
	// OfExpression validation is handled in validateExpression
	return nil
}

// VisitStringLength visits and validates a string length node
func (v *Validator) VisitStringLength(_ *ast.StringLength) any {
	// StringLength validation is handled in validateExpression
	return nil
}

// VisitArrayIndex visits and validates an array index node
func (v *Validator) VisitArrayIndex(_ *ast.ArrayIndex) any {
	// ArrayIndex validation is handled in validateExpression
	return nil
}

// isModuleFunction checks if an identifier is a known module
func (v *Validator) isModuleFunction(moduleName string) bool {
	// List of known YARA modules
	knownModules := []string{
		"pe", "elf", "macho", "dotnet", "cuckoo", "hash", "text",
	}

	return slices.Contains(knownModules, moduleName)
}
