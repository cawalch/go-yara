// Package semantic implements semantic analysis and validation for YARA rules.
package semantic

import (
	"fmt"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

// SemanticError represents a semantic analysis error
type SemanticError struct {
	Message  string
	Position token.Position
}

func (e *SemanticError) Error() string {
	return fmt.Sprintf("semantic error at %d:%d: %s",
		e.Position.Line, e.Position.Column, e.Message)
}

// Validator performs semantic analysis on YARA rules
type Validator struct {
	symbolTable *SymbolTable
	errors      []error
}

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

	// First pass: collect all rule and string definitions
	for _, rule := range program.Rules {
		v.collectSymbols(rule)
	}

	// Second pass: validate all rules
	for _, rule := range program.Rules {
		v.validateRule(rule)
	}

	return v.errors
}

// collectSymbols collects all symbols from a rule
func (v *Validator) collectSymbols(rule *ast.Rule) {
	// Enter rule scope
	v.symbolTable.EnterScope(fmt.Sprintf("rule_%s", rule.Name))

	// Define the rule itself
	if err := v.symbolTable.DefineRule(rule.Name, rule.Pos, rule); err != nil {
		v.addError(&SemanticError{
			Message:  err.Error(),
			Position: rule.Pos,
		})
	}

	// Define strings
	for _, str := range rule.Strings {
		if err := v.symbolTable.DefineString(str.Identifier, str.Pos, str); err != nil {
			v.addError(&SemanticError{
				Message:  err.Error(),
				Position: str.Pos,
			})
		}
	}

	// Exit rule scope
	v.symbolTable.ExitScope()
}

// validateRule performs semantic validation on a single rule
func (v *Validator) validateRule(rule *ast.Rule) {
	// Enter rule scope for validation
	v.symbolTable.EnterScope(fmt.Sprintf("rule_%s", rule.Name))

	// Re-define strings in the new scope for validation
	for _, str := range rule.Strings {
		if err := v.symbolTable.DefineString(str.Identifier, str.Pos, str); err != nil {
			v.addError(&SemanticError{
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
				v.addError(&SemanticError{
					Message:  fmt.Sprintf("duplicate meta key: %s", m.Key),
					Position: m.Pos,
				})
			}
		}

		// Define meta as variable for potential use in conditions
		if err := v.symbolTable.DefineVariable(m.Key, m.Pos, SymbolVariable); err != nil {
			v.addError(&SemanticError{
				Message:  err.Error(),
				Position: m.Pos,
			})
		}
	}
}

// validateStrings validates the strings section
func (v *Validator) validateStrings(strings []*ast.String) {
	for _, str := range strings {
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
			v.addError(&SemanticError{
				Message:  "condition must evaluate to boolean or numeric",
				Position: condition.Position(),
			})
		}
	}
}

// validateExpression validates an expression and returns its type
func (v *Validator) validateExpression(expr ast.Expression) (*TypeInfo, []error) {
	var errors []error

	switch e := expr.(type) {
	case *ast.Literal:
		return InferTypeFromLiteral(e.Type, e.Value), nil

	case *ast.Identifier:
		// Check for special keywords first
		switch e.Name {
		case "filesize":
			return &TypeInfo{DataType: TypeInteger, IntegerType: Uint64Type}, nil
		case "entrypoint":
			return &TypeInfo{DataType: TypeInteger, IntegerType: Uint64Type}, nil
		case "them":
			return &TypeInfo{DataType: TypeBoolean}, nil
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
		if symbol, exists := v.symbolTable.Lookup(e.Name); exists {
			symbol.Used = true
			return v.getTypeFromSymbol(symbol), nil
		} else {
			errors = append(errors, &SemanticError{
				Message:  fmt.Sprintf("undefined identifier: %s", e.Name),
				Position: e.Position(),
			})
			return &TypeInfo{DataType: TypeUnknown}, errors
		}

	case *ast.BinaryOp:
		leftType, leftErrs := v.validateExpression(e.Left)
		rightType, rightErrs := v.validateExpression(e.Right)

		errors = append(errors, leftErrs...)
		errors = append(errors, rightErrs...)

		if leftType != nil && rightType != nil {
			resultType, err := InferTypeFromBinaryOp(leftType, e.Op, rightType)
			if err != nil {
				errors = append(errors, &SemanticError{
					Message:  err.Error(),
					Position: e.Position(),
				})
				return &TypeInfo{DataType: TypeUnknown}, errors
			}
			return resultType, errors
		}

	case *ast.UnaryOp:
		operandType, operandErrs := v.validateExpression(e.Right)
		errors = append(errors, operandErrs...)

		if operandType != nil {
			resultType, err := InferTypeFromUnaryOp(e.Op, operandType)
			if err != nil {
				errors = append(errors, &SemanticError{
					Message:  err.Error(),
					Position: e.Position(),
				})
				return &TypeInfo{DataType: TypeUnknown}, errors
			}
			return resultType, errors
		}

	default:
		// For other expression types, return unknown for now
		// These will be implemented as more AST nodes are added
		return &TypeInfo{DataType: TypeUnknown}, nil
	}

	return &TypeInfo{DataType: TypeUnknown}, errors
}

// getTypeFromSymbol returns the type information for a symbol
func (v *Validator) getTypeFromSymbol(symbol *Symbol) *TypeInfo {
	switch symbol.Type {
	case SymbolRule:
		return &TypeInfo{DataType: TypeBoolean}
	case SymbolString:
		return &TypeInfo{DataType: TypeBoolean}
	case SymbolVariable:
		// For now, assume variables are integers
		// This will be refined as we add more type information
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

// VisitProgram implements the Visitor pattern for Program nodes
func (v *Validator) VisitProgram(program *ast.Program) interface{} {
	return v.ValidateProgram(program)
}

// VisitRule implements the Visitor pattern for Rule nodes
func (v *Validator) VisitRule(rule *ast.Rule) interface{} {
	v.validateRule(rule)
	return nil
}

// VisitMeta implements the Visitor pattern for Meta nodes
func (v *Validator) VisitMeta(meta *ast.Meta) interface{} {
	// Meta validation is handled in validateMeta
	return nil
}

// VisitString implements the Visitor pattern for String nodes
func (v *Validator) VisitString(str *ast.String) interface{} {
	// String validation is handled in validateStrings
	return nil
}

// VisitCondition implements the Visitor pattern for Condition nodes
func (v *Validator) VisitCondition(condition *ast.Condition) interface{} {
	if condition.Expression != nil {
		v.validateCondition(condition.Expression)
	}
	return nil
}

// VisitBinaryOp implements the Visitor pattern for BinaryOp nodes
func (v *Validator) VisitBinaryOp(binaryOp *ast.BinaryOp) interface{} {
	// Binary operation validation is handled in validateExpression
	return nil
}

// VisitUnaryOp implements the Visitor pattern for UnaryOp nodes
func (v *Validator) VisitUnaryOp(unaryOp *ast.UnaryOp) interface{} {
	// Unary operation validation is handled in validateExpression
	return nil
}

// VisitIdentifier implements the Visitor pattern for Identifier nodes
func (v *Validator) VisitIdentifier(identifier *ast.Identifier) interface{} {
	// Identifier validation is handled in validateExpression
	return nil
}

// VisitLiteral implements the Visitor pattern for Literal nodes
func (v *Validator) VisitLiteral(literal *ast.Literal) interface{} {
	// Literal validation is handled in validateExpression
	return nil
}
