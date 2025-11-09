package ast

// ============================================================================
// Focused Visitor Interfaces - Interface Segregation Principle
// ============================================================================
//
// This file implements the Interface Segregation Principle to address
// interface pollution in the original monolithic Visitor interface (23 methods).
//
// Instead of one large interface, we now have focused interfaces:
// - RuleVisitor: Handles rule structure (5 methods)
// - ExpressionVisitor: Handles expressions and operations (5 methods)
// - PatternVisitor: Handles string patterns (4 methods)
// - VariableVisitor: Handles variable references (2 methods)
// - ControlFlowVisitor: Handles loops and control structures (3 methods)
// - ModuleVisitor: Handles imports and includes (2 methods)
//
// Benefits:
// - Consumers implement only needed methods
// - Easier testing with focused mock visitors
// - Better separation of concerns
// - More maintainable code
//
// Usage Examples:
//
// // For simple rule processing:
// type RuleProcessor struct{}
// func (r *RuleProcessor) VisitProgram(p *Program) any { /* ... */ }
// func (r *RuleProcessor) VisitRule(rule *Rule) any { /* ... */ }
// // Only implement RuleVisitor methods you need
//
// // For expression evaluation:
// type ExpressionEvaluator struct{}
// func (e *ExpressionEvaluator) VisitBinaryOp(op *BinaryOp) any { /* ... */ }
// func (e *ExpressionEvaluator) VisitLiteral(lit *Literal) any { /* ... */ }
// // Only implement ExpressionVisitor methods you need
//
// ============================================================================

// Core node visitors - handle rule structure
type RuleVisitor interface {
	VisitProgram(*Program) any
	VisitRule(*Rule) any
	VisitMeta(*Meta) any
	VisitString(*String) any
	VisitCondition(*Condition) any
}

// Expression visitors - handle expressions and operations
type ExpressionVisitor interface {
	VisitBinaryOp(*BinaryOp) any
	VisitUnaryOp(*UnaryOp) any
	VisitIdentifier(*Identifier) any
	VisitLiteral(*Literal) any
	VisitFunctionCall(*FunctionCall) any
}

// Pattern visitors - handle string and pattern matching
type PatternVisitor interface {
	VisitTextString(*TextString) any
	VisitHexString(*HexString) any
	VisitRegexPattern(*RegexPattern) any
	VisitStringLength(*StringLength) any
}

// Variable visitors - handle variable references
type VariableVisitor interface {
	VisitGlobalVariable(*GlobalVariable) any
	VisitExternalVariable(*ExternalVariable) any
}

// Control flow visitors - handle loops and control structures
type ControlFlowVisitor interface {
	VisitForLoop(*ForLoop) any
	VisitOfExpression(*OfExpression) any
	VisitArrayIndex(*ArrayIndex) any
}

// Module system visitors - handle imports and includes
type ModuleVisitor interface {
	VisitImport(*Import) any
	VisitInclude(*Include) any
}

// Visitor is the complete interface for visiting all AST nodes
// Kept for backward compatibility - consumers can use focused interfaces instead
type Visitor interface {
	RuleVisitor
	ExpressionVisitor
	PatternVisitor
	VariableVisitor
	ControlFlowVisitor
	ModuleVisitor
}

// BaseVisitor provides default implementations for all visitor interfaces
type BaseVisitor struct{}

// RuleVisitor implementations
func (v *BaseVisitor) VisitProgram(_ *Program) any     { return nil }
func (v *BaseVisitor) VisitRule(_ *Rule) any           { return nil }
func (v *BaseVisitor) VisitMeta(_ *Meta) any           { return nil }
func (v *BaseVisitor) VisitString(_ *String) any       { return nil }
func (v *BaseVisitor) VisitCondition(_ *Condition) any { return nil }

// ExpressionVisitor implementations
func (v *BaseVisitor) VisitBinaryOp(_ *BinaryOp) any         { return nil }
func (v *BaseVisitor) VisitUnaryOp(_ *UnaryOp) any           { return nil }
func (v *BaseVisitor) VisitIdentifier(_ *Identifier) any     { return nil }
func (v *BaseVisitor) VisitLiteral(_ *Literal) any           { return nil }
func (v *BaseVisitor) VisitFunctionCall(_ *FunctionCall) any { return nil }

// PatternVisitor implementations
func (v *BaseVisitor) VisitTextString(_ *TextString) any     { return nil }
func (v *BaseVisitor) VisitHexString(_ *HexString) any       { return nil }
func (v *BaseVisitor) VisitRegexPattern(_ *RegexPattern) any { return nil }
func (v *BaseVisitor) VisitStringLength(_ *StringLength) any { return nil }

// VariableVisitor implementations
func (v *BaseVisitor) VisitGlobalVariable(_ *GlobalVariable) any     { return nil }
func (v *BaseVisitor) VisitExternalVariable(_ *ExternalVariable) any { return nil }

// ControlFlowVisitor implementations
func (v *BaseVisitor) VisitForLoop(_ *ForLoop) any           { return nil }
func (v *BaseVisitor) VisitOfExpression(_ *OfExpression) any { return nil }
func (v *BaseVisitor) VisitArrayIndex(_ *ArrayIndex) any     { return nil }

// ModuleVisitor implementations
func (v *BaseVisitor) VisitImport(_ *Import) any   { return nil }
func (v *BaseVisitor) VisitInclude(_ *Include) any { return nil }

// Focused base visitors for common use cases

// RuleBaseVisitor provides implementations only for rule structure
type RuleBaseVisitor struct{}

func (v *RuleBaseVisitor) VisitProgram(_ *Program) any     { return nil }
func (v *RuleBaseVisitor) VisitRule(_ *Rule) any           { return nil }
func (v *RuleBaseVisitor) VisitMeta(_ *Meta) any           { return nil }
func (v *RuleBaseVisitor) VisitString(_ *String) any       { return nil }
func (v *RuleBaseVisitor) VisitCondition(_ *Condition) any { return nil }

// ExpressionBaseVisitor provides implementations only for expressions
type ExpressionBaseVisitor struct{}

func (v *ExpressionBaseVisitor) VisitBinaryOp(_ *BinaryOp) any         { return nil }
func (v *ExpressionBaseVisitor) VisitUnaryOp(_ *UnaryOp) any           { return nil }
func (v *ExpressionBaseVisitor) VisitIdentifier(_ *Identifier) any     { return nil }
func (v *ExpressionBaseVisitor) VisitLiteral(_ *Literal) any           { return nil }
func (v *ExpressionBaseVisitor) VisitFunctionCall(_ *FunctionCall) any { return nil }
