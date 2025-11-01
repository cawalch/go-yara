package ast

// Visitor is the interface for visiting AST nodes
type Visitor interface {
	VisitProgram(*Program) any
	VisitRule(*Rule) any
	VisitMeta(*Meta) any
	VisitString(*String) any
	VisitCondition(*Condition) any
	VisitBinaryOp(*BinaryOp) any
	VisitUnaryOp(*UnaryOp) any
	VisitIdentifier(*Identifier) any
	VisitLiteral(*Literal) any
	VisitTextString(*TextString) any
	VisitHexString(*HexString) any
	VisitRegexPattern(*RegexPattern) any
	VisitGlobalVariable(*GlobalVariable) any
	VisitExternalVariable(*ExternalVariable) any
	VisitImport(*Import) any
	VisitInclude(*Include) any
	VisitStringLength(*StringLength) any
	VisitArrayIndex(*ArrayIndex) any
	VisitForLoop(*ForLoop) any
	VisitOfExpression(*OfExpression) any
	VisitFunctionCall(*FunctionCall) any
	// Add more as needed
}

// BaseVisitor provides default implementations
type BaseVisitor struct{}

// VisitProgram visits a Program node
func (v *BaseVisitor) VisitProgram(_ *Program) any { return nil }

// VisitRule visits a Rule node
func (v *BaseVisitor) VisitRule(_ *Rule) any { return nil }

// VisitMeta visits a Meta node
func (v *BaseVisitor) VisitMeta(_ *Meta) any { return nil }

// VisitString visits a String node
func (v *BaseVisitor) VisitString(_ *String) any { return nil }

// VisitCondition visits a Condition node
func (v *BaseVisitor) VisitCondition(_ *Condition) any { return nil }

// VisitBinaryOp visits a BinaryOp node
func (v *BaseVisitor) VisitBinaryOp(_ *BinaryOp) any { return nil }

// VisitUnaryOp visits a UnaryOp node
func (v *BaseVisitor) VisitUnaryOp(_ *UnaryOp) any { return nil }

// VisitIdentifier visits an Identifier node
func (v *BaseVisitor) VisitIdentifier(_ *Identifier) any { return nil }

// VisitLiteral visits a Literal node
func (v *BaseVisitor) VisitLiteral(_ *Literal) any { return nil }

// VisitTextString visits a TextString node
func (v *BaseVisitor) VisitTextString(_ *TextString) any { return nil }

// VisitHexString visits a HexString node
func (v *BaseVisitor) VisitHexString(_ *HexString) any { return nil }

// VisitRegexPattern visits a RegexPattern node
func (v *BaseVisitor) VisitRegexPattern(_ *RegexPattern) any { return nil }

// VisitGlobalVariable visits a GlobalVariable node
func (v *BaseVisitor) VisitGlobalVariable(_ *GlobalVariable) any { return nil }

// VisitExternalVariable visits an ExternalVariable node
func (v *BaseVisitor) VisitExternalVariable(_ *ExternalVariable) any { return nil }

// VisitImport visits an Import node
func (v *BaseVisitor) VisitImport(_ *Import) any { return nil }

// VisitInclude visits an Include node
func (v *BaseVisitor) VisitInclude(_ *Include) any { return nil }

// VisitStringLength visits a StringLength node
func (v *BaseVisitor) VisitStringLength(_ *StringLength) any { return nil }

// VisitArrayIndex visits an ArrayIndex node
func (v *BaseVisitor) VisitArrayIndex(_ *ArrayIndex) any { return nil }

// VisitForLoop visits a ForLoop node
func (v *BaseVisitor) VisitForLoop(_ *ForLoop) any { return nil }

// VisitOfExpression visits an OfExpression node
func (v *BaseVisitor) VisitOfExpression(_ *OfExpression) any { return nil }

// VisitFunctionCall visits a FunctionCall node
func (v *BaseVisitor) VisitFunctionCall(_ *FunctionCall) any { return nil }
