package ast

// Visitor is the interface for visiting AST nodes
type Visitor interface {
	VisitProgram(*Program) interface{}
	VisitRule(*Rule) interface{}
	VisitMeta(*Meta) interface{}
	VisitString(*String) interface{}
	VisitCondition(*Condition) interface{}
	VisitBinaryOp(*BinaryOp) interface{}
	VisitUnaryOp(*UnaryOp) interface{}
	VisitIdentifier(*Identifier) interface{}
	VisitLiteral(*Literal) interface{}
	VisitTextString(*TextString) interface{}
	VisitHexString(*HexString) interface{}
	VisitRegexPattern(*RegexPattern) interface{}
	VisitGlobalVariable(*GlobalVariable) interface{}
	VisitImport(*Import) interface{}
	VisitInclude(*Include) interface{}
	VisitStringLength(*StringLength) interface{}
	VisitArrayIndex(*ArrayIndex) interface{}
	VisitForLoop(*ForLoop) interface{}
	VisitOfExpression(*OfExpression) interface{}
	// Add more as needed
}

// BaseVisitor provides default implementations
type BaseVisitor struct{}

// VisitProgram visits a Program node
func (v *BaseVisitor) VisitProgram(n *Program) interface{} { return nil }

// VisitRule visits a Rule node
func (v *BaseVisitor) VisitRule(n *Rule) interface{} { return nil }

// VisitMeta visits a Meta node
func (v *BaseVisitor) VisitMeta(n *Meta) interface{} { return nil }

// VisitString visits a String node
func (v *BaseVisitor) VisitString(n *String) interface{} { return nil }

// VisitCondition visits a Condition node
func (v *BaseVisitor) VisitCondition(n *Condition) interface{} { return nil }

// VisitBinaryOp visits a BinaryOp node
func (v *BaseVisitor) VisitBinaryOp(n *BinaryOp) interface{} { return nil }

// VisitUnaryOp visits a UnaryOp node
func (v *BaseVisitor) VisitUnaryOp(n *UnaryOp) interface{} { return nil }

// VisitIdentifier visits an Identifier node
func (v *BaseVisitor) VisitIdentifier(n *Identifier) interface{} { return nil }

// VisitLiteral visits a Literal node
func (v *BaseVisitor) VisitLiteral(n *Literal) interface{} { return nil }

// VisitTextString visits a TextString node
func (v *BaseVisitor) VisitTextString(n *TextString) interface{} { return nil }

// VisitHexString visits a HexString node
func (v *BaseVisitor) VisitHexString(n *HexString) interface{} { return nil }

// VisitRegexPattern visits a RegexPattern node
func (v *BaseVisitor) VisitRegexPattern(n *RegexPattern) interface{} { return nil }

// VisitGlobalVariable visits a GlobalVariable node
func (v *BaseVisitor) VisitGlobalVariable(n *GlobalVariable) interface{} { return nil }

// VisitImport visits an Import node
func (v *BaseVisitor) VisitImport(n *Import) interface{} { return nil }

// VisitInclude visits an Include node
func (v *BaseVisitor) VisitInclude(n *Include) interface{} { return nil }

// VisitStringLength visits a StringLength node
func (v *BaseVisitor) VisitStringLength(n *StringLength) interface{} { return nil }

// VisitArrayIndex visits an ArrayIndex node
func (v *BaseVisitor) VisitArrayIndex(n *ArrayIndex) interface{} { return nil }

// VisitForLoop visits a ForLoop node
func (v *BaseVisitor) VisitForLoop(n *ForLoop) interface{} { return nil }

// VisitOfExpression visits an OfExpression node
func (v *BaseVisitor) VisitOfExpression(n *OfExpression) interface{} { return nil }
