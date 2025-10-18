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
