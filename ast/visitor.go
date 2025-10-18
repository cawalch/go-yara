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

func (v *BaseVisitor) VisitProgram(n *Program) interface{}     { return nil }
func (v *BaseVisitor) VisitRule(n *Rule) interface{}           { return nil }
func (v *BaseVisitor) VisitMeta(n *Meta) interface{}           { return nil }
func (v *BaseVisitor) VisitString(n *String) interface{}       { return nil }
func (v *BaseVisitor) VisitCondition(n *Condition) interface{} { return nil }
func (v *BaseVisitor) VisitBinaryOp(n *BinaryOp) interface{}   { return nil }
func (v *BaseVisitor) VisitUnaryOp(n *UnaryOp) interface{}     { return nil }
func (v *BaseVisitor) VisitIdentifier(n *Identifier) interface{} { return nil }
func (v *BaseVisitor) VisitLiteral(n *Literal) interface{}     { return nil }
func (v *BaseVisitor) VisitTextString(n *TextString) interface{} { return nil }
func (v *BaseVisitor) VisitHexString(n *HexString) interface{} { return nil }
func (v *BaseVisitor) VisitRegexPattern(n *RegexPattern) interface{} { return nil }