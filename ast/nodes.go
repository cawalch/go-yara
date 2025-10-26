package ast

import (
	"fmt"
	"github.com/cawalch/go-yara/token"
)

// Program represents the root of the AST
type Program struct {
	Pos               token.Position
	Rules             []*Rule
	GlobalVariables   []*GlobalVariable
	ExternalVariables []*ExternalVariable
	Imports           []*Import
	Includes          []*Include
}

func (p *Program) node() {}

// Position returns the position of the Program node
func (p *Program) Position() token.Position { return p.Pos }

// Accept implements the Visitor pattern for Program
func (p *Program) Accept(v Visitor) interface{} {
	return v.VisitProgram(p)
}

// Rule represents a YARA rule
type Rule struct {
	Pos       token.Position
	Name      string
	Modifiers []Modifier
	Tags      []string
	Meta      []*Meta
	Strings   []*String
	Condition Expression
}

func (r *Rule) node() {}

// Position returns the position of the Rule node
func (r *Rule) Position() token.Position { return r.Pos }

// Accept implements the Visitor pattern for Rule
func (r *Rule) Accept(v Visitor) interface{} {
	return v.VisitRule(r)
}

// MetaValue represents the value of a meta entry
// This provides type safety compared to interface{}
type MetaValue interface {
	isMetaValue()
}

// MetaString represents a string meta value
type MetaString string

func (m MetaString) isMetaValue() {}

// MetaInt represents an integer meta value
type MetaInt int64

func (m MetaInt) isMetaValue() {}

// MetaBool represents a boolean meta value
type MetaBool bool

func (m MetaBool) isMetaValue() {}

// Meta represents a metadata entry
type Meta struct {
	Pos   token.Position
	Key   string
	Value MetaValue
}

// String returns the string representation of the meta value
func (m *Meta) String() string {
	switch v := m.Value.(type) {
	case MetaString:
		return string(v)
	case MetaInt:
		return fmt.Sprintf("%d", int64(v))
	case MetaBool:
		return fmt.Sprintf("%t", bool(v))
	default:
		return fmt.Sprintf("%v", v)
	}
}

// AsString returns the meta value as a string, or empty string if not a string
func (m *Meta) AsString() string {
	if str, ok := m.Value.(MetaString); ok {
		return string(str)
	}
	return ""
}

// AsInt returns the meta value as an int64, or 0 if not an integer
func (m *Meta) AsInt() int64 {
	if i, ok := m.Value.(MetaInt); ok {
		return int64(i)
	}
	return 0
}

// AsBool returns the meta value as a bool, or false if not a boolean
func (m *Meta) AsBool() bool {
	if b, ok := m.Value.(MetaBool); ok {
		return bool(b)
	}
	return false
}

func (m *Meta) node() {}

// Position returns the position of the Meta node
func (m *Meta) Position() token.Position { return m.Pos }

// Accept implements the Visitor pattern for Meta
func (m *Meta) Accept(v Visitor) interface{} {
	return v.VisitMeta(m)
}

// String represents a string definition
type String struct {
	Pos        token.Position
	Identifier string
	Pattern    Pattern
	Modifiers  []StringModifier
}

func (s *String) node() {}

// Position returns the position of the String node
func (s *String) Position() token.Position { return s.Pos }

// Accept implements the Visitor pattern for String
func (s *String) Accept(v Visitor) interface{} {
	return v.VisitString(s)
}

// Condition represents the condition section
type Condition struct {
	Pos        token.Position
	Expression Expression
}

func (c *Condition) node() {}

// Position returns the position of the Condition node
func (c *Condition) Position() token.Position { return c.Pos }

// Accept implements the Visitor pattern for Condition
func (c *Condition) Accept(v Visitor) interface{} {
	return v.VisitCondition(c)
}

// BinaryOp represents a binary operation
type BinaryOp struct {
	Pos   token.Position
	Left  Expression
	Op    token.TokenType
	Right Expression
}

func (b *BinaryOp) node() {}

// Position returns the position of the BinaryOp node
func (b *BinaryOp) Position() token.Position { return b.Pos }

func (b *BinaryOp) expression() {}

// Accept implements the Visitor pattern for BinaryOp
func (b *BinaryOp) Accept(v Visitor) interface{} {
	return v.VisitBinaryOp(b)
}

// UnaryOp represents a unary operation
type UnaryOp struct {
	Pos   token.Position
	Op    token.TokenType
	Right Expression
}

func (u *UnaryOp) node() {}

// Position returns the position of the UnaryOp node
func (u *UnaryOp) Position() token.Position { return u.Pos }

func (u *UnaryOp) expression() {}

// Accept implements the Visitor pattern for UnaryOp
func (u *UnaryOp) Accept(v Visitor) interface{} {
	return v.VisitUnaryOp(u)
}

// Identifier represents an identifier
type Identifier struct {
	Pos  token.Position
	Name string
}

func (i *Identifier) node() {}

// Position returns the position of the Identifier node
func (i *Identifier) Position() token.Position { return i.Pos }

func (i *Identifier) expression() {}

// Accept implements the Visitor pattern for Identifier
func (i *Identifier) Accept(v Visitor) interface{} {
	return v.VisitIdentifier(i)
}

// Literal represents a literal value
type Literal struct {
	Pos   token.Position
	Type  token.TokenType
	Value interface{}
}

func (l *Literal) node() {}

// Position returns the position of the Literal node
func (l *Literal) Position() token.Position { return l.Pos }

func (l *Literal) expression() {}

// Accept implements the Visitor pattern for Literal
func (l *Literal) Accept(v Visitor) interface{} {
	return v.VisitLiteral(l)
}

// GlobalVariable represents a global variable declaration
type GlobalVariable struct {
	Pos   token.Position
	Name  string
	Value Expression
}

func (g *GlobalVariable) node() {}

// Position returns position of GlobalVariable node
func (g *GlobalVariable) Position() token.Position { return g.Pos }

// Accept implements the Visitor pattern for GlobalVariable
func (g *GlobalVariable) Accept(v Visitor) interface{} {
	return v.VisitGlobalVariable(g)
}

// ExternalVariable represents an external variable declaration
type ExternalVariable struct {
	Pos        token.Position
	Name       string
	Identifier string // For binding to runtime values
	TypeHint   string // Optional type hint (integer, string, boolean)
}

func (e *ExternalVariable) node() {}

// Position returns position of ExternalVariable node
func (e *ExternalVariable) Position() token.Position { return e.Pos }

// Accept implements the Visitor pattern for ExternalVariable
func (e *ExternalVariable) Accept(v Visitor) interface{} {
	return v.VisitExternalVariable(e)
}

// Import represents an import statement
type Import struct {
	Pos    token.Position
	Module string
}

func (i *Import) node() {}

// Position returns position of Import node
func (i *Import) Position() token.Position { return i.Pos }

// Accept implements the Visitor pattern for Import
func (i *Import) Accept(v Visitor) interface{} {
	return v.VisitImport(i)
}

// Include represents an include statement
type Include struct {
	Pos  token.Position
	File string
}

func (i *Include) node() {}

// Position returns position of Include node
func (i *Include) Position() token.Position { return i.Pos }

// Accept implements the Visitor pattern for Include
func (i *Include) Accept(v Visitor) interface{} {
	return v.VisitInclude(i)
}

// StringLength represents a string length expression
type StringLength struct {
	Pos    token.Position
	String Expression
}

func (s *StringLength) node() {}

// Position returns position of StringLength node
func (s *StringLength) Position() token.Position { return s.Pos }

func (s *StringLength) expression() {}

// Accept implements the Visitor pattern for StringLength
func (s *StringLength) Accept(v Visitor) interface{} {
	return v.VisitStringLength(s)
}

// ArrayIndex represents an array indexing expression
type ArrayIndex struct {
	Pos   token.Position
	Array Expression
	Index Expression
}

func (a *ArrayIndex) node() {}

// Position returns position of ArrayIndex node
func (a *ArrayIndex) Position() token.Position { return a.Pos }

func (a *ArrayIndex) expression() {}

// Accept implements the Visitor pattern for ArrayIndex
func (a *ArrayIndex) Accept(v Visitor) interface{} {
	return v.VisitArrayIndex(a)
}

// ForLoop represents a for loop expression
type ForLoop struct {
	Pos        token.Position
	Quantifier string // "all", "any", "none"
	Variable   string
	Range      Expression
	Condition  Expression
}

func (f *ForLoop) node() {}

// Position returns position of ForLoop node
func (f *ForLoop) Position() token.Position { return f.Pos }

func (f *ForLoop) expression() {}

// Accept implements the Visitor pattern for ForLoop
func (f *ForLoop) Accept(v Visitor) interface{} {
	return v.VisitForLoop(f)
}

// OfExpression represents an "of" expression
type OfExpression struct {
	Pos     token.Position
	Count   Expression
	Strings Expression // Can be "them" or a list of strings
}

func (o *OfExpression) node() {}

// Position returns position of OfExpression node
func (o *OfExpression) Position() token.Position { return o.Pos }

func (o *OfExpression) expression() {}

// Accept implements the Visitor pattern for OfExpression
func (o *OfExpression) Accept(v Visitor) interface{} {
	return v.VisitOfExpression(o)
}

// FunctionCall represents a function call expression
type FunctionCall struct {
	Pos      token.Position
	Function string
	Args     []Expression
}

func (f *FunctionCall) node() {}

// Position returns position of FunctionCall node
func (f *FunctionCall) Position() token.Position { return f.Pos }

func (f *FunctionCall) expression() {}

// Accept implements the Visitor pattern for FunctionCall
func (f *FunctionCall) Accept(v Visitor) interface{} {
	return v.VisitFunctionCall(f)
}
