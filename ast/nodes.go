package ast

import "github.com/cawalch/go-yara/token"

// Program represents the root of the AST
type Program struct {
	Pos   token.Position
	Rules []*Rule
}

func (p *Program) node()                    {}
func (p *Program) Position() token.Position { return p.Pos }
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

func (r *Rule) node()                    {}
func (r *Rule) Position() token.Position { return r.Pos }
func (r *Rule) Accept(v Visitor) interface{} {
	return v.VisitRule(r)
}

// Meta represents a metadata entry
type Meta struct {
	Pos   token.Position
	Key   string
	Value interface{} // string, int64, or bool
}

func (m *Meta) node()                    {}
func (m *Meta) Position() token.Position { return m.Pos }
func (m *Meta) Accept(v Visitor) interface{} {
	return v.VisitMeta(m)
}

// String represents a string definition
type String struct {
	Pos       token.Position
	Identifier string
	Pattern   Pattern
	Modifiers []StringModifier
}

func (s *String) node()                    {}
func (s *String) Position() token.Position { return s.Pos }
func (s *String) Accept(v Visitor) interface{} {
	return v.VisitString(s)
}

// Condition represents the condition section
type Condition struct {
	Pos        token.Position
	Expression Expression
}

func (c *Condition) node()                    {}
func (c *Condition) Position() token.Position { return c.Pos }
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

func (b *BinaryOp) node()                    {}
func (b *BinaryOp) Position() token.Position { return b.Pos }
func (b *BinaryOp) expression()              {}
func (b *BinaryOp) Accept(v Visitor) interface{} {
	return v.VisitBinaryOp(b)
}

// UnaryOp represents a unary operation
type UnaryOp struct {
	Pos   token.Position
	Op    token.TokenType
	Right Expression
}

func (u *UnaryOp) node()                    {}
func (u *UnaryOp) Position() token.Position { return u.Pos }
func (u *UnaryOp) expression()              {}
func (u *UnaryOp) Accept(v Visitor) interface{} {
	return v.VisitUnaryOp(u)
}

// Identifier represents an identifier
type Identifier struct {
	Pos  token.Position
	Name string
}

func (i *Identifier) node()                    {}
func (i *Identifier) Position() token.Position { return i.Pos }
func (i *Identifier) expression()              {}
func (i *Identifier) Accept(v Visitor) interface{} {
	return v.VisitIdentifier(i)
}

// Literal represents a literal value
type Literal struct {
	Pos   token.Position
	Type  token.TokenType
	Value interface{}
}

func (l *Literal) node()                    {}
func (l *Literal) Position() token.Position { return l.Pos }
func (l *Literal) expression()              {}
func (l *Literal) Accept(v Visitor) interface{} {
	return v.VisitLiteral(l)
}