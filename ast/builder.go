package ast

import "github.com/cawalch/go-yara/token"

// Builder provides convenient methods for constructing AST nodes
type Builder struct{}

// NewBuilder creates a new AST builder
func NewBuilder() *Builder {
	return &Builder{}
}

// Program creates a new Program node
func (b *Builder) Program(rules []*Rule) *Program {
	return &Program{
		Pos:             token.Position{},
		Rules:           rules,
		GlobalVariables: []*GlobalVariable{},
		Imports:         []*Import{},
		Includes:        []*Include{},
	}
}

// Rule creates a new Rule node
func (b *Builder) Rule(pos token.Position, name string) *Rule {
	return &Rule{
		Pos:  pos,
		Name: name,
	}
}

// BinaryOp creates a new BinaryOp node
func (b *Builder) BinaryOp(
	pos token.Position,
	left Expression,
	op token.TokenType,
	right Expression,
) *BinaryOp {
	return &BinaryOp{
		Pos:   pos,
		Left:  left,
		Op:    op,
		Right: right,
	}
}

// UnaryOp creates a new UnaryOp node
func (b *Builder) UnaryOp(pos token.Position, op token.TokenType, right Expression) *UnaryOp {
	return &UnaryOp{
		Pos:   pos,
		Op:    op,
		Right: right,
	}
}

// Identifier creates a new Identifier node
func (b *Builder) Identifier(pos token.Position, name string) *Identifier {
	return &Identifier{
		Pos:  pos,
		Name: name,
	}
}

// Literal creates a new Literal node
func (b *Builder) Literal(pos token.Position, typ token.TokenType, value interface{}) *Literal {
	return &Literal{
		Pos:   pos,
		Type:  typ,
		Value: value,
	}
}

// TextString creates a new TextString node
func (b *Builder) TextString(pos token.Position, value string) *TextString {
	return &TextString{
		Pos:   pos,
		Value: value,
	}
}

// HexString creates a new HexString node
func (b *Builder) HexString(pos token.Position, value string) *HexString {
	return &HexString{
		Pos:   pos,
		Value: value,
	}
}

// RegexPattern creates a new RegexPattern node
func (b *Builder) RegexPattern(pos token.Position, value string) *RegexPattern {
	return &RegexPattern{
		Pos:   pos,
		Value: value,
	}
}

// Meta creates a new Meta node
func (b *Builder) Meta(pos token.Position, key string, value any) *Meta {
	return &Meta{
		Pos:   pos,
		Key:   key,
		Value: value,
	}
}

// String creates a new String node
func (b *Builder) String(
	pos token.Position,
	identifier string,
	pattern Pattern,
	modifiers []StringModifier,
) *String {
	return &String{
		Pos:        pos,
		Identifier: identifier,
		Pattern:    pattern,
		Modifiers:  modifiers,
	}
}

// Condition creates a new Condition node
func (b *Builder) Condition(pos token.Position, expr Expression) *Condition {
	return &Condition{
		Pos:        pos,
		Expression: expr,
	}
}

// GlobalVariable creates a new GlobalVariable node
func (b *Builder) GlobalVariable(pos token.Position, name string, value Expression) *GlobalVariable {
	return &GlobalVariable{
		Pos:   pos,
		Name:  name,
		Value: value,
	}
}

// Import creates a new Import node
func (b *Builder) Import(pos token.Position, module string) *Import {
	return &Import{
		Pos:    pos,
		Module: module,
	}
}

// Include creates a new Include node
func (b *Builder) Include(pos token.Position, file string) *Include {
	return &Include{
		Pos:  pos,
		File: file,
	}
}

// StringLength creates a new StringLength node
func (b *Builder) StringLength(pos token.Position, strExpr Expression) *StringLength {
	return &StringLength{
		Pos:    pos,
		String: strExpr,
	}
}

// ArrayIndex creates a new ArrayIndex node
func (b *Builder) ArrayIndex(pos token.Position, arrayExpr, indexExpr Expression) *ArrayIndex {
	return &ArrayIndex{
		Pos:   pos,
		Array: arrayExpr,
		Index: indexExpr,
	}
}

// ForLoop creates a new ForLoop node
func (b *Builder) ForLoop(pos token.Position, quantifier, variable string, rangeExpr, conditionExpr Expression) *ForLoop {
	return &ForLoop{
		Pos:        pos,
		Quantifier: quantifier,
		Variable:   variable,
		Range:      rangeExpr,
		Condition:  conditionExpr,
	}
}

// OfExpression creates a new OfExpression node
func (b *Builder) OfExpression(pos token.Position, countExpr, stringsExpr Expression) *OfExpression {
	return &OfExpression{
		Pos:     pos,
		Count:   countExpr,
		Strings: stringsExpr,
	}
}

// FunctionCall creates a new FunctionCall node
func (b *Builder) FunctionCall(pos token.Position, function string, args []Expression) *FunctionCall {
	return &FunctionCall{
		Pos:      pos,
		Function: function,
		Args:     args,
	}
}
