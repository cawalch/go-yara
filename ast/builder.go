package ast

import "github.com/cawalch/go-yara/token"

// Builder provides convenient methods for constructing AST nodes
type Builder struct{}

func NewBuilder() *Builder {
	return &Builder{}
}

func (b *Builder) Program(rules []*Rule) *Program {
	return &Program{
		Pos:   token.Position{},
		Rules: rules,
	}
}

func (b *Builder) Rule(pos token.Position, name string) *Rule {
	return &Rule{
		Pos:  pos,
		Name: name,
	}
}

func (b *Builder) BinaryOp(pos token.Position, left Expression, op token.TokenType, right Expression) *BinaryOp {
	return &BinaryOp{
		Pos:   pos,
		Left:  left,
		Op:    op,
		Right: right,
	}
}

func (b *Builder) UnaryOp(pos token.Position, op token.TokenType, right Expression) *UnaryOp {
	return &UnaryOp{
		Pos:   pos,
		Op:    op,
		Right: right,
	}
}

func (b *Builder) Identifier(pos token.Position, name string) *Identifier {
	return &Identifier{
		Pos:  pos,
		Name: name,
	}
}

func (b *Builder) Literal(pos token.Position, typ token.TokenType, value interface{}) *Literal {
	return &Literal{
		Pos:   pos,
		Type:  typ,
		Value: value,
	}
}

func (b *Builder) TextString(pos token.Position, value string) *TextString {
	return &TextString{
		Pos:   pos,
		Value: value,
	}
}

func (b *Builder) HexString(pos token.Position, value string) *HexString {
	return &HexString{
		Pos:   pos,
		Value: value,
	}
}

func (b *Builder) RegexPattern(pos token.Position, value string) *RegexPattern {
	return &RegexPattern{
		Pos:   pos,
		Value: value,
	}
}

func (b *Builder) Meta(pos token.Position, key string, value interface{}) *Meta {
	return &Meta{
		Pos:   pos,
		Key:   key,
		Value: value,
	}
}

func (b *Builder) String(pos token.Position, identifier string, pattern Pattern, modifiers []StringModifier) *String {
	return &String{
		Pos:        pos,
		Identifier: identifier,
		Pattern:    pattern,
		Modifiers:  modifiers,
	}
}

func (b *Builder) Condition(pos token.Position, expr Expression) *Condition {
	return &Condition{
		Pos:        pos,
		Expression: expr,
	}
}