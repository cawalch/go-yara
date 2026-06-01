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
		Pos:               token.Position{},
		Rules:             rules,
		GlobalVariables:   []*GlobalVariable{},
		ExternalVariables: []*ExternalVariable{},
		Imports:           []*Import{},
		Includes:          []*Include{},
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
	op token.Type,
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
func (b *Builder) UnaryOp(pos token.Position, op token.Type, right Expression) *UnaryOp {
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
func (b *Builder) Literal(pos token.Position, typ token.Type, value any) *Literal {
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
func (b *Builder) Meta(pos token.Position, key string, value MetaValue) *Meta {
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

// ExternalVariable creates a new ExternalVariable node
func (b *Builder) ExternalVariable(pos token.Position, name, identifier, typeHint string) *ExternalVariable {
	return &ExternalVariable{
		Pos:        pos,
		Name:       name,
		Identifier: identifier,
		TypeHint:   typeHint,
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

// StringLength creates a new StringLength node for the YARA ! operator
// This implements the correct YARA syntax for string length operations
func (b *Builder) StringLength(pos token.Position, strExpr Expression) *StringLength {
	return &StringLength{
		Pos:    pos,
		String: strExpr,
	}
}

// ForLoop creates a new ForLoop node
func (b *Builder) ForLoop(pos token.Position, quantifier, variable string, rng, condition Expression) *ForLoop {
	var variables []string
	if variable != "" {
		variables = []string{variable}
	}
	return &ForLoop{
		Pos:        pos,
		Quantifier: quantifier,
		Variables:  variables,
		Range:      rng,
		Condition:  condition,
	}
}

// ForLoopMultiVar creates a new ForLoop node with multiple iterator variables (e.g. k, v)
func (b *Builder) ForLoopMultiVar(pos token.Position, quantifier string, variables []string, rng, condition Expression) *ForLoop {
	return &ForLoop{
		Pos:        pos,
		Quantifier: quantifier,
		Variables:  variables,
		Range:      rng,
		Condition:  condition,
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

// PercentExpression creates a new PercentExpression node
func (b *Builder) PercentExpression(pos token.Position, value Expression) *PercentExpression {
	return &PercentExpression{
		Pos:   pos,
		Value: value,
	}
}

// StringOffset creates a new StringOffset node for the YARA @ operator
// This implements the correct YARA syntax for string offset operations
func (b *Builder) StringOffset(pos token.Position, strExpr, indexExpr Expression) *StringOffset {
	return &StringOffset{
		Pos:    pos,
		String: strExpr,
		Index:  indexExpr, // nil for @a, non-nil for @a[i]
	}
}

// StringCount creates a new StringCount node for the YARA # operator
// This implements the correct YARA syntax for string count operations
func (b *Builder) StringCount(pos token.Position, strExpr, indexExpr Expression) *StringCount {
	return &StringCount{
		Pos:    pos,
		String: strExpr,
		Index:  indexExpr, // nil for #a, non-nil for #a[i]
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
