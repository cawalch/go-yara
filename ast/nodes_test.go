package ast

import (
	"testing"

	"github.com/cawalch/go-yara/token"
)

// TestNodePositions tests that all nodes return correct positions
func TestNodePositions(t *testing.T) {
	builder := NewBuilder()
	pos := token.Position{Line: 5, Column: 10}

	tests := []struct {
		name string
		node Node
	}{
		{
			name: "Program",
			node: builder.Program([]*Rule{}),
		},
		{
			name: "Rule",
			node: builder.Rule(pos, "test"),
		},
		{
			name: "Meta",
			node: builder.Meta(pos, "key", MetaString("value")),
		},
		{
			name: "String",
			node: builder.String(pos, "$s1", builder.TextString(pos, "test"), nil),
		},
		{
			name: "Condition",
			node: builder.Condition(pos, builder.Identifier(pos, "test")),
		},
		{
			name: "BinaryOp",
			node: builder.BinaryOp(pos, builder.Identifier(pos, "a"), token.PLUS, builder.Identifier(pos, "b")),
		},
		{
			name: "UnaryOp",
			node: builder.UnaryOp(pos, token.NOT, builder.Identifier(pos, "x")),
		},
		{
			name: "Identifier",
			node: builder.Identifier(pos, "test"),
		},
		{
			name: "Literal",
			node: builder.Literal(pos, token.INTEGER_LIT, 42),
		},
		{
			name: "TextString",
			node: builder.TextString(pos, "hello"),
		},
		{
			name: "HexString",
			node: builder.HexString(pos, "AB CD"),
		},
		{
			name: "RegexPattern",
			node: builder.RegexPattern(pos, "/test/"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nodePos := tt.node.Position()
			// Program doesn't have a meaningful position, so skip it
			if _, ok := tt.node.(*Program); ok {
				return
			}
			if nodePos.Line != pos.Line || nodePos.Column != pos.Column {
				t.Errorf("%s.Position() = %v, want %v", tt.name, nodePos, pos)
			}
		})
	}
}

// TestAcceptVisitor tests that all nodes accept visitors
func TestAcceptVisitor(t *testing.T) {
	builder := NewBuilder()
	pos := token.Position{Line: 1, Column: 1}

	visitor := &CountingVisitor{}

	tests := []struct {
		name          string
		node          Node
		expectedCount int
	}{
		{
			name:          "Program",
			node:          builder.Program([]*Rule{}),
			expectedCount: 1,
		},
		{
			name:          "Rule",
			node:          builder.Rule(pos, "test"),
			expectedCount: 1,
		},
		{
			name:          "Meta",
			node:          builder.Meta(pos, "key", MetaString("value")),
			expectedCount: 1,
		},
		{
			name:          "String",
			node:          builder.String(pos, "$s1", builder.TextString(pos, "test"), nil),
			expectedCount: 1,
		},
		{
			name:          "Condition",
			node:          builder.Condition(pos, builder.Identifier(pos, "test")),
			expectedCount: 1,
		},
		{
			name:          "BinaryOp",
			node:          builder.BinaryOp(pos, builder.Identifier(pos, "a"), token.PLUS, builder.Identifier(pos, "b")),
			expectedCount: 1,
		},
		{
			name:          "UnaryOp",
			node:          builder.UnaryOp(pos, token.NOT, builder.Identifier(pos, "x")),
			expectedCount: 1,
		},
		{
			name:          "Identifier",
			node:          builder.Identifier(pos, "test"),
			expectedCount: 1,
		},
		{
			name:          "Literal",
			node:          builder.Literal(pos, token.INTEGER_LIT, 42),
			expectedCount: 1,
		},
		{
			name:          "TextString",
			node:          builder.TextString(pos, "hello"),
			expectedCount: 1,
		},
		{
			name:          "HexString",
			node:          builder.HexString(pos, "AB CD"),
			expectedCount: 1,
		},
		{
			name:          "RegexPattern",
			node:          builder.RegexPattern(pos, "/test/"),
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			visitor.count = 0
			tt.node.Accept(visitor)
			if visitor.count != tt.expectedCount {
				t.Errorf("%s.Accept() called visitor %d times, want %d", tt.name, visitor.count, tt.expectedCount)
			}
		})
	}
}

// TestExpressionMarker tests that expression nodes implement the expression marker
func TestExpressionMarker(t *testing.T) {
	builder := NewBuilder()
	pos := token.Position{Line: 1, Column: 1}

	expressions := []Expression{
		builder.BinaryOp(pos, builder.Identifier(pos, "a"), token.PLUS, builder.Identifier(pos, "b")),
		builder.UnaryOp(pos, token.NOT, builder.Identifier(pos, "x")),
		builder.Identifier(pos, "test"),
		builder.Literal(pos, token.INTEGER_LIT, 42),
	}

	for i, expr := range expressions {
		// This should compile - just checking the marker interface works
		expr.expression()
		// If we get here without panic, the test passes
		t.Logf("Expression %d implements expression marker", i)
	}
}

// TestPatternMarker tests that pattern nodes implement the pattern marker
func TestPatternMarker(t *testing.T) {
	builder := NewBuilder()
	pos := token.Position{Line: 1, Column: 1}

	patterns := []Pattern{
		builder.TextString(pos, "test"),
		builder.HexString(pos, "AB CD"),
		builder.RegexPattern(pos, "/test/"),
	}

	for i, pattern := range patterns {
		// This should compile - just checking the marker interface works
		pattern.pattern()
		// If we get here without panic, the test passes
		t.Logf("Pattern %d implements pattern marker", i)
	}
}

// TestUnaryOpCreation tests UnaryOp builder
func TestUnaryOpCreation(t *testing.T) {
	builder := NewBuilder()
	pos := token.Position{Line: 3, Column: 5}

	operand := builder.Identifier(pos, "test")
	unary := builder.UnaryOp(pos, token.NOT, operand)

	if unary.Op != token.NOT {
		t.Errorf("UnaryOp.Op = %v, want %v", unary.Op, token.NOT)
	}
	if unary.Right != operand {
		t.Error("UnaryOp.Right does not match")
	}
	if unary.Pos.Line != pos.Line {
		t.Errorf("UnaryOp.Pos.Line = %d, want %d", unary.Pos.Line, pos.Line)
	}
}

// TestLiteralCreation tests Literal builder
func TestLiteralCreation(t *testing.T) {
	builder := NewBuilder()
	pos := token.Position{Line: 2, Column: 8}

	tests := []struct {
		name     string
		tokType  token.TokenType
		value    interface{}
		checkVal func(interface{}) bool
	}{
		{
			name:    "Integer",
			tokType: token.INTEGER_LIT,
			value:   42,
			checkVal: func(v interface{}) bool {
				return v.(int) == 42
			},
		},
		{
			name:    "Boolean True",
			tokType: token.TRUE,
			value:   true,
			checkVal: func(v interface{}) bool {
				return v.(bool) == true
			},
		},
		{
			name:    "Boolean False",
			tokType: token.FALSE,
			value:   false,
			checkVal: func(v interface{}) bool {
				return v.(bool) == false
			},
		},
		{
			name:    "String",
			tokType: token.STRING_LIT,
			value:   "test",
			checkVal: func(v interface{}) bool {
				return v.(string) == "test"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			literal := builder.Literal(pos, tt.tokType, tt.value)
			if literal.Type != tt.tokType {
				t.Errorf("Literal.Type = %v, want %v", literal.Type, tt.tokType)
			}
			if !tt.checkVal(literal.Value) {
				t.Errorf("Literal.Value = %v, want %v", literal.Value, tt.value)
			}
		})
	}
}

// TestMetaCreation tests Meta builder
func TestMetaCreation(t *testing.T) {
	builder := NewBuilder()
	pos := token.Position{Line: 4, Column: 2}

	meta := builder.Meta(pos, "author", MetaString("test_user"))

	if meta.Key != "author" {
		t.Errorf("Meta.Key = %s, want author", meta.Key)
	}
	if meta.AsString() != "test_user" {
		t.Errorf("Meta.Value = %s, want test_user", meta.AsString())
	}
}

// TestConditionCreation tests Condition builder
func TestConditionCreation(t *testing.T) {
	builder := NewBuilder()
	pos := token.Position{Line: 10, Column: 4}

	expr := builder.Identifier(pos, "$s1")
	condition := builder.Condition(pos, expr)

	if condition.Expression != expr {
		t.Error("Condition.Expression does not match")
	}
}

// CountingVisitor counts how many times each visit method is called
type CountingVisitor struct {
	count int
}

func (v *CountingVisitor) VisitProgram(n *Program) any {
	v.count++
	return nil
}

func (v *CountingVisitor) VisitRule(n *Rule) any {
	v.count++
	return nil
}

func (v *CountingVisitor) VisitMeta(n *Meta) any {
	v.count++
	return nil
}

func (v *CountingVisitor) VisitString(n *String) any {
	v.count++
	return nil
}

func (v *CountingVisitor) VisitCondition(n *Condition) any {
	v.count++
	return nil
}

func (v *CountingVisitor) VisitBinaryOp(n *BinaryOp) any {
	v.count++
	return nil
}

func (v *CountingVisitor) VisitUnaryOp(n *UnaryOp) any {
	v.count++
	return nil
}

func (v *CountingVisitor) VisitIdentifier(n *Identifier) any {
	v.count++
	return nil
}

func (v *CountingVisitor) VisitLiteral(n *Literal) any {
	v.count++
	return nil
}

func (v *CountingVisitor) VisitTextString(n *TextString) any {
	v.count++
	return nil
}

func (v *CountingVisitor) VisitHexString(n *HexString) any {
	v.count++
	return nil
}

func (v *CountingVisitor) VisitRegexPattern(n *RegexPattern) any {
	v.count++
	return nil
}

func (v *CountingVisitor) VisitGlobalVariable(n *GlobalVariable) any {
	v.count++
	return nil
}

func (v *CountingVisitor) VisitImport(n *Import) any {
	v.count++
	return nil
}

func (v *CountingVisitor) VisitInclude(n *Include) any {
	v.count++
	return nil
}

func (v *CountingVisitor) VisitStringLength(n *StringLength) any {
	v.count++
	return nil
}

func (v *CountingVisitor) VisitExternalVariable(n *ExternalVariable) any {
	v.count++
	return nil
}

func (v *CountingVisitor) VisitArrayIndex(n *ArrayIndex) any {
	v.count++
	return nil
}

func (v *CountingVisitor) VisitForLoop(n *ForLoop) any {
	v.count++
	return nil
}

func (v *CountingVisitor) VisitOfExpression(n *OfExpression) any {
	v.count++
	return nil
}

func (v *CountingVisitor) VisitFunctionCall(n *FunctionCall) any {
	v.count++
	return nil
}
