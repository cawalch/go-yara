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
			node: builder.Literal(pos, token.IntegerLit, 42),
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

// TestExpressionMarker tests that expression nodes implement the expression marker
func TestExpressionMarker(t *testing.T) {
	builder := NewBuilder()
	pos := token.Position{Line: 1, Column: 1}

	expressions := []Expression{
		builder.BinaryOp(pos, builder.Identifier(pos, "a"), token.PLUS, builder.Identifier(pos, "b")),
		builder.UnaryOp(pos, token.NOT, builder.Identifier(pos, "x")),
		builder.Identifier(pos, "test"),
		builder.Literal(pos, token.IntegerLit, 42),
	}

	for i, expr := range expressions {
		// This should compile - just checking the marker interface works
		expr.expression()
		// If we get here without panic, the test passes
		t.Logf("Expression %d implements expression marker", i)
	}
}

func TestRemainingBuilderExpressionContracts(t *testing.T) {
	builder := NewBuilder()
	pos := token.Position{Line: 7, Column: 11}
	value := builder.Literal(pos, token.IntegerLit, 50)
	stringExpr := builder.Identifier(pos, "$a")
	indexExpr := builder.Literal(pos, token.IntegerLit, 2)
	rangeExpr := builder.Identifier(pos, "range")
	condition := builder.Identifier(pos, "condition")

	t.Run("ForLoopMultiVar", func(t *testing.T) {
		variables := []string{"key", "value"}
		loop := builder.ForLoopMultiVar(pos, "all", variables, rangeExpr, condition)
		assertBuiltExpression(t, loop, pos)
		if loop.Quantifier != "all" || len(loop.Variables) != 2 || loop.Variables[0] != "key" || loop.Variables[1] != "value" {
			t.Fatalf("ForLoopMultiVar fields = %+v", loop)
		}
		if loop.Range != rangeExpr || loop.Condition != condition {
			t.Fatalf("ForLoopMultiVar range/condition = %T/%T", loop.Range, loop.Condition)
		}
	})

	t.Run("PercentExpression", func(t *testing.T) {
		percent := builder.PercentExpression(pos, value)
		assertBuiltExpression(t, percent, pos)
		if percent.Value != value {
			t.Fatalf("PercentExpression.Value = %v, want %v", percent.Value, value)
		}
	})

	t.Run("StringOffset", func(t *testing.T) {
		offset := builder.StringOffset(pos, stringExpr, indexExpr)
		assertBuiltExpression(t, offset, pos)
		if offset.String != stringExpr || offset.Index != indexExpr {
			t.Fatalf("StringOffset fields = %+v", offset)
		}
	})

	t.Run("StringCount", func(t *testing.T) {
		count := builder.StringCount(pos, stringExpr, indexExpr)
		assertBuiltExpression(t, count, pos)
		if count.String != stringExpr || count.Index != indexExpr {
			t.Fatalf("StringCount fields = %+v", count)
		}
	})
}

func assertBuiltExpression(t *testing.T, expr Expression, wantPos token.Position) {
	t.Helper()
	if got := expr.Position(); got != wantPos {
		t.Fatalf("%T.Position() = %v, want %v", expr, got, wantPos)
	}
	expr.expression()
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
		tokType  token.Type
		value    any
		checkVal func(any) bool
	}{
		{
			name:    "Integer",
			tokType: token.IntegerLit,
			value:   42,
			checkVal: func(v any) bool {
				return v.(int) == 42
			},
		},
		{
			name:    "Boolean True",
			tokType: token.TRUE,
			value:   true,
			checkVal: func(v any) bool {
				return v.(bool) == true
			},
		},
		{
			name:    "Boolean False",
			tokType: token.FALSE,
			value:   false,
			checkVal: func(v any) bool {
				return v.(bool) == false
			},
		},
		{
			name:    "String",
			tokType: token.StringLit,
			value:   "test",
			checkVal: func(v any) bool {
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
