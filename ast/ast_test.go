package ast

import (
	"testing"

	"github.com/cawalch/go-yara/token"
)

func TestProgramCreation(t *testing.T) {
	builder := NewBuilder()
	rule := builder.Rule(token.Position{Line: 1, Column: 1}, "test_rule")
	program := builder.Program([]*Rule{rule})

	if program == nil {
		t.Fatal("program is nil")
	}
	if len(program.Rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(program.Rules))
	}
}

func TestVisitorPattern(t *testing.T) {
	builder := NewBuilder()
	rule := builder.Rule(token.Position{Line: 1, Column: 1}, "test_rule")

	visitor := &TestVisitor{}
	rule.Accept(visitor)

	if !visitor.visited {
		t.Error("visitor was not called")
	}
}

type TestVisitor struct {
	visited bool
}

func (v *TestVisitor) VisitRule(r *Rule) any {
	v.visited = true
	return nil
}

// Implement other visitor methods...
func (v *TestVisitor) VisitProgram(n *Program) any           { return nil }
func (v *TestVisitor) VisitMeta(n *Meta) any                 { return nil }
func (v *TestVisitor) VisitString(n *String) any             { return nil }
func (v *TestVisitor) VisitCondition(n *Condition) any       { return nil }
func (v *TestVisitor) VisitBinaryOp(n *BinaryOp) any         { return nil }
func (v *TestVisitor) VisitUnaryOp(n *UnaryOp) any           { return nil }
func (v *TestVisitor) VisitIdentifier(n *Identifier) any     { return nil }
func (v *TestVisitor) VisitLiteral(n *Literal) any           { return nil }
func (v *TestVisitor) VisitTextString(n *TextString) any     { return nil }
func (v *TestVisitor) VisitHexString(n *HexString) any       { return nil }
func (v *TestVisitor) VisitRegexPattern(n *RegexPattern) any { return nil }

func TestBuilderUtilities(t *testing.T) {
	builder := NewBuilder()

	// Test binary operation
	left := builder.Identifier(token.Position{Line: 1, Column: 1}, "a")
	right := builder.Identifier(token.Position{Line: 1, Column: 5}, "b")
	binOp := builder.BinaryOp(token.Position{Line: 1, Column: 3}, left, token.PLUS, right)

	if binOp.Op != token.PLUS {
		t.Errorf("expected PLUS operator, got %v", binOp.Op)
	}
	if binOp.Left.(*Identifier).Name != "a" {
		t.Errorf("expected left operand 'a', got %s", binOp.Left.(*Identifier).Name)
	}
	if binOp.Right.(*Identifier).Name != "b" {
		t.Errorf("expected right operand 'b', got %s", binOp.Right.(*Identifier).Name)
	}
}

func TestNodeInterfaces(t *testing.T) {
	builder := NewBuilder()

	// Test that nodes implement Node interface
	rule := builder.Rule(token.Position{Line: 1, Column: 1}, "test")
	var _ Node = rule

	// Test that expressions implement Expression interface
	ident := builder.Identifier(token.Position{Line: 1, Column: 1}, "test")
	var _ Expression = ident

	binOp := builder.BinaryOp(token.Position{Line: 1, Column: 3}, ident, token.PLUS, ident)
	var _ Expression = binOp
}

func TestPatternNodes(t *testing.T) {
	builder := NewBuilder()

	textStr := builder.TextString(token.Position{Line: 1, Column: 1}, "hello")
	var _ Pattern = textStr
	var _ Node = textStr

	hexStr := builder.HexString(token.Position{Line: 1, Column: 1}, "AB CD")
	var _ Pattern = hexStr
	var _ Node = hexStr

	regex := builder.RegexPattern(token.Position{Line: 1, Column: 1}, "/test/")
	var _ Pattern = regex
	var _ Node = regex
}

func TestStringNode(t *testing.T) {
	builder := NewBuilder()

	pattern := builder.TextString(token.Position{Line: 1, Column: 10}, "test")
	modifiers := []StringModifier{
		{Type: StringModifierNocase},
	}

	str := builder.String(token.Position{Line: 1, Column: 1}, "$a", pattern, modifiers)

	if str.Identifier != "$a" {
		t.Errorf("expected identifier '$a', got %s", str.Identifier)
	}
	if str.Pattern.(*TextString).Value != "test" {
		t.Errorf("expected pattern 'test', got %s", str.Pattern.(*TextString).Value)
	}
	if len(str.Modifiers) != 1 {
		t.Errorf("expected 1 modifier, got %d", len(str.Modifiers))
	}
	if str.Modifiers[0].Type != StringModifierNocase {
		t.Errorf("expected nocase modifier, got %v", str.Modifiers[0].Type)
	}
}
