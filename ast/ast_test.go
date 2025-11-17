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

// Ensure TestVisitor implements the full Visitor interface
var _ Visitor = (*TestVisitor)(nil)

func (v *TestVisitor) VisitRule(_ *Rule) any {
	v.visited = true
	return nil
}

// Implement other visitor methods...
func (v *TestVisitor) VisitProgram(_ *Program) any                   { return nil }
func (v *TestVisitor) VisitMeta(_ *Meta) any                         { return nil }
func (v *TestVisitor) VisitString(_ *String) any                     { return nil }
func (v *TestVisitor) VisitCondition(_ *Condition) any               { return nil }
func (v *TestVisitor) VisitBinaryOp(_ *BinaryOp) any                 { return nil }
func (v *TestVisitor) VisitExternalVariable(_ *ExternalVariable) any { return nil }
func (v *TestVisitor) VisitUnaryOp(_ *UnaryOp) any                   { return nil }
func (v *TestVisitor) VisitIdentifier(_ *Identifier) any             { return nil }
func (v *TestVisitor) VisitLiteral(_ *Literal) any                   { return nil }
func (v *TestVisitor) VisitTextString(_ *TextString) any             { return nil }
func (v *TestVisitor) VisitHexString(_ *HexString) any               { return nil }
func (v *TestVisitor) VisitRegexPattern(_ *RegexPattern) any         { return nil }
func (v *TestVisitor) VisitGlobalVariable(_ *GlobalVariable) any     { return nil }
func (v *TestVisitor) VisitImport(_ *Import) any                     { return nil }
func (v *TestVisitor) VisitInclude(_ *Include) any                   { return nil }
func (v *TestVisitor) VisitStringLength(_ *StringLength) any         { return nil }
func (v *TestVisitor) VisitStringOffset(_ *StringOffset) any         { return nil }
func (v *TestVisitor) VisitStringCount(_ *StringCount) any           { return nil }
func (v *TestVisitor) VisitForLoop(_ *ForLoop) any                   { return nil }
func (v *TestVisitor) VisitOfExpression(_ *OfExpression) any         { return nil }
func (v *TestVisitor) VisitFunctionCall(_ *FunctionCall) any         { return nil }

func TestBuilderUtilities(t *testing.T) {
	builder := NewBuilder()

	// Test binary operation
	left := builder.Identifier(token.Position{Line: 1, Column: 1}, "a")
	right := builder.Identifier(token.Position{Line: 1, Column: 5}, "b")
	binOp := builder.BinaryOp(token.Position{Line: 1, Column: 3}, left, token.PLUS, right)

	if binOp.Op != token.PLUS {
		t.Errorf("expected PLUS operator, got %v", binOp.Op)
	}
	leftIdent, ok := binOp.Left.(*Identifier)
	if !ok {
		t.Fatalf("expected *Identifier for left operand, got %T", binOp.Left)
	}
	if leftIdent.Name != "a" {
		t.Errorf("expected left operand 'a', got %s", leftIdent.Name)
	}

	rightIdent, ok := binOp.Right.(*Identifier)
	if !ok {
		t.Fatalf("expected *Identifier for right operand, got %T", binOp.Right)
	}
	if rightIdent.Name != "b" {
		t.Errorf("expected right operand 'b', got %s", rightIdent.Name)
	}
}

func TestNodeInterfaces(_ *testing.T) {
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

func TestPatternNodes(_ *testing.T) {
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
	textStr, ok := str.Pattern.(*TextString)
	if !ok {
		t.Fatalf("expected *TextString for pattern, got %T", str.Pattern)
	}
	if textStr.Value != "test" {
		t.Errorf("expected pattern 'test', got %s", textStr.Value)
	}
	if len(str.Modifiers) != 1 {
		t.Errorf("expected 1 modifier, got %d", len(str.Modifiers))
	}
	if str.Modifiers[0].Type != StringModifierNocase {
		t.Errorf("expected nocase modifier, got %v", str.Modifiers[0].Type)
	}
}

func TestMetaNode(t *testing.T) {
	builder := NewBuilder()

	meta := builder.Meta(token.Position{Line: 1, Column: 1}, "author", MetaString("test"))

	if meta.Key != "author" {
		t.Errorf("expected key 'author', got %s", meta.Key)
	}
	if meta.AsString() != "test" {
		t.Errorf("expected value 'test', got %v", meta.AsString())
	}
}

func TestConditionNode(t *testing.T) {
	builder := NewBuilder()

	expr := builder.Literal(token.Position{Line: 1, Column: 1}, token.TRUE, true)
	condition := builder.Condition(token.Position{Line: 1, Column: 1}, expr)

	literal, ok := condition.Expression.(*Literal)
	if !ok {
		t.Fatalf("expected *Literal for expression, got %T", condition.Expression)
	}
	if literal.Value != true {
		t.Errorf("expected expression value true, got %v", literal.Value)
	}
}

func TestUnaryOpNode(t *testing.T) {
	builder := NewBuilder()

	right := builder.Literal(token.Position{Line: 1, Column: 5}, token.TRUE, true)
	unaryOp := builder.UnaryOp(token.Position{Line: 1, Column: 1}, token.NOT, right)

	if unaryOp.Op != token.NOT {
		t.Errorf("expected NOT operator, got %v", unaryOp.Op)
	}
	rightLiteral, ok := unaryOp.Right.(*Literal)
	if !ok {
		t.Fatalf("expected *Literal for right operand, got %T", unaryOp.Right)
	}
	if rightLiteral.Value != true {
		t.Errorf("expected right operand true, got %v", rightLiteral.Value)
	}
}

func TestLiteralNode(t *testing.T) {
	builder := NewBuilder()

	literal := builder.Literal(token.Position{Line: 1, Column: 1}, token.IntegerLit, int64(42))

	if literal.Type != token.IntegerLit {
		t.Errorf("expected IntegerLit type, got %v", literal.Type)
	}
	if literal.Value != int64(42) {
		t.Errorf("expected value 42, got %v", literal.Value)
	}
}

func TestHexStringNode(t *testing.T) {
	builder := NewBuilder()

	hexStr := builder.HexString(token.Position{Line: 1, Column: 1}, "AB CD")

	if hexStr.Value != "AB CD" {
		t.Errorf("expected value 'AB CD', got %s", hexStr.Value)
	}
}

func TestRegexPatternNode(t *testing.T) {
	builder := NewBuilder()

	regex := builder.RegexPattern(token.Position{Line: 1, Column: 1}, "/test/")

	if regex.Value != "/test/" {
		t.Errorf("expected value '/test/', got %s", regex.Value)
	}
}

func TestRuleWithMetaAndTags(t *testing.T) {
	builder := NewBuilder()

	meta := builder.Meta(token.Position{Line: 2, Column: 1}, "author", MetaString("test"))
	rule := builder.Rule(token.Position{Line: 1, Column: 1}, "test_rule")
	rule.Meta = []*Meta{meta}
	rule.Tags = []string{"tag1", "tag2"}

	if rule.Name != "test_rule" {
		t.Errorf("expected name 'test_rule', got %s", rule.Name)
	}
	if len(rule.Meta) != 1 {
		t.Errorf("expected 1 meta, got %d", len(rule.Meta))
	}
	if len(rule.Tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(rule.Tags))
	}
}

func TestProgramWithMultipleRules(t *testing.T) {
	builder := NewBuilder()

	rule1 := builder.Rule(token.Position{Line: 1, Column: 1}, "rule1")
	rule2 := builder.Rule(token.Position{Line: 5, Column: 1}, "rule2")
	program := builder.Program([]*Rule{rule1, rule2})

	if len(program.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(program.Rules))
	}
	if program.Rules[0].Name != "rule1" {
		t.Errorf("expected first rule 'rule1', got %s", program.Rules[0].Name)
	}
	if program.Rules[1].Name != "rule2" {
		t.Errorf("expected second rule 'rule2', got %s", program.Rules[1].Name)
	}
}
