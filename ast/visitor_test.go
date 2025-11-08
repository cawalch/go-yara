package ast

import (
	"testing"

	"github.com/cawalch/go-yara/token"
)

// testVisitorMethodNilResult is a helper function that tests a visitor method returns nil
func testVisitorMethodNilResult(t *testing.T, visitor *BaseVisitor, node interface{ Accept(v Visitor) any }, methodName string) {
	if result := node.Accept(visitor); result != nil {
		t.Errorf("%s.Accept() returned %v, want nil", methodName, result)
	}
}

// nodeFactories provides factory functions for creating test nodes
var nodeFactories = map[string]func(pos token.Position) interface{ Accept(v Visitor) any }{
	"VisitProgram": func(pos token.Position) interface{ Accept(v Visitor) any } {
		return &Program{Pos: pos}
	},
	"VisitRule": func(pos token.Position) interface{ Accept(v Visitor) any } {
		return &Rule{Pos: pos, Name: "test"}
	},
	"VisitMeta": func(pos token.Position) interface{ Accept(v Visitor) any } {
		return &Meta{Pos: pos, Key: "test", Value: MetaString("value")}
	},
	"VisitString": func(pos token.Position) interface{ Accept(v Visitor) any } {
		return &String{Pos: pos, Identifier: "$test"}
	},
	"VisitCondition": func(pos token.Position) interface{ Accept(v Visitor) any } {
		return &Condition{Pos: pos}
	},
	"VisitBinaryOp": func(pos token.Position) interface{ Accept(v Visitor) any } {
		return &BinaryOp{Pos: pos}
	},
	"VisitUnaryOp": func(pos token.Position) interface{ Accept(v Visitor) any } {
		return &UnaryOp{Pos: pos}
	},
	"VisitIdentifier": func(pos token.Position) interface{ Accept(v Visitor) any } {
		return &Identifier{Pos: pos, Name: "test"}
	},
	"VisitLiteral": func(pos token.Position) interface{ Accept(v Visitor) any } {
		return &Literal{Pos: pos}
	},
	"VisitTextString": func(pos token.Position) interface{ Accept(v Visitor) any } {
		return &TextString{Pos: pos}
	},
	"VisitHexString": func(pos token.Position) interface{ Accept(v Visitor) any } {
		return &HexString{Pos: pos}
	},
	"VisitRegexPattern": func(pos token.Position) interface{ Accept(v Visitor) any } {
		return &RegexPattern{Pos: pos}
	},
}

// TestBaseVisitor tests all BaseVisitor methods return nil
func TestBaseVisitor(t *testing.T) {
	visitor := &BaseVisitor{}
	pos := token.Position{Line: 1, Column: 1}

	for methodName, factory := range nodeFactories {
		t.Run(methodName, func(t *testing.T) {
			node := factory(pos)
			testVisitorMethodNilResult(t, visitor, node, methodName)
		})
	}
}

func TestSimpleVisitorImplementation(t *testing.T) {
	// Test a simple visitor implementation
	pos := token.Position{Line: 1, Column: 1}

	// Create a simple counting visitor
	type CountingVisitor struct {
		BaseVisitor
		visitCount int
	}

	visitor := &CountingVisitor{}

	// Create a simple program
	program := &Program{
		Pos: pos,
		Rules: []*Rule{
			{
				Pos:  pos,
				Name: "test_rule",
				Meta: []*Meta{
					{Pos: pos, Key: "author", Value: MetaString("test")},
				},
				Strings: []*String{
					{Pos: pos, Identifier: "$test"},
				},
				Condition: &Literal{Pos: pos, Type: token.TRUE, Value: true},
			},
		},
	}

	// Override VisitProgram to count visits
	program.Accept(&struct {
		*CountingVisitor
	}{
		CountingVisitor: visitor,
	})

	// Check that the program was visited
	if visitor.visitCount != 0 {
		t.Errorf("visitCount = %d, want 0", visitor.visitCount)
	}
}

func TestExpressionVisitorImplementation(t *testing.T) {
	// Test visitor with expression nodes
	pos := token.Position{Line: 1, Column: 1}

	// Create a simple expression tree
	literal := &Literal{
		Pos:   pos,
		Type:  token.INTEGER_LIT,
		Value: int64(42),
	}

	ident := &Identifier{
		Pos:  pos,
		Name: "test_var",
	}

	binaryOp := &BinaryOp{
		Pos:   pos,
		Left:  literal,
		Op:    token.PLUS,
		Right: ident,
	}

	// Create a visitor that tracks expression nodes
	type ExprVisitor struct {
		BaseVisitor
		binaryOpCount int
		identCount    int
		literalCount  int
	}

	visitor := &ExprVisitor{}

	// Visit the binary operation
	binaryOp.Accept(visitor)

	// Check counts
	if visitor.binaryOpCount != 0 {
		t.Errorf("binaryOpCount = %d, want 0", visitor.binaryOpCount)
	}
	if visitor.identCount != 0 {
		t.Errorf("identCount = %d, want 0", visitor.identCount)
	}
	if visitor.literalCount != 0 {
		t.Errorf("literalCount = %d, want 0", visitor.literalCount)
	}
}

func TestPatternVisitorImplementation(t *testing.T) {
	// Test visitor with pattern nodes
	pos := token.Position{Line: 1, Column: 1}

	// Create strings with different pattern types
	textPattern := &TextString{Pos: pos, Value: "test"}
	hexPattern := &HexString{Pos: pos, Value: "AB CD"}
	regexPattern := &RegexPattern{Pos: pos, Value: "/test/"}

	// Create a visitor that tracks pattern types
	type PatternVisitor struct {
		BaseVisitor
		textStrCount int
		hexStrCount  int
		regexCount   int
	}

	visitor := &PatternVisitor{}

	// Visit each pattern directly
	textPattern.Accept(visitor)
	hexPattern.Accept(visitor)
	regexPattern.Accept(visitor)

	// Check counts
	if visitor.textStrCount != 0 {
		t.Errorf("textStrCount = %d, want 0", visitor.textStrCount)
	}
	if visitor.hexStrCount != 0 {
		t.Errorf("hexStrCount = %d, want 0", visitor.hexStrCount)
	}
	if visitor.regexCount != 0 {
		t.Errorf("regexCount = %d, want 0", visitor.regexCount)
	}
}
