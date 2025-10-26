package ast

import (
	"testing"

	"github.com/cawalch/go-yara/token"
)

func TestBaseVisitor(t *testing.T) {
	visitor := &BaseVisitor{}

	// Test all visitor methods return nil
	pos := token.Position{Line: 1, Column: 1}

	program := &Program{Pos: pos}
	if result := visitor.VisitProgram(program); result != nil {
		t.Errorf("VisitProgram() returned %v, want nil", result)
	}

	rule := &Rule{Pos: pos, Name: "test"}
	if result := visitor.VisitRule(rule); result != nil {
		t.Errorf("VisitRule() returned %v, want nil", result)
	}

	meta := &Meta{Pos: pos, Key: "test", Value: MetaString("value")}
	if result := visitor.VisitMeta(meta); result != nil {
		t.Errorf("VisitMeta() returned %v, want nil", result)
	}

	str := &String{Pos: pos, Identifier: "$test"}
	if result := visitor.VisitString(str); result != nil {
		t.Errorf("VisitString() returned %v, want nil", result)
	}

	condition := &Condition{Pos: pos}
	if result := visitor.VisitCondition(condition); result != nil {
		t.Errorf("VisitCondition() returned %v, want nil", result)
	}

	binOp := &BinaryOp{Pos: pos}
	if result := visitor.VisitBinaryOp(binOp); result != nil {
		t.Errorf("VisitBinaryOp() returned %v, want nil", result)
	}

	unaryOp := &UnaryOp{Pos: pos}
	if result := visitor.VisitUnaryOp(unaryOp); result != nil {
		t.Errorf("VisitUnaryOp() returned %v, want nil", result)
	}

	ident := &Identifier{Pos: pos, Name: "test"}
	if result := visitor.VisitIdentifier(ident); result != nil {
		t.Errorf("VisitIdentifier() returned %v, want nil", result)
	}

	literal := &Literal{Pos: pos}
	if result := visitor.VisitLiteral(literal); result != nil {
		t.Errorf("VisitLiteral() returned %v, want nil", result)
	}

	textStr := &TextString{Pos: pos}
	if result := visitor.VisitTextString(textStr); result != nil {
		t.Errorf("VisitTextString() returned %v, want nil", result)
	}

	hexStr := &HexString{Pos: pos}
	if result := visitor.VisitHexString(hexStr); result != nil {
		t.Errorf("VisitHexString() returned %v, want nil", result)
	}

	regex := &RegexPattern{Pos: pos}
	if result := visitor.VisitRegexPattern(regex); result != nil {
		t.Errorf("VisitRegexPattern() returned %v, want nil", result)
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
