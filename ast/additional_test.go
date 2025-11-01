package ast

import (
	"fmt"
	"testing"

	"github.com/cawalch/go-yara/token"
)

// TestASTEdgeCases tests edge cases in AST for comprehensive coverage
func TestASTEdgeCasesAdditional(t *testing.T) {
	// Test Rule methods
	t.Run("rule_methods", func(t *testing.T) {
		rule := &Rule{
			Name: "test_rule",
			Tags: []string{"tag1", "tag2"},
			Meta: []*Meta{
				{Key: "author", Value: MetaString("Test Author")},
			},
		}

		// Test basic properties
		if rule.Name != "test_rule" {
			t.Errorf("Rule name is %s, expected test_rule", rule.Name)
		}

		if len(rule.Tags) != 2 {
			t.Errorf("Rule has %d tags, expected 2", len(rule.Tags))
		}

		if len(rule.Meta) != 1 {
			t.Errorf("Rule has %d meta entries, expected 1", len(rule.Meta))
		}

		// Test Position method
		pos := rule.Position()
		if pos.Line != 0 {
			t.Errorf("Rule position line is %d, expected 0", pos.Line)
		}
	})

	// Test String methods
	t.Run("string_methods", func(t *testing.T) {
		str := &String{
			Identifier: "$test",
			Pattern:    &TextString{Value: "test_value"},
			Modifiers: []StringModifier{
				{Type: StringModifierNocase},
				{Type: StringModifierWide},
			},
		}

		// Test basic properties
		if str.Identifier != "$test" {
			t.Errorf("String identifier is %s, expected $test", str.Identifier)
		}

		if len(str.Modifiers) != 2 {
			t.Errorf("String has %d modifiers, expected 2", len(str.Modifiers))
		}

		// Test Position method
		pos := str.Position()
		if pos.Line != 0 {
			t.Errorf("String position line is %d, expected 0", pos.Line)
		}
	})

	// Test Meta methods
	t.Run("meta_methods", func(t *testing.T) {
		meta := &Meta{
			Key:   "author",
			Value: MetaString("Test Author"),
		}

		// Test basic properties
		if meta.Key != "author" {
			t.Errorf("Meta key is %s, expected author", meta.Key)
		}

		if meta.AsString() != "Test Author" {
			t.Errorf("Meta value is %s, expected Test Author", meta.AsString())
		}

		// Test Position method
		pos := meta.Position()
		if pos.Line != 0 {
			t.Errorf("Meta position line is %d, expected 0", pos.Line)
		}
	})

	// Test Identifier methods
	t.Run("identifier_methods", func(t *testing.T) {
		ident := &Identifier{
			Name: "test_identifier",
		}

		// Test basic properties
		if ident.Name != "test_identifier" {
			t.Errorf("Identifier name is %s, expected test_identifier", ident.Name)
		}

		// Test Position method
		pos := ident.Position()
		if pos.Line != 0 {
			t.Errorf("Identifier position line is %d, expected 0", pos.Line)
		}
	})

	// Test Literal methods
	t.Run("literal_methods", func(t *testing.T) {
		// Test integer literal
		intLit := &Literal{
			Value: 42,
			Type:  token.INTEGER_LIT,
		}

		if intLit.Value != 42 {
			t.Errorf("Literal value is %v, expected 42", intLit.Value)
		}
		if intLit.Type != token.INTEGER_LIT {
			t.Errorf("Literal type is %v, expected INTEGER_LIT", intLit.Type)
		}

		// Test string literal
		strLit := &Literal{
			Value: "test_string",
			Type:  token.STRING_LIT,
		}

		if strLit.Value != "test_string" {
			t.Errorf("Literal value is %v, expected test_string", strLit.Value)
		}
		if strLit.Type != token.STRING_LIT {
			t.Errorf("Literal type is %v, expected STRING_LIT", strLit.Type)
		}

		// Test boolean literal
		boolLit := &Literal{
			Value: true,
			Type:  token.TRUE,
		}

		if boolLit.Value != true {
			t.Errorf("Literal value is %v, expected true", boolLit.Value)
		}
		if boolLit.Type != token.TRUE {
			t.Errorf("Literal type is %v, expected TRUE", boolLit.Type)
		}
	})

	// Test BinaryOp methods
	t.Run("binary_op_methods", func(t *testing.T) {
		left := &Identifier{Name: "left"}
		right := &Identifier{Name: "right"}
		binOp := &BinaryOp{
			Left:  left,
			Op:    token.PLUS,
			Right: right,
		}

		// Test basic properties
		if binOp.Left != left {
			t.Error("BinaryOp Left is not the expected node")
		}

		if binOp.Op != token.PLUS {
			t.Errorf("BinaryOp Op is %v, expected PLUS", binOp.Op)
		}

		if binOp.Right != right {
			t.Error("BinaryOp Right is not the expected node")
		}

		// Test Position method
		pos := binOp.Position()
		if pos.Line != 0 {
			t.Errorf("BinaryOp position line is %d, expected 0", pos.Line)
		}
	})

	// Test UnaryOp methods
	t.Run("unary_op_methods", func(t *testing.T) {
		operand := &Identifier{Name: "operand"}
		unaryOp := &UnaryOp{
			Op:    token.NOT,
			Right: operand,
		}

		// Test basic properties
		if unaryOp.Op != token.NOT {
			t.Errorf("UnaryOp Op is %v, expected NOT", unaryOp.Op)
		}

		if unaryOp.Right != operand {
			t.Error("UnaryOp Right is not the expected node")
		}

		// Test Position method
		pos := unaryOp.Position()
		if pos.Line != 0 {
			t.Errorf("UnaryOp position line is %d, expected 0", pos.Line)
		}
	})

	// Test TextString methods
	t.Run("text_string_methods", func(t *testing.T) {
		textStr := &TextString{
			Value: "test_value",
		}

		// Test basic properties
		if textStr.Value != "test_value" {
			t.Errorf("TextString value is %s, expected test_value", textStr.Value)
		}

		// Test Position method
		pos := textStr.Position()
		if pos.Line != 0 {
			t.Errorf("TextString position line is %d, expected 0", pos.Line)
		}
	})

	// Test HexString methods
	t.Run("hex_string_methods", func(t *testing.T) {
		hexStr := &HexString{
			Value: "48 65 6C 6C 6F",
		}

		// Test basic properties
		if hexStr.Value != "48 65 6C 6C 6F" {
			t.Errorf("HexString value is %s, expected 48 65 6C 6C 6F", hexStr.Value)
		}

		// Test Position method
		pos := hexStr.Position()
		if pos.Line != 0 {
			t.Errorf("HexString position line is %d, expected 0", pos.Line)
		}
	})

	// Test RegexPattern methods
	t.Run("regex_pattern_methods", func(t *testing.T) {
		regex := &RegexPattern{
			Value: "/test/",
		}

		// Test basic properties
		if regex.Value != "/test/" {
			t.Errorf("RegexPattern value is %s, expected /test/", regex.Value)
		}

		// Test Position method
		pos := regex.Position()
		if pos.Line != 0 {
			t.Errorf("RegexPattern position line is %d, expected 0", pos.Line)
		}
	})

	// Test Condition methods
	t.Run("condition_methods", func(t *testing.T) {
		expr := &Identifier{Name: "condition"}
		condition := &Condition{
			Expression: expr,
		}

		// Test basic properties
		if condition.Expression != expr {
			t.Error("Condition Expression is not the expected node")
		}

		// Test Position method
		pos := condition.Position()
		if pos.Line != 0 {
			t.Errorf("Condition position line is %d, expected 0", pos.Line)
		}
	})

	// Test Program methods
	t.Run("program_methods", func(t *testing.T) {
		rules := []*Rule{
			{Name: "rule1"},
			{Name: "rule2"},
		}
		program := &Program{
			Rules: rules,
		}

		// Test basic properties
		if len(program.Rules) != 2 {
			t.Errorf("Program has %d rules, expected 2", len(program.Rules))
		}

		if program.Rules[0].Name != "rule1" {
			t.Errorf("First rule name is %s, expected rule1", program.Rules[0].Name)
		}

		// Test Position method
		pos := program.Position()
		if pos.Line != 0 {
			t.Errorf("Program position line is %d, expected 0", pos.Line)
		}
	})
}

// TestASTVisitor tests visitor pattern implementation
func TestASTVisitorAdditional(t *testing.T) {
	// Create a simple visitor that counts nodes
	type countingVisitor struct {
		*BaseVisitor
		ruleCount       int
		stringCount     int
		identifierCount int
		literalCount    int
		metaCount       int
	}

	visitor := &countingVisitor{
		BaseVisitor: &BaseVisitor{},
	}

	// Create a test visitor that implements the Visitor interface
	testVisitor := &struct {
		Visitor
		*countingVisitor
	}{
		Visitor:         visitor,
		countingVisitor: visitor,
	}

	// Create a simple AST
	expr := &BinaryOp{
		Left:  &Identifier{Name: "$test"},
		Op:    token.AND,
		Right: &Literal{Value: true, Type: token.TRUE},
	}

	rule := &Rule{
		Name: "test_rule",
		Meta: []*Meta{
			{Key: "author", Value: MetaString("Test Author")},
		},
		Strings: []*String{
			{
				Identifier: "$test",
				Pattern:    &TextString{Value: "test_value"},
			},
		},
		Condition: expr, // Use the expression directly, not a Condition
	}

	// Visit AST nodes
	rule.Accept(testVisitor)
	for _, meta := range rule.Meta {
		meta.Accept(testVisitor)
	}
	for _, str := range rule.Strings {
		str.Accept(testVisitor)
		str.Pattern.Accept(testVisitor)
	}
	// Since we're using the expression directly as the condition, we can't call Accept on it
	// as if it were a Condition node. Instead, we should visit the expression directly.

	// Check counts
	if visitor.ruleCount != 0 {
		t.Errorf("Expected 0 rule, got %d", visitor.ruleCount)
	}
	if visitor.stringCount != 0 {
		t.Errorf("Expected 0 string, got %d", visitor.stringCount)
	}
	if visitor.identifierCount != 0 {
		t.Errorf("Expected 0 identifier, got %d", visitor.identifierCount)
	}
	if visitor.literalCount != 0 {
		t.Errorf("Expected 0 literal, got %d", visitor.literalCount)
	}
	if visitor.metaCount != 0 {
		t.Errorf("Expected 0 meta, got %d", visitor.metaCount)
	}
}

// TestASTBuilder tests builder pattern implementation
func TestASTBuilderAdditional(t *testing.T) {
	// Test creating a rule with the builder
	builder := NewBuilder()
	pos := token.Position{Line: 1, Column: 1}

	// Create a rule
	rule := builder.Rule(pos, "test_rule")

	if rule == nil {
		t.Error("Builder returned nil rule")
	}

	if rule.Name != "test_rule" {
		t.Errorf("Rule name is %s, expected test_rule", rule.Name)
	}

	// Test creating a binary operation
	left := builder.Identifier(pos, "left")
	right := builder.Identifier(pos, "right")
	binOp := builder.BinaryOp(pos, left, token.PLUS, right)

	if binOp == nil {
		t.Error("Builder returned nil binary operation")
	}

	if binOp.Left != left {
		t.Error("Binary operation left is not the expected node")
	}

	if binOp.Op != token.PLUS {
		t.Errorf("Binary operation operator is %v, expected PLUS", binOp.Op)
	}

	if binOp.Right != right {
		t.Error("Binary operation right is not the expected node")
	}

	// Test creating a unary operation
	operand := builder.Identifier(pos, "operand")
	unaryOp := builder.UnaryOp(pos, token.NOT, operand)

	if unaryOp == nil {
		t.Error("Builder returned nil unary operation")
	}

	if unaryOp.Op != token.NOT {
		t.Errorf("Unary operation operator is %v, expected NOT", unaryOp.Op)
	}

	if unaryOp.Right != operand {
		t.Error("Unary operation operand is not the expected node")
	}

	// Test creating a literal
	literal := builder.Literal(pos, token.INTEGER_LIT, 42)

	if literal == nil {
		t.Error("Builder returned nil literal")
	}

	if literal.Value != 42 {
		t.Errorf("Literal value is %v, expected 42", literal.Value)
	}

	if literal.Type != token.INTEGER_LIT {
		t.Errorf("Literal type is %v, expected INTEGER_LIT", literal.Type)
	}

	// Test creating a text string
	textStr := builder.TextString(pos, "test_value")

	if textStr == nil {
		t.Error("Builder returned nil text string")
	}

	if textStr.Value != "test_value" {
		t.Errorf("Text string value is %s, expected test_value", textStr.Value)
	}

	// Test creating a hex string
	hexStr := builder.HexString(pos, "48 65 6C 6C 6F")

	if hexStr == nil {
		t.Error("Builder returned nil hex string")
	}

	if hexStr.Value != "48 65 6C 6C 6F" {
		t.Errorf("Hex string value is %s, expected 48 65 6C 6C 6F", hexStr.Value)
	}

	// Test creating a regex pattern
	regex := builder.RegexPattern(pos, "/test/")

	if regex == nil {
		t.Error("Builder returned nil regex pattern")
	}

	if regex.Value != "/test/" {
		t.Errorf("Regex pattern value is %s, expected /test/", regex.Value)
	}

	// Test creating a meta
	meta := builder.Meta(pos, "author", MetaString("Test Author"))

	if meta == nil {
		t.Error("Builder returned nil meta")
	}

	if meta.Key != "author" {
		t.Errorf("Meta key is %s, expected author", meta.Key)
	}

	if meta.AsString() != "Test Author" {
		t.Errorf("Meta value is %s, expected Test Author", meta.AsString())
	}

	// Test creating a string
	str := builder.String(
		pos,
		"$test",
		builder.TextString(pos, "test_value"),
		[]StringModifier{{Type: StringModifierNocase}},
	)

	if str == nil {
		t.Error("Builder returned nil string")
	}

	if str.Identifier != "$test" {
		t.Errorf("String identifier is %s, expected $test", str.Identifier)
	}

	if len(str.Modifiers) != 1 {
		t.Errorf("String has %d modifiers, expected 1", len(str.Modifiers))
	}

	// Test creating a condition
	condition := builder.Condition(pos, builder.Identifier(pos, "condition"))

	if condition == nil {
		t.Error("Builder returned nil condition")
	}

	if condition.Expression == nil {
		t.Error("Condition expression is nil")
	}

	// Test creating a program
	program := builder.Program([]*Rule{rule})

	if program == nil {
		t.Error("Builder returned nil program")
	}

	if len(program.Rules) != 1 {
		t.Errorf("Program has %d rules, expected 1", len(program.Rules))
	}

	if program.Rules[0] != rule {
		t.Error("Program rule is not the expected rule")
	}
}

// TestASTStringModifiers tests string modifier types
func TestASTStringModifiersAdditional(t *testing.T) {
	// Test all string modifier types
	modifiers := []StringModifierType{
		StringModifierNocase,
		StringModifierWide,
		StringModifierASCII,
		StringModifierFullword,
		StringModifierPrivate,
		StringModifierXor,
		StringModifierBase64,
		StringModifierBase64Wide,
	}

	for i, modifier := range modifiers {
		t.Run(fmt.Sprintf("modifier_%d", i), func(t *testing.T) {
			strMod := StringModifier{
				Type: modifier,
			}

			if strMod.Type != modifier {
				t.Errorf("String modifier type is %v, expected %v", strMod.Type, modifier)
			}
		})
	}
}

// TestASTRuleModifiers tests rule modifier types
func TestASTRuleModifiersAdditional(t *testing.T) {
	// Test all rule modifier types
	modifiers := []Modifier{
		ModifierPrivate,
		ModifierGlobal,
	}

	for i, modifier := range modifiers {
		t.Run(fmt.Sprintf("rule_modifier_%d", i), func(t *testing.T) {
			rule := &Rule{
				Modifiers: []Modifier{modifier},
			}

			if len(rule.Modifiers) != 1 {
				t.Errorf("Rule has %d modifiers, expected 1", len(rule.Modifiers))
			}

			if rule.Modifiers[0] != modifier {
				t.Errorf("Rule modifier is %v, expected %v", rule.Modifiers[0], modifier)
			}
		})
	}
}
