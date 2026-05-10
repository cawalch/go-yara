package semantic

import (
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

// Helper functions to reduce repetitive AST construction for smoke tests
func createTestPos() token.Position {
	return token.Position{Line: 1, Column: 1}
}

func createTestProgram() *ast.Program {
	pos := createTestPos()
	return &ast.Program{
		Pos:   pos,
		Rules: []*ast.Rule{},
	}
}

func createTestRule() *ast.Rule {
	pos := createTestPos()
	return &ast.Rule{
		Pos:  pos,
		Name: "test",
		Condition: &ast.Literal{
			Type:  token.TRUE,
			Value: true,
			Pos:   pos,
		},
	}
}

func createTestBinaryOp() *ast.BinaryOp {
	pos := createTestPos()
	return &ast.BinaryOp{
		Pos: pos,
		Left: &ast.Literal{
			Type:  token.IntegerLit,
			Value: int64(1),
			Pos:   pos,
		},
		Op: token.PLUS,
		Right: &ast.Literal{
			Type:  token.IntegerLit,
			Value: int64(2),
			Pos:   pos,
		},
	}
}

func createTestUnaryOp() *ast.UnaryOp {
	pos := createTestPos()
	return &ast.UnaryOp{
		Pos: pos,
		Op:  token.NOT,
		Right: &ast.Literal{
			Type:  token.TRUE,
			Value: true,
			Pos:   pos,
		},
	}
}

// TestValidatorVisitorMethods tests that visitor methods don't panic when called
func TestValidatorVisitorMethods(t *testing.T) {
	validator := NewValidator()

	t.Run("StructureNodes", func(_ *testing.T) {
		// Test VisitProgram
		validator.VisitProgram(createTestProgram())

		// Test VisitRule
		validator.VisitRule(createTestRule())
	})

	t.Run("RuleComponents", func(_ *testing.T) {
		pos := createTestPos()

		// Test VisitMeta
		meta := &ast.Meta{
			Pos:   pos,
			Key:   "test",
			Value: ast.MetaString("value"),
		}
		validator.VisitMeta(meta)

		// Test VisitString
		str := &ast.String{
			Pos:        pos,
			Identifier: "$test",
			Pattern: &ast.TextString{
				Pos:   pos,
				Value: "test",
			},
		}
		validator.VisitString(str)

		// Test VisitCondition
		condition := &ast.Condition{
			Pos: pos,
			Expression: &ast.Literal{
				Type:  token.TRUE,
				Value: true,
				Pos:   pos,
			},
		}
		validator.VisitCondition(condition)
	})

	t.Run("Expressions", func(_ *testing.T) {
		// Test VisitBinaryOp
		validator.VisitBinaryOp(createTestBinaryOp())

		// Test VisitUnaryOp
		validator.VisitUnaryOp(createTestUnaryOp())

		pos := createTestPos()

		// Test VisitIdentifier
		ident := &ast.Identifier{
			Pos:  pos,
			Name: "test",
		}
		validator.VisitIdentifier(ident)

		// Test VisitLiteral
		literal := &ast.Literal{
			Pos:   pos,
			Type:  token.IntegerLit,
			Value: int64(42),
		}
		validator.VisitLiteral(literal)
	})
}

// TestValidatorGetSymbolTable tests GetSymbolTable method
func TestValidatorGetSymbolTable(t *testing.T) {
	validator := NewValidator()

	st := validator.GetSymbolTable()
	if st == nil {
		t.Error("GetSymbolTable() returned nil")
	}
}

// TestValidatorHasErrors tests HasErrors method
func TestValidatorHasErrors(t *testing.T) {
	validator := NewValidator()

	// Initially should have no errors
	if validator.HasErrors() {
		t.Error("HasErrors() should return false initially")
	}
}

// TestValidatorGetErrors tests GetErrors method
func TestValidatorGetErrors(t *testing.T) {
	validator := NewValidator()

	errors := validator.GetErrors()
	if len(errors) != 0 {
		t.Errorf("GetErrors() returned %d errors, want 0", len(errors))
	}
}

// TestValidatorGetTypeFromSymbol tests getTypeFromSymbol method
func TestValidatorGetTypeFromSymbol(t *testing.T) {
	st := NewSymbolTable()
	st.EnterScope("test")
	pos := token.Position{Line: 1, Column: 1}

	// Define different symbol types
	rule := &ast.Rule{Name: "test_rule", Pos: pos}
	_ = st.DefineRule("test_rule", pos, rule)

	str := &ast.String{Identifier: "$s1", Pos: pos}
	_ = st.DefineString("$s1", pos, str)

	_ = st.DefineVariable("var1", pos, SymbolVariable)

	validator := NewValidator()
	validator.symbolTable = st

	tests := []struct {
		name         string
		symbolName   string
		expectedType DataType
	}{
		{"rule_symbol", "test_rule", TypeBoolean},
		{"string_symbol", "$s1", TypeBoolean},
		{"variable_symbol", "var1", TypeInteger},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			symbol, exists := st.Lookup(tt.symbolName)
			if !exists {
				t.Fatalf("Symbol %s not found", tt.symbolName)
			}

			typeInfo := validator.getTypeFromSymbol(symbol)
			if typeInfo.DataType != tt.expectedType {
				t.Errorf("getTypeFromSymbol() got %v, want %v", typeInfo.DataType, tt.expectedType)
			}
		})
	}
}

// TestValidatorCollectSymbols tests collectSymbols method
func TestValidatorCollectSymbols(t *testing.T) {
	validator := NewValidator()

	pos := token.Position{Line: 1, Column: 1}

	rule := &ast.Rule{
		Pos:  pos,
		Name: "test_rule",
		Strings: []*ast.String{
			{
				Pos:        pos,
				Identifier: "$s1",
				Pattern: &ast.TextString{
					Pos:   pos,
					Value: "test",
				},
			},
		},
		Condition: &ast.Identifier{
			Name: "$s1",
			Pos:  pos,
		},
	}

	// Use the full ValidateProgram method to properly test symbol collection
	program := &ast.Program{
		Pos:   pos,
		Rules: []*ast.Rule{rule},
	}

	errors := validator.ValidateProgram(program)

	// Should complete without panic and have minimal errors
	if len(errors) > 0 {
		t.Logf("ValidateProgram() returned errors: %v", errors)
	}
}

// TestValidatorValidateRule tests validateRule method
func TestValidatorValidateRule(t *testing.T) {
	validator := NewValidator()

	pos := token.Position{Line: 1, Column: 1}

	// First collect symbols
	rule := &ast.Rule{
		Pos:  pos,
		Name: "test_rule",
		Meta: []*ast.Meta{
			{
				Pos:   pos,
				Key:   "author",
				Value: ast.MetaString("test"),
			},
		},
		Strings: []*ast.String{
			{
				Pos:        pos,
				Identifier: "$s1",
				Pattern: &ast.TextString{
					Pos:   pos,
					Value: "test",
				},
			},
		},
		Condition: &ast.Identifier{
			Name: "$s1",
			Pos:  pos,
		},
	}

	// Collect symbols first
	validator.collectSymbols(rule)

	// Then validate
	validator.validateRule(rule)

	// Should not have errors for valid rule
	if validator.HasErrors() {
		t.Errorf("validateRule() unexpected errors: %v", validator.GetErrors())
	}
}
