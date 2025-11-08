package ast

import (
	"testing"

	"github.com/cawalch/go-yara/token"
)

// TestMetaValueConversions tests the Meta value conversion methods
func TestMetaValueConversions(t *testing.T) {
	pos := token.Position{Line: 1, Column: 1}

	tests := []struct {
		name     string
		meta     *Meta
		wantStr  string
		wantInt  int64
		wantBool bool
	}{
		{
			name:     "MetaString conversion",
			meta:     &Meta{Pos: pos, Key: "test", Value: MetaString("hello")},
			wantStr:  "hello",
			wantInt:  0,
			wantBool: false,
		},
		{
			name:     "MetaInt conversion",
			meta:     &Meta{Pos: pos, Key: "test", Value: MetaInt(42)},
			wantStr:  "",
			wantInt:  42,
			wantBool: false,
		},
		{
			name:     "MetaBool true conversion",
			meta:     &Meta{Pos: pos, Key: "test", Value: MetaBool(true)},
			wantStr:  "",
			wantInt:  0,
			wantBool: true,
		},
		{
			name:     "MetaBool false conversion",
			meta:     &Meta{Pos: pos, Key: "test", Value: MetaBool(false)},
			wantStr:  "",
			wantInt:  0,
			wantBool: false,
		},
		{
			name:     "Type mismatch returns defaults",
			meta:     &Meta{Pos: pos, Key: "test", Value: MetaString("not_a_bool")},
			wantStr:  "not_a_bool",
			wantInt:  0,
			wantBool: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotStr := tt.meta.AsString(); gotStr != tt.wantStr {
				t.Errorf("Meta.AsString() = %q, want %q", gotStr, tt.wantStr)
			}
			if gotInt := tt.meta.AsInt(); gotInt != tt.wantInt {
				t.Errorf("Meta.AsInt() = %d, want %d", gotInt, tt.wantInt)
			}
			if gotBool := tt.meta.AsBool(); gotBool != tt.wantBool {
				t.Errorf("Meta.AsBool() = %v, want %v", gotBool, tt.wantBool)
			}
		})
	}
}

// TestMetaStringRepresentation tests the Meta String() method
func TestMetaStringRepresentation(t *testing.T) {
	pos := token.Position{Line: 1, Column: 1}

	tests := []struct {
		name     string
		meta     *Meta
		expected string
	}{
		{
			name:     "MetaString representation",
			meta:     &Meta{Pos: pos, Key: "author", Value: MetaString("test_user")},
			expected: "test_user",
		},
		{
			name:     "MetaInt representation",
			meta:     &Meta{Pos: pos, Key: "version", Value: MetaInt(123)},
			expected: "123",
		},
		{
			name:     "MetaBool true representation",
			meta:     &Meta{Pos: pos, Key: "enabled", Value: MetaBool(true)},
			expected: "true",
		},
		{
			name:     "MetaBool false representation",
			meta:     &Meta{Pos: pos, Key: "enabled", Value: MetaBool(false)},
			expected: "false",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.meta.String(); got != tt.expected {
				t.Errorf("Meta.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestAdvancedNodeTypes tests nodes that have 0% coverage
func TestAdvancedNodeTypes(t *testing.T) {
	builder := NewBuilder()
	pos := token.Position{Line: 5, Column: 10}

	tests := []struct {
		name string
		node Node
	}{
		{
			name: "GlobalVariable",
			node: builder.GlobalVariable(pos, "global_var", builder.Literal(pos, token.INTEGER_LIT, 42)),
		},
		{
			name: "ExternalVariable",
			node: builder.ExternalVariable(pos, "ext_var", "ext_identifier", "integer"),
		},
		{
			name: "Import",
			node: builder.Import(pos, "pe"),
		},
		{
			name: "Include",
			node: builder.Include(pos, "rules.yar"),
		},
		{
			name: "StringLength",
			node: builder.StringLength(pos, builder.Identifier(pos, "$s1")),
		},
		{
			name: "ArrayIndex",
			node: builder.ArrayIndex(pos, builder.Identifier(pos, "array"), builder.Literal(pos, token.INTEGER_LIT, 0)),
		},
		{
			name: "ForLoop",
			node: builder.ForLoop(pos, "all", "i", builder.Identifier(pos, "range"), builder.Identifier(pos, "condition")),
		},
		{
			name: "OfExpression",
			node: builder.OfExpression(pos, builder.Literal(pos, token.INTEGER_LIT, 2), builder.Identifier(pos, "them")),
		},
		{
			name: "FunctionCall",
			node: builder.FunctionCall(pos, "module.function", []Expression{
				builder.Literal(pos, token.STRING_LIT, "arg1"),
				builder.Literal(pos, token.INTEGER_LIT, 42),
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test Position method
			nodePos := tt.node.Position()
			if nodePos.Line != pos.Line || nodePos.Column != pos.Column {
				t.Errorf("%s.Position() = %v, want %v", tt.name, nodePos, pos)
			}

			// Test Accept method - should not panic
			visitor := &ComprehensiveTestVisitor{}
			result := tt.node.Accept(visitor)
			if result == nil {
				t.Errorf("%s.Accept() returned nil", tt.name)
			}

			// Test node marker - should not panic
			switch n := tt.node.(type) {
			case *GlobalVariable, *ExternalVariable, *Import, *Include:
				// These are just node markers
			case Expression:
				// These should also implement expression marker
				n.expression()
			}
		})
	}
}

// TestAdvancedBuilderMethods tests builder methods with 0% coverage
func TestAdvancedBuilderMethods(t *testing.T) {
	builder := NewBuilder()
	pos := token.Position{Line: 3, Column: 7}

	tests := []struct {
		name        string
		testFunc    func(t *testing.T, builder *Builder, pos token.Position)
		description string
	}{
		{
			name: "GlobalVariable",
			testFunc: func(t *testing.T, builder *Builder, pos token.Position) {
				value := builder.Literal(pos, token.INTEGER_LIT, 42)
				gv := builder.GlobalVariable(pos, "test_global", value)

				if gv.Name != "test_global" {
					t.Errorf("GlobalVariable.Name = %q, want %q", gv.Name, "test_global")
				}
				if gv.Value != value {
					t.Error("GlobalVariable.Value does not match")
				}
				if gv.Pos.Line != pos.Line {
					t.Errorf("GlobalVariable.Pos.Line = %d, want %d", gv.Pos.Line, pos.Line)
				}
			},
			description: "Test GlobalVariable builder method",
		},
		{
			name: "ExternalVariable",
			testFunc: func(t *testing.T, builder *Builder, pos token.Position) {
				ev := builder.ExternalVariable(pos, "test_ext", "binding_id", "string")

				if ev.Name != "test_ext" {
					t.Errorf("ExternalVariable.Name = %q, want %q", ev.Name, "test_ext")
				}
				if ev.Identifier != "binding_id" {
					t.Errorf("ExternalVariable.Identifier = %q, want %q", ev.Identifier, "binding_id")
				}
				if ev.TypeHint != "string" {
					t.Errorf("ExternalVariable.TypeHint = %q, want %q", ev.TypeHint, "string")
				}
			},
			description: "Test ExternalVariable builder method",
		},
		{
			name: "Import",
			testFunc: func(t *testing.T, builder *Builder, pos token.Position) {
				import_ := builder.Import(pos, "pe")

				if import_.Module != "pe" {
					t.Errorf("Import.Module = %q, want %q", import_.Module, "pe")
				}
			},
			description: "Test Import builder method",
		},
		{
			name: "Include",
			testFunc: func(t *testing.T, builder *Builder, pos token.Position) {
				include := builder.Include(pos, "rules/common.yar")

				if include.File != "rules/common.yar" {
					t.Errorf("Include.File = %q, want %q", include.File, "rules/common.yar")
				}
			},
			description: "Test Include builder method",
		},
		{
			name: "StringLength",
			testFunc: func(t *testing.T, builder *Builder, pos token.Position) {
				stringExpr := builder.Identifier(pos, "$s1")
				strLen := builder.StringLength(pos, stringExpr)

				if strLen.String != stringExpr {
					t.Error("StringLength.String does not match")
				}
			},
			description: "Test StringLength builder method",
		},
		{
			name: "ArrayIndex",
			testFunc: func(t *testing.T, builder *Builder, pos token.Position) {
				array := builder.Identifier(pos, "my_array")
				index := builder.Literal(pos, token.INTEGER_LIT, 5)
				arrayIdx := builder.ArrayIndex(pos, array, index)

				if arrayIdx.Array != array {
					t.Error("ArrayIndex.Array does not match")
				}
				if arrayIdx.Index != index {
					t.Error("ArrayIndex.Index does not match")
				}
			},
			description: "Test ArrayIndex builder method",
		},
		{
			name: "ForLoop",
			testFunc: func(t *testing.T, builder *Builder, pos token.Position) {
				quantifier := "any"
				variable := "i"
				rangeExpr := builder.Identifier(pos, "1..10")
				condition := builder.Identifier(pos, "valid")
				forLoop := builder.ForLoop(pos, quantifier, variable, rangeExpr, condition)

				if forLoop.Quantifier != quantifier {
					t.Errorf("ForLoop.Quantifier = %q, want %q", forLoop.Quantifier, quantifier)
				}
				if forLoop.Variable != variable {
					t.Errorf("ForLoop.Variable = %q, want %q", forLoop.Variable, variable)
				}
				if forLoop.Range != rangeExpr {
					t.Error("ForLoop.Range does not match")
				}
				if forLoop.Condition != condition {
					t.Error("ForLoop.Condition does not match")
				}
			},
			description: "Test ForLoop builder method",
		},
		{
			name: "OfExpression",
			testFunc: func(t *testing.T, builder *Builder, pos token.Position) {
				count := builder.Literal(pos, token.INTEGER_LIT, 3)
				strings := builder.Identifier(pos, "them")
				ofExpr := builder.OfExpression(pos, count, strings)

				if ofExpr.Count != count {
					t.Error("OfExpression.Count does not match")
				}
				if ofExpr.Strings != strings {
					t.Error("OfExpression.Strings does not match")
				}
			},
			description: "Test OfExpression builder method",
		},
		{
			name: "FunctionCall",
			testFunc: func(t *testing.T, builder *Builder, pos token.Position) {
				args := []Expression{
					builder.Literal(pos, token.STRING_LIT, "test"),
					builder.Literal(pos, token.INTEGER_LIT, 123),
				}
				fnCall := builder.FunctionCall(pos, "pe.section", args)

				if fnCall.Function != "pe.section" {
					t.Errorf("FunctionCall.Function = %q, want %q", fnCall.Function, "pe.section")
				}
				if len(fnCall.Args) != len(args) {
					t.Errorf("FunctionCall.Args length = %d, want %d", len(fnCall.Args), len(args))
				}
				for i, arg := range args {
					if fnCall.Args[i] != arg {
						t.Errorf("FunctionCall.Args[%d] does not match", i)
					}
				}
			},
			description: "Test FunctionCall builder method",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+" builder", func(t *testing.T) {
			t.Logf("Testing %s: %s", tt.name, tt.description)
			tt.testFunc(t, builder, pos)
		})
	}
}

// TestExpressionInterface tests that expression nodes implement the expression marker
func TestExpressionInterface(t *testing.T) {
	builder := NewBuilder()
	pos := token.Position{Line: 1, Column: 1}

	expressions := []Expression{
		builder.StringLength(pos, builder.Identifier(pos, "$s1")),
		builder.ArrayIndex(pos, builder.Identifier(pos, "arr"), builder.Literal(pos, token.INTEGER_LIT, 0)),
		builder.ForLoop(pos, "all", "i", builder.Identifier(pos, "range"), builder.Identifier(pos, "cond")),
		builder.OfExpression(pos, builder.Literal(pos, token.INTEGER_LIT, 2), builder.Identifier(pos, "them")),
		builder.FunctionCall(pos, "test.func", []Expression{}),
	}

	for i, expr := range expressions {
		t.Run("Expression marker test", func(t *testing.T) {
			// This should compile without error - tests the expression marker
			expr.expression()
			t.Logf("Expression %d implements expression marker", i)
		})

		t.Run("Expression visitor test", func(t *testing.T) {
			visitor := &ComprehensiveTestVisitor{}
			result := expr.Accept(visitor)
			if result == nil {
				t.Errorf("Expression %d.Accept() returned nil", i)
			}
		})
	}
}

// TestAdvancedNodesWithEdgeCases tests edge cases and boundary conditions
func TestAdvancedNodesWithEdgeCases(t *testing.T) {
	builder := NewBuilder()
	pos := token.Position{Line: 0, Column: 0}

	t.Run("ExternalVariable with empty type hint", func(t *testing.T) {
		ev := builder.ExternalVariable(pos, "test", "", "")
		if ev.TypeHint != "" {
			t.Errorf("Expected empty TypeHint, got %q", ev.TypeHint)
		}
	})

	t.Run("FunctionCall with no arguments", func(t *testing.T) {
		fnCall := builder.FunctionCall(pos, "noargs", []Expression{})
		if fnCall.Args == nil {
			t.Error("FunctionCall.Args should not be nil")
		}
		if len(fnCall.Args) != 0 {
			t.Errorf("Expected 0 arguments, got %d", len(fnCall.Args))
		}
	})

	t.Run("FunctionCall with nil arguments slice", func(t *testing.T) {
		fnCall := builder.FunctionCall(pos, "nilargs", nil)
		// The builder should handle nil args gracefully
		if fnCall.Args == nil {
			// This is actually acceptable behavior - builder may initialize to nil
			t.Logf("FunctionCall.Args is nil when nil slice passed to builder")
		}
	})

	t.Run("Complex nested expressions", func(t *testing.T) {
		// Test deeply nested expressions
		nested := builder.ArrayIndex(
			pos,
			builder.Identifier(pos, "complex_array"),
			builder.FunctionCall(
				pos,
				"get_index",
				[]Expression{
					builder.StringLength(pos, builder.Identifier(pos, "$pattern")),
				},
			),
		)

		// Should not panic
		nested.expression()
		visitor := &ComprehensiveTestVisitor{}
		result := nested.Accept(visitor)
		if result == nil {
			t.Error("Nested expression.Accept() returned nil")
		}
	})
}

// TestProgramWithAdvancedNodes tests creating complete programs with all node types
func TestProgramWithAdvancedNodes(t *testing.T) {
	builder := NewBuilder()
	pos := token.Position{Line: 1, Column: 1}

	// Create a comprehensive program with all node types
	globalVar := builder.GlobalVariable(pos, "GLOBAL_FLAG", builder.Literal(pos, token.TRUE, true))
	extVar := builder.ExternalVariable(pos, "filename", "", "string")
	import_ := builder.Import(pos, "pe")
	include := builder.Include(pos, "common.yar")

	rule := builder.Rule(pos, "ComprehensiveTest")
	rule.Modifiers = []Modifier{ModifierPrivate}
	rule.Tags = []string{"test", "comprehensive"}
	rule.Meta = []*Meta{
		{Pos: pos, Key: "description", Value: MetaString("Test rule with all node types")},
		{Pos: pos, Key: "version", Value: MetaInt(1)},
		{Pos: pos, Key: "enabled", Value: MetaBool(true)},
	}

	// Add strings
	testString := builder.String(pos, "$test", builder.TextString(pos, "pattern"), nil)
	rule.Strings = []*String{testString}

	// Complex condition with all advanced expression types
	conditionExpr := builder.OfExpression(
		pos,
		builder.Literal(pos, token.INTEGER_LIT, 1),
		builder.ForLoop(
			pos,
			"any",
			"i",
			builder.StringLength(pos, builder.Identifier(pos, "$test")),
			builder.BinaryOp(
				pos,
				builder.ArrayIndex(
					pos,
					builder.FunctionCall(
						pos,
						"pe.sections",
						[]Expression{
							builder.Identifier(pos, "filename"),
						},
					),
					builder.Identifier(pos, "i"),
				),
				token.EQ,
				builder.Literal(pos, token.STRING_LIT, ".text"),
			),
		),
	)
	rule.Condition = conditionExpr

	program := builder.Program([]*Rule{rule})
	program.GlobalVariables = []*GlobalVariable{globalVar}
	program.ExternalVariables = []*ExternalVariable{extVar}
	program.Imports = []*Import{import_}
	program.Includes = []*Include{include}

	// Test the program structure
	if len(program.Rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(program.Rules))
	}
	if len(program.GlobalVariables) != 1 {
		t.Errorf("Expected 1 global variable, got %d", len(program.GlobalVariables))
	}
	if len(program.ExternalVariables) != 1 {
		t.Errorf("Expected 1 external variable, got %d", len(program.ExternalVariables))
	}
	if len(program.Imports) != 1 {
		t.Errorf("Expected 1 import, got %d", len(program.Imports))
	}
	if len(program.Includes) != 1 {
		t.Errorf("Expected 1 include, got %d", len(program.Includes))
	}

	// Test program visitor
	visitor := &ComprehensiveTestVisitor{}
	result := program.Accept(visitor)
	if result == nil {
		t.Error("Program.Accept() returned nil")
	}
}

// ComprehensiveTestVisitor is a visitor that implements all visitor methods for testing
type ComprehensiveTestVisitor struct {
	visitedNodes []string
}

func (v *ComprehensiveTestVisitor) VisitProgram(p *Program) any {
	v.visitedNodes = append(v.visitedNodes, "Program")
	return "visited_program"
}

func (v *ComprehensiveTestVisitor) VisitRule(r *Rule) any {
	v.visitedNodes = append(v.visitedNodes, "Rule")
	return "visited_rule"
}

func (v *ComprehensiveTestVisitor) VisitMeta(m *Meta) any {
	v.visitedNodes = append(v.visitedNodes, "Meta")
	return "visited_meta"
}

func (v *ComprehensiveTestVisitor) VisitString(s *String) any {
	v.visitedNodes = append(v.visitedNodes, "String")
	return "visited_string"
}

func (v *ComprehensiveTestVisitor) VisitCondition(c *Condition) any {
	v.visitedNodes = append(v.visitedNodes, "Condition")
	return "visited_condition"
}

func (v *ComprehensiveTestVisitor) VisitBinaryOp(b *BinaryOp) any {
	v.visitedNodes = append(v.visitedNodes, "BinaryOp")
	return "visited_binary_op"
}

func (v *ComprehensiveTestVisitor) VisitUnaryOp(u *UnaryOp) any {
	v.visitedNodes = append(v.visitedNodes, "UnaryOp")
	return "visited_unary_op"
}

func (v *ComprehensiveTestVisitor) VisitIdentifier(i *Identifier) any {
	v.visitedNodes = append(v.visitedNodes, "Identifier")
	return "visited_identifier"
}

func (v *ComprehensiveTestVisitor) VisitLiteral(l *Literal) any {
	v.visitedNodes = append(v.visitedNodes, "Literal")
	return "visited_literal"
}

func (v *ComprehensiveTestVisitor) VisitTextString(t *TextString) any {
	v.visitedNodes = append(v.visitedNodes, "TextString")
	return "visited_text_string"
}

func (v *ComprehensiveTestVisitor) VisitHexString(h *HexString) any {
	v.visitedNodes = append(v.visitedNodes, "HexString")
	return "visited_hex_string"
}

func (v *ComprehensiveTestVisitor) VisitRegexPattern(r *RegexPattern) any {
	v.visitedNodes = append(v.visitedNodes, "RegexPattern")
	return "visited_regex_pattern"
}

func (v *ComprehensiveTestVisitor) VisitGlobalVariable(g *GlobalVariable) any {
	v.visitedNodes = append(v.visitedNodes, "GlobalVariable")
	return "visited_global_variable"
}

func (v *ComprehensiveTestVisitor) VisitExternalVariable(e *ExternalVariable) any {
	v.visitedNodes = append(v.visitedNodes, "ExternalVariable")
	return "visited_external_variable"
}

func (v *ComprehensiveTestVisitor) VisitImport(i *Import) any {
	v.visitedNodes = append(v.visitedNodes, "Import")
	return "visited_import"
}

func (v *ComprehensiveTestVisitor) VisitInclude(i *Include) any {
	v.visitedNodes = append(v.visitedNodes, "Include")
	return "visited_include"
}

func (v *ComprehensiveTestVisitor) VisitStringLength(s *StringLength) any {
	v.visitedNodes = append(v.visitedNodes, "StringLength")
	return "visited_string_length"
}

func (v *ComprehensiveTestVisitor) VisitArrayIndex(a *ArrayIndex) any {
	v.visitedNodes = append(v.visitedNodes, "ArrayIndex")
	return "visited_array_index"
}

func (v *ComprehensiveTestVisitor) VisitForLoop(f *ForLoop) any {
	v.visitedNodes = append(v.visitedNodes, "ForLoop")
	return "visited_for_loop"
}

func (v *ComprehensiveTestVisitor) VisitOfExpression(o *OfExpression) any {
	v.visitedNodes = append(v.visitedNodes, "OfExpression")
	return "visited_of_expression"
}

func (v *ComprehensiveTestVisitor) VisitFunctionCall(f *FunctionCall) any {
	v.visitedNodes = append(v.visitedNodes, "FunctionCall")
	return "visited_function_call"
}
