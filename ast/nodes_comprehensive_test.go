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

	// Group test cases by logical categories
	nodeTests := map[string][]struct {
		name string
		node Node
	}{
		"Variables": {
			{
				name: "GlobalVariable",
				node: builder.GlobalVariable(pos, "global_var", builder.Literal(pos, token.IntegerLit, 42)),
			},
			{
				name: "ExternalVariable",
				node: builder.ExternalVariable(pos, "ext_var", "ext_identifier", "integer"),
			},
		},
		"ModuleDeclarations": {
			{
				name: "Import",
				node: builder.Import(pos, "pe"),
			},
			{
				name: "Include",
				node: builder.Include(pos, "rules.yar"),
			},
		},
		"Expressions": {
			{
				name: "StringLength",
				node: builder.StringLength(pos, builder.Identifier(pos, "$s1")),
			},
			{
				name: "ArrayIndex",
				node: builder.ArrayIndex(pos, builder.Identifier(pos, "array"), builder.Literal(pos, token.IntegerLit, 0)),
			},
			{
				name: "ForLoop",
				node: builder.ForLoop(pos, "all", "i", builder.Identifier(pos, "range"), builder.Identifier(pos, "condition")),
			},
			{
				name: "OfExpression",
				node: builder.OfExpression(pos, builder.Literal(pos, token.IntegerLit, 2), builder.Identifier(pos, "them")),
			},
			{
				name: "FunctionCall",
				node: builder.FunctionCall(pos, "module.function", []Expression{
					builder.Literal(pos, token.StringLit, "arg1"),
					builder.Literal(pos, token.IntegerLit, 42),
				}),
			},
		},
	}

	for category, tests := range nodeTests {
		t.Run(category, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					validateAdvancedNode(t, tt.name, tt.node, pos)
				})
			}
		})
	}
}

// validateAdvancedNode is a helper that performs common validation for advanced node types
func validateAdvancedNode(t *testing.T, name string, node Node, expectedPos token.Position) {
	// Test Position method
	nodePos := node.Position()
	if nodePos.Line != expectedPos.Line || nodePos.Column != expectedPos.Column {
		t.Errorf("%s.Position() = %v, want %v", name, nodePos, expectedPos)
	}

	// Test Accept method - should not panic
	visitor := &ComprehensiveTestVisitor{}
	result := node.Accept(visitor)
	if result == nil {
		t.Errorf("%s.Accept() returned nil", name)
	}

	// Test node marker - should not panic
	switch n := node.(type) {
	case *GlobalVariable, *ExternalVariable, *Import, *Include:
		// These are just node markers
	case Expression:
		// These should also implement expression marker
		n.expression()
	}
}

// TestAdvancedBuilderMethods_Variables tests variable-related builder methods
func TestAdvancedBuilderMethods_Variables(t *testing.T) {
	builder := NewBuilder()
	pos := token.Position{Line: 3, Column: 7}

	t.Run("GlobalVariable builder", func(t *testing.T) {
		value := builder.Literal(pos, token.IntegerLit, 42)
		gv := builder.GlobalVariable(pos, "test_global", value)

		if gv.Name != "test_global" || gv.Value != value || gv.Pos.Line != pos.Line {
			t.Error("GlobalVariable fields do not match expected values")
		}
	})

	t.Run("ExternalVariable builder", func(t *testing.T) {
		ev := builder.ExternalVariable(pos, "test_ext", "binding_id", "string")

		if ev.Name != "test_ext" || ev.Identifier != "binding_id" || ev.TypeHint != "string" {
			t.Error("ExternalVariable fields do not match expected values")
		}
	})
}

// TestAdvancedBuilderMethods_Imports tests import-related builder methods
func TestAdvancedBuilderMethods_Imports(t *testing.T) {
	builder := NewBuilder()
	pos := token.Position{Line: 3, Column: 7}

	t.Run("Import builder", func(t *testing.T) {
		importVal := builder.Import(pos, "pe")

		if importVal.Module != "pe" {
			t.Errorf("Import.Module = %q, want %q", importVal.Module, "pe")
		}
	})

	t.Run("Include builder", func(t *testing.T) {
		include := builder.Include(pos, "rules/common.yar")

		if include.File != "rules/common.yar" {
			t.Errorf("Include.File = %q, want %q", include.File, "rules/common.yar")
		}
	})
}

// TestAdvancedBuilderMethods_Expressions tests expression builder methods using focused helper functions
func TestAdvancedBuilderMethods_Expressions(t *testing.T) {
	t.Run("StringLength builder", testStringLengthBuilder)
	t.Run("ArrayIndex builder", testArrayIndexBuilder)
	t.Run("ForLoop builder", testForLoopBuilder)
	t.Run("OfExpression builder", testOfExpressionBuilder)
	t.Run("FunctionCall builder", testFunctionCallBuilder)
}

func testStringLengthBuilder(t *testing.T) {
	builder := NewBuilder()
	pos := token.Position{Line: 3, Column: 7}

	stringExpr := builder.Identifier(pos, "$s1")
	strLen := builder.StringLength(pos, stringExpr)

	if strLen.String != stringExpr {
		t.Error("StringLength.String does not match")
	}
}

func testArrayIndexBuilder(t *testing.T) {
	builder := NewBuilder()
	pos := token.Position{Line: 3, Column: 7}

	array := builder.Identifier(pos, "my_array")
	index := builder.Literal(pos, token.IntegerLit, 5)
	arrayIdx := builder.ArrayIndex(pos, array, index)

	if arrayIdx.Array != array || arrayIdx.Index != index {
		t.Error("ArrayIndex fields do not match expected values")
	}
}

func testForLoopBuilder(t *testing.T) {
	builder := NewBuilder()
	pos := token.Position{Line: 3, Column: 7}

	quantifier := "any"
	variable := "i"
	rangeExpr := builder.Identifier(pos, "1..10")
	condition := builder.Identifier(pos, "valid")
	forLoop := builder.ForLoop(pos, quantifier, variable, rangeExpr, condition)

	if forLoop.Quantifier != quantifier || forLoop.Variable != variable ||
		forLoop.Range != rangeExpr || forLoop.Condition != condition {
		t.Error("ForLoop fields do not match expected values")
	}
}

func testOfExpressionBuilder(t *testing.T) {
	builder := NewBuilder()
	pos := token.Position{Line: 3, Column: 7}

	count := builder.Literal(pos, token.IntegerLit, 3)
	strings := builder.Identifier(pos, "them")
	ofExpr := builder.OfExpression(pos, count, strings)

	if ofExpr.Count != count || ofExpr.Strings != strings {
		t.Error("OfExpression fields do not match expected values")
	}
}

func testFunctionCallBuilder(t *testing.T) {
	builder := NewBuilder()
	pos := token.Position{Line: 3, Column: 7}

	args := []Expression{
		builder.Literal(pos, token.StringLit, "test"),
		builder.Literal(pos, token.IntegerLit, 123),
	}
	fnCall := builder.FunctionCall(pos, "pe.section", args)

	if fnCall.Function != "pe.section" || len(fnCall.Args) != len(args) {
		t.Error("FunctionCall basic fields do not match")
	}
	if len(args) > 0 && (len(fnCall.Args) == 0 || fnCall.Args[0] != args[0]) {
		t.Error("FunctionCall arguments do not match")
	}
}

// TestExpressionInterface tests that expression nodes implement the expression marker
func TestExpressionInterface(t *testing.T) {
	builder := NewBuilder()
	pos := token.Position{Line: 1, Column: 1}

	expressions := []Expression{
		builder.StringLength(pos, builder.Identifier(pos, "$s1")),
		builder.ArrayIndex(pos, builder.Identifier(pos, "arr"), builder.Literal(pos, token.IntegerLit, 0)),
		builder.ForLoop(pos, "all", "i", builder.Identifier(pos, "range"), builder.Identifier(pos, "cond")),
		builder.OfExpression(pos, builder.Literal(pos, token.IntegerLit, 2), builder.Identifier(pos, "them")),
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
	t.Run("ProgramStructure", testProgramStructure)
	t.Run("ProgramVisitor", testProgramVisitor)
}

// testProgramStructure tests the basic structure of a program with advanced nodes
func testProgramStructure(t *testing.T) {
	program := createComprehensiveProgram(t)

	programStructureTests := []struct {
		name     string
		actual   int
		expected int
	}{
		{"rules", len(program.Rules), 1},
		{"global_variables", len(program.GlobalVariables), 1},
		{"external_variables", len(program.ExternalVariables), 1},
		{"imports", len(program.Imports), 1},
		{"includes", len(program.Includes), 1},
	}

	for _, tt := range programStructureTests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.actual != tt.expected {
				t.Errorf("Expected %d %s, got %d", tt.expected, tt.name, tt.actual)
			}
		})
	}
}

// testProgramVisitor tests that the program visitor pattern works correctly
func testProgramVisitor(t *testing.T) {
	program := createComprehensiveProgram(t)

	visitor := &ComprehensiveTestVisitor{}
	result := program.Accept(visitor)

	if result == nil {
		t.Error("Program.Accept() returned nil")
	}
}

// createComprehensiveProgram is a helper that creates a program with all advanced node types
func createComprehensiveProgram(_ *testing.T) *Program {
	builder := NewBuilder()
	pos := token.Position{Line: 1, Column: 1}

	// Create program components
	globalVar := builder.GlobalVariable(pos, "GLOBAL_FLAG", builder.Literal(pos, token.TRUE, true))
	extVar := builder.ExternalVariable(pos, "filename", "", "string")
	importVal := builder.Import(pos, "pe")
	include := builder.Include(pos, "common.yar")

	// Create comprehensive rule
	rule := createComprehensiveRule(builder, pos)

	// Build program
	program := builder.Program([]*Rule{rule})
	program.GlobalVariables = []*GlobalVariable{globalVar}
	program.ExternalVariables = []*ExternalVariable{extVar}
	program.Imports = []*Import{importVal}
	program.Includes = []*Include{include}

	return program
}

// createComprehensiveRule creates a rule with all advanced features
func createComprehensiveRule(builder *Builder, pos token.Position) *Rule {
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
	rule.Condition = builder.OfExpression(
		pos,
		builder.Literal(pos, token.IntegerLit, 1),
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
						[]Expression{builder.Identifier(pos, "filename")},
					),
					builder.Identifier(pos, "i"),
				),
				token.EQ,
				builder.Literal(pos, token.StringLit, ".text"),
			),
		),
	)

	return rule
}

// ComprehensiveTestVisitor is a visitor that implements all visitor methods for testing
type ComprehensiveTestVisitor struct {
	visitedNodes []string
}

// Ensure ComprehensiveTestVisitor implements the full Visitor interface
var _ Visitor = (*ComprehensiveTestVisitor)(nil)

func (v *ComprehensiveTestVisitor) VisitProgram(_ *Program) any {
	v.visitedNodes = append(v.visitedNodes, "Program")
	return "visited_program"
}

func (v *ComprehensiveTestVisitor) VisitRule(_ *Rule) any {
	v.visitedNodes = append(v.visitedNodes, "Rule")
	return "visited_rule"
}

func (v *ComprehensiveTestVisitor) VisitMeta(_ *Meta) any {
	v.visitedNodes = append(v.visitedNodes, "Meta")
	return "visited_meta"
}

func (v *ComprehensiveTestVisitor) VisitString(_ *String) any {
	v.visitedNodes = append(v.visitedNodes, "String")
	return "visited_string"
}

func (v *ComprehensiveTestVisitor) VisitCondition(_ *Condition) any {
	v.visitedNodes = append(v.visitedNodes, "Condition")
	return "visited_condition"
}

func (v *ComprehensiveTestVisitor) VisitBinaryOp(_ *BinaryOp) any {
	v.visitedNodes = append(v.visitedNodes, "BinaryOp")
	return "visited_binary_op"
}

func (v *ComprehensiveTestVisitor) VisitUnaryOp(_ *UnaryOp) any {
	v.visitedNodes = append(v.visitedNodes, "UnaryOp")
	return "visited_unary_op"
}

func (v *ComprehensiveTestVisitor) VisitIdentifier(_ *Identifier) any {
	v.visitedNodes = append(v.visitedNodes, "Identifier")
	return "visited_identifier"
}

func (v *ComprehensiveTestVisitor) VisitLiteral(_ *Literal) any {
	v.visitedNodes = append(v.visitedNodes, "Literal")
	return "visited_literal"
}

func (v *ComprehensiveTestVisitor) VisitTextString(_ *TextString) any {
	v.visitedNodes = append(v.visitedNodes, "TextString")
	return "visited_text_string"
}

func (v *ComprehensiveTestVisitor) VisitHexString(_ *HexString) any {
	v.visitedNodes = append(v.visitedNodes, "HexString")
	return "visited_hex_string"
}

func (v *ComprehensiveTestVisitor) VisitRegexPattern(_ *RegexPattern) any {
	v.visitedNodes = append(v.visitedNodes, "RegexPattern")
	return "visited_regex_pattern"
}

func (v *ComprehensiveTestVisitor) VisitGlobalVariable(_ *GlobalVariable) any {
	v.visitedNodes = append(v.visitedNodes, "GlobalVariable")
	return "visited_global_variable"
}

func (v *ComprehensiveTestVisitor) VisitExternalVariable(_ *ExternalVariable) any {
	v.visitedNodes = append(v.visitedNodes, "ExternalVariable")
	return "visited_external_variable"
}

func (v *ComprehensiveTestVisitor) VisitImport(_ *Import) any {
	v.visitedNodes = append(v.visitedNodes, "Import")
	return "visited_import"
}

func (v *ComprehensiveTestVisitor) VisitInclude(_ *Include) any {
	v.visitedNodes = append(v.visitedNodes, "Include")
	return "visited_include"
}

func (v *ComprehensiveTestVisitor) VisitStringLength(_ *StringLength) any {
	v.visitedNodes = append(v.visitedNodes, "StringLength")
	return "visited_string_length"
}

func (v *ComprehensiveTestVisitor) VisitStringOffset(_ *StringOffset) any {
	v.visitedNodes = append(v.visitedNodes, "StringOffset")
	return "visited_string_offset"
}

func (v *ComprehensiveTestVisitor) VisitStringCount(_ *StringCount) any {
	v.visitedNodes = append(v.visitedNodes, "StringCount")
	return "visited_string_count"
}

func (v *ComprehensiveTestVisitor) VisitArrayIndex(_ *ArrayIndex) any {
	v.visitedNodes = append(v.visitedNodes, "ArrayIndex")
	return "visited_array_index"
}

func (v *ComprehensiveTestVisitor) VisitForLoop(_ *ForLoop) any {
	v.visitedNodes = append(v.visitedNodes, "ForLoop")
	return "visited_for_loop"
}

func (v *ComprehensiveTestVisitor) VisitOfExpression(_ *OfExpression) any {
	v.visitedNodes = append(v.visitedNodes, "OfExpression")
	return "visited_of_expression"
}

func (v *ComprehensiveTestVisitor) VisitFunctionCall(_ *FunctionCall) any {
	v.visitedNodes = append(v.visitedNodes, "FunctionCall")
	return "visited_function_call"
}
