package compiler

import (
	"strings"
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

// TestConditionCompiler_ParseSizeLiteral tests the parseSizeLiteral function
func TestConditionCompiler_ParseSizeLiteral(t *testing.T) {
	tests := []struct {
		literal  string
		expected int64
		wantErr  bool
	}{
		{"10KB", 10 * 1024, false},
		{"5MB", 5 * 1024 * 1024, false},
		{"0x10KB", 0x10 * 1024, false},
		{"invalid", 0, true},
		{"", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.literal, func(t *testing.T) {
			got, err := parseSizeLiteral(tt.literal)
			if tt.wantErr && err == nil {
				t.Errorf("parseSizeLiteral(%q) expected error", tt.literal)
			}
			if !tt.wantErr && (err != nil || got != tt.expected) {
				t.Errorf("parseSizeLiteral(%q) = %d, %v, want %d, nil", tt.literal, got, err, tt.expected)
			}
		})
	}
}

// TestConditionCompiler_StringOffsetFunctions tests string offset related functions
func TestConditionCompiler_StringOffsetFunctions(t *testing.T) {
	emitter := NewEmitter()
	stringOffsets := map[string]int{"$test": 0}
	cc := NewConditionCompiler(emitter, stringOffsets)

	t.Run("findStringOffset", func(t *testing.T) {
		offset, found := cc.findStringOffset("$test")
		if !found || offset != 0 {
			t.Errorf("findStringOffset failed: got %d, %v", offset, found)
		}
	})

	t.Run("emit string identifier", func(t *testing.T) {
		before := emitter.GetInstructionCount()
		cc.emitStringIdentifier(0, "$test", 1, 1)
		if emitter.GetInstructionCount() <= before {
			t.Fatal("string identifier emitter did not emit instructions")
		}
	})
}

// TestConditionCompiler_VariableManagement tests variable-related functions
func TestConditionCompiler_VariableManagement(t *testing.T) {
	emitter := NewEmitter()
	stringOffsets := map[string]int{"$test": 0}
	cc := NewConditionCompiler(emitter, stringOffsets)

	t.Run("SetRuleIndexMap", func(t *testing.T) {
		ruleIndexMap := map[string]int{"rule1": 0}
		cc.SetRuleIndexMap(ruleIndexMap)
		if index, ok := cc.ruleIndexMap["rule1"]; !ok || index != 0 {
			t.Fatalf("SetRuleIndexMap() map = %v, want rule1 at index 0", cc.ruleIndexMap)
		}
	})

	t.Run("Variable maps", func(t *testing.T) {
		cc.AddVariable("test_var", 0)

		varMap := cc.GetVariableMap()
		if index, ok := varMap["test_var"]; !ok || index != 0 {
			t.Fatalf("GetVariableMap() = %v, want test_var at index 0", varMap)
		}

		cc.SetExternalVariables(map[string]int{"external": 1})
		if index, ok := cc.GetExternalVariables()["external"]; !ok || index != 1 {
			t.Fatalf("GetExternalVariables() = %v, want external at index 1", cc.GetExternalVariables())
		}

		cc.SetGlobalVariables(map[string]int{"global": 2})
		if index, ok := cc.GetGlobalVariables()["global"]; !ok || index != 2 {
			t.Fatalf("GetGlobalVariables() = %v, want global at index 2", cc.GetGlobalVariables())
		}
	})

	t.Run("SetStringOffsets", func(t *testing.T) {
		newOffsets := map[string]int{"$new": 1}
		cc.SetStringOffsets(newOffsets)
		if offset, ok := cc.findStringOffset("$new"); !ok || offset != 1 {
			t.Fatalf("findStringOffset($new) = %d, %v, want 1, true", offset, ok)
		}
	})
}

// TestConditionCompiler_BooleanExpressions tests boolean expression compilation
func TestConditionCompiler_BooleanExpressions(t *testing.T) {
	emitter := NewEmitter()
	stringOffsets := map[string]int{"$test": 0}
	cc := NewConditionCompiler(emitter, stringOffsets)
	pos := token.Position{Line: 1, Column: 1}
	builder := ast.NewBuilder()

	t.Run("CompileBooleanExpression", func(t *testing.T) {
		expr := builder.Literal(pos, token.TRUE, true)
		if err := cc.CompileBooleanExpression(expr, false); err != nil {
			t.Fatalf("CompileBooleanExpression() error = %v", err)
		}
	})

	t.Run("Short circuit functions", func(t *testing.T) {
		expr := builder.Literal(pos, token.TRUE, true)
		andOp := builder.BinaryOp(pos, expr, token.AND, expr)
		orOp := builder.BinaryOp(pos, expr, token.OR, expr)

		if err := cc.compileShortCircuitAnd(andOp); err != nil {
			t.Fatalf("compileShortCircuitAnd() error = %v", err)
		}
		if err := cc.compileShortCircuitOr(orOp); err != nil {
			t.Fatalf("compileShortCircuitOr() error = %v", err)
		}
	})
}

// TestConditionCompiler_SpecialOperators tests special operator compilation
func TestConditionCompiler_SpecialOperators(t *testing.T) {
	emitter := NewEmitter()
	stringOffsets := map[string]int{"$test": 0}
	cc := NewConditionCompiler(emitter, stringOffsets)
	pos := token.Position{Line: 1, Column: 1}
	builder := ast.NewBuilder()

	t.Run("String offset operator", func(t *testing.T) {
		atExpr := builder.BinaryOp(
			pos,
			builder.Identifier(pos, "$test"),
			token.AT,
			builder.Literal(pos, token.IntegerLit, 0),
		)
		if err := cc.compileStringOffsetOperator(atExpr); err != nil {
			t.Fatalf("compileStringOffsetOperator() error = %v", err)
		}
	})

	t.Run("Hash operator", func(t *testing.T) {
		hashExpr := builder.UnaryOp(
			pos,
			token.HASH,
			builder.Identifier(pos, "$test"),
		)
		if err := cc.compileHashOperator(hashExpr); err != nil {
			t.Fatalf("compileHashOperator() error = %v", err)
		}
	})

	t.Run("At operator", func(t *testing.T) {
		atUnaryExpr := builder.UnaryOp(
			pos,
			token.AT,
			builder.Identifier(pos, "$test"),
		)
		if err := cc.compileAtOperator(atUnaryExpr); err != nil {
			t.Fatalf("compileAtOperator() error = %v", err)
		}
	})

	t.Run("Defined operator", func(t *testing.T) {
		definedExpr := builder.UnaryOp(
			pos,
			token.DEFINED,
			builder.Identifier(pos, "test_var"),
		)
		err := cc.compileDefinedOperator(definedExpr)
		if err == nil || !strings.Contains(err.Error(), "undefined identifier: test_var") {
			t.Fatalf("compileDefinedOperator() error = %v, want undefined identifier", err)
		}
	})

	t.Run("Size literal", func(t *testing.T) {
		sizeExpr := builder.Literal(pos, token.StringLit, "10KB")
		if err := cc.compileSizeLiteral(sizeExpr); err != nil {
			t.Fatalf("compileSizeLiteral() error = %v", err)
		}
	})
}

// TestConditionCompiler_AdvancedExpressions tests advanced expression compilation
func TestConditionCompiler_AdvancedExpressions(t *testing.T) {
	emitter := NewEmitter()
	stringOffsets := map[string]int{"$test": 0}
	cc := NewConditionCompiler(emitter, stringOffsets)
	pos := token.Position{Line: 1, Column: 1}
	builder := ast.NewBuilder()

	t.Run("Of expression", func(t *testing.T) {
		ofExpr := builder.OfExpression(
			pos,
			builder.Literal(pos, token.IntegerLit, 1),
			builder.Identifier(pos, "them"),
		)
		if err := cc.compileOfExpression(ofExpr); err != nil {
			t.Fatalf("compileOfExpression() error = %v", err)
		}
	})

	t.Run("Count expression", func(t *testing.T) {
		ofExpr := builder.OfExpression(
			pos,
			builder.Literal(pos, token.IntegerLit, 1),
			builder.Identifier(pos, "them"),
		)
		if err := cc.compileCountExpression(ofExpr); err != nil {
			t.Fatalf("compileCountExpression() error = %v", err)
		}
	})

	t.Run("Strings expression", func(t *testing.T) {
		stringsExpr := builder.Identifier(pos, "them")
		if err := cc.compileStringsExpression(stringsExpr); err != nil {
			t.Fatalf("compileStringsExpression() error = %v", err)
		}
	})

	t.Run("Function call", func(t *testing.T) {
		fnCall := builder.FunctionCall(
			pos,
			"pe.section",
			[]ast.Expression{
				builder.Literal(pos, token.StringLit, ".text"),
			},
		)
		err := cc.compileFunctionCall(fnCall)
		if err == nil || !strings.Contains(err.Error(), "unsupported module: pe") {
			t.Fatalf("compileFunctionCall() error = %v, want unsupported pe module", err)
		}
	})

	t.Run("String length", func(t *testing.T) {
		strLenExpr := builder.StringLength(
			pos,
			builder.Identifier(pos, "$test"),
		)
		if err := cc.compileStringLength(strLenExpr); err != nil {
			t.Fatalf("compileStringLength() error = %v", err)
		}
	})
}

// TestConditionCompiler_RuleReferences tests rule reference functions
func TestConditionCompiler_RuleReferences(t *testing.T) {
	emitter := NewEmitter()
	stringOffsets := map[string]int{"$test": 0}
	cc := NewConditionCompiler(emitter, stringOffsets)

	t.Run("isRuleReference", func(t *testing.T) {
		ruleName := "test_rule"
		if cc.isRuleReference(ruleName) {
			t.Fatalf("isRuleReference(%q) = true, want false", ruleName)
		}
	})

	t.Run("compileRuleReference", func(t *testing.T) {
		ruleName := "test_rule"
		line := 1
		column := 1
		err := cc.compileRuleReference(ruleName, line, column)
		if err == nil || !strings.Contains(err.Error(), "undefined rule reference: test_rule") {
			t.Fatalf("compileRuleReference() error = %v, want undefined rule reference", err)
		}
	})

	t.Run("compileRuleReference operand", func(t *testing.T) {
		cc.SetRuleIndexMap(map[string]int{"test_rule": 7})
		if err := cc.compileRuleReference("test_rule", 1, 1); err != nil {
			t.Fatalf("compileRuleReference() error = %v", err)
		}
		instructions := emitter.GetInstructions()
		instruction := instructions[len(instructions)-1]
		if instruction.Opcode != OpPushRuleRef ||
			instruction.Operand.Type != OperandImmediate8 ||
			instruction.Operand.Value != 7 {
			t.Fatalf("rule reference instruction = %#v", instruction)
		}
	})

	t.Run("compileRuleReference overflow", func(t *testing.T) {
		cc.SetRuleIndexMap(map[string]int{"test_rule": 256})
		err := cc.compileRuleReference("test_rule", 1, 1)
		if err == nil || !strings.Contains(err.Error(), "exceeds bytecode capacity") {
			t.Fatalf("compileRuleReference() error = %v, want capacity error", err)
		}
	})

	t.Run("emitModuleFunctionCall", func(t *testing.T) {
		moduleName := "pe"
		line := 1
		column := 1
		err := cc.emitModuleFunctionCall(moduleName, line, column)
		if err == nil {
			t.Fatal("emitModuleFunctionCall() expected unsupported module error, got nil")
		}
		if !strings.Contains(err.Error(), "unsupported module: pe") {
			t.Fatalf("emitModuleFunctionCall() error = %v, want unsupported module: pe", err)
		}
	})
}

// TestConditionCompiler_TypeDetection tests type detection functions
func TestConditionCompiler_TypeDetection(t *testing.T) {
	emitter := NewEmitter()
	stringOffsets := map[string]int{"$test": 0}
	cc := NewConditionCompiler(emitter, stringOffsets)
	pos := token.Position{Line: 1, Column: 1}
	builder := ast.NewBuilder()

	intLit := builder.Literal(pos, token.IntegerLit, 42)
	floatLit := builder.Literal(pos, token.FloatLit, 3.14)
	ident := builder.Identifier(pos, "var")

	t.Run("isFloatExpression", func(t *testing.T) {
		if !cc.isFloatExpression(floatLit) {
			t.Error("isFloatExpression should return true for float literal")
		}
		if cc.isFloatExpression(intLit) {
			t.Error("isFloatExpression should return false for int literal")
		}
		if cc.isFloatExpression(ident) {
			t.Error("isFloatExpression should return false for identifier")
		}
	})

	t.Run("isLiteralFloat", func(t *testing.T) {
		if !cc.isLiteralFloat(floatLit) {
			t.Error("isLiteralFloat should return true for float literal")
		}
		if cc.isLiteralFloat(intLit) {
			t.Error("isLiteralFloat should return false for int literal")
		}
	})
}

// TestConditionCompiler_MixedTypeOperations tests mixed type comparison and operations
func TestConditionCompiler_MixedTypeOperations(t *testing.T) {
	emitter := NewEmitter()
	stringOffsets := map[string]int{"$test": 0}
	cc := NewConditionCompiler(emitter, stringOffsets)
	pos := token.Position{Line: 1, Column: 1}
	builder := ast.NewBuilder()

	t.Run("isMixedTypeComparison", func(t *testing.T) {
		tests := []struct {
			leftIsFloat  bool
			rightIsFloat bool
			expected     bool
		}{
			{false, true, true},
			{true, false, true},
			{false, false, false},
			{true, true, false},
		}

		for _, tt := range tests {
			result := cc.isMixedTypeComparison(tt.leftIsFloat, tt.rightIsFloat)
			if result != tt.expected {
				t.Errorf("isMixedTypeComparison(%v, %v) = %v, want %v",
					tt.leftIsFloat, tt.rightIsFloat, result, tt.expected)
			}
		}
	})

	t.Run("Mixed type handlers", func(t *testing.T) {
		bitShiftOp := builder.BinaryOp(
			pos,
			builder.Literal(pos, token.IntegerLit, 42),
			token.LeftShift,
			builder.Literal(pos, token.FloatLit, 3.14),
		)

		comparisonOp := builder.BinaryOp(
			pos,
			builder.Literal(pos, token.IntegerLit, 42),
			token.EQ,
			builder.Literal(pos, token.FloatLit, 3.14),
		)

		arithmeticOp := builder.BinaryOp(
			pos,
			builder.Literal(pos, token.IntegerLit, 42),
			token.PLUS,
			builder.Literal(pos, token.FloatLit, 3.14),
		)

		cc.handleBitShiftFloatConversion(bitShiftOp, false, true, false)
		result := cc.handleMixedTypeLiteralComparison(comparisonOp)
		if !result {
			t.Fatal("handleMixedTypeLiteralComparison() = false, want true")
		}

		cc.convertForMixedTypeComparison(comparisonOp, false, true)
		cc.convertForMixedTypeArithmetic(arithmeticOp, false, true)
	})
}

// TestConditionCompiler_OptimizationAndValidation tests optimization and validation functions
func TestConditionCompiler_OptimizationAndValidation(t *testing.T) {
	emitter := NewEmitter()
	stringOffsets := map[string]int{"$test": 0}
	cc := NewConditionCompiler(emitter, stringOffsets)
	pos := token.Position{Line: 1, Column: 1}
	builder := ast.NewBuilder()

	expr := builder.Literal(pos, token.IntegerLit, 42)

	t.Run("ValidateExpression", func(t *testing.T) {
		err := cc.ValidateExpression(expr)
		if err != nil {
			t.Errorf("ValidateExpression failed: %v", err)
		}
	})

	t.Run("Optimization functions", func(t *testing.T) {
		// Test optimization
		optimized := cc.OptimizeExpression(expr)
		if optimized == nil {
			t.Error("OptimizeExpression returned nil")
		}

		// Test stats
		stats := cc.GetStats()
		if stats == nil {
			t.Error("GetStats returned nil")
		}
	})

	t.Run("EmitJump", func(t *testing.T) {
		// Test EmitJump with proper parameters
		config := ConditionalJumpConfig{
			Opcode:      OpJz,
			TargetLabel: "test_label",
			Position:    JumpPosition{Line: 1, Column: 1},
		}
		if err := cc.EmitJump(config); err != nil {
			t.Fatalf("EmitJump() error = %v", err)
		}
	})
}

// TestConditionCompilerEdgeCasesAndErrors tests edge cases and error conditions
func TestConditionCompilerEdgeCasesAndErrors(t *testing.T) {
	t.Run("NilAndEmptyInputs", testConditionCompilerNilInputs)
	t.Run("UndefinedReferences", testConditionCompilerUndefinedReferences)
	t.Run("InvalidSizeLiterals", testConditionCompilerInvalidSizeLiterals)
	t.Run("ComplexExpressions", testConditionCompilerComplexExpressions)
	t.Run("FunctionCallVariations", testConditionCompilerFunctionCallVariations)
}

// testConditionCompilerNilInputs tests edge cases with nil and empty inputs
func testConditionCompilerNilInputs(t *testing.T) {
	emitter := NewEmitter()
	cc := NewConditionCompiler(emitter, map[string]int{})

	tests := []struct {
		name string
		test func(*testing.T, *ConditionCompiler)
	}{
		{
			name: "nil_string_offsets_map",
			test: func(t *testing.T, _ *ConditionCompiler) {
				nilCC := NewConditionCompiler(emitter, nil)
				if offset, ok := nilCC.findStringOffset("$test"); ok {
					t.Fatalf("findStringOffset() = %d, true with nil offsets, want not found", offset)
				}
			},
		},
		{
			name: "nil_expression_validation",
			test: func(t *testing.T, cc *ConditionCompiler) {
				err := cc.ValidateExpression(nil)
				if err == nil || !strings.Contains(err.Error(), "unsupported expression type") {
					t.Fatalf("ValidateExpression(nil) error = %v, want unsupported expression type", err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.test(t, cc)
		})
	}
}

// testConditionCompilerUndefinedReferences tests behavior with undefined references
func testConditionCompilerUndefinedReferences(t *testing.T) {
	emitter := NewEmitter()
	cc := NewConditionCompiler(emitter, map[string]int{})
	pos := token.Position{Line: 1, Column: 1}
	builder := ast.NewBuilder()

	tests := []struct {
		name string
		test func(*testing.T, *ConditionCompiler, *ast.Builder, token.Position)
	}{
		{
			name: "undefined_string",
			test: func(t *testing.T, cc *ConditionCompiler, _ *ast.Builder, _ token.Position) {
				if offset, ok := cc.findStringOffset("$undefined"); ok {
					t.Fatalf("findStringOffset() = %d, true for undefined string", offset)
				}
			},
		},
		{
			name: "undefined_variable",
			test: func(t *testing.T, cc *ConditionCompiler, builder *ast.Builder, pos token.Position) {
				undefinedExpr := builder.Identifier(pos, "undefined_var")
				err := cc.compileExpression(undefinedExpr)
				if err == nil || !strings.Contains(err.Error(), "undefined identifier: undefined_var") {
					t.Fatalf("compileExpression() error = %v, want undefined identifier", err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.test(t, cc, builder, pos)
		})
	}
}

// testConditionCompilerInvalidSizeLiterals tests invalid size literal parsing
func testConditionCompilerInvalidSizeLiterals(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "invalid_string", input: "invalid"},
		{name: "invalid_unit", input: "10XB"},
		{name: "float_with_unit", input: "10.5KB"},
		{name: "negative_value", input: "-10KB"},
		{name: "empty_string", input: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseSizeLiteral(tt.input)
			if err == nil {
				t.Errorf("parseSizeLiteral(%q) should have failed", tt.input)
			}
		})
	}
}

// testConditionCompilerComplexExpressions tests compilation of complex nested expressions
func testConditionCompilerComplexExpressions(t *testing.T) {
	emitter := NewEmitter()
	cc := NewConditionCompiler(emitter, map[string]int{})
	pos := token.Position{Line: 1, Column: 1}
	builder := ast.NewBuilder()

	tests := []struct {
		name          string
		expr          ast.Expression
		errorContains string
	}{
		{
			name: "nested_function_call",
			expr: builder.BinaryOp(
				pos,
				builder.FunctionCall(
					pos,
					"module.function",
					[]ast.Expression{
						builder.StringLength(pos, builder.Identifier(pos, "$test")),
					},
				),
				token.EQ,
				builder.Literal(pos, token.IntegerLit, 42),
			),
			errorContains: "unsupported module: module",
		},
		{
			name: "chained_binary_ops",
			expr: builder.BinaryOp(
				pos,
				builder.BinaryOp(
					pos,
					builder.Identifier(pos, "a"),
					token.PLUS,
					builder.Identifier(pos, "b"),
				),
				token.MULTIPLY,
				builder.Identifier(pos, "c"),
			),
			errorContains: "undefined identifier: c",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cc.compileExpression(tt.expr)
			if err == nil || !strings.Contains(err.Error(), tt.errorContains) {
				t.Fatalf("compileExpression() error = %v, want substring %q", err, tt.errorContains)
			}
		})
	}
}

// testConditionCompilerFunctionCallVariations tests function calls with different argument patterns
func testConditionCompilerFunctionCallVariations(t *testing.T) {
	emitter := NewEmitter()
	cc := NewConditionCompiler(emitter, map[string]int{})
	pos := token.Position{Line: 1, Column: 1}
	builder := ast.NewBuilder()

	tests := []struct {
		name     string
		function string
		args     []ast.Expression
	}{
		{
			name:     "no_arguments",
			function: "test.function",
			args:     []ast.Expression{},
		},
		{
			name:     "single_argument",
			function: "test.function",
			args: []ast.Expression{
				builder.Literal(pos, token.StringLit, "arg1"),
			},
		},
		{
			name:     "multiple_types",
			function: "test.function",
			args: []ast.Expression{
				builder.Literal(pos, token.StringLit, "arg1"),
				builder.Literal(pos, token.IntegerLit, 42),
				builder.Literal(pos, token.FloatLit, 3.14),
				builder.Identifier(pos, "var"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := builder.FunctionCall(pos, tt.function, tt.args)
			err := cc.compileFunctionCall(fn)
			if err == nil || !strings.Contains(err.Error(), "unsupported module: test") {
				t.Fatalf("compileFunctionCall() error = %v, want unsupported test module", err)
			}
		})
	}
}
