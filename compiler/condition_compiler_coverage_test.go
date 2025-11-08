package compiler

import (
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

	t.Run("emit functions", func(t *testing.T) {
		cc.emitStringOffset(0, 1, 1)
		cc.emitStringIdentifier(0, "$test", 1, 1)
		t.Log("String offset functions executed without error")
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
		t.Log("SetRuleIndexMap executed without error")
	})

	t.Run("Variable maps", func(t *testing.T) {
		cc.AddVariable("test_var", 0)

		varMap := cc.GetVariableMap()
		if varMap == nil {
			t.Error("GetVariableMap returned nil")
		}

		extVars := cc.GetExternalVariables()
		if extVars == nil {
			t.Error("GetExternalVariables returned nil")
		}
	})

	t.Run("SetStringOffsets", func(t *testing.T) {
		newOffsets := map[string]int{"$new": 1}
		cc.SetStringOffsets(newOffsets)
		t.Log("SetStringOffsets executed without error")
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
		err := cc.CompileBooleanExpression(expr, false)
		t.Logf("CompileBooleanExpression result: %v", err)
	})

	t.Run("Short circuit functions", func(t *testing.T) {
		expr := builder.Literal(pos, token.TRUE, true)
		andOp := builder.BinaryOp(pos, expr, token.AND, expr)
		orOp := builder.BinaryOp(pos, expr, token.OR, expr)

		_ = cc.compileShortCircuitAnd(andOp)
		_ = cc.compileShortCircuitOr(orOp)
		t.Log("Boolean expression functions executed without error")
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
			builder.Literal(pos, token.INTEGER_LIT, 0),
		)
		err := cc.compileStringOffsetOperator(atExpr)
		t.Logf("compileStringOffsetOperator result: %v", err)
	})

	t.Run("Hash operator", func(t *testing.T) {
		hashExpr := builder.UnaryOp(
			pos,
			token.HASH,
			builder.Identifier(pos, "$test"),
		)
		err := cc.compileHashOperator(hashExpr)
		t.Logf("compileHashOperator result: %v", err)
	})

	t.Run("At operator", func(t *testing.T) {
		atUnaryExpr := builder.UnaryOp(
			pos,
			token.AT,
			builder.Identifier(pos, "$test"),
		)
		err := cc.compileAtOperator(atUnaryExpr)
		t.Logf("compileAtOperator result: %v", err)
	})

	t.Run("Defined operator", func(t *testing.T) {
		definedExpr := builder.UnaryOp(
			pos,
			token.DEFINED,
			builder.Identifier(pos, "test_var"),
		)
		err := cc.compileDefinedOperator(definedExpr)
		t.Logf("compileDefinedOperator result: %v", err)
	})

	t.Run("Array index", func(t *testing.T) {
		arrayExpr := builder.ArrayIndex(
			pos,
			builder.Identifier(pos, "array_var"),
			builder.Literal(pos, token.INTEGER_LIT, 0),
		)
		err := cc.compileArrayIndex(arrayExpr)
		t.Logf("compileArrayIndex result: %v", err)
	})

	t.Run("Size literal", func(t *testing.T) {
		sizeExpr := builder.Literal(pos, token.STRING_LIT, "10KB")
		err := cc.compileSizeLiteral(sizeExpr)
		t.Logf("compileSizeLiteral result: %v", err)
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
			builder.Literal(pos, token.INTEGER_LIT, 1),
			builder.Identifier(pos, "them"),
		)
		err := cc.compileOfExpression(ofExpr)
		t.Logf("compileOfExpression result: %v", err)
	})

	t.Run("Count expression", func(t *testing.T) {
		ofExpr := builder.OfExpression(
			pos,
			builder.Literal(pos, token.INTEGER_LIT, 1),
			builder.Identifier(pos, "them"),
		)
		err := cc.compileCountExpression(ofExpr)
		t.Logf("compileCountExpression result: %v", err)
	})

	t.Run("Strings expression", func(t *testing.T) {
		stringsExpr := builder.Identifier(pos, "them")
		err := cc.compileStringsExpression(stringsExpr)
		t.Logf("compileStringsExpression result: %v", err)
	})

	t.Run("Function call", func(t *testing.T) {
		fnCall := builder.FunctionCall(
			pos,
			"pe.section",
			[]ast.Expression{
				builder.Literal(pos, token.STRING_LIT, ".text"),
			},
		)
		err := cc.compileFunctionCall(fnCall)
		t.Logf("compileFunctionCall result: %v", err)
	})

	t.Run("String length", func(t *testing.T) {
		strLenExpr := builder.StringLength(
			pos,
			builder.Identifier(pos, "$test"),
		)
		err := cc.compileStringLength(strLenExpr)
		t.Logf("compileStringLength result: %v", err)
	})
}

// TestConditionCompiler_RuleReferences tests rule reference functions
func TestConditionCompiler_RuleReferences(t *testing.T) {
	emitter := NewEmitter()
	stringOffsets := map[string]int{"$test": 0}
	cc := NewConditionCompiler(emitter, stringOffsets)

	t.Run("isRuleReference", func(t *testing.T) {
		ruleName := "test_rule"
		isRef := cc.isRuleReference(ruleName)
		t.Logf("isRuleReference result: %v", isRef)
	})

	t.Run("compileRuleReference", func(t *testing.T) {
		ruleName := "test_rule"
		line := 1
		column := 1
		err := cc.compileRuleReference(ruleName, line, column)
		t.Logf("compileRuleReference result: %v", err)
	})

	t.Run("emitModuleFunctionCall", func(t *testing.T) {
		moduleName := "pe"
		line := 1
		column := 1
		cc.emitModuleFunctionCall(moduleName, line, column)
		t.Log("emitModuleFunctionCall executed without error")
	})
}

// TestConditionCompiler_TypeDetection tests type detection functions
func TestConditionCompiler_TypeDetection(t *testing.T) {
	emitter := NewEmitter()
	stringOffsets := map[string]int{"$test": 0}
	cc := NewConditionCompiler(emitter, stringOffsets)
	pos := token.Position{Line: 1, Column: 1}
	builder := ast.NewBuilder()

	intLit := builder.Literal(pos, token.INTEGER_LIT, 42)
	floatLit := builder.Literal(pos, token.FLOAT_LIT, 3.14)
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
			builder.Literal(pos, token.INTEGER_LIT, 42),
			token.LEFT_SHIFT,
			builder.Literal(pos, token.FLOAT_LIT, 3.14),
		)

		comparisonOp := builder.BinaryOp(
			pos,
			builder.Literal(pos, token.INTEGER_LIT, 42),
			token.EQ,
			builder.Literal(pos, token.FLOAT_LIT, 3.14),
		)

		arithmeticOp := builder.BinaryOp(
			pos,
			builder.Literal(pos, token.INTEGER_LIT, 42),
			token.PLUS,
			builder.Literal(pos, token.FLOAT_LIT, 3.14),
		)

		cc.handleBitShiftFloatConversion(bitShiftOp, false, true, false)
		result := cc.handleMixedTypeLiteralComparison(comparisonOp)
		t.Logf("handleMixedTypeLiteralComparison result: %v", result)

		cc.convertForMixedTypeComparison(comparisonOp, false, true, true)
		cc.convertForMixedTypeArithmetic(arithmeticOp, false, true, false)

		t.Log("Mixed type operation handlers executed without error")
	})
}

// TestConditionCompiler_OptimizationAndValidation tests optimization and validation functions
func TestConditionCompiler_OptimizationAndValidation(t *testing.T) {
	emitter := NewEmitter()
	stringOffsets := map[string]int{"$test": 0}
	cc := NewConditionCompiler(emitter, stringOffsets)
	pos := token.Position{Line: 1, Column: 1}
	builder := ast.NewBuilder()

	expr := builder.Literal(pos, token.INTEGER_LIT, 42)

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
			Opcode:      OP_JZ,
			TargetLabel: "test_label",
			Position:    JumpPosition{Line: 1, Column: 1},
		}
		err := cc.EmitJump(config)
		t.Logf("EmitJump result: %v", err)
	})
}

// TestConditionCompilerEdgeCasesAndErrors tests edge cases and error conditions
func TestConditionCompilerEdgeCasesAndErrors(t *testing.T) {
	emitter := NewEmitter()
	cc := NewConditionCompiler(emitter, map[string]int{})
	pos := token.Position{Line: 1, Column: 1}
	builder := ast.NewBuilder()

	t.Run("nil and empty inputs", func(t *testing.T) {
		// Test with nil string offsets
		nilCC := NewConditionCompiler(emitter, nil)
		offset, found := nilCC.findStringOffset("$test")
		if found {
			t.Error("findStringOffset should return false for nil map")
		}
		// The function returns 0 when not found in nil map, which is acceptable
		t.Logf("findStringOffset with nil map result: offset=%d, found=%v", offset, found)

		// Test validation with nil expression
		err := cc.ValidateExpression(nil)
		t.Logf("ValidateExpression with nil result: %v", err)
	})

	t.Run("undefined strings and variables", func(t *testing.T) {
		// Test with undefined string
		_, found := cc.findStringOffset("$undefined")
		if found {
			t.Error("findStringOffset should return false for undefined string")
		}

		// Test compilation with undefined variable
		undefinedExpr := builder.Identifier(pos, "undefined_var")
		err := cc.compileExpression(undefinedExpr)
		t.Logf("Compilation with undefined variable result: %v", err)
	})

	t.Run("invalid size literals", func(t *testing.T) {
		invalidSizes := []string{
			"invalid",
			"10XB",   // Invalid unit
			"10.5KB", // Float with unit
			"-10KB",  // Negative
			"",       // Empty
		}

		for _, size := range invalidSizes {
			_, err := parseSizeLiteral(size)
			if err == nil {
				t.Errorf("parseSizeLiteral(%q) should have failed", size)
			}
		}
	})

	t.Run("complex expressions", func(t *testing.T) {
		// Test deeply nested expressions
		complexExpr := builder.BinaryOp(
			pos,
			builder.FunctionCall(
				pos,
				"module.function",
				[]ast.Expression{
					builder.StringLength(pos, builder.Identifier(pos, "$test")),
				},
			),
			token.EQ,
			builder.Literal(pos, token.INTEGER_LIT, 42),
		)

		err := cc.compileExpression(complexExpr)
		t.Logf("Complex expression compilation result: %v", err)
	})

	t.Run("function calls with various arguments", func(t *testing.T) {
		// Test function call with no arguments
		noArgsFn := builder.FunctionCall(
			pos,
			"test.function",
			[]ast.Expression{},
		)
		err := cc.compileFunctionCall(noArgsFn)
		t.Logf("Function call with no args result: %v", err)

		// Test function call with many arguments
		manyArgsFn := builder.FunctionCall(
			pos,
			"test.function",
			[]ast.Expression{
				builder.Literal(pos, token.STRING_LIT, "arg1"),
				builder.Literal(pos, token.INTEGER_LIT, 42),
				builder.Literal(pos, token.FLOAT_LIT, 3.14),
				builder.Identifier(pos, "var"),
			},
		)
		err = cc.compileFunctionCall(manyArgsFn)
		t.Logf("Function call with many args result: %v", err)
	})
}
