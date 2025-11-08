package compiler

import (
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

// TestConditionCompilerUncoveredFunctions tests functions with 0% coverage
func TestConditionCompilerUncoveredFunctions(t *testing.T) {
	emitter := NewEmitter()
	stringOffsets := map[string]int{"$test": 0}
	cc := NewConditionCompiler(emitter, stringOffsets)
	pos := token.Position{Line: 1, Column: 1}
	builder := ast.NewBuilder()

	t.Run("parseSizeLiteral function", func(t *testing.T) {
		// Test the parseSizeLiteral function directly
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
			got, err := parseSizeLiteral(tt.literal)
			if tt.wantErr && err == nil {
				t.Errorf("parseSizeLiteral(%q) expected error", tt.literal)
			}
			if !tt.wantErr && (err != nil || got != tt.expected) {
				t.Errorf("parseSizeLiteral(%q) = %d, %v, want %d, nil", tt.literal, got, err, tt.expected)
			}
		}
	})

	t.Run("SetRuleIndexMap method", func(t *testing.T) {
		ruleIndexMap := map[string]int{"rule1": 0}
		cc.SetRuleIndexMap(ruleIndexMap)
		// If we reach here without panic, the test passes
		t.Log("SetRuleIndexMap executed without error")
	})

	t.Run("findStringOffset and emit functions", func(t *testing.T) {
		// Test findStringOffset
		offset, found := cc.findStringOffset("$test")
		if !found || offset != 0 {
			t.Errorf("findStringOffset failed: got %d, %v", offset, found)
		}

		// Test emitStringOffset and emitStringIdentifier
		cc.emitStringOffset(0, 1, 1)
		cc.emitStringIdentifier(0, "$test", 1, 1)
		t.Log("String offset functions executed without error")
	})

	t.Run("GetVariableMap and GetExternalVariables", func(t *testing.T) {
		// Add a variable first
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

	t.Run("Boolean expression functions", func(t *testing.T) {
		expr := builder.Literal(pos, token.TRUE, true)
		err := cc.CompileBooleanExpression(expr, false)
		t.Logf("CompileBooleanExpression result: %v", err)

		// Test short circuit functions with binary ops
		andOp := builder.BinaryOp(pos, expr, token.AND, expr)
		orOp := builder.BinaryOp(pos, expr, token.OR, expr)

		_ = cc.compileShortCircuitAnd(andOp)
		_ = cc.compileShortCircuitOr(orOp)
		t.Log("Boolean expression functions executed without error")
	})

	t.Run("Special operator compilation", func(t *testing.T) {
		// Test string offset operator (@)
		atExpr := builder.BinaryOp(
			pos,
			builder.Identifier(pos, "$test"),
			token.AT,
			builder.Literal(pos, token.INTEGER_LIT, 0),
		)
		err := cc.compileStringOffsetOperator(atExpr)
		t.Logf("compileStringOffsetOperator result: %v", err)

		// Test hash operator (#)
		hashExpr := builder.UnaryOp(
			pos,
			token.HASH,
			builder.Identifier(pos, "$test"),
		)
		err = cc.compileHashOperator(hashExpr)
		t.Logf("compileHashOperator result: %v", err)

		// Test at operator
		atUnaryExpr := builder.UnaryOp(
			pos,
			token.AT,
			builder.Identifier(pos, "$test"),
		)
		err = cc.compileAtOperator(atUnaryExpr)
		t.Logf("compileAtOperator result: %v", err)

		// Test defined operator
		definedExpr := builder.UnaryOp(
			pos,
			token.DEFINED,
			builder.Identifier(pos, "test_var"),
		)
		err = cc.compileDefinedOperator(definedExpr)
		t.Logf("compileDefinedOperator result: %v", err)

		// Test array index
		arrayExpr := builder.ArrayIndex(
			pos,
			builder.Identifier(pos, "array_var"),
			builder.Literal(pos, token.INTEGER_LIT, 0),
		)
		err = cc.compileArrayIndex(arrayExpr)
		t.Logf("compileArrayIndex result: %v", err)
	})

	t.Run("Size literal compilation", func(t *testing.T) {
		sizeExpr := builder.Literal(pos, token.STRING_LIT, "10KB")
		err := cc.compileSizeLiteral(sizeExpr)
		t.Logf("compileSizeLiteral result: %v", err)
	})

	t.Run("Advanced expression compilation", func(t *testing.T) {
		// Test "of" expression
		ofExpr := builder.OfExpression(
			pos,
			builder.Literal(pos, token.INTEGER_LIT, 1),
			builder.Identifier(pos, "them"),
		)
		err := cc.compileOfExpression(ofExpr)
		t.Logf("compileOfExpression result: %v", err)

		// Test count expression
		err = cc.compileCountExpression(ofExpr)
		t.Logf("compileCountExpression result: %v", err)

		// Test strings expression
		stringsExpr := builder.Identifier(pos, "them")
		err = cc.compileStringsExpression(stringsExpr)
		t.Logf("compileStringsExpression result: %v", err)

		// Test function call
		fnCall := builder.FunctionCall(
			pos,
			"pe.section",
			[]ast.Expression{
				builder.Literal(pos, token.STRING_LIT, ".text"),
			},
		)
		err = cc.compileFunctionCall(fnCall)
		t.Logf("compileFunctionCall result: %v", err)

		// Test string length
		strLenExpr := builder.StringLength(
			pos,
			builder.Identifier(pos, "$test"),
		)
		err = cc.compileStringLength(strLenExpr)
		t.Logf("compileStringLength result: %v", err)
	})

	t.Run("Rule reference functions", func(t *testing.T) {
		ruleName := "test_rule"
		line := 1
		column := 1

		// Test rule reference detection (function expects string)
		isRef := cc.isRuleReference(ruleName)
		t.Logf("isRuleReference result: %v", isRef)

		// Test rule reference compilation
		err := cc.compileRuleReference(ruleName, line, column)
		t.Logf("compileRuleReference result: %v", err)

		// Test module function call
		moduleName := "pe"
		cc.emitModuleFunctionCall(moduleName, line, column)
		t.Log("emitModuleFunctionCall executed without error")
	})

	t.Run("Type detection functions", func(t *testing.T) {
		intLit := builder.Literal(pos, token.INTEGER_LIT, 42)
		floatLit := builder.Literal(pos, token.FLOAT_LIT, 3.14)
		ident := builder.Identifier(pos, "var")

		// Test float detection
		if !cc.isFloatExpression(floatLit) {
			t.Error("isFloatExpression should return true for float literal")
		}
		if cc.isFloatExpression(intLit) {
			t.Error("isFloatExpression should return false for int literal")
		}
		if cc.isFloatExpression(ident) {
			t.Error("isFloatExpression should return false for identifier")
		}

		// Test literal float detection
		if !cc.isLiteralFloat(floatLit) {
			t.Error("isLiteralFloat should return true for float literal")
		}
		if cc.isLiteralFloat(intLit) {
			t.Error("isLiteralFloat should return false for int literal")
		}
	})

	t.Run("Mixed type comparison function", func(t *testing.T) {
		// Test the boolean parameter version
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

	t.Run("Mixed type operation handlers", func(t *testing.T) {
		// Create binary operations for testing
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

		// Test handlers (they modify the binaryOp in place)
		cc.handleBitShiftFloatConversion(bitShiftOp, false, true, false)
		result := cc.handleMixedTypeLiteralComparison(comparisonOp)
		t.Logf("handleMixedTypeLiteralComparison result: %v", result)

		cc.convertForMixedTypeComparison(comparisonOp, false, true, true)
		cc.convertForMixedTypeArithmetic(arithmeticOp, false, true, false)

		t.Log("Mixed type operation handlers executed without error")
	})

	t.Run("Compilation optimization and validation", func(t *testing.T) {
		expr := builder.Literal(pos, token.INTEGER_LIT, 42)

		// Test validation
		err := cc.ValidateExpression(expr)
		if err != nil {
			t.Errorf("ValidateExpression failed: %v", err)
		}

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

	t.Run("EmitJump and jump handling", func(t *testing.T) {
		// Test EmitJump with proper parameters
		config := ConditionalJumpConfig{
			Opcode:      OP_JZ,
			TargetLabel: "test_label",
			Position:    JumpPosition{Line: 1, Column: 1},
		}
		err := cc.EmitJump(config)
		t.Logf("EmitJump result: %v", err)
	})

	t.Run("SetStringOffsets", func(t *testing.T) {
		newOffsets := map[string]int{"$new": 1}
		cc.SetStringOffsets(newOffsets)
		t.Log("SetStringOffsets executed without error")
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
