package compiler

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

// ConditionCompiler handles compilation of conditions to bytecode
type ConditionCompiler struct {
	emitter           *Emitter
	stringOffsets     map[string]int // String identifier to bytecode offset
	variableMap       map[string]int // Variable name to index
	externalVariables map[string]int // External variable name to index
	ruleIndexMap      map[string]int // Rule name to index in compiled rules
	labelCounter      int            // For generating unique labels
	labels            map[string]int // Label name to bytecode offset
	pendingJumps      []PendingJump  // Jumps that need label resolution
}

// PendingJump represents a jump instruction that needs label resolution
type PendingJump struct {
	Opcode       Opcode
	Label        string
	Position     int
	Line, Column int
}

// NewConditionCompiler creates a new condition compiler
func NewConditionCompiler(emitter *Emitter, stringOffsets map[string]int) *ConditionCompiler {
	return &ConditionCompiler{
		emitter:           emitter,
		stringOffsets:     stringOffsets,
		variableMap:       make(map[string]int),
		externalVariables: make(map[string]int),
		ruleIndexMap:      make(map[string]int),
		labelCounter:      0,
		labels:            make(map[string]int),
		pendingJumps:      make([]PendingJump, 0),
	}
}

// SetRuleIndexMap sets the rule index map for resolving rule identifiers
func (cc *ConditionCompiler) SetRuleIndexMap(ruleIndexMap map[string]int) {
	cc.ruleIndexMap = ruleIndexMap
}

// generateLabel returns a unique label identifier for internal jump targets.
// Kept unexported; used by tests to verify uniqueness/format.
func (cc *ConditionCompiler) generateLabel() string {
	cc.labelCounter++
	return fmt.Sprintf("L%d", cc.labelCounter)
}

// defineLabel defines a label at the current bytecode position
func (cc *ConditionCompiler) defineLabel(label string) {
	cc.labels[label] = cc.emitter.GetLength()
}

// JumpPosition holds position information for jump instructions
type JumpPosition struct {
	Line   int
	Column int
}

// emitJumpWithLabel emits a jump instruction that will be resolved later
func (cc *ConditionCompiler) emitJumpWithLabel(opcode Opcode, label string, position JumpPosition) {
	// Record the pending jump
	pos := cc.emitter.GetLength()
	cc.pendingJumps = append(cc.pendingJumps, PendingJump{
		Opcode:   opcode,
		Label:    label,
		Position: pos,
		Line:     position.Line,
		Column:   position.Column,
	})

	// Emit placeholder operand (will be fixed up during resolution)
	cc.emitter.EmitOpcodeWithOperand(opcode, Operand{Type: OperandImmediate32, Value: 0}, position.Line, position.Column)
}

// resolveJumps resolves all pending jumps with their target labels
func (cc *ConditionCompiler) resolveJumps() error {
	for _, jump := range cc.pendingJumps {
		targetOffset, exists := cc.labels[jump.Label]
		if !exists {
			return fmt.Errorf("undefined label: %s", jump.Label)
		}

		// Calculate relative offset from jump instruction position
		relativeOffset := targetOffset - jump.Position - 1 // +1 because jump is relative to next instruction

		// Update the operand in the bytecode
		if err := cc.emitter.UpdateOperand(jump.Position, Operand{Type: OperandImmediate32, Value: uint64(relativeOffset)}); err != nil {
			return fmt.Errorf("failed to resolve jump to label %s: %w", jump.Label, err)
		}
	}

	// Clear pending jumps after resolution
	cc.pendingJumps = cc.pendingJumps[:0]
	return nil
}

// compileExpressions compiles multiple expressions with consistent error handling
// Reduces boilerplate error handling code in binary operations
func (cc *ConditionCompiler) compileExpressions(exprs ...ast.Expression) error {
	for _, expr := range exprs {
		if err := cc.compileExpression(expr); err != nil {
			return err
		}
	}
	return nil
}

// findStringOffset finds a string offset, trying both with and without $ prefix
// Reduces code duplication in unary operator compilation
func (cc *ConditionCompiler) findStringOffset(name string) (int, bool) {
	if offset, exists := cc.stringOffsets[name]; exists {
		return offset, true
	}
	// Try with $ prefix
	if offset, exists := cc.stringOffsets["$"+name]; exists {
		return offset, true
	}
	return 0, false
}

// emitStringOffset loads a string identifier from VM memory with overflow protection
// Reduces code duplication in string operator compilation
func (cc *ConditionCompiler) emitStringOffset(offset, line, column int) {
	// Safe conversion with overflow check
	if offset < 0 {
		cc.emitter.EmitOpcodeWithOperand(OP_PUSH_M, Operand{Type: OperandImmediate64, Value: uint64(0)}, line, column)
	} else {
		cc.emitter.EmitOpcodeWithOperand(OP_PUSH_M, Operand{Type: OperandImmediate64, Value: uint64(offset)}, line, column)
	}
}


// emitStringIdentifier pushes a string identifier as ValueTypeString for pattern operations
// Used by AT and IN operators that need the string identifier, not the FOUND result
func (cc *ConditionCompiler) emitStringIdentifier(offset int, identifier string, line, column int) {
	// identifier parameter reserved for future use when string identifiers are needed
	_ = identifier // nolint: revive
	// For AT and IN operations, we need to set up a memory slot that contains
	// the string identifier as a ValueTypeString, then push that memory slot reference

	// Use OP_PUSH_M to push the memory slot that should contain the string identifier
	// The interpreter should have already set this up via SetMemoryString during execution
	cc.emitter.EmitOpcodeWithOperand(OP_PUSH_M, Operand{Type: OperandImmediate64, Value: uint64(offset)}, line, column)
}

// CompileCondition compiles a condition expression to bytecode
func (cc *ConditionCompiler) CompileCondition(condition *ast.Condition) error {
	if err := cc.compileExpression(condition.Expression); err != nil {
		return err
	}

	// Resolve any pending jumps
	if err := cc.resolveJumps(); err != nil {
		return fmt.Errorf("failed to resolve jumps: %w", err)
	}

	return nil
}

// compileExpression compiles an expression to bytecode
func (cc *ConditionCompiler) compileExpression(expr ast.Expression) error {
	switch e := expr.(type) {
	case *ast.Literal:
		return cc.compileLiteral(e)
	case *ast.Identifier:
		return cc.compileIdentifier(e)
	case *ast.BinaryOp:
		return cc.compileBinaryOp(e)
	case *ast.UnaryOp:
		return cc.compileUnaryOp(e)
	case *ast.StringLength:
		return cc.compileStringLength(e)
	case *ast.OfExpression:
		return cc.compileOfExpression(e)
	case *ast.FunctionCall:
		return cc.compileFunctionCall(e)
	case *ast.ArrayIndex:
		return cc.compileArrayIndex(e)
	default:
		return fmt.Errorf("unsupported expression type: %T", expr)
	}
}

// compileLiteral compiles a literal value
func (cc *ConditionCompiler) compileLiteral(lit *ast.Literal) error {
	switch lit.Type {
	case token.INTEGER_LIT:
		if value, ok := lit.Value.(int64); ok {
			// Safe conversion with explicit overflow handling
			if value < 0 {
				cc.emitter.EmitPush(uint64(0), lit.Pos.Line, lit.Pos.Column)
			} else {
				cc.emitter.EmitPush(uint64(value), lit.Pos.Line, lit.Pos.Column)
			}
		}
	case token.HEX_INTEGER_LIT:
		if value, ok := lit.Value.(int64); ok {
			// Safe conversion with explicit truncation
			cc.emitter.EmitPush(uint64(value), lit.Pos.Line, lit.Pos.Column)
		} else {
			// Handle case where value is not int64
			cc.emitter.EmitPush(0, lit.Pos.Line, lit.Pos.Column)
		}
	case token.OCTAL_INTEGER_LIT:
		if value, ok := lit.Value.(int64); ok {
			// Safe conversion with explicit truncation
			cc.emitter.EmitPush(uint64(value), lit.Pos.Line, lit.Pos.Column)
		} else {
			// Handle case where value is not int64
			cc.emitter.EmitPush(0, lit.Pos.Line, lit.Pos.Column)
		}
	case token.FLOAT_LIT:
		if value, ok := lit.Value.(float64); ok {
			// Use dedicated double push instruction for floating point values
			cc.emitter.EmitPushDouble(value, lit.Pos.Line, lit.Pos.Column)
		}
	case token.STRING_LIT:
		if value, ok := lit.Value.(string); ok {
			// Push string length or reference
			cc.emitter.EmitPush(uint64(len(value)), lit.Pos.Line, lit.Pos.Column)
		}
	case token.SIZE_LIT:
		if value, ok := lit.Value.(int64); ok {
			// Size literals (KB, MB, GB) are already converted to bytes by the parser
			// Safe conversion with explicit overflow handling
			if value < 0 {
				cc.emitter.EmitPush(uint64(0), lit.Pos.Line, lit.Pos.Column)
			} else {
				cc.emitter.EmitPush(uint64(value), lit.Pos.Line, lit.Pos.Column)
			}
		}
	case token.TRUE:
		cc.emitter.EmitPush(1, lit.Pos.Line, lit.Pos.Column)
	case token.FALSE:
		cc.emitter.EmitPush(0, lit.Pos.Line, lit.Pos.Column)
	default:
		return fmt.Errorf("unsupported literal type: %s", lit.Type)
	}
	return nil
}

// compileIdentifier compiles an identifier reference
func (cc *ConditionCompiler) compileIdentifier(ident *ast.Identifier) error {
	// Check if it's a string identifier (addressed via interpreter memory)
	if offset, exists := cc.stringOffsets[ident.Name]; exists {
		// For string identifiers, we need to push the string identifier itself
		// This allows operations like AT and IN to work with the string pattern
		// Safe conversion with explicit truncation
		cc.emitter.EmitOpcodeWithOperand(OP_PUSH_M, Operand{Type: OperandImmediate64, Value: uint64(offset)}, ident.Pos.Line, ident.Pos.Column)

		// Only emit FOUND if we're not in a context where we need the raw string identifier
		// For now, we'll emit FOUND to maintain compatibility with existing behavior
		// AT operations will need to be handled differently in a future iteration
		cc.emitter.EmitOpcode(OP_FOUND, ident.Pos.Line, ident.Pos.Column)
		return nil
	}

	// Check if it's an external variable
	if index, exists := cc.externalVariables[ident.Name]; exists {
		// Emit external variable load opcode
		// The interpreter will handle loading the actual value from runtime context
		cc.emitter.EmitOpcodeWithOperand(OP_PUSH_M, Operand{Type: OperandImmediate32, Value: uint64(index)}, ident.Pos.Line, ident.Pos.Column)
		return nil
	}

	// Check if it's a variable
	if index, exists := cc.variableMap[ident.Name]; exists {
		// Safe conversion with overflow check
		if index < 0 {
			cc.emitter.EmitOpcodeWithOperand(OP_OBJ_LOAD, Operand{Type: OperandImmediate32, Value: uint64(0)}, ident.Pos.Line, ident.Pos.Column)
		} else {
			// Safe conversion with explicit truncation
			cc.emitter.EmitOpcodeWithOperand(OP_OBJ_LOAD, Operand{Type: OperandImmediate32, Value: uint64(index)}, ident.Pos.Line, ident.Pos.Column)
		}
		return nil
	}

	// Check for rule identifiers - these should be handled by the interpreter
	// Rule identifiers evaluate to boolean based on whether the rule matches
	// Check if this identifier is a rule name in our rule index map
	if ruleIndex, exists := cc.ruleIndexMap[ident.Name]; exists {
		// Emit rule reference using the proper opcode
		cc.emitter.EmitOpcodeWithOperand(OP_PUSH_RULE, Operand{Type: OperandImmediate8, Value: uint64(ruleIndex)}, ident.Pos.Line, ident.Pos.Column)
		return nil
	}

	// Check for special identifiers
	switch ident.Name {
	case "filesize":
		cc.emitter.EmitOpcode(OP_FILESIZE, ident.Pos.Line, ident.Pos.Column)
	case "entrypoint":
		cc.emitter.EmitOpcode(OP_ENTRYPOINT, ident.Pos.Line, ident.Pos.Column)
	case "them":
		// "them" is used in quantifier expressions like "any of them"
		// In YARA, "them" refers to all strings in the current rule
		// Emit a reference to all strings in the current rule
		cc.emitter.EmitOpcode(OP_PUSH_M, ident.Pos.Line, ident.Pos.Column)
		cc.emitter.EmitPush(0, ident.Pos.Line, ident.Pos.Column) // Will be replaced with string count by interpreter
	case "flags":
		// YARA builtin variable that contains PE header flags
		// This should be implemented as a module import in the future
		// For now, emit a placeholder value of 0
		cc.emitter.EmitPush(0, ident.Pos.Line, ident.Pos.Column)
	case QuantifierAny, QuantifierAll, QuantifierNone:
		// Quantifier keywords used in expressions like "any of them"
		// These are handled as part of the OF operation, so just push a placeholder
		cc.emitter.EmitOpcode(OP_PUSH_8, ident.Pos.Line, ident.Pos.Column)

	default:
		// Check if this might be a module function (e.g., pe.section, cuckoo.sync)
		if cc.isModuleFunction(ident.Name) {
			// Emit module function call bytecode
			cc.emitModuleFunctionCall(ident.Name, ident.Pos.Line, ident.Pos.Column)
			return nil
		}

		// For undefined identifiers, we should emit OP_PUSH_U and return an error
		// This allows the interpreter to handle undefined values properly
		cc.emitter.EmitOpcode(OP_PUSH_U, ident.Pos.Line, ident.Pos.Column)
		return fmt.Errorf("undefined identifier: %s", ident.Name)
	}

	return nil
}

// compileStringOffsetOperator handles AT and IN operators that require string identifiers
func (cc *ConditionCompiler) compileStringOffsetOperator(binOp *ast.BinaryOp) error {
	// Check if left operand is a string identifier
	if id, ok := binOp.Left.(*ast.Identifier); ok {
		if offset, exists := cc.findStringOffset(id.Name); exists {
			// Push string identifier as ValueTypeString
			cc.emitStringIdentifier(offset, id.Name, binOp.Pos.Line, binOp.Pos.Column)
			// Compile right operand (offset or range expression)
			if err := cc.compileExpression(binOp.Right); err != nil {
				return err
			}
			// Emit appropriate opcode
			var opcode Opcode
			switch binOp.Op {
			case token.AT:
				opcode = OP_FOUND_AT
			case token.IN:
				opcode = OP_FOUND_IN
			}
			cc.emitter.EmitOpcode(opcode, binOp.Pos.Line, binOp.Pos.Column)
			return nil
		}
		return fmt.Errorf("undefined string identifier: %s", id.Name)
	}

	operatorName := "AT"
	if binOp.Op == token.IN {
		operatorName = "IN"
	}
	return fmt.Errorf("%s operator requires string identifier as left operand", operatorName)
}

// isFloatExpression checks if an expression contains floating point literals
func (cc *ConditionCompiler) isFloatExpression(expr ast.Expression) bool {
	switch e := expr.(type) {
	case *ast.Literal:
		return e.Type == token.FLOAT_LIT
	case *ast.BinaryOp:
		// Recursively check both operands
		return cc.isFloatExpression(e.Left) || cc.isFloatExpression(e.Right)
	case *ast.UnaryOp:
		// Recursively check the operand
		return cc.isFloatExpression(e.Right)
	default:
		// For other expression types (identifiers, function calls, etc.),
		// we can't determine the type at compile time, so default to integer
		return false
	}
}

// isLiteralFloat checks if an expression is a floating point literal
func (cc *ConditionCompiler) isLiteralFloat(expr ast.Expression) bool {
	if lit, ok := expr.(*ast.Literal); ok {
		return lit.Type == token.FLOAT_LIT
	}
	if unaryOp, ok := expr.(*ast.UnaryOp); ok && unaryOp.Op == token.MINUS {
		// Check if this is a unary negation of a float literal
		return cc.isLiteralFloat(unaryOp.Right)
	}
	return false
}

// isMixedTypeComparison checks if a comparison involves mixed types (int vs float)
func (cc *ConditionCompiler) isMixedTypeComparison(leftIsFloat, rightIsFloat bool) bool {
	return leftIsFloat != rightIsFloat
}

// isComparisonOperator checks if the operator is a comparison operation
func (cc *ConditionCompiler) isComparisonOperator(op token.TokenType) bool {
	return op == token.EQ || op == token.NEQ ||
		op == token.LT || op == token.LE ||
		op == token.GT || op == token.GE ||
		op == token.LEFT_SHIFT || op == token.RIGHT_SHIFT ||
		op == token.MODULO
}

// isNonCommutativeOperator checks if the operator requires specific operand order
func (cc *ConditionCompiler) isNonCommutativeOperator(op token.TokenType) bool {
	return op == token.MINUS || op == token.DIVIDE
}

// compileOperands compiles the operands in the appropriate order
func (cc *ConditionCompiler) compileOperands(binOp *ast.BinaryOp) error {
	isComparison := cc.isComparisonOperator(binOp.Op)
	isNonCommutative := cc.isNonCommutativeOperator(binOp.Op)

	if isComparison || isNonCommutative {
		// Compile left operand first for comparisons and non-commutative operations
		return cc.compileExpressions(binOp.Left, binOp.Right)
	}
	// Compile right operand first for commutative operations (for stack-based evaluation)
	return cc.compileExpressions(binOp.Right, binOp.Left)
}

// handleBitShiftFloatConversion handles float-to-int conversion for bit shift operations
func (cc *ConditionCompiler) handleBitShiftFloatConversion(binOp *ast.BinaryOp, leftIsFloat, rightIsFloat, isComparison bool) {
	if isComparison {
		// For bit shifts, we compiled left then right (treated as comparison)
		// Stack order after compilation: [left, right]
		if leftIsFloat {
			// Left is float - need to convert left (second on stack)
			cc.emitter.EmitOpcode(OP_SWAPUNDEF, binOp.Pos.Line, binOp.Pos.Column)
			// Convert float to int (truncate)
			cc.emitter.EmitOpcode(OP_INT_TO_DBL, binOp.Pos.Line, binOp.Pos.Column) // This is actually DBL_TO_INT, but we don't have that opcode
			cc.emitter.EmitOpcode(OP_SWAPUNDEF, binOp.Pos.Line, binOp.Pos.Column)
		}
		if rightIsFloat {
			// Right is float - need to convert right (top of stack)
			// Convert float to int (truncate)
			// Note: YARA doesn't have a direct float-to-int conversion, so this is a limitation
			_ = rightIsFloat // Suppress unused parameter warning - placeholder for future implementation
		}
	}
}

// handleMixedTypeLiteralComparison handles literal comparisons between different types
func (cc *ConditionCompiler) handleMixedTypeLiteralComparison(binOp *ast.BinaryOp) bool {
	if cc.isLiteralFloat(binOp.Left) || cc.isLiteralFloat(binOp.Right) {
		// For literal comparisons, YARA treats different types as unequal
		// So: 1 == 1.0 is false, 1 != 1.0 is true regardless of numeric value
		var result int64 // Default to false for equality
		if binOp.Op == token.NEQ {
			result = 1 // Mixed types are always unequal
		}
		// Replace the comparison with a constant result
		cc.emitter.EmitPush(uint64(result), binOp.Pos.Line, binOp.Pos.Column)
		return true
	}
	return false
}

// convertForMixedTypeComparison handles type conversion for mixed-type comparisons
func (cc *ConditionCompiler) convertForMixedTypeComparison(binOp *ast.BinaryOp, leftIsFloat, rightIsFloat, isComparison bool) {
	if isComparison {
		// For comparisons, we compiled left then right
		// Stack order after compilation: [left, right]
		if leftIsFloat && !rightIsFloat {
			// Left is float, right is int - convert right to double
			cc.emitter.EmitOpcode(OP_INT_TO_DBL, binOp.Pos.Line, binOp.Pos.Column)
		} else if !leftIsFloat && rightIsFloat {
			// Left is int, right is float - convert left to double
			cc.emitter.EmitOpcode(OP_SWAPUNDEF, binOp.Pos.Line, binOp.Pos.Column)
			cc.emitter.EmitOpcode(OP_INT_TO_DBL, binOp.Pos.Line, binOp.Pos.Column)
			cc.emitter.EmitOpcode(OP_SWAPUNDEF, binOp.Pos.Line, binOp.Pos.Column)
		}
	}
}

// convertForMixedTypeArithmetic handles type conversion for mixed-type arithmetic
func (cc *ConditionCompiler) convertForMixedTypeArithmetic(binOp *ast.BinaryOp, leftIsFloat, rightIsFloat, isComparison bool) {
	if isComparison {
		// For comparisons, we compiled left then right
		// Stack order after compilation: [left, right]
		if leftIsFloat && !rightIsFloat {
			// Left is float, right is int - need to convert right (top of stack)
			cc.emitter.EmitOpcode(OP_INT_TO_DBL, binOp.Pos.Line, binOp.Pos.Column)
		} else if !leftIsFloat && rightIsFloat {
			// Left is int, right is float - need to convert left (second on stack)
			// This requires swapping, converting, then swapping back
			cc.emitter.EmitOpcode(OP_SWAPUNDEF, binOp.Pos.Line, binOp.Pos.Column)
			cc.emitter.EmitOpcode(OP_INT_TO_DBL, binOp.Pos.Line, binOp.Pos.Column)
			cc.emitter.EmitOpcode(OP_SWAPUNDEF, binOp.Pos.Line, binOp.Pos.Column)
		}
	} else {
		// For arithmetic, we compiled right then left
		// Stack order after compilation: [right, left]
		if leftIsFloat && !rightIsFloat {
			// Left is float, right is int - need to convert right (bottom of stack)
			// This requires swapping, converting, then swapping back
			cc.emitter.EmitOpcode(OP_SWAPUNDEF, binOp.Pos.Line, binOp.Pos.Column)
			cc.emitter.EmitOpcode(OP_INT_TO_DBL, binOp.Pos.Line, binOp.Pos.Column)
			cc.emitter.EmitOpcode(OP_SWAPUNDEF, binOp.Pos.Line, binOp.Pos.Column)
		} else if !leftIsFloat && rightIsFloat {
			// Left is int, right is float - need to convert left (top of stack)
			cc.emitter.EmitOpcode(OP_INT_TO_DBL, binOp.Pos.Line, binOp.Pos.Column)
		}
	}
}

// handleFloatOperations handles type conversion and special cases for float operations
func (cc *ConditionCompiler) handleFloatOperations(binOp *ast.BinaryOp, leftIsFloat, rightIsFloat, isComparison bool) error {
	isFloatOp := leftIsFloat || rightIsFloat

	if !isFloatOp {
		return nil
	}

	if binOp.Op == token.LEFT_SHIFT || binOp.Op == token.RIGHT_SHIFT {
		// For bit shift operations, both operands should be integers
		cc.handleBitShiftFloatConversion(binOp, leftIsFloat, rightIsFloat, isComparison)
	} else if cc.isMixedTypeComparison(leftIsFloat, rightIsFloat) && (binOp.Op == token.EQ || binOp.Op == token.NEQ) {
		// For mixed-type equality/inequality comparisons, check if we can determine at compile time
		if cc.handleMixedTypeLiteralComparison(binOp) {
			return nil
		}
		// For non-literal mixed types (expressions), do runtime type conversion
		cc.convertForMixedTypeComparison(binOp, leftIsFloat, rightIsFloat, isComparison)
	} else {
		// For regular arithmetic and comparison operations, convert integer to double
		cc.convertForMixedTypeArithmetic(binOp, leftIsFloat, rightIsFloat, isComparison)
	}

	return nil
}

// selectOpcode selects the appropriate opcode based on the operator and operand types
func (cc *ConditionCompiler) selectOpcode(binOp *ast.BinaryOp, isFloatOp bool) (Opcode, error) {
	switch binOp.Op {
	case token.AND:
		return OP_AND, nil
	case token.OR:
		return OP_OR, nil
	case token.PLUS:
		if isFloatOp {
			return OP_DBL_ADD, nil
		}
		return OP_INT_ADD, nil
	case token.MINUS:
		if isFloatOp {
			return OP_DBL_SUB, nil
		}
		return OP_INT_SUB, nil
	case token.MULTIPLY:
		if isFloatOp {
			return OP_DBL_MUL, nil
		}
		return OP_INT_MUL, nil
	case token.DIVIDE:
		if isFloatOp {
			return OP_DBL_DIV, nil
		}
		return OP_INT_DIV, nil
	case token.MODULO:
		return OP_MOD, nil
	case token.BITWISE_AND:
		return OP_BITWISE_AND, nil
	case token.BITWISE_OR:
		return OP_BITWISE_OR, nil
	case token.BITWISE_XOR:
		return OP_BITWISE_XOR, nil
	case token.LEFT_SHIFT:
		return OP_SHL, nil
	case token.RIGHT_SHIFT:
		return OP_SHR, nil
	case token.EQ:
		if isFloatOp {
			return OP_DBL_EQ, nil
		}
		return OP_INT_EQ, nil
	case token.NEQ:
		if isFloatOp {
			return OP_DBL_NEQ, nil
		}
		return OP_INT_NEQ, nil
	case token.LT:
		if isFloatOp {
			return OP_DBL_LT, nil
		}
		return OP_INT_LT, nil
	case token.LE:
		if isFloatOp {
			return OP_DBL_LE, nil
		}
		return OP_INT_LE, nil
	case token.GT:
		if isFloatOp {
			return OP_DBL_GT, nil
		}
		return OP_INT_GT, nil
	case token.GE:
		if isFloatOp {
			return OP_DBL_GE, nil
		}
		return OP_INT_GE, nil
	case token.CONTAINS:
		return OP_CONTAINS, nil
	case token.MATCHES:
		return OP_MATCHES, nil
	case token.OF:
		return OP_OF, nil
	default:
		return 0, fmt.Errorf("unsupported binary operator: %s", binOp.Op)
	}
}

// handleSpecialOperators handles operators with special compilation requirements
func (cc *ConditionCompiler) handleSpecialOperators(binOp *ast.BinaryOp) error {
	switch binOp.Op {
	case token.AT, token.IN:
		// Handle AT and IN operators with string identifier logic
		return cc.compileStringOffsetOperator(binOp)
	case token.DOT:
		// DOT operator represents range expression: start..end
		// For range expressions, we need to push both start and end values
		// The OP_FOUND_IN expects: [end, start, string_identifier] on stack
		// Since this is the right operand of IN, we compile left then right (end then start)
		if err := cc.compileExpressions(binOp.Left, binOp.Right); err != nil {
			return err
		}
		// No opcode needed - the range values are pushed for OP_FOUND_IN
		return nil
	}
	return nil
}

// compileBinaryOp compiles a binary operation with appropriate type handling
func (cc *ConditionCompiler) compileBinaryOp(binOp *ast.BinaryOp) error {
	// Handle special operators first
	if err := cc.handleSpecialOperators(binOp); err != nil {
		return err
	}

	// Compile operands in appropriate order
	if err := cc.compileOperands(binOp); err != nil {
		return err
	}

	// Check operand types
	leftIsFloat := cc.isFloatExpression(binOp.Left)
	rightIsFloat := cc.isFloatExpression(binOp.Right)
	isComparison := cc.isComparisonOperator(binOp.Op)
	isFloatOp := leftIsFloat || rightIsFloat

	// Handle float operations and type conversion
	if err := cc.handleFloatOperations(binOp, leftIsFloat, rightIsFloat, isComparison); err != nil {
		return err
	}

	// Select and emit appropriate opcode
	opcode, err := cc.selectOpcode(binOp, isFloatOp)
	if err != nil {
		return err
	}

	cc.emitter.EmitOpcode(opcode, binOp.Pos.Line, binOp.Pos.Column)
	return nil
}

// compileUnaryOp compiles a unary operation
func (cc *ConditionCompiler) compileUnaryOp(unaryOp *ast.UnaryOp) error {
	// Special handling for position/count and other YARA-specific unary ops
	switch unaryOp.Op {
	case token.HASH:
		// '#' COUNT operator: expects a string identifier operand (e.g., #$a)
		if id, ok := unaryOp.Right.(*ast.Identifier); ok {
			if offset, exists := cc.findStringOffset(id.Name); exists {
				cc.emitStringOffset(offset, unaryOp.Pos.Line, unaryOp.Pos.Column)
				cc.emitter.EmitOpcode(OP_COUNT, unaryOp.Pos.Line, unaryOp.Pos.Column)
				return nil
			}
			return fmt.Errorf("undefined string identifier for count operator: %s", id.Name)
		}
		return errors.New("COUNT (#) expects a string identifier operand")
	case token.AT:
		// '@' OFFSET operator: expects a string identifier operand (e.g., @$a)
		// Semantics: offset of first match => index = 1
		if id, ok := unaryOp.Right.(*ast.Identifier); ok {
			if offset, exists := cc.findStringOffset(id.Name); exists {
				// OP_OFFSET expects stack: [pattern_name, index] -> [offset]
				cc.emitStringOffset(offset, unaryOp.Pos.Line, unaryOp.Pos.Column)
				cc.emitter.EmitPush(1, unaryOp.Pos.Line, unaryOp.Pos.Column)
				cc.emitter.EmitOpcode(OP_OFFSET, unaryOp.Pos.Line, unaryOp.Pos.Column)
				return nil
			}
			return fmt.Errorf("undefined string identifier for position operator: %s", id.Name)
		}
		return errors.New("POSITION (@) expects a string identifier operand")
	case token.NOT:
		// Check if this is actually a '!' string length operator
		// In YARA, '!' before a string identifier means string length
		if id, ok := unaryOp.Right.(*ast.Identifier); ok {
			if offset, exists := cc.findStringOffset(id.Name); exists {
				// OP_LENGTH expects stack: [pattern_name] -> [length]
				cc.emitStringOffset(offset, unaryOp.Pos.Line, unaryOp.Pos.Column)
				cc.emitter.EmitOpcode(OP_LENGTH, unaryOp.Pos.Line, unaryOp.Pos.Column)
				return nil
			}
			return fmt.Errorf("undefined string identifier for length operator: %s", id.Name)
		}
		// Fall through to generic stack-based NOT after compiling operand
		if err := cc.compileExpression(unaryOp.Right); err != nil {
			return err
		}
		cc.emitter.EmitOpcode(OP_NOT, unaryOp.Pos.Line, unaryOp.Pos.Column)
		return nil
	case token.BITWISE_NOT:
		if err := cc.compileExpression(unaryOp.Right); err != nil {
			return err
		}
		cc.emitter.EmitOpcode(OP_BITWISE_NOT, unaryOp.Pos.Line, unaryOp.Pos.Column)
		return nil
	case token.MINUS:
		// Use appropriate opcode based on operand type
		if cc.isLiteralFloat(unaryOp.Right) {
			// For floating point literals, use double minus
			if err := cc.compileExpression(unaryOp.Right); err != nil {
				return err
			}
			cc.emitter.EmitOpcode(OP_DBL_MINUS, unaryOp.Pos.Line, unaryOp.Pos.Column)
		} else {
			// For integers and other types, use integer minus
			if err := cc.compileExpression(unaryOp.Right); err != nil {
				return err
			}
			cc.emitter.EmitOpcode(OP_INT_MINUS, unaryOp.Pos.Line, unaryOp.Pos.Column)
		}
		return nil
	case token.DEFINED:
		// defined() operator - check if identifier is defined
		if err := cc.compileExpression(unaryOp.Right); err != nil {
			return err
		}
		cc.emitter.EmitOpcode(OP_DEFINED, unaryOp.Pos.Line, unaryOp.Pos.Column)
		return nil
	default:
		return fmt.Errorf("unsupported unary operator: %s", unaryOp.Op)
	}
}

// compileArrayIndex compiles an array indexing expression (e.g., @string[i], #string[i])
func (cc *ConditionCompiler) compileArrayIndex(arrayIndex *ast.ArrayIndex) error {
	// Check if the array expression is a unary operation (@ or #)
	unaryOp, ok := arrayIndex.Array.(*ast.UnaryOp)
	if !ok {
		return errors.New("array indexing requires @ or # operator")
	}

	// Compile the index expression first
	if err := cc.compileExpression(arrayIndex.Index); err != nil {
		return err
	}

	// Handle both @string[i] (offset of ith match) and #string[i] (length of ith match)
	if unaryOp.Op == token.AT || unaryOp.Op == token.HASH {
		// Get the string identifier
		ident, isIdent := unaryOp.Right.(*ast.Identifier)
		if !isIdent {
			if unaryOp.Op == token.AT {
				return errors.New("@ operator expects a string identifier")
			}
			return errors.New("# operator expects a string identifier")
		}

		if offset, hasOffset := cc.stringOffsets[ident.Name]; hasOffset {
			// Push the string identifier from memory
			cc.emitter.EmitOpcodeWithOperand(OP_PUSH_M, Operand{Type: OperandImmediate64, Value: uint64(offset)}, arrayIndex.Pos.Line, arrayIndex.Pos.Column)

			// Push a marker to indicate the operation type
			var marker int64
			if unaryOp.Op == token.AT {
				marker = 0 // 0 = offset
			} else {
				marker = 1 // 1 = length
			}
			cc.emitter.EmitPush(uint64(marker), arrayIndex.Pos.Line, arrayIndex.Pos.Column)

			// Emit INDEX_ARRAY to perform the indexing operation
			cc.emitter.EmitOpcode(OP_INDEX_ARRAY, arrayIndex.Pos.Line, arrayIndex.Pos.Column)
			return nil
		}
		return fmt.Errorf("undefined string identifier: %s", ident.Name)
	}

	return fmt.Errorf("unsupported operator for array indexing: %s", unaryOp.Op)
}

// AddVariable adds a variable to the variable map
func (cc *ConditionCompiler) AddVariable(name string, index int) {
	cc.variableMap[name] = index
}

// GetVariableIndex returns the index of a variable
func (cc *ConditionCompiler) GetVariableIndex(name string) (int, bool) {
	index, exists := cc.variableMap[name]
	return index, exists
}

// ConditionalJumpConfig holds configuration for conditional jump instruction emission
type ConditionalJumpConfig struct {
	Opcode      Opcode
	TargetLabel string
	Position    JumpPosition
}

// EmitJump emits a jump instruction with label management
func (cc *ConditionCompiler) EmitJump(config ConditionalJumpConfig) error {
	cc.emitJumpWithLabel(config.Opcode, config.TargetLabel, config.Position)
	return nil
}

// CompileBooleanExpression compiles a boolean expression with short-circuit evaluation
func (cc *ConditionCompiler) CompileBooleanExpression(expr ast.Expression, shortCircuit bool) error {
	if !shortCircuit {
		return cc.compileExpression(expr)
	}

	// For short-circuit evaluation, we need to handle AND/OR specially
	binOp, ok := expr.(*ast.BinaryOp)
	if ok {
		switch binOp.Op {
		case token.AND:
			return cc.compileShortCircuitAnd(binOp)
		case token.OR:
			return cc.compileShortCircuitOr(binOp)
		}
	}

	return cc.compileExpression(expr)
}

// compileShortCircuitBinary compiles binary operations with short-circuit evaluation
func (cc *ConditionCompiler) compileShortCircuitBinary(binOp *ast.BinaryOp, jumpOpcode, resultOpcode Opcode) error {
	// Compile left operand
	if err := cc.compileExpression(binOp.Left); err != nil {
		return err
	}

	// Generate labels for short-circuit
	endLabel := cc.generateLabel()

	// Emit jump for short-circuit to end label
	position := JumpPosition{Line: binOp.Pos.Line, Column: binOp.Pos.Column}
	cc.emitJumpWithLabel(jumpOpcode, endLabel, position)

	// Compile right operand
	if err := cc.compileExpression(binOp.Right); err != nil {
		return err
	}

	// Define the end label
	cc.defineLabel(endLabel)

	// Emit result operation
	cc.emitter.EmitOpcode(resultOpcode, binOp.Pos.Line, binOp.Pos.Column)

	return nil
}

// compileShortCircuitAnd compiles AND with short-circuit evaluation
func (cc *ConditionCompiler) compileShortCircuitAnd(andOp *ast.BinaryOp) error {
	return cc.compileShortCircuitBinary(andOp, OP_JFALSE, OP_AND)
}

// compileShortCircuitOr compiles OR with short-circuit evaluation
func (cc *ConditionCompiler) compileShortCircuitOr(orOp *ast.BinaryOp) error {
	return cc.compileShortCircuitBinary(orOp, OP_JTRUE, OP_OR)
}

// GetVariableMap returns the variable map
func (cc *ConditionCompiler) GetVariableMap() map[string]int {
	return cc.variableMap
}

// GetExternalVariables returns the external variables map
func (cc *ConditionCompiler) GetExternalVariables() map[string]int {
	return cc.externalVariables
}

// SetStringOffsets sets the string offsets map
func (cc *ConditionCompiler) SetStringOffsets(offsets map[string]int) {
	cc.stringOffsets = offsets
}

// GetStats returns compilation statistics
func (cc *ConditionCompiler) GetStats() map[string]any {
	stats := make(map[string]any)

	stats["variables"] = len(cc.variableMap)
	stats["label_counter"] = cc.labelCounter

	return stats
}

// ValidateExpression validates that an expression can be compiled
func (cc *ConditionCompiler) ValidateExpression(expr ast.Expression) error {
	// This would perform semantic validation of the expression
	// For now, just try to compile it and return any errors
	savedEmitter := cc.emitter
	cc.emitter = NewEmitter()

	err := cc.compileExpression(expr)

	cc.emitter = savedEmitter
	return err
}

// OptimizeExpression optimizes an expression for better bytecode generation
func (cc *ConditionCompiler) OptimizeExpression(expr ast.Expression) ast.Expression {
	// This would perform various optimizations:
	// - Constant folding
	// - Dead code elimination
	// - Strength reduction
	// For now, return the expression as-is
	return expr
}

// EstimateComplexity estimates the complexity of an expression
func (cc *ConditionCompiler) EstimateComplexity(expr ast.Expression) int {
	complexity := 0

	switch e := expr.(type) {
	case *ast.Literal:
		complexity = 1
	case *ast.Identifier:
		complexity = 2
	case *ast.BinaryOp:
		complexity = cc.EstimateComplexity(e.Left) + cc.EstimateComplexity(e.Right) + 1
	case *ast.UnaryOp:
		complexity = cc.EstimateComplexity(e.Right) + 1
	}

	return complexity
}

// Debug printing functions

// PrintExpression prints a human-readable representation of an expression
func (cc *ConditionCompiler) PrintExpression(expr ast.Expression) {
	cc.printExpressionRecursive(expr, 0)
}

func (cc *ConditionCompiler) printExpressionRecursive(expr ast.Expression, depth int) {
	indent := ""
	var indentSb904 strings.Builder
	for range depth {
		indentSb904.WriteString("  ")
	}
	indent += indentSb904.String()

	switch e := expr.(type) {
	case *ast.Literal:
		fmt.Printf("%sLiteral(%s: %v)\n", indent, e.Type, e.Value)
	case *ast.Identifier:
		fmt.Printf("%sIdentifier(%s)\n", indent, e.Name)
	case *ast.BinaryOp:
		fmt.Printf("%sBinaryOp(%s)\n", indent, e.Op)
		cc.printExpressionRecursive(e.Left, depth+1)
		cc.printExpressionRecursive(e.Right, depth+1)
	case *ast.UnaryOp:
		fmt.Printf("%sUnaryOp(%s)\n", indent, e.Op)
		cc.printExpressionRecursive(e.Right, depth+1)
	case *ast.OfExpression:
		fmt.Printf("%sOfExpression\n", indent)
		cc.printExpressionRecursive(e.Count, depth+1)
		cc.printExpressionRecursive(e.Strings, depth+1)
	}
}

// compileOfExpression compiles an "of" expression (e.g., "any of them", "1 of ($a, $b)")
func (cc *ConditionCompiler) compileOfExpression(ofExpr *ast.OfExpression) error {
	// Handle count expression (e.g., "any", "all", "none", "1", "2")
	switch countExpr := ofExpr.Count.(type) {
	case *ast.Identifier:
		switch countExpr.Name {
		case QuantifierAny:
			cc.emitter.EmitPush(1, countExpr.Pos.Line, countExpr.Pos.Column) // At least 1
		case QuantifierAll:
			// Will be replaced with total string count by interpreter
			cc.emitter.EmitOpcode(OP_PUSH_M, countExpr.Pos.Line, countExpr.Pos.Column)
		case QuantifierNone:
			cc.emitter.EmitPush(0, countExpr.Pos.Line, countExpr.Pos.Column) // 0 matches
		default:
			// Regular identifier, compile normally
			if err := cc.compileExpression(ofExpr.Count); err != nil {
				return fmt.Errorf("compiling count expression in of-expression: %w", err)
			}
		}
	default:
		// Regular expression, compile normally
		if err := cc.compileExpression(ofExpr.Count); err != nil {
			return fmt.Errorf("compiling count expression in of-expression: %w", err)
		}
	}

	// Handle strings expression (e.g., "them", "($a, $b)")
	switch stringsExpr := ofExpr.Strings.(type) {
	case *ast.Identifier:
		if stringsExpr.Name == "them" {
			// "them" refers to all strings in the current rule
			// Emit a reference to all strings
			cc.emitter.EmitOpcode(OP_PUSH_M, stringsExpr.Pos.Line, stringsExpr.Pos.Column)
			cc.emitter.EmitPush(0, stringsExpr.Pos.Line, stringsExpr.Pos.Column) // Placeholder for string count
		} else if cc.isRuleReference(stringsExpr.Name) {
			// This is a rule reference (e.g., "none of (a)" where "a" is a rule)
			// Compile as a proper rule reference
			if err := cc.compileRuleReference(stringsExpr.Name, stringsExpr.Pos.Line, stringsExpr.Pos.Column); err != nil {
				return fmt.Errorf("compiling rule reference '%s': %w", stringsExpr.Name, err)
			}
		} else {
			// Regular identifier, compile normally
			if err := cc.compileExpression(ofExpr.Strings); err != nil {
				return fmt.Errorf("compiling strings expression in of-expression: %w", err)
			}
		}
	default:
		// Regular expression, compile normally
		if err := cc.compileExpression(ofExpr.Strings); err != nil {
			return fmt.Errorf("compiling strings expression in of-expression: %w", err)
		}
	}

	// Emit OP_OF opcode
	cc.emitter.EmitOpcode(OP_OF, ofExpr.Pos.Line, ofExpr.Pos.Column)
	return nil
}

// compileFunctionCall compiles a function call expression (e.g., "uint32(0)", "int16be(10)")
func (cc *ConditionCompiler) compileFunctionCall(call *ast.FunctionCall) error {
	// Compile function arguments first (in reverse order for stack-based evaluation)
	for i := len(call.Args) - 1; i >= 0; i-- {
		if err := cc.compileExpression(call.Args[i]); err != nil {
			return fmt.Errorf("compiling function argument %d: %w", i, err)
		}
	}

	// Map function names to opcodes
	var opcode Opcode
	switch call.Function {
	case "uint8":
		opcode = OP_UINT8
	case "uint16":
		opcode = OP_UINT16
	case "uint32":
		opcode = OP_UINT32
	case "uint8be":
		opcode = OP_UINT8BE
	case "uint16be":
		opcode = OP_UINT16BE
	case "uint32be":
		opcode = OP_UINT32BE
	case "int8":
		opcode = OP_INT8
	case "int16":
		opcode = OP_INT16
	case "int32":
		opcode = OP_INT32
	case "int8be":
		opcode = OP_INT8BE
	case "int16be":
		opcode = OP_INT16BE
	case "int32be":
		opcode = OP_INT32BE
	case "concat":
		opcode = OP_CONCAT
	default:
		return fmt.Errorf("unsupported function: %s", call.Function)
	}

	// Emit the function call opcode
	cc.emitter.EmitOpcode(opcode, call.Pos.Line, call.Pos.Column)
	return nil
}

// isRuleReference checks if the given identifier refers to a rule in the current compilation
func (cc *ConditionCompiler) isRuleReference(name string) bool {
	// Check if this identifier refers to a rule using the rule index map
	_, exists := cc.ruleIndexMap[name]
	return exists
}

// compileRuleReference compiles a rule reference for dependency operations
func (cc *ConditionCompiler) compileRuleReference(ruleName string, line, column int) error {
	// Check if this is actually a rule reference
	if !cc.isRuleReference(ruleName) {
		return fmt.Errorf("undefined rule reference: %s", ruleName)
	}

	// Find the rule index in the rule index map
	ruleIndex, exists := cc.ruleIndexMap[ruleName]
	if !exists {
		return fmt.Errorf("rule '%s' not found in compilation context", ruleName)
	}

	// Emit a special rule reference opcode instead of trying to push a string
	// This allows the interpreter to handle rule dependencies natively
	cc.emitter.EmitOpcodeWithOperand(OP_PUSH_RULE_REF,
		Operand{Type: OperandImmediate64, Value: uint64(ruleIndex)},
		line, column)

	return nil
}

// isModuleFunction checks if an identifier is a module function
func (cc *ConditionCompiler) isModuleFunction(name string) bool {
	// List of known module functions
	moduleFunctions := []string{
		// PE module functions
		"pe.machine", "pe.sections", "pe.entry_point", "pe.characteristics",
		"pe.subsystem", "pe.dll_name", "pe.exports", "pe.imports",
		"pe.version", "pe.timestamp", "pe.linked_modules",

		// Cuckoo module functions
		"cuckoo.sync", "cuckoo.file", "cuckoo.network", "cuckoo.registry",
		"cuckoo.process", "cuckoo.api", "cuckoo.behavior", "cuckoo.strings",

		// Other common modules
		"hash.md5", "hash.sha1", "hash.sha256", "hash.ssdeep",
		"elf", "macho", "dotnet", "text",
	}

	// Check if the identifier contains a dot (module.function)
	if strings.Contains(name, ".") {
		parts := strings.Split(name, ".")
		if len(parts) == 2 {
			moduleName := parts[0]
			functionName := parts[1]

			// Check if module is known
			for _, module := range moduleFunctions {
				if strings.HasPrefix(module, moduleName+".") {
					return true
				}
			}

			// Check if function is known for any module
			if slices.Contains(moduleFunctions, functionName) {
				return true
			}
		}
	}

	return false
}

// emitModuleFunctionCall emits bytecode for a module function call
func (cc *ConditionCompiler) emitModuleFunctionCall(name string, line, column int) {
	// For now, emit a placeholder value that matches the expected return type
	// In a full implementation, this would:
	// 1. Look up the module in a registry
	// 2. Call the module function with appropriate arguments
	// 3. Handle the return value

	// Common module function return types (approximated):
	switch name {
	case "pe.machine", "pe.sections", "pe.entry_point", "pe.characteristics",
		"pe.subsystem", "pe.dll_name", "pe.exports", "pe.imports",
		"pe.version", "pe.timestamp", "pe.linked_modules":
		// PE module functions typically return integer or string values
		cc.emitter.EmitPush(0, line, column) // Placeholder return value
	case "cuckoo.sync", "cuckoo.file", "cuckoo.network", "cuckoo.registry",
		"cuckoo.process", "cuckoo.api", "cuckoo.behavior", "cuckoo.strings":
		// Cuckoo module functions typically return boolean or structured data
		cc.emitter.EmitPush(0, line, column) // Placeholder return value
	case "hash.md5", "hash.sha1", "hash.sha256", "hash.ssdeep":
		// Hash functions return strings
		cc.emitter.EmitPush(0, line, column) // Placeholder hash length
	default:
		// Unknown module function, emit undefined
		cc.emitter.EmitOpcode(OP_PUSH_U, line, column)
	}
}

// compileStringLength compiles a string length expression (!string)
func (cc *ConditionCompiler) compileStringLength(strLen *ast.StringLength) error {
	// Compile the string identifier
	if err := cc.compileExpression(strLen.String); err != nil {
		return err
	}

	// Emit the OP_LENGTH opcode
	cc.emitter.EmitOpcode(OP_LENGTH, strLen.Pos.Line, strLen.Pos.Column)
	return nil
}
