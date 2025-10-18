// Package compiler provides bytecode generation and compilation for YARA rules.
package compiler

import (
	"fmt"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

// ConditionCompiler handles compilation of conditions to bytecode
type ConditionCompiler struct {
	emitter       *Emitter
	stringOffsets map[string]int // String identifier to bytecode offset
	variableMap   map[string]int // Variable name to index
	labelCounter  int            // For generating unique labels
}

// NewConditionCompiler creates a new condition compiler
func NewConditionCompiler(emitter *Emitter, stringOffsets map[string]int) *ConditionCompiler {
	return &ConditionCompiler{
		emitter:       emitter,
		stringOffsets: stringOffsets,
		variableMap:   make(map[string]int),
		labelCounter:  0,
	}
}

// CompileCondition compiles a condition expression to bytecode
func (cc *ConditionCompiler) CompileCondition(condition *ast.Condition) error {
	return cc.compileExpression(condition.Expression)
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
	default:
		return fmt.Errorf("unsupported expression type")
	}
}

// compileLiteral compiles a literal value
func (cc *ConditionCompiler) compileLiteral(lit *ast.Literal) error {
	switch lit.Type {
	case token.INTEGER_LIT:
		if value, ok := lit.Value.(int64); ok {
			cc.emitter.EmitPush(uint64(value), lit.Pos.Line, lit.Pos.Column)
		}
	case token.STRING_LIT:
		if value, ok := lit.Value.(string); ok {
			// Push string length or reference
			cc.emitter.EmitPush(uint64(len(value)), lit.Pos.Line, lit.Pos.Column)
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
	// Check if it's a string identifier
	if offset, exists := cc.stringOffsets[ident.Name]; exists {
		// Push string offset and emit FOUND instruction
		cc.emitter.EmitPush(uint64(offset), ident.Pos.Line, ident.Pos.Column)
		cc.emitter.EmitOpcode(OP_FOUND, ident.Pos.Line, ident.Pos.Column)
		return nil
	}

	// Check if it's a variable
	if index, exists := cc.variableMap[ident.Name]; exists {
		cc.emitter.EmitOpcodeWithOperand(OP_OBJ_LOAD, Operand{Type: OperandImmediate32, Value: uint64(index)}, ident.Pos.Line, ident.Pos.Column)
		return nil
	}

	// Check for special identifiers
	switch ident.Name {
	case "filesize":
		cc.emitter.EmitOpcode(OP_FILESIZE, ident.Pos.Line, ident.Pos.Column)
	case "entrypoint":
		cc.emitter.EmitOpcode(OP_ENTRYPOINT, ident.Pos.Line, ident.Pos.Column)
	default:
		return fmt.Errorf("undefined identifier: %s", ident.Name)
	}

	return nil
}

// compileBinaryOp compiles a binary operation
func (cc *ConditionCompiler) compileBinaryOp(binOp *ast.BinaryOp) error {
	// Compile right operand first (for stack-based evaluation)
	if err := cc.compileExpression(binOp.Right); err != nil {
		return err
	}

	// Compile left operand
	if err := cc.compileExpression(binOp.Left); err != nil {
		return err
	}

	// Emit appropriate opcode based on operator
	var opcode Opcode
	switch binOp.Op {
	case token.AND:
		opcode = OP_AND
	case token.OR:
		opcode = OP_OR
	case token.PLUS:
		opcode = OP_INT_ADD
	case token.MINUS:
		opcode = OP_INT_SUB
	case token.MULTIPLY:
		opcode = OP_INT_MUL
	case token.DIVIDE:
		opcode = OP_INT_DIV
	case token.MODULO:
		opcode = OP_MOD
	case token.BITWISE_AND:
		opcode = OP_BITWISE_AND
	case token.BITWISE_OR:
		opcode = OP_BITWISE_OR
	case token.BITWISE_XOR:
		opcode = OP_BITWISE_XOR
	case token.LEFT_SHIFT:
		opcode = OP_SHL
	case token.RIGHT_SHIFT:
		opcode = OP_SHR
	case token.EQ:
		opcode = OP_INT_EQ
	case token.NEQ:
		opcode = OP_INT_NEQ
	case token.LT:
		opcode = OP_INT_LT
	case token.LE:
		opcode = OP_INT_LE
	case token.GT:
		opcode = OP_INT_GT
	case token.GE:
		opcode = OP_INT_GE
	case token.CONTAINS:
		opcode = OP_CONTAINS
	case token.MATCHES:
		opcode = OP_MATCHES
	default:
		return fmt.Errorf("unsupported binary operator: %s", binOp.Op)
	}

	cc.emitter.EmitOpcode(opcode, binOp.Pos.Line, binOp.Pos.Column)
	return nil
}

// compileUnaryOp compiles a unary operation
func (cc *ConditionCompiler) compileUnaryOp(unaryOp *ast.UnaryOp) error {
	// Compile the operand
	if err := cc.compileExpression(unaryOp.Right); err != nil {
		return err
	}

	// Emit appropriate opcode
	var opcode Opcode
	switch unaryOp.Op {
	case token.NOT:
		opcode = OP_NOT
	case token.BITWISE_NOT:
		opcode = OP_BITWISE_NOT
	case token.MINUS:
		opcode = OP_INT_MINUS
	default:
		return fmt.Errorf("unsupported unary operator: %s", unaryOp.Op)
	}

	cc.emitter.EmitOpcode(opcode, unaryOp.Pos.Line, unaryOp.Pos.Column)
	return nil
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

// generateLabel generates a unique label for jumps
func (cc *ConditionCompiler) generateLabel() string {
	cc.labelCounter++
	return fmt.Sprintf("L%d", cc.labelCounter)
}

// EmitJump emits a jump instruction with label management
func (cc *ConditionCompiler) EmitJump(opcode Opcode, targetLabel string, line, pos int) error {
	// For now, emit a placeholder jump
	// In a full implementation, this would manage label resolution
	cc.emitter.EmitOpcode(opcode, line, pos)
	return nil
}

// CompileBooleanExpression compiles a boolean expression with short-circuit evaluation
func (cc *ConditionCompiler) CompileBooleanExpression(expr ast.Expression, shortCircuit bool) error {
	if !shortCircuit {
		return cc.compileExpression(expr)
	}

	// For short-circuit evaluation, we need to handle AND/OR specially
	switch e := expr.(type) {
	case *ast.BinaryOp:
		if e.Op == token.AND {
			return cc.compileShortCircuitAnd(e)
		} else if e.Op == token.OR {
			return cc.compileShortCircuitOr(e)
		}
	}

	return cc.compileExpression(expr)
}

// compileShortCircuitAnd compiles AND with short-circuit evaluation
func (cc *ConditionCompiler) compileShortCircuitAnd(andOp *ast.BinaryOp) error {
	// Compile left operand
	if err := cc.compileExpression(andOp.Left); err != nil {
		return err
	}

	// Emit jump if false (short-circuit) - target will be fixed up later
	cc.emitter.EmitJump(OP_JFALSE, 0, andOp.Pos.Line, andOp.Pos.Column)

	// Compile right operand
	if err := cc.compileExpression(andOp.Right); err != nil {
		return err
	}

	// Emit AND operation
	cc.emitter.EmitOpcode(OP_AND, andOp.Pos.Line, andOp.Pos.Column)

	return nil
}

// compileShortCircuitOr compiles OR with short-circuit evaluation
func (cc *ConditionCompiler) compileShortCircuitOr(orOp *ast.BinaryOp) error {
	// Compile left operand
	if err := cc.compileExpression(orOp.Left); err != nil {
		return err
	}

	// Emit jump if true (short-circuit) - target will be fixed up later
	cc.emitter.EmitJump(OP_JTRUE, 0, orOp.Pos.Line, orOp.Pos.Column)

	// Compile right operand
	if err := cc.compileExpression(orOp.Right); err != nil {
		return err
	}

	// Emit OR operation
	cc.emitter.EmitOpcode(OP_OR, orOp.Pos.Line, orOp.Pos.Column)

	return nil
}

// GetVariableMap returns the variable map
func (cc *ConditionCompiler) GetVariableMap() map[string]int {
	return cc.variableMap
}

// SetStringOffsets sets the string offsets map
func (cc *ConditionCompiler) SetStringOffsets(offsets map[string]int) {
	cc.stringOffsets = offsets
}

// GetStats returns compilation statistics
func (cc *ConditionCompiler) GetStats() map[string]interface{} {
	stats := make(map[string]interface{})

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
	for i := 0; i < depth; i++ {
		indent += "  "
	}

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
	}
}