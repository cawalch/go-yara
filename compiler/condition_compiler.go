package compiler

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

// safeInt64ToUint64 safely converts int64 to uint64, handling negative values
func safeInt64ToUint64(value int64) uint64 {
	if value < 0 {
		return 0
	}
	return uint64(value)
}

// safeMax returns the maximum of two integers safely
func safeMax(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

type ConditionCompiler struct {
	emitter           *Emitter
	stringOffsets     map[string]int
	variableMap       map[string]int
	externalVariables map[string]int
	ruleIndexMap      map[string]int
	labelCounter      int
	labels            map[string]int
	pendingJumps      []PendingJump
}

func parseSizeLiteral(literal string) (int64, error) {
	re := regexp.MustCompile(`^(0x[0-9a-fA-F]+|\d+)(KB|MB|GB|TB)$`)
	matches := re.FindStringSubmatch(strings.TrimSpace(literal))
	if matches == nil {
		return 0, fmt.Errorf("invalid size literal format: %s", literal)
	}

	var num int64
	var err error
	if strings.HasPrefix(matches[1], "0x") {
		num, err = strconv.ParseInt(matches[1], 0, 64)
	} else {
		num, err = strconv.ParseInt(matches[1], 10, 64)
	}
	if err != nil {
		return 0, fmt.Errorf("invalid number in size literal: %s", matches[1])
	}

	sizeMultipliers := map[string]int64{
		"KB": 1024,
		"MB": 1024 * 1024,
		"GB": 1024 * 1024 * 1024,
		"TB": 1024 * 1024 * 1024 * 1024,
	}

	if multiplier, exists := sizeMultipliers[strings.ToUpper(matches[2])]; exists {
		return num * multiplier, nil
	}
	return 0, fmt.Errorf("unsupported size unit: %s", matches[2])
}

type PendingJump struct {
	Opcode       Opcode
	Label        string
	Position     int
	Line, Column int
}

func NewConditionCompiler(emitter *Emitter, stringOffsets map[string]int) *ConditionCompiler {
	return &ConditionCompiler{
		emitter:           emitter,
		stringOffsets:     stringOffsets,
		variableMap:       make(map[string]int),
		externalVariables: make(map[string]int),
		ruleIndexMap:      make(map[string]int),
		labels:            make(map[string]int),
		pendingJumps:      make([]PendingJump, 0),
	}
}

func (cc *ConditionCompiler) SetRuleIndexMap(ruleIndexMap map[string]int) {
	cc.ruleIndexMap = ruleIndexMap
}

func (cc *ConditionCompiler) generateLabel() string {
	cc.labelCounter++
	return fmt.Sprintf("L%d", cc.labelCounter)
}

func (cc *ConditionCompiler) defineLabel(label string) {
	cc.labels[label] = cc.emitter.GetLength()
}

func (cc *ConditionCompiler) emitJumpWithLabel(opcode Opcode, label string, line, column int) {
	pos := cc.emitter.GetLength()
	cc.pendingJumps = append(cc.pendingJumps, PendingJump{
		Opcode:   opcode,
		Label:    label,
		Position: pos,
		Line:     line,
		Column:   column,
	})
	cc.emitter.EmitOpcodeWithOperand(opcode, Operand{Type: OperandImmediate32, Value: 0}, line, column)
}

func (cc *ConditionCompiler) resolveJumps() error {
	for _, jump := range cc.pendingJumps {
		targetOffset, exists := cc.labels[jump.Label]
		if !exists {
			return fmt.Errorf("undefined label: %s", jump.Label)
		}
		relativeOffset := targetOffset - jump.Position - 1
		// #nosec G115 - safe conversion with explicit bounds checking
		if err := cc.emitter.UpdateOperand(jump.Position, Operand{Type: OperandImmediate32, Value: uint64(int64(relativeOffset))}); err != nil {
			return fmt.Errorf("failed to resolve jump to label %s: %w", jump.Label, err)
		}
	}
	cc.pendingJumps = cc.pendingJumps[:0]
	return nil
}

func (cc *ConditionCompiler) compileExpressions(exprs ...ast.Expression) error {
	for _, expr := range exprs {
		if err := cc.compileExpression(expr); err != nil {
			return err
		}
	}
	return nil
}

func (cc *ConditionCompiler) findStringOffset(name string) (int, bool) {
	if offset, exists := cc.stringOffsets[name]; exists {
		return offset, true
	}
	if offset, exists := cc.stringOffsets["$"+name]; exists {
		return offset, true
	}
	return 0, false
}

func (cc *ConditionCompiler) emitStringOffset(offset, line, column int) {
	if offset < 0 {
		cc.emitter.EmitOpcodeWithOperand(OP_PUSH_M, Operand{Type: OperandImmediate64, Value: uint64(0)}, line, column)
	} else {
		cc.emitter.EmitOpcodeWithOperand(OP_PUSH_M, Operand{Type: OperandImmediate64, Value: uint64(int64(offset))}, line, column) // #nosec G115
	}
}

func (cc *ConditionCompiler) emitStringIdentifier(offset int, identifier string, line, column int) {
	_ = identifier
	cc.emitter.EmitOpcodeWithOperand(OP_PUSH_M, Operand{Type: OperandImmediate64, Value: uint64(int64(offset))}, line, column) // #nosec G115
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

func (cc *ConditionCompiler) compileLiteral(lit *ast.Literal) error {
	if lit.Type == token.SIZE_LIT {
		return cc.compileSizeLiteral(lit)
	}

	if !cc.compileSimpleLiteral(lit) {
		return fmt.Errorf("unsupported literal type: %s", lit.Type)
	}

	return nil
}

// compileSimpleLiteral compiles simple literal types (integer, float, string, boolean)
func (cc *ConditionCompiler) compileSimpleLiteral(lit *ast.Literal) bool {
	switch lit.Type {
	case token.INTEGER_LIT, token.HEX_INTEGER_LIT, token.OCTAL_INTEGER_LIT:
		cc.compileIntegerLiteral(lit)
		return true

	case token.FLOAT_LIT:
		cc.compileFloatLiteral(lit)
		return true

	case token.STRING_LIT:
		cc.compileStringLiteral(lit)
		return true

	case token.TRUE, token.FALSE:
		cc.compileBooleanLiteral(lit)
		return true

	default:
		return false
	}
}

// compileIntegerLiteral compiles integer literals
func (cc *ConditionCompiler) compileIntegerLiteral(lit *ast.Literal) {
	if value, ok := lit.Value.(int64); ok {
		cc.emitter.EmitPush(safeInt64ToUint64(safeMax(0, value)), lit.Pos.Line, lit.Pos.Column)
	} else {
		cc.emitter.EmitPush(0, lit.Pos.Line, lit.Pos.Column)
	}
}

// compileFloatLiteral compiles float literals
func (cc *ConditionCompiler) compileFloatLiteral(lit *ast.Literal) {
	if value, ok := lit.Value.(float64); ok {
		cc.emitter.EmitPushDouble(value, lit.Pos.Line, lit.Pos.Column)
	}
}

// compileStringLiteral compiles string literals
func (cc *ConditionCompiler) compileStringLiteral(lit *ast.Literal) {
	if value, ok := lit.Value.(string); ok {
		cc.emitter.EmitPush(uint64(int64(len(value))), lit.Pos.Line, lit.Pos.Column) // #nosec G115
	}
}

// compileBooleanLiteral compiles boolean literals
func (cc *ConditionCompiler) compileBooleanLiteral(lit *ast.Literal) {
	if lit.Type == token.TRUE {
		cc.emitter.EmitPush(1, lit.Pos.Line, lit.Pos.Column)
	} else {
		cc.emitter.EmitPush(0, lit.Pos.Line, lit.Pos.Column)
	}
}

func (cc *ConditionCompiler) compileSizeLiteral(lit *ast.Literal) error {
	if value, ok := lit.Value.(int64); ok {
		cc.emitter.EmitPush(safeInt64ToUint64(safeMax(0, value)), lit.Pos.Line, lit.Pos.Column)
		return nil
	}
	if litStr, isStr := lit.Value.(string); isStr {
		if parsed, err := parseSizeLiteral(litStr); err == nil {
			cc.emitter.EmitPush(safeInt64ToUint64(parsed), lit.Pos.Line, lit.Pos.Column)
			return nil
		} else {
			return fmt.Errorf("failed to parse size literal %s: %w", litStr, err)
		}
	}
	return fmt.Errorf("SIZE_LIT token has invalid value: %v (type: %T)", lit.Value, lit.Value)
}

// compileIdentifier compiles an identifier reference
func (cc *ConditionCompiler) compileIdentifier(ident *ast.Identifier) error {
	if offset, exists := cc.stringOffsets[ident.Name]; exists {
		// Safe conversion: offset is expected to be non-negative
		if offset >= 0 {
			cc.emitter.EmitOpcodeWithOperand(OP_PUSH_M, Operand{Type: OperandImmediate64, Value: uint64(offset)}, ident.Pos.Line, ident.Pos.Column)
		} else {
			cc.emitter.EmitOpcodeWithOperand(OP_PUSH_M, Operand{Type: OperandImmediate64, Value: 0}, ident.Pos.Line, ident.Pos.Column)
		}
		cc.emitter.EmitOpcode(OP_FOUND, ident.Pos.Line, ident.Pos.Column)
		return nil
	}

	if index, exists := cc.externalVariables[ident.Name]; exists {
		cc.emitter.EmitOpcodeWithOperand(OP_PUSH_M, Operand{Type: OperandImmediate32, Value: uint64(int64(index))}, ident.Pos.Line, ident.Pos.Column) // #nosec G115
		return nil
	}

	if index, exists := cc.variableMap[ident.Name]; exists {
		cc.emitter.EmitOpcodeWithOperand(OP_OBJ_LOAD, Operand{Type: OperandImmediate32, Value: safeInt64ToUint64(safeMax(0, int64(index)))}, ident.Pos.Line, ident.Pos.Column)
		return nil
	}

	if ruleIndex, exists := cc.ruleIndexMap[ident.Name]; exists {
		cc.emitter.EmitOpcodeWithOperand(OP_PUSH_RULE, Operand{Type: OperandImmediate8, Value: uint64(int64(ruleIndex))}, ident.Pos.Line, ident.Pos.Column) // #nosec G115
		return nil
	}

	specialIdentifiers := map[string]func(){
		"filesize":     func() { cc.emitter.EmitOpcode(OP_FILESIZE, ident.Pos.Line, ident.Pos.Column) },
		"entrypoint":   func() { cc.emitter.EmitOpcode(OP_ENTRYPOINT, ident.Pos.Line, ident.Pos.Column) },
		"them":         func() { cc.emitter.EmitPush(0xFFFFFFFE, ident.Pos.Line, ident.Pos.Column) },
		"flags":        func() { cc.emitter.EmitPush(0, ident.Pos.Line, ident.Pos.Column) },
		QuantifierAny:  func() { cc.emitter.EmitOpcode(OP_PUSH_8, ident.Pos.Line, ident.Pos.Column) },
		QuantifierAll:  func() { cc.emitter.EmitOpcode(OP_PUSH_8, ident.Pos.Line, ident.Pos.Column) },
		QuantifierNone: func() { cc.emitter.EmitOpcode(OP_PUSH_8, ident.Pos.Line, ident.Pos.Column) },
	}

	if handler, exists := specialIdentifiers[ident.Name]; exists {
		handler()
		return nil
	}

	if cc.isModuleFunction(ident.Name) {
		cc.emitModuleFunctionCall(ident.Name, ident.Pos.Line, ident.Pos.Column)
		return nil
	}

	cc.emitter.EmitOpcode(OP_PUSH_U, ident.Pos.Line, ident.Pos.Column)
	return fmt.Errorf("undefined identifier: %s", ident.Name)

}

func (cc *ConditionCompiler) compileStringOffsetOperator(binOp *ast.BinaryOp) error {
	id, ok := binOp.Left.(*ast.Identifier)
	if !ok {
		return fmt.Errorf("%s operator requires string identifier as left operand", map[token.TokenType]string{
			token.AT: "AT", token.IN: "IN",
		}[binOp.Op])
	}

	offset, exists := cc.findStringOffset(id.Name)
	if !exists {
		return fmt.Errorf("undefined string identifier: %s", id.Name)
	}

	cc.emitStringIdentifier(offset, id.Name, binOp.Pos.Line, binOp.Pos.Column)
	if err := cc.compileExpression(binOp.Right); err != nil {
		return err
	}

	opcodes := map[token.TokenType]Opcode{token.AT: OP_FOUND_AT, token.IN: OP_FOUND_IN}
	cc.emitter.EmitOpcode(opcodes[binOp.Op], binOp.Pos.Line, binOp.Pos.Column)
	return nil
}

func (cc *ConditionCompiler) isFloatExpression(expr ast.Expression) bool {
	switch e := expr.(type) {
	case *ast.Literal:
		return e.Type == token.FLOAT_LIT
	case *ast.BinaryOp:
		return cc.isFloatExpression(e.Left) || cc.isFloatExpression(e.Right)
	case *ast.UnaryOp:
		return cc.isFloatExpression(e.Right)
	default:
		return false
	}
}

func (cc *ConditionCompiler) isLiteralFloat(expr ast.Expression) bool {
	if lit, ok := expr.(*ast.Literal); ok {
		return lit.Type == token.FLOAT_LIT
	}
	if unaryOp, ok := expr.(*ast.UnaryOp); ok && unaryOp.Op == token.MINUS {
		return cc.isLiteralFloat(unaryOp.Right)
	}
	return false
}

func (cc *ConditionCompiler) isMixedTypeComparison(leftIsFloat, rightIsFloat bool) bool {
	return leftIsFloat != rightIsFloat
}

func (cc *ConditionCompiler) isComparisonOperator(op token.TokenType) bool {
	return slices.Contains([]token.TokenType{
		token.EQ, token.NEQ, token.LT, token.LE, token.GT, token.GE,
		token.LEFT_SHIFT, token.RIGHT_SHIFT, token.MODULO,
	}, op)
}

func (cc *ConditionCompiler) isNonCommutativeOperator(op token.TokenType) bool {
	return op == token.MINUS || op == token.DIVIDE
}

func (cc *ConditionCompiler) compileOperands(binOp *ast.BinaryOp) error {
	isComparison := cc.isComparisonOperator(binOp.Op)
	isNonCommutative := cc.isNonCommutativeOperator(binOp.Op)

	if isComparison || isNonCommutative {
		return cc.compileExpressions(binOp.Left, binOp.Right)
	}
	return cc.compileExpressions(binOp.Right, binOp.Left)
}

func (cc *ConditionCompiler) handleBitShiftFloatConversion(binOp *ast.BinaryOp, leftIsFloat, rightIsFloat, isComparison bool) {
	if isComparison {
		if leftIsFloat {
			cc.emitter.EmitOpcode(OP_SWAPUNDEF, binOp.Pos.Line, binOp.Pos.Column)
			cc.emitter.EmitOpcode(OP_INT_TO_DBL, binOp.Pos.Line, binOp.Pos.Column)
			cc.emitter.EmitOpcode(OP_SWAPUNDEF, binOp.Pos.Line, binOp.Pos.Column)
		}
		if rightIsFloat {
			_ = rightIsFloat
		}
	}
}

func (cc *ConditionCompiler) handleMixedTypeLiteralComparison(binOp *ast.BinaryOp) bool {
	if cc.isLiteralFloat(binOp.Left) || cc.isLiteralFloat(binOp.Right) {
		result := int64(0)
		if binOp.Op == token.NEQ {
			result = 1
		}
		cc.emitter.EmitPush(safeInt64ToUint64(result), binOp.Pos.Line, binOp.Pos.Column)
		return true
	}
	return false
}

func (cc *ConditionCompiler) convertForMixedType(binOp *ast.BinaryOp, leftIsFloat, rightIsFloat, isComparison bool) {
	if isComparison {
		if leftIsFloat && !rightIsFloat {
			cc.emitter.EmitOpcode(OP_INT_TO_DBL, binOp.Pos.Line, binOp.Pos.Column)
		} else if !leftIsFloat && rightIsFloat {
			cc.emitter.EmitOpcode(OP_SWAPUNDEF, binOp.Pos.Line, binOp.Pos.Column)
			cc.emitter.EmitOpcode(OP_INT_TO_DBL, binOp.Pos.Line, binOp.Pos.Column)
			cc.emitter.EmitOpcode(OP_SWAPUNDEF, binOp.Pos.Line, binOp.Pos.Column)
		}
	} else {
		if leftIsFloat && !rightIsFloat {
			cc.emitter.EmitOpcode(OP_SWAPUNDEF, binOp.Pos.Line, binOp.Pos.Column)
			cc.emitter.EmitOpcode(OP_INT_TO_DBL, binOp.Pos.Line, binOp.Pos.Column)
			cc.emitter.EmitOpcode(OP_SWAPUNDEF, binOp.Pos.Line, binOp.Pos.Column)
		} else if !leftIsFloat && rightIsFloat {
			cc.emitter.EmitOpcode(OP_INT_TO_DBL, binOp.Pos.Line, binOp.Pos.Column)
		}
	}
}

func (cc *ConditionCompiler) convertForMixedTypeComparison(binOp *ast.BinaryOp, leftIsFloat, rightIsFloat, isComparison bool) {
	if !isComparison {
		return
	}
	cc.convertForMixedType(binOp, leftIsFloat, rightIsFloat, isComparison)
}

func (cc *ConditionCompiler) convertForMixedTypeArithmetic(binOp *ast.BinaryOp, leftIsFloat, rightIsFloat, isComparison bool) {
	if isComparison {
		cc.convertForMixedType(binOp, leftIsFloat, rightIsFloat, isComparison)
	} else {
		cc.convertForMixedType(binOp, leftIsFloat, rightIsFloat, isComparison)
	}
}

func (cc *ConditionCompiler) handleFloatOperations(binOp *ast.BinaryOp, leftIsFloat, rightIsFloat, isComparison bool) error {
	isFloatOp := leftIsFloat || rightIsFloat
	if !isFloatOp {
		return nil
	}

	switch {
	case binOp.Op == token.LEFT_SHIFT || binOp.Op == token.RIGHT_SHIFT:
		cc.handleBitShiftFloatConversion(binOp, leftIsFloat, rightIsFloat, isComparison)
	case cc.isMixedTypeComparison(leftIsFloat, rightIsFloat) && (binOp.Op == token.EQ || binOp.Op == token.NEQ):
		if cc.handleMixedTypeLiteralComparison(binOp) {
			return nil
		}
		cc.convertForMixedType(binOp, leftIsFloat, rightIsFloat, isComparison)
	default:
		cc.convertForMixedType(binOp, leftIsFloat, rightIsFloat, isComparison)
	}

	return nil
}

type opcodeMapping struct {
	intOp, dblOp Opcode
}

func (cc *ConditionCompiler) selectOpcode(binOp *ast.BinaryOp, isFloatOp bool) (Opcode, error) {
	opcodeMap := map[token.TokenType]opcodeMapping{
		token.AND:         {OP_AND, OP_AND},
		token.OR:          {OP_OR, OP_OR},
		token.PLUS:        {OP_INT_ADD, OP_DBL_ADD},
		token.MINUS:       {OP_INT_SUB, OP_DBL_SUB},
		token.MULTIPLY:    {OP_INT_MUL, OP_DBL_MUL},
		token.DIVIDE:      {OP_INT_DIV, OP_DBL_DIV},
		token.MODULO:      {OP_MOD, OP_MOD},
		token.BITWISE_AND: {OP_BITWISE_AND, OP_BITWISE_AND},
		token.BITWISE_OR:  {OP_BITWISE_OR, OP_BITWISE_OR},
		token.BITWISE_XOR: {OP_BITWISE_XOR, OP_BITWISE_XOR},
		token.LEFT_SHIFT:  {OP_SHL, OP_SHL},
		token.RIGHT_SHIFT: {OP_SHR, OP_SHR},
		token.EQ:          {OP_INT_EQ, OP_DBL_EQ},
		token.NEQ:         {OP_INT_NEQ, OP_DBL_NEQ},
		token.LT:          {OP_INT_LT, OP_DBL_LT},
		token.LE:          {OP_INT_LE, OP_DBL_LE},
		token.GT:          {OP_INT_GT, OP_DBL_GT},
		token.GE:          {OP_INT_GE, OP_DBL_GE},
		token.CONTAINS:    {OP_CONTAINS, OP_CONTAINS},
		token.MATCHES:     {OP_MATCHES, OP_MATCHES},
		token.OF:          {OP_OF, OP_OF},
	}

	mapping, exists := opcodeMap[binOp.Op]
	if !exists {
		return 0, fmt.Errorf("unsupported binary operator: %s", binOp.Op)
	}

	if isFloatOp {
		return mapping.dblOp, nil
	}
	return mapping.intOp, nil
}

func (cc *ConditionCompiler) handleSpecialOperators(binOp *ast.BinaryOp) error {
	switch binOp.Op {
	case token.AT, token.IN:
		return cc.compileStringOffsetOperator(binOp)
	case token.DOT:
		return cc.compileExpressions(binOp.Left, binOp.Right)
	}
	return nil
}

func (cc *ConditionCompiler) compileBinaryOp(binOp *ast.BinaryOp) error {
	if err := cc.handleSpecialOperators(binOp); err != nil {
		return err
	}

	if err := cc.compileOperands(binOp); err != nil {
		return err
	}

	leftIsFloat := cc.isFloatExpression(binOp.Left)
	rightIsFloat := cc.isFloatExpression(binOp.Right)
	isComparison := cc.isComparisonOperator(binOp.Op)
	isFloatOp := leftIsFloat || rightIsFloat

	if err := cc.handleFloatOperations(binOp, leftIsFloat, rightIsFloat, isComparison); err != nil {
		return err
	}

	opcode, err := cc.selectOpcode(binOp, isFloatOp)
	if err != nil {
		return err
	}

	cc.emitter.EmitOpcode(opcode, binOp.Pos.Line, binOp.Pos.Column)
	return nil
}

func (cc *ConditionCompiler) compileUnaryOp(unaryOp *ast.UnaryOp) error {
	switch unaryOp.Op {
	case token.HASH:
		return cc.compileHashOperator(unaryOp)
	case token.AT:
		return cc.compileAtOperator(unaryOp)
	case token.NOT:
		return cc.compileNotOperator(unaryOp)
	case token.BITWISE_NOT:
		return cc.compileBitwiseNotOperator(unaryOp)
	case token.MINUS:
		return cc.compileMinusOperator(unaryOp)
	case token.DEFINED:
		return cc.compileDefinedOperator(unaryOp)
	default:
		return fmt.Errorf("unsupported unary operator: %s", unaryOp.Op)
	}
}

func (cc *ConditionCompiler) compileHashOperator(unaryOp *ast.UnaryOp) error {
	id, ok := unaryOp.Right.(*ast.Identifier)
	if !ok {
		return errors.New("COUNT (#) expects a string identifier operand")
	}

	offset, exists := cc.findStringOffset(id.Name)
	if !exists {
		return fmt.Errorf("undefined string identifier for count operator: %s", id.Name)
	}

	cc.emitStringOffset(offset, unaryOp.Pos.Line, unaryOp.Pos.Column)
	cc.emitter.EmitOpcode(OP_COUNT, unaryOp.Pos.Line, unaryOp.Pos.Column)
	return nil
}

func (cc *ConditionCompiler) compileAtOperator(unaryOp *ast.UnaryOp) error {
	id, ok := unaryOp.Right.(*ast.Identifier)
	if !ok {
		return errors.New("POSITION (@) expects a string identifier operand")
	}

	offset, exists := cc.findStringOffset(id.Name)
	if !exists {
		return fmt.Errorf("undefined string identifier for position operator: %s", id.Name)
	}

	cc.emitStringOffset(offset, unaryOp.Pos.Line, unaryOp.Pos.Column)
	cc.emitter.EmitPush(1, unaryOp.Pos.Line, unaryOp.Pos.Column)
	cc.emitter.EmitOpcode(OP_OFFSET, unaryOp.Pos.Line, unaryOp.Pos.Column)
	return nil
}

func (cc *ConditionCompiler) compileNotOperator(unaryOp *ast.UnaryOp) error {
	if id, ok := unaryOp.Right.(*ast.Identifier); ok {
		if offset, exists := cc.findStringOffset(id.Name); exists {
			cc.emitStringOffset(offset, unaryOp.Pos.Line, unaryOp.Pos.Column)
			cc.emitter.EmitOpcode(OP_LENGTH, unaryOp.Pos.Line, unaryOp.Pos.Column)
			return nil
		}
		return fmt.Errorf("undefined string identifier for length operator: %s", id.Name)
	}

	if err := cc.compileExpression(unaryOp.Right); err != nil {
		return err
	}
	cc.emitter.EmitOpcode(OP_NOT, unaryOp.Pos.Line, unaryOp.Pos.Column)
	return nil
}

func (cc *ConditionCompiler) compileBitwiseNotOperator(unaryOp *ast.UnaryOp) error {
	if err := cc.compileExpression(unaryOp.Right); err != nil {
		return err
	}
	cc.emitter.EmitOpcode(OP_BITWISE_NOT, unaryOp.Pos.Line, unaryOp.Pos.Column)
	return nil
}

func (cc *ConditionCompiler) compileMinusOperator(unaryOp *ast.UnaryOp) error {
	if err := cc.compileExpression(unaryOp.Right); err != nil {
		return err
	}

	if cc.isLiteralFloat(unaryOp.Right) {
		cc.emitter.EmitOpcode(OP_DBL_MINUS, unaryOp.Pos.Line, unaryOp.Pos.Column)
	} else {
		cc.emitter.EmitOpcode(OP_INT_MINUS, unaryOp.Pos.Line, unaryOp.Pos.Column)
	}
	return nil
}

func (cc *ConditionCompiler) compileDefinedOperator(unaryOp *ast.UnaryOp) error {
	if err := cc.compileExpression(unaryOp.Right); err != nil {
		return err
	}
	cc.emitter.EmitOpcode(OP_DEFINED, unaryOp.Pos.Line, unaryOp.Pos.Column)
	return nil
}

func (cc *ConditionCompiler) compileArrayIndex(arrayIndex *ast.ArrayIndex) error {
	unaryOp, ok := arrayIndex.Array.(*ast.UnaryOp)
	if !ok {
		return errors.New("array indexing requires @ or # operator")
	}

	if err := cc.compileExpression(arrayIndex.Index); err != nil {
		return err
	}

	if unaryOp.Op != token.AT && unaryOp.Op != token.HASH {
		return fmt.Errorf("unsupported operator for array indexing: %s", unaryOp.Op)
	}

	ident, isIdent := unaryOp.Right.(*ast.Identifier)
	if !isIdent {
		return fmt.Errorf("%s operator expects a string identifier", map[token.TokenType]string{
			token.AT: "@", token.HASH: "#",
		}[unaryOp.Op])
	}

	offset, hasOffset := cc.stringOffsets[ident.Name]
	if !hasOffset {
		return fmt.Errorf("undefined string identifier: %s", ident.Name)
	}

	cc.emitter.EmitOpcodeWithOperand(OP_PUSH_M, Operand{Type: OperandImmediate64, Value: uint64(int64(offset))}, arrayIndex.Pos.Line, arrayIndex.Pos.Column) // #nosec G115

	marker := int64(0)
	if unaryOp.Op == token.HASH {
		marker = 1
	}
	cc.emitter.EmitPush(safeInt64ToUint64(marker), arrayIndex.Pos.Line, arrayIndex.Pos.Column)
	cc.emitter.EmitOpcode(OP_INDEX_ARRAY, arrayIndex.Pos.Line, arrayIndex.Pos.Column)
	return nil
}

func (cc *ConditionCompiler) AddVariable(name string, index int) {
	cc.variableMap[name] = index
}

func (cc *ConditionCompiler) GetVariableIndex(name string) (int, bool) {
	index, exists := cc.variableMap[name]
	return index, exists
}

func (cc *ConditionCompiler) CompileBooleanExpression(expr ast.Expression, shortCircuit bool) error {
	if !shortCircuit {
		return cc.compileExpression(expr)
	}

	if binOp, ok := expr.(*ast.BinaryOp); ok {
		switch binOp.Op {
		case token.AND:
			return cc.compileShortCircuitBinary(binOp, OP_JFALSE, OP_AND)
		case token.OR:
			return cc.compileShortCircuitBinary(binOp, OP_JTRUE, OP_OR)
		}
	}

	return cc.compileExpression(expr)
}

func (cc *ConditionCompiler) compileShortCircuitBinary(binOp *ast.BinaryOp, jumpOpcode, resultOpcode Opcode) error {
	if err := cc.compileExpression(binOp.Left); err != nil {
		return err
	}

	endLabel := cc.generateLabel()
	cc.emitJumpWithLabel(jumpOpcode, endLabel, binOp.Pos.Line, binOp.Pos.Column)

	if err := cc.compileExpression(binOp.Right); err != nil {
		return err
	}

	cc.defineLabel(endLabel)
	cc.emitter.EmitOpcode(resultOpcode, binOp.Pos.Line, binOp.Pos.Column)
	return nil
}

func (cc *ConditionCompiler) GetVariableMap() map[string]int {
	return cc.variableMap
}

func (cc *ConditionCompiler) GetExternalVariables() map[string]int {
	return cc.externalVariables
}

func (cc *ConditionCompiler) SetStringOffsets(offsets map[string]int) {
	cc.stringOffsets = offsets
}

func (cc *ConditionCompiler) GetStats() map[string]any {
	return map[string]any{
		"variables":     len(cc.variableMap),
		"label_counter": cc.labelCounter,
	}
}

func (cc *ConditionCompiler) ValidateExpression(expr ast.Expression) error {
	savedEmitter := cc.emitter
	cc.emitter = NewEmitter()
	defer func() { cc.emitter = savedEmitter }()
	return cc.compileExpression(expr)
}

func (cc *ConditionCompiler) OptimizeExpression(expr ast.Expression) ast.Expression {
	return expr
}

func (cc *ConditionCompiler) EstimateComplexity(expr ast.Expression) int {
	switch e := expr.(type) {
	case *ast.Literal:
		return 1
	case *ast.Identifier:
		return 2
	case *ast.BinaryOp:
		return cc.EstimateComplexity(e.Left) + cc.EstimateComplexity(e.Right) + 1
	case *ast.UnaryOp:
		return cc.EstimateComplexity(e.Right) + 1
	default:
		return 0
	}
}

type JumpPosition struct {
	Line   int
	Column int
}

type ConditionalJumpConfig struct {
	Opcode      Opcode
	TargetLabel string
	Position    JumpPosition
}

func (cc *ConditionCompiler) EmitJump(config ConditionalJumpConfig) error {
	cc.emitJumpWithLabel(config.Opcode, config.TargetLabel, config.Position.Line, config.Position.Column)
	return nil
}

func (cc *ConditionCompiler) compileShortCircuitAnd(andOp *ast.BinaryOp) error {
	return cc.compileShortCircuitBinary(andOp, OP_JFALSE, OP_AND)
}

func (cc *ConditionCompiler) compileShortCircuitOr(orOp *ast.BinaryOp) error {
	return cc.compileShortCircuitBinary(orOp, OP_JTRUE, OP_OR)
}

func (cc *ConditionCompiler) compileOfExpression(ofExpr *ast.OfExpression) error {
	if err := cc.compileCountExpression(ofExpr.Count); err != nil {
		return fmt.Errorf("compiling count expression in of-expression: %w", err)
	}

	if err := cc.compileStringsExpression(ofExpr.Strings); err != nil {
		return fmt.Errorf("compiling strings expression in of-expression: %w", err)
	}

	cc.emitter.EmitOpcode(OP_OF, ofExpr.Pos.Line, ofExpr.Pos.Column)
	return nil
}

func (cc *ConditionCompiler) compileCountExpression(countExpr ast.Expression) error {
	if ident, ok := countExpr.(*ast.Identifier); ok {
		switch ident.Name {
		case QuantifierAny:
			cc.emitter.EmitPush(1, ident.Pos.Line, ident.Pos.Column)
			return nil
		case QuantifierAll:
			cc.emitter.EmitOpcode(OP_PUSH_M, ident.Pos.Line, ident.Pos.Column)
			return nil
		case QuantifierNone:
			cc.emitter.EmitPush(0, ident.Pos.Line, ident.Pos.Column)
			return nil
		}
	}
	return cc.compileExpression(countExpr)
}

func (cc *ConditionCompiler) compileStringsExpression(stringsExpr ast.Expression) error {
	if ident, ok := stringsExpr.(*ast.Identifier); ok {
		switch {
		case ident.Name == "them":
			cc.emitter.EmitPush(0xFFFFFFFE, ident.Pos.Line, ident.Pos.Column)
			return nil
		case cc.isRuleReference(ident.Name):
			return cc.compileRuleReference(ident.Name, ident.Pos.Line, ident.Pos.Column)
		}
	}
	return cc.compileExpression(stringsExpr)
}

func (cc *ConditionCompiler) compileFunctionCall(call *ast.FunctionCall) error {
	for i := len(call.Args) - 1; i >= 0; i-- {
		if err := cc.compileExpression(call.Args[i]); err != nil {
			return fmt.Errorf("compiling function argument %d: %w", i, err)
		}
	}

	functionOpcodes := map[string]Opcode{
		"uint8": OP_UINT8, "uint16": OP_UINT16, "uint32": OP_UINT32,
		"uint8be": OP_UINT8BE, "uint16be": OP_UINT16BE, "uint32be": OP_UINT32BE,
		"int8": OP_INT8, "int16": OP_INT16, "int32": OP_INT32,
		"int8be": OP_INT8BE, "int16be": OP_INT16BE, "int32be": OP_INT32BE,
		"concat": OP_CONCAT,
	}

	opcode, exists := functionOpcodes[call.Function]
	if !exists {
		return fmt.Errorf("unsupported function: %s", call.Function)
	}

	cc.emitter.EmitOpcode(opcode, call.Pos.Line, call.Pos.Column)
	return nil
}

func (cc *ConditionCompiler) isRuleReference(name string) bool {
	_, exists := cc.ruleIndexMap[name]
	return exists
}

func (cc *ConditionCompiler) compileRuleReference(ruleName string, line, column int) error {
	ruleIndex, exists := cc.ruleIndexMap[ruleName]
	if !exists {
		return fmt.Errorf("undefined rule reference: %s", ruleName)
	}

	cc.emitter.EmitOpcodeWithOperand(OP_PUSH_RULE_REF,
		Operand{Type: OperandImmediate64, Value: uint64(int64(ruleIndex))}, // #nosec G115
		line, column)
	return nil
}

func (cc *ConditionCompiler) isModuleFunction(name string) bool {
	if !strings.Contains(name, ".") {
		return false
	}

	parts := strings.Split(name, ".")
	if len(parts) != 2 {
		return false
	}

	modulePrefixes := []string{"pe.", "cuckoo.", "hash.", "elf.", "macho.", "dotnet.", "text."}
	moduleName := parts[0]

	for _, prefix := range modulePrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}

	moduleFunctions := map[string]bool{
		"elf": true, "macho": true, "dotnet": true, "text": true,
	}

	return moduleFunctions[moduleName]
}

func (cc *ConditionCompiler) emitModuleFunctionCall(name string, line, column int) {
	cc.emitter.EmitPush(0, line, column)
}

func (cc *ConditionCompiler) compileStringLength(strLen *ast.StringLength) error {
	if err := cc.compileExpression(strLen.String); err != nil {
		return err
	}
	cc.emitter.EmitOpcode(OP_LENGTH, strLen.Pos.Line, strLen.Pos.Column)
	return nil
}
