package compiler

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
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

// ConditionCompiler compiles YARA condition expressions to bytecode
type ConditionCompiler struct {
	emitter           *Emitter
	stringOffsets     map[string]int
	variableMap       map[string]int
	externalVariables map[string]int
	ruleIndexMap      map[string]int
	labelCounter      int
	labels            map[string]int
	pendingJumps      []PendingJump
	stringSets        [][]string
	stringSetIndex    map[string]int
	anonymousStrings  []string
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

// PendingJump represents a pending jump operation in bytecode generation
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
		labels:            make(map[string]int),
		pendingJumps:      make([]PendingJump, 0),
		stringSets:        make([][]string, 0, 8),
		stringSetIndex:    make(map[string]int),
	}
}

// SetRuleIndexMap sets the rule index map for the compiler
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
		cc.emitter.EmitOpcodeWithOperand(OpPushM, Operand{Type: OperandImmediate64, Value: uint64(0)}, line, column)
	} else {
		cc.emitter.EmitOpcodeWithOperand(OpPushM, Operand{Type: OperandImmediate64, Value: uint64(int64(offset))}, line, column) // #nosec G115
	}
}

func (cc *ConditionCompiler) emitStringIdentifier(offset int, identifier string, line, column int) {
	_ = offset
	cc.emitter.EmitPushString(identifier, line, column)
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
	case *ast.OfExpression:
		return cc.compileOfExpression(e)
	case *ast.ForLoop:
		return cc.compileForLoop(e)
	case *ast.FunctionCall:
		return cc.compileFunctionCall(e)
	case *ast.StringLength:
		return cc.compileStringLength(e)
	case *ast.StringOffset:
		return cc.compileStringOffset(e)
	case *ast.StringCount:
		return cc.compileStringCount(e)
	default:
		return fmt.Errorf("unsupported expression type: %T", expr)
	}
}

func (cc *ConditionCompiler) compileLiteral(lit *ast.Literal) error {
	switch lit.Type {
	case token.SizeLit:
		return cc.compileSizeLiteral(lit)
	case token.FILESIZE:
		cc.emitter.EmitOpcode(OpFilesize, lit.Pos.Line, lit.Pos.Column)
		return nil
	case token.ENTRYPOINT:
		cc.emitter.EmitOpcode(OpEntrypoint, lit.Pos.Line, lit.Pos.Column)
		return nil
	}

	if !cc.compileSimpleLiteral(lit) {
		return fmt.Errorf("unsupported literal type: %s", lit.Type)
	}

	return nil
}

// compileSimpleLiteral compiles simple literal types (integer, float, string, boolean)
func (cc *ConditionCompiler) compileSimpleLiteral(lit *ast.Literal) bool {
	switch lit.Type {
	case token.IntegerLit, token.HexIntegerLit, token.OctalIntegerLit:
		cc.compileIntegerLiteral(lit)
		return true

	case token.FloatLit:
		cc.compileFloatLiteral(lit)
		return true

	case token.StringLit:
		cc.compileStringLiteral(lit)
		return true

	case token.RegexLit:
		cc.compileRegexLiteral(lit)
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
	} else if strValue, ok := lit.Value.(string); ok {
		// Handle case where literal value is stored as string (parse it)
		if intVal, err := parseIntLiteral(strValue); err == nil {
			cc.emitter.EmitPush(safeInt64ToUint64(safeMax(0, intVal)), lit.Pos.Line, lit.Pos.Column)
		} else {
			cc.emitter.EmitPush(0, lit.Pos.Line, lit.Pos.Column)
		}
	} else {
		cc.emitter.EmitPush(0, lit.Pos.Line, lit.Pos.Column)
	}
}

// parseIntLiteral parses a string as an integer literal
func parseIntLiteral(s string) (int64, error) {
	return strconv.ParseInt(s, 10, 64)
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
		cc.emitter.EmitPushString(value, lit.Pos.Line, lit.Pos.Column)
	}
}

// compileRegexLiteral compiles regex literals
func (cc *ConditionCompiler) compileRegexLiteral(lit *ast.Literal) {
	if value, ok := lit.Value.(string); ok {
		// Push the regex literal; OpMatches will handle compilation and matching.
		cc.emitter.EmitPushString(value, lit.Pos.Line, lit.Pos.Column)
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
		parsed, err := parseSizeLiteral(litStr)
		if err == nil {
			cc.emitter.EmitPush(safeInt64ToUint64(parsed), lit.Pos.Line, lit.Pos.Column)
			return nil
		}
		return fmt.Errorf("failed to parse size literal %s: %w", litStr, err)
	}
	return fmt.Errorf("SizeLit token has invalid value: %v (type: %T)", lit.Value, lit.Value)
}

// compileIdentifier compiles an identifier reference
func (cc *ConditionCompiler) compileIdentifier(ident *ast.Identifier) error {
	if offset, exists := cc.stringOffsets[ident.Name]; exists {
		cc.emitStringIdentifier(offset, ident.Name, ident.Pos.Line, ident.Pos.Column)
		cc.emitter.EmitOpcode(OpFound, ident.Pos.Line, ident.Pos.Column)
		return nil
	}

	if index, exists := cc.externalVariables[ident.Name]; exists {
		cc.emitter.EmitOpcodeWithOperand(OpPushM, Operand{Type: OperandImmediate32, Value: uint64(int64(index))}, ident.Pos.Line, ident.Pos.Column) // #nosec G115
		return nil
	}

	if index, exists := cc.variableMap[ident.Name]; exists {
		cc.emitter.EmitOpcodeWithOperand(OpObjLoad, Operand{Type: OperandImmediate32, Value: safeInt64ToUint64(safeMax(0, int64(index)))}, ident.Pos.Line, ident.Pos.Column)
		return nil
	}

	if ruleIndex, exists := cc.ruleIndexMap[ident.Name]; exists {
		cc.emitter.EmitOpcodeWithOperand(OpPushRule, Operand{Type: OperandImmediate8, Value: uint64(int64(ruleIndex))}, ident.Pos.Line, ident.Pos.Column) // #nosec G115
		return nil
	}

	specialIdentifiers := map[string]func(){
		"filesize":     func() { cc.emitter.EmitOpcode(OpFilesize, ident.Pos.Line, ident.Pos.Column) },
		"entrypoint":   func() { cc.emitter.EmitOpcode(OpEntrypoint, ident.Pos.Line, ident.Pos.Column) },
		"them":         func() { cc.emitter.EmitPush(stringSetAll, ident.Pos.Line, ident.Pos.Column) },
		"flags":        func() { cc.emitter.EmitPush(0, ident.Pos.Line, ident.Pos.Column) },
		QuantifierAny:  func() { cc.emitter.EmitOpcode(OpPush8, ident.Pos.Line, ident.Pos.Column) },
		QuantifierAll:  func() { cc.emitter.EmitOpcode(OpPush8, ident.Pos.Line, ident.Pos.Column) },
		QuantifierNone: func() { cc.emitter.EmitOpcode(OpPush8, ident.Pos.Line, ident.Pos.Column) },
	}

	if handler, exists := specialIdentifiers[ident.Name]; exists {
		handler()
		return nil
	}

	if ident.Name == "$" {
		return cc.compileAnonymousIdentifier(ident.Pos.Line, ident.Pos.Column)
	}

	if cc.isModuleFunction(ident.Name) {
		cc.emitModuleFunctionCall(ident.Name, ident.Pos.Line, ident.Pos.Column)
		return nil
	}

	cc.emitter.EmitOpcode(OpPushU, ident.Pos.Line, ident.Pos.Column)
	return fmt.Errorf("undefined identifier: %s", ident.Name)

}

func (cc *ConditionCompiler) compileAnonymousIdentifier(line, column int) error {
	cc.emitter.EmitPush(1, line, column)
	cc.emitter.EmitPush(stringSetAnonymous, line, column)
	cc.emitter.EmitOpcode(OpOf, line, column)
	return nil
}

func (cc *ConditionCompiler) compileStringOffsetOperator(binOp *ast.BinaryOp) error {
	id, ok := binOp.Left.(*ast.Identifier)
	if !ok {
		return fmt.Errorf("%s operator requires string identifier as left operand", map[token.Type]string{
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

	opcodes := map[token.Type]Opcode{token.AT: OpFoundAt, token.IN: OpFoundIn}
	cc.emitter.EmitOpcode(opcodes[binOp.Op], binOp.Pos.Line, binOp.Pos.Column)
	return nil
}

// compileCommaOperator compiles COMMA operators used in 'of' expressions
// The COMMA creates a string list/set that can be iterated over by the 'of' operator
func (cc *ConditionCompiler) compileCommaOperator(binOp *ast.BinaryOp) error {
	// Compile the left side of the comma
	if err := cc.compileExpression(binOp.Left); err != nil {
		return fmt.Errorf("compiling left operand of comma: %w", err)
	}

	// Compile the right side of the comma
	if err := cc.compileExpression(binOp.Right); err != nil {
		return fmt.Errorf("compiling right operand of comma: %w", err)
	}

	// Emit the comma operation to create a string list
	// For now, we'll treat it as a push operation since the 'of' operator
	// will handle the list creation from the stack
	cc.emitter.EmitOpcode(OpNop, binOp.Pos.Line, binOp.Pos.Column)

	return nil
}

func (cc *ConditionCompiler) isFloatExpression(expr ast.Expression) bool {
	switch e := expr.(type) {
	case *ast.Literal:
		return e.Type == token.FloatLit
	case *ast.BinaryOp:
		return cc.isFloatExpression(e.Left) || cc.isFloatExpression(e.Right)
	case *ast.UnaryOp:
		return cc.isFloatExpression(e.Right)
	default:
		return false
	}
}

func (cc *ConditionCompiler) isStringExpression(expr ast.Expression) bool {
	switch e := expr.(type) {
	case *ast.Literal:
		return e.Type == token.StringLit || e.Type == token.RegexLit
	case *ast.FunctionCall:
		return cc.isStringFunction(e.Function)
	case *ast.BinaryOp:
		return cc.isStringExpression(e.Left) || cc.isStringExpression(e.Right)
	case *ast.UnaryOp:
		return cc.isStringExpression(e.Right)
	default:
		return false
	}
}

func (cc *ConditionCompiler) isStringFunction(name string) bool {
	switch name {
	case "string", "concat", "tostring", "md5", "sha1", "sha256":
		return true
	default:
		return false
	}
}

func (cc *ConditionCompiler) isLiteralFloat(expr ast.Expression) bool {
	if lit, ok := expr.(*ast.Literal); ok {
		return lit.Type == token.FloatLit
	}
	if unaryOp, ok := expr.(*ast.UnaryOp); ok && unaryOp.Op == token.MINUS {
		return cc.isLiteralFloat(unaryOp.Right)
	}
	return false
}

func (cc *ConditionCompiler) isMixedTypeComparison(leftIsFloat, rightIsFloat bool) bool {
	return leftIsFloat != rightIsFloat
}

func (cc *ConditionCompiler) isComparisonOperator(op token.Type) bool {
	return slices.Contains([]token.Type{
		token.EQ, token.NEQ, token.LT, token.LE, token.GT, token.GE,
		token.LeftShift, token.RightShift, token.MODULO,
		token.CONTAINS, token.ICONTAINS, token.STARTSWITH, token.ISTARTSWITH,
		token.ENDSWITH, token.IENDSWITH, token.IEQUALS, token.MATCHES,
	}, op)
}

func (cc *ConditionCompiler) isStringComparisonOperator(op token.Type) bool {
	switch op {
	case token.EQ, token.NEQ, token.LT, token.LE, token.GT, token.GE:
		return true
	default:
		return false
	}
}

func (cc *ConditionCompiler) isNonCommutativeOperator(op token.Type) bool {
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
			cc.emitter.EmitOpcode(OpSwapundef, binOp.Pos.Line, binOp.Pos.Column)
			cc.emitter.EmitOpcode(OpIntToDbl, binOp.Pos.Line, binOp.Pos.Column)
			cc.emitter.EmitOpcode(OpSwapundef, binOp.Pos.Line, binOp.Pos.Column)
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
		cc.convertForMixedTypeComparison(binOp, leftIsFloat, rightIsFloat)
	} else {
		cc.convertForMixedTypeArithmetic(binOp, leftIsFloat, rightIsFloat)
	}
}

func (cc *ConditionCompiler) convertForMixedTypeComparison(binOp *ast.BinaryOp, leftIsFloat, rightIsFloat bool) {
	if leftIsFloat && !rightIsFloat {
		cc.emitter.EmitOpcode(OpIntToDbl, binOp.Pos.Line, binOp.Pos.Column)
	} else if !leftIsFloat && rightIsFloat {
		cc.emitIntToDoubleWithSwap(binOp)
	}
}

func (cc *ConditionCompiler) convertForMixedTypeArithmetic(binOp *ast.BinaryOp, leftIsFloat, rightIsFloat bool) {
	if leftIsFloat && !rightIsFloat {
		cc.emitIntToDoubleWithSwap(binOp)
	} else if !leftIsFloat && rightIsFloat {
		cc.emitter.EmitOpcode(OpIntToDbl, binOp.Pos.Line, binOp.Pos.Column)
	}
}

func (cc *ConditionCompiler) emitIntToDoubleWithSwap(binOp *ast.BinaryOp) {
	cc.emitter.EmitOpcode(OpSwapundef, binOp.Pos.Line, binOp.Pos.Column)
	cc.emitter.EmitOpcode(OpIntToDbl, binOp.Pos.Line, binOp.Pos.Column)
	cc.emitter.EmitOpcode(OpSwapundef, binOp.Pos.Line, binOp.Pos.Column)
}

func (cc *ConditionCompiler) handleFloatOperations(binOp *ast.BinaryOp, leftIsFloat, rightIsFloat, isComparison bool) error {
	isFloatOp := leftIsFloat || rightIsFloat
	if !isFloatOp {
		return nil
	}

	switch {
	case binOp.Op == token.LeftShift || binOp.Op == token.RightShift:
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

func (cc *ConditionCompiler) selectOpcode(binOp *ast.BinaryOp, isFloatOp, isStringCompare bool) (Opcode, error) {
	if isStringCompare {
		switch binOp.Op {
		case token.EQ:
			return OpStrEq, nil
		case token.NEQ:
			return OpStrNeq, nil
		case token.LT:
			return OpStrLt, nil
		case token.LE:
			return OpStrLe, nil
		case token.GT:
			return OpStrGt, nil
		case token.GE:
			return OpStrGe, nil
		}
	}

	opcodeMap := map[token.Type]opcodeMapping{
		token.AND:         {OpAnd, OpAnd},
		token.OR:          {OpOr, OpOr},
		token.PLUS:        {OpIntAdd, OpDblAdd},
		token.MINUS:       {OpIntSub, OpDblSub},
		token.MULTIPLY:    {OpIntMul, OpDblMul},
		token.DIVIDE:      {OpIntDiv, OpDblDiv},
		token.MODULO:      {OpMod, OpMod},
		token.BitwiseAnd:  {OpBitwiseAnd, OpBitwiseAnd},
		token.BitwiseOr:   {OpBitwiseOr, OpBitwiseOr},
		token.BitwiseXor:  {OpBitwiseXor, OpBitwiseXor},
		token.LeftShift:   {OpShl, OpShl},
		token.RightShift:  {OpShr, OpShr},
		token.EQ:          {OpIntEq, OpDblEq},
		token.NEQ:         {OpIntNeq, OpDblNeq},
		token.LT:          {OpIntLt, OpDblLt},
		token.LE:          {OpIntLe, OpDblLe},
		token.GT:          {OpIntGt, OpDblGt},
		token.GE:          {OpIntGe, OpDblGe},
		token.CONTAINS:    {OpContains, OpContains},
		token.MATCHES:     {OpMatches, OpMatches},
		token.STARTSWITH:  {OpStartswith, OpStartswith},
		token.ENDSWITH:    {OpEndswith, OpEndswith},
		token.ICONTAINS:   {OpIcontains, OpIcontains},
		token.ISTARTSWITH: {OpIstartswith, OpIstartswith},
		token.IENDSWITH:   {OpIendswith, OpIendswith},
		token.IEQUALS:     {OpIequals, OpIequals},
		token.OF:          {OpOf, OpOf},
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

func (cc *ConditionCompiler) handleSpecialOperators(binOp *ast.BinaryOp) (bool, error) {
	switch binOp.Op {
	case token.AT, token.IN:
		return true, cc.compileStringOffsetOperator(binOp)
	case token.DOT:
		return true, cc.compileExpressions(binOp.Left, binOp.Right)
	case token.COMMA:
		// COMMA creates a string list for 'of' expressions
		return true, cc.compileCommaOperator(binOp)
	}
	return false, nil
}

func (cc *ConditionCompiler) compileBinaryOp(binOp *ast.BinaryOp) error {
	handled, err := cc.handleSpecialOperators(binOp)
	if err != nil {
		return err
	}
	if handled {
		return nil
	}

	if err := cc.compileOperands(binOp); err != nil {
		return err
	}

	leftIsFloat := cc.isFloatExpression(binOp.Left)
	rightIsFloat := cc.isFloatExpression(binOp.Right)
	leftIsString := cc.isStringExpression(binOp.Left)
	rightIsString := cc.isStringExpression(binOp.Right)
	isStringCompare := cc.isStringComparisonOperator(binOp.Op) && (leftIsString || rightIsString)
	isComparison := cc.isComparisonOperator(binOp.Op)
	isFloatOp := leftIsFloat || rightIsFloat

	if isStringCompare {
		opcode, err := cc.selectOpcode(binOp, false, true)
		if err != nil {
			return err
		}
		cc.emitter.EmitOpcode(opcode, binOp.Pos.Line, binOp.Pos.Column)
		return nil
	}

	if err := cc.handleFloatOperations(binOp, leftIsFloat, rightIsFloat, isComparison); err != nil {
		return err
	}

	opcode, err := cc.selectOpcode(binOp, isFloatOp, false)
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
	case token.StringLength:
		return cc.compileStringLengthOperator(unaryOp)
	case token.NOT:
		return cc.compileNotOperator(unaryOp)
	case token.BitwiseNot:
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

	// Push string identifier for count operation.
	cc.emitStringIdentifier(offset, id.Name, unaryOp.Pos.Line, unaryOp.Pos.Column)
	cc.emitter.EmitOpcode(OpCount, unaryOp.Pos.Line, unaryOp.Pos.Column)
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

	// Push string identifier for offset operation.
	cc.emitStringIdentifier(offset, id.Name, unaryOp.Pos.Line, unaryOp.Pos.Column)
	cc.emitter.EmitPush(1, unaryOp.Pos.Line, unaryOp.Pos.Column) // Default to first match (1-based)
	cc.emitter.EmitOpcode(OpOffset, unaryOp.Pos.Line, unaryOp.Pos.Column)
	return nil
}

func (cc *ConditionCompiler) compileStringLengthOperator(unaryOp *ast.UnaryOp) error {
	id, ok := unaryOp.Right.(*ast.Identifier)
	if !ok {
		return errors.New("STRING LENGTH (!) expects a string identifier operand")
	}

	offset, exists := cc.findStringOffset(id.Name)
	if !exists {
		return fmt.Errorf("undefined string identifier for string length operator: %s", id.Name)
	}

	// Push string identifier for length operation.
	cc.emitStringIdentifier(offset, id.Name, unaryOp.Pos.Line, unaryOp.Pos.Column)
	cc.emitter.EmitPush(1, unaryOp.Pos.Line, unaryOp.Pos.Column) // Default to first match (1-based)
	cc.emitter.EmitOpcode(OpLength, unaryOp.Pos.Line, unaryOp.Pos.Column)
	return nil
}

func (cc *ConditionCompiler) compileNotOperator(unaryOp *ast.UnaryOp) error {
	if id, ok := unaryOp.Right.(*ast.Identifier); ok {
		if offset, exists := cc.findStringOffset(id.Name); exists {
			cc.emitStringIdentifier(offset, id.Name, unaryOp.Pos.Line, unaryOp.Pos.Column)
			cc.emitter.EmitOpcode(OpLength, unaryOp.Pos.Line, unaryOp.Pos.Column)
			return nil
		}
		return fmt.Errorf("undefined string identifier for length operator: %s", id.Name)
	}

	if err := cc.compileExpression(unaryOp.Right); err != nil {
		return err
	}
	cc.emitter.EmitOpcode(OpNot, unaryOp.Pos.Line, unaryOp.Pos.Column)
	return nil
}

func (cc *ConditionCompiler) compileBitwiseNotOperator(unaryOp *ast.UnaryOp) error {
	if err := cc.compileExpression(unaryOp.Right); err != nil {
		return err
	}
	cc.emitter.EmitOpcode(OpBitwiseNot, unaryOp.Pos.Line, unaryOp.Pos.Column)
	return nil
}

func (cc *ConditionCompiler) compileMinusOperator(unaryOp *ast.UnaryOp) error {
	if err := cc.compileExpression(unaryOp.Right); err != nil {
		return err
	}

	if cc.isLiteralFloat(unaryOp.Right) {
		cc.emitter.EmitOpcode(OpDblMinus, unaryOp.Pos.Line, unaryOp.Pos.Column)
	} else {
		cc.emitter.EmitOpcode(OpIntMinus, unaryOp.Pos.Line, unaryOp.Pos.Column)
	}
	return nil
}

func (cc *ConditionCompiler) compileDefinedOperator(unaryOp *ast.UnaryOp) error {
	if err := cc.compileExpression(unaryOp.Right); err != nil {
		return err
	}
	cc.emitter.EmitOpcode(OpDefined, unaryOp.Pos.Line, unaryOp.Pos.Column)
	return nil
}

// compileStringLength compiles string length expressions (!a or !a[i])
func (cc *ConditionCompiler) compileStringLength(strLen *ast.StringLength) error {
	id, ok := strLen.String.(*ast.Identifier)
	if !ok {
		return errors.New("STRING LENGTH (!) expects a string identifier operand")
	}

	offset, exists := cc.findStringOffset(id.Name)
	if !exists {
		return fmt.Errorf("undefined string identifier for string length operator: %s", id.Name)
	}

	cc.emitStringIdentifier(offset, id.Name, strLen.Pos.Line, strLen.Pos.Column)

	// If there's an index, compile it and push it
	if strLen.Index != nil {
		if err := cc.compileExpression(strLen.Index); err != nil {
			return err
		}
	} else {
		// Default to first match (1-based)
		cc.emitter.EmitPush(1, strLen.Pos.Line, strLen.Pos.Column)
	}

	cc.emitter.EmitOpcode(OpLength, strLen.Pos.Line, strLen.Pos.Column)
	return nil
}

// compileStringOffset compiles string offset expressions (@a or @a[i])
func (cc *ConditionCompiler) compileStringOffset(strOffset *ast.StringOffset) error {
	id, ok := strOffset.String.(*ast.Identifier)
	if !ok {
		return errors.New("STRING OFFSET (@) expects a string identifier operand")
	}

	offset, exists := cc.findStringOffset(id.Name)
	if !exists {
		return fmt.Errorf("undefined string identifier for string offset operator: %s", id.Name)
	}

	cc.emitStringIdentifier(offset, id.Name, strOffset.Pos.Line, strOffset.Pos.Column)

	// If there's an index, compile it and push it
	if strOffset.Index != nil {
		if err := cc.compileExpression(strOffset.Index); err != nil {
			return err
		}
	} else {
		// Default to first match (1-based)
		cc.emitter.EmitPush(1, strOffset.Pos.Line, strOffset.Pos.Column)
	}

	cc.emitter.EmitOpcode(OpOffset, strOffset.Pos.Line, strOffset.Pos.Column)
	return nil
}

// compileStringCount compiles string count expressions (#a)
func (cc *ConditionCompiler) compileStringCount(strCount *ast.StringCount) error {
	id, ok := strCount.String.(*ast.Identifier)
	if !ok {
		return errors.New("STRING COUNT (#) expects a string identifier operand")
	}

	offset, exists := cc.findStringOffset(id.Name)
	if !exists {
		return fmt.Errorf("undefined string identifier for string count operator: %s", id.Name)
	}

	cc.emitStringIdentifier(offset, id.Name, strCount.Pos.Line, strCount.Pos.Column)
	cc.emitter.EmitOpcode(OpCount, strCount.Pos.Line, strCount.Pos.Column)
	return nil
}

/*
// func (cc *ConditionCompiler) compileArrayIndex(arrayIndex *ast.ArrayIndex) error {
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
		return fmt.Errorf("%s operator expects a string identifier", map[token.Type]string{
			token.AT: "@", token.HASH: "#",
		}[unaryOp.Op])
	}

	offset, hasOffset := cc.stringOffsets[ident.Name]
	if !hasOffset {
		return fmt.Errorf("undefined string identifier: %s", ident.Name)
	}

	cc.emitter.EmitOpcodeWithOperand(OpPushM, Operand{Type: OperandImmediate64, Value: uint64(int64(offset))}, arrayIndex.Pos.Line, arrayIndex.Pos.Column) // #nosec G115

	marker := int64(0)
	if unaryOp.Op == token.HASH {
		marker = 1
	}
	cc.emitter.EmitPush(safeInt64ToUint64(marker), arrayIndex.Pos.Line, arrayIndex.Pos.Column)
	cc.emitter.EmitOpcode(OpIndexArray, arrayIndex.Pos.Line, arrayIndex.Pos.Column)
	return nil
}
*/

// AddVariable adds a variable to the compiler's variable map
func (cc *ConditionCompiler) AddVariable(name string, index int) {
	cc.variableMap[name] = index
}

// GetVariableIndex retrieves the index of a variable
func (cc *ConditionCompiler) GetVariableIndex(name string) (int, bool) {
	index, exists := cc.variableMap[name]
	return index, exists
}

// CompileBooleanExpression compiles a boolean expression to bytecode
func (cc *ConditionCompiler) CompileBooleanExpression(expr ast.Expression, shortCircuit bool) error {
	if !shortCircuit {
		return cc.compileExpression(expr)
	}

	if binOp, ok := expr.(*ast.BinaryOp); ok {
		switch binOp.Op {
		case token.AND:
			return cc.compileShortCircuitBinary(binOp, OpJfalse, OpAnd)
		case token.OR:
			return cc.compileShortCircuitBinary(binOp, OpJtrue, OpOr)
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

// GetVariableMap returns the compiler's variable map
func (cc *ConditionCompiler) GetVariableMap() map[string]int {
	return cc.variableMap
}

// GetExternalVariables returns the compiler's external variables map
func (cc *ConditionCompiler) GetExternalVariables() map[string]int {
	return cc.externalVariables
}

// SetStringOffsets sets the string offsets for the compiler
func (cc *ConditionCompiler) SetStringOffsets(offsets map[string]int) {
	cc.stringOffsets = offsets
}

// SetAnonymousStrings sets the anonymous string identifiers for the current rule.
func (cc *ConditionCompiler) SetAnonymousStrings(ids []string) {
	cc.anonymousStrings = nil
	if len(ids) == 0 {
		return
	}
	cc.anonymousStrings = make([]string, len(ids))
	copy(cc.anonymousStrings, ids)
}

// GetStringSets returns the compiled string sets for this condition.
func (cc *ConditionCompiler) GetStringSets() [][]string {
	sets := make([][]string, len(cc.stringSets))
	for i, set := range cc.stringSets {
		copied := make([]string, len(set))
		copy(copied, set)
		sets[i] = copied
	}
	return sets
}

// ResetForRule clears per-rule state while preserving external/rule variable maps.
func (cc *ConditionCompiler) ResetForRule() {
	cc.labelCounter = 0
	cc.labels = make(map[string]int)
	cc.pendingJumps = cc.pendingJumps[:0]
	cc.stringSets = cc.stringSets[:0]
	cc.stringSetIndex = make(map[string]int)
}

// GetStats returns compilation statistics
func (cc *ConditionCompiler) GetStats() map[string]any {
	return map[string]any{
		"variables":     len(cc.variableMap),
		"label_counter": cc.labelCounter,
	}
}

// ValidateExpression validates an expression
func (cc *ConditionCompiler) ValidateExpression(expr ast.Expression) error {
	savedEmitter := cc.emitter
	cc.emitter = NewEmitter()
	defer func() { cc.emitter = savedEmitter }()
	return cc.compileExpression(expr)
}

// OptimizeExpression optimizes an expression
func (cc *ConditionCompiler) OptimizeExpression(expr ast.Expression) ast.Expression {
	return expr
}

// EstimateComplexity estimates the complexity of an expression
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

// JumpPosition represents a position for a jump operation
type JumpPosition struct {
	Line   int
	Column int
}

// ConditionalJumpConfig represents configuration for conditional jumps
type ConditionalJumpConfig struct {
	Opcode      Opcode
	TargetLabel string
	Position    JumpPosition
}

// EmitJump emits a jump operation
func (cc *ConditionCompiler) EmitJump(config ConditionalJumpConfig) error {
	cc.emitJumpWithLabel(config.Opcode, config.TargetLabel, config.Position.Line, config.Position.Column)
	return nil
}

func (cc *ConditionCompiler) compileShortCircuitAnd(andOp *ast.BinaryOp) error {
	return cc.compileShortCircuitBinary(andOp, OpJfalse, OpAnd)
}

func (cc *ConditionCompiler) compileShortCircuitOr(orOp *ast.BinaryOp) error {
	return cc.compileShortCircuitBinary(orOp, OpJtrue, OpOr)
}

func (cc *ConditionCompiler) compileForLoop(forLoop *ast.ForLoop) error {
	if forLoop.Variable == "" {
		return cc.compileForLoopOverStrings(forLoop)
	}

	start, end, ok := cc.extractForLoopRange(forLoop.Range)
	if !ok {
		return fmt.Errorf("unsupported for-loop range")
	}
	if end < start {
		return fmt.Errorf("invalid for-loop range: %d..%d", start, end)
	}
	const maxUnroll = 1024
	if end-start+1 > maxUnroll {
		return fmt.Errorf("for-loop range too large (%d); max %d supported", end-start+1, maxUnroll)
	}

	expressions := make([]ast.Expression, 0, end-start+1)
	for i := start; i <= end; i++ {
		lit := &ast.Literal{Type: token.IntegerLit, Value: i, Pos: forLoop.Pos}
		expr := cc.replaceIdentifier(forLoop.Condition, forLoop.Variable, lit)
		expressions = append(expressions, expr)
	}

	return cc.compileForLoopExpressions(forLoop.Quantifier, expressions, forLoop.Pos)
}

func (cc *ConditionCompiler) compileForLoopOverStrings(forLoop *ast.ForLoop) error {
	var ids []string
	if expr, ok := forLoop.Range.(*ast.Identifier); ok {
		if expr.Name == "them" {
			ids = cc.allStringIdentifiers()
		}
		if expr.Name == "$" {
			ids = cc.anonymousStringIdentifiers()
		}
	}
	if ids == nil {
		var err error
		ids, err = cc.collectStringSet(forLoop.Range)
		if err != nil {
			return err
		}
	}
	if len(ids) == 0 {
		return cc.compileForLoopExpressions(forLoop.Quantifier, nil, forLoop.Pos)
	}

	expressions := make([]ast.Expression, 0, len(ids))
	for _, id := range ids {
		replacement := &ast.Identifier{Name: id, Pos: forLoop.Pos}
		expr := cc.replaceIdentifier(forLoop.Condition, "$", replacement)
		expressions = append(expressions, expr)
	}

	return cc.compileForLoopExpressions(forLoop.Quantifier, expressions, forLoop.Pos)
}

func (cc *ConditionCompiler) compileForLoopExpressions(quantifier string, exprs []ast.Expression, pos token.Position) error {
	if len(exprs) == 0 {
		// Empty range: any => false, all/none => true
		result := int64(0)
		switch quantifier {
		case QuantifierAll, QuantifierNone:
			result = 1
		default:
			if count, ok := parseNumericQuantifier(quantifier); ok && count <= 0 {
				result = 1
			}
		}
		cc.emitter.EmitPush(uint64(result), pos.Line, pos.Column) // #nosec G115
		return nil
	}

	switch quantifier {
	case QuantifierAny:
		return cc.compileBooleanFold(exprs, OpOr)
	case QuantifierAll:
		return cc.compileBooleanFold(exprs, OpAnd)
	case QuantifierNone:
		negated := make([]ast.Expression, 0, len(exprs))
		for _, expr := range exprs {
			negated = append(negated, &ast.UnaryOp{Op: token.NOT, Right: expr, Pos: pos})
		}
		return cc.compileBooleanFold(negated, OpAnd)
	default:
		if count, ok := parseNumericQuantifier(quantifier); ok {
			return cc.compileNumericForLoop(exprs, count, pos)
		}
		return fmt.Errorf("unsupported for-loop quantifier: %s", quantifier)
	}
}

func parseNumericQuantifier(quantifier string) (int64, bool) {
	if quantifier == "" {
		return 0, false
	}
	val, err := strconv.ParseInt(quantifier, 10, 64)
	if err != nil {
		return 0, false
	}
	return val, true
}

func (cc *ConditionCompiler) compileNumericForLoop(exprs []ast.Expression, count int64, pos token.Position) error {
	if count <= 0 {
		cc.emitter.EmitPush(1, pos.Line, pos.Column)
		return nil
	}
	if err := cc.compileExpression(exprs[0]); err != nil {
		return err
	}
	for i := 1; i < len(exprs); i++ {
		if err := cc.compileExpression(exprs[i]); err != nil {
			return err
		}
		cc.emitter.EmitOpcode(OpIntAdd, pos.Line, pos.Column)
	}
	cc.emitter.EmitPush(uint64(count), pos.Line, pos.Column) // #nosec G115
	cc.emitter.EmitOpcode(OpIntGe, pos.Line, pos.Column)
	return nil
}

func (cc *ConditionCompiler) compileBooleanFold(exprs []ast.Expression, op Opcode) error {
	if len(exprs) == 0 {
		return nil
	}
	if err := cc.compileExpression(exprs[0]); err != nil {
		return err
	}
	for i := 1; i < len(exprs); i++ {
		if err := cc.compileExpression(exprs[i]); err != nil {
			return err
		}
		cc.emitter.EmitOpcode(op, 0, 0)
	}
	return nil
}

func (cc *ConditionCompiler) extractForLoopRange(expr ast.Expression) (int64, int64, bool) {
	switch e := expr.(type) {
	case *ast.BinaryOp:
		if e.Op != token.DOT {
			return 0, 0, false
		}
		start, ok := cc.extractIntLiteral(e.Left)
		if !ok {
			return 0, 0, false
		}
		end, ok := cc.extractIntLiteral(e.Right)
		if !ok {
			return 0, 0, false
		}
		return start, end, true
	default:
		val, ok := cc.extractIntLiteral(expr)
		if !ok {
			return 0, 0, false
		}
		return val, val, true
	}
}

func (cc *ConditionCompiler) extractIntLiteral(expr ast.Expression) (int64, bool) {
	lit, ok := expr.(*ast.Literal)
	if !ok {
		return 0, false
	}
	switch v := lit.Value.(type) {
	case int64:
		return v, true
	case int:
		return int64(v), true
	case string:
		if i, err := strconv.ParseInt(v, 0, 64); err == nil {
			return i, true
		}
	}
	return 0, false
}

func (cc *ConditionCompiler) replaceIdentifier(expr ast.Expression, name string, replacement ast.Expression) ast.Expression {
	switch e := expr.(type) {
	case *ast.Identifier:
		if e.Name == name {
			return replacement
		}
		return e
	case *ast.Literal:
		return e
	case *ast.BinaryOp:
		return &ast.BinaryOp{
			Op:    e.Op,
			Left:  cc.replaceIdentifier(e.Left, name, replacement),
			Right: cc.replaceIdentifier(e.Right, name, replacement),
			Pos:   e.Pos,
		}
	case *ast.UnaryOp:
		return &ast.UnaryOp{
			Op:    e.Op,
			Right: cc.replaceIdentifier(e.Right, name, replacement),
			Pos:   e.Pos,
		}
	case *ast.FunctionCall:
		args := make([]ast.Expression, len(e.Args))
		for i, arg := range e.Args {
			args[i] = cc.replaceIdentifier(arg, name, replacement)
		}
		return &ast.FunctionCall{
			Pos:      e.Pos,
			Function: e.Function,
			Args:     args,
		}
	case *ast.StringCount:
		var idx ast.Expression
		if e.Index != nil {
			idx = cc.replaceIdentifier(e.Index, name, replacement)
		}
		return &ast.StringCount{
			Pos:    e.Pos,
			String: cc.replaceIdentifier(e.String, name, replacement),
			Index:  idx,
		}
	case *ast.StringOffset:
		var idx ast.Expression
		if e.Index != nil {
			idx = cc.replaceIdentifier(e.Index, name, replacement)
		}
		return &ast.StringOffset{
			Pos:    e.Pos,
			String: cc.replaceIdentifier(e.String, name, replacement),
			Index:  idx,
		}
	case *ast.StringLength:
		var idx ast.Expression
		if e.Index != nil {
			idx = cc.replaceIdentifier(e.Index, name, replacement)
		}
		return &ast.StringLength{
			Pos:    e.Pos,
			String: cc.replaceIdentifier(e.String, name, replacement),
			Index:  idx,
		}
	case *ast.OfExpression:
		return &ast.OfExpression{
			Pos:     e.Pos,
			Count:   cc.replaceIdentifier(e.Count, name, replacement),
			Strings: cc.replaceIdentifier(e.Strings, name, replacement),
		}
	}
	return expr
}

func (cc *ConditionCompiler) compileOfExpression(ofExpr *ast.OfExpression) error {
	if err := cc.compileCountExpression(ofExpr.Count); err != nil {
		return fmt.Errorf("compiling count expression in of-expression: %w", err)
	}

	if err := cc.compileStringsExpression(ofExpr.Strings); err != nil {
		return fmt.Errorf("compiling strings expression in of-expression: %w", err)
	}

	cc.emitter.EmitOpcode(OpOf, ofExpr.Pos.Line, ofExpr.Pos.Column)
	return nil
}

func (cc *ConditionCompiler) compileCountExpression(countExpr ast.Expression) error {
	if ident, ok := countExpr.(*ast.Identifier); ok {
		switch ident.Name {
		case QuantifierAny:
			cc.emitter.EmitPush(1, ident.Pos.Line, ident.Pos.Column)
			return nil
		case QuantifierAll:
			cc.emitter.EmitPush(0xFFFFFFFF, ident.Pos.Line, ident.Pos.Column)
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
			cc.emitter.EmitPush(stringSetAll, ident.Pos.Line, ident.Pos.Column)
			return nil
		case ident.Name == "$":
			cc.emitter.EmitPush(stringSetAnonymous, ident.Pos.Line, ident.Pos.Column)
			return nil
		case cc.isRuleReference(ident.Name):
			return cc.compileRuleReference(ident.Name, ident.Pos.Line, ident.Pos.Column)
		case cc.isStringSetIdentifier(ident.Name):
			ids, err := cc.expandStringSetIdentifier(ident.Name)
			if err != nil {
				return err
			}
			index := cc.internStringSet(ids)
			cc.emitter.EmitPush(uint64(index), ident.Pos.Line, ident.Pos.Column)
			return nil
		}
	}
	if binOp, ok := stringsExpr.(*ast.BinaryOp); ok && binOp.Op == token.COMMA {
		ids, err := cc.collectStringSetFromComma(binOp)
		if err != nil {
			return err
		}
		index := cc.internStringSet(ids)
		cc.emitter.EmitPush(uint64(index), binOp.Pos.Line, binOp.Pos.Column)
		return nil
	}
	return cc.compileExpression(stringsExpr)
}

func (cc *ConditionCompiler) isStringSetIdentifier(name string) bool {
	if name == "$" {
		return true
	}
	if strings.HasSuffix(name, "*") {
		return strings.HasPrefix(name, "$")
	}
	_, exists := cc.stringOffsets[name]
	if exists {
		return true
	}
	_, exists = cc.stringOffsets["$"+name]
	return exists
}

func (cc *ConditionCompiler) expandStringSetIdentifier(name string) ([]string, error) {
	if name == "$" {
		return cc.anonymousStringIdentifiers(), nil
	}
	if before, ok := strings.CutSuffix(name, "*"); ok {
		prefix := before
		return cc.matchingStringIdentifiers(prefix), nil
	}
	if _, ok := cc.stringOffsets[name]; ok {
		return []string{name}, nil
	}
	if _, ok := cc.stringOffsets["$"+name]; ok {
		return []string{"$" + name}, nil
	}
	return nil, fmt.Errorf("undefined string identifier: %s", name)
}

func (cc *ConditionCompiler) matchingStringIdentifiers(prefix string) []string {
	matches := make([]string, 0)
	for ident := range cc.stringOffsets {
		if strings.HasPrefix(ident, prefix) {
			matches = append(matches, ident)
		}
	}
	sort.Strings(matches)
	return matches
}

func (cc *ConditionCompiler) allStringIdentifiers() []string {
	ids := make([]string, 0, len(cc.stringOffsets))
	for ident := range cc.stringOffsets {
		ids = append(ids, ident)
	}
	sort.Strings(ids)
	return ids
}

func (cc *ConditionCompiler) anonymousStringIdentifiers() []string {
	if len(cc.anonymousStrings) == 0 {
		return nil
	}
	ids := make([]string, len(cc.anonymousStrings))
	copy(ids, cc.anonymousStrings)
	sort.Strings(ids)
	return ids
}

func (cc *ConditionCompiler) collectStringSetFromComma(expr *ast.BinaryOp) ([]string, error) {
	leftIDs, err := cc.collectStringSet(expr.Left)
	if err != nil {
		return nil, err
	}
	rightIDs, err := cc.collectStringSet(expr.Right)
	if err != nil {
		return nil, err
	}
	leftIDs = append(leftIDs, rightIDs...)
	return cc.uniqueSortedStrings(leftIDs), nil
}

func (cc *ConditionCompiler) collectStringSet(expr ast.Expression) ([]string, error) {
	switch e := expr.(type) {
	case *ast.Identifier:
		return cc.expandStringSetIdentifier(e.Name)
	case *ast.BinaryOp:
		if e.Op == token.COMMA {
			return cc.collectStringSetFromComma(e)
		}
	}
	return nil, fmt.Errorf("unsupported string set expression")
}

func (cc *ConditionCompiler) uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	sort.Strings(values)
	out := make([]string, 0, len(values))
	var last string
	for i, v := range values {
		if i == 0 || v != last {
			out = append(out, v)
			last = v
		}
	}
	return out
}

func (cc *ConditionCompiler) internStringSet(ids []string) int {
	normalized := cc.uniqueSortedStrings(append([]string(nil), ids...))
	key := strings.Join(normalized, "\x00")
	if idx, ok := cc.stringSetIndex[key]; ok {
		return idx
	}
	idx := len(cc.stringSets)
	cc.stringSets = append(cc.stringSets, normalized)
	cc.stringSetIndex[key] = idx
	return idx
}

func (cc *ConditionCompiler) compileFunctionCall(call *ast.FunctionCall) error {
	for i := 0; i < len(call.Args); i++ {
		if err := cc.compileExpression(call.Args[i]); err != nil {
			return fmt.Errorf("compiling function argument %d: %w", i, err)
		}
	}

	functionOpcodes := map[string]Opcode{
		// Data type conversion functions
		"uint8": OpUint8, "uint16": OpUint16, "uint32": OpUint32, "uint64": OpUint64,
		"uint8be": OpUint8be, "uint16be": OpUint16be, "uint32be": OpUint32be, "uint64be": OpUint64be,
		"int8": OpInt8, "int16": OpInt16, "int32": OpInt32, "int64": OpInt64,
		"int8be": OpInt8be, "int16be": OpInt16be, "int32be": OpInt32be, "int64be": OpInt64be,

		// Logical/text functions backed by opcodes
		"defined": OpDefined,
	}

	if opcode, exists := functionOpcodes[call.Function]; exists {
		cc.emitter.EmitOpcode(opcode, call.Pos.Line, call.Pos.Column)
		return nil
	}

	switch call.Function {
	case "concat":
		if len(call.Args) < 2 {
			return fmt.Errorf("concat requires at least 2 arguments")
		}
		cc.emitter.EmitOpcodeWithOperand(OpCall,
			Operand{Type: OperandImmediate32, Value: encodeBuiltinCall(builtinConcat, len(call.Args))},
			call.Pos.Line, call.Pos.Column)
		return nil
	case "tostring":
		if len(call.Args) != 1 {
			return fmt.Errorf("tostring requires exactly 1 argument")
		}
		cc.emitter.EmitOpcodeWithOperand(OpCall,
			Operand{Type: OperandImmediate32, Value: encodeBuiltinCall(builtinToString, len(call.Args))},
			call.Pos.Line, call.Pos.Column)
		return nil
	case "int":
		if len(call.Args) != 1 {
			return fmt.Errorf("int requires exactly 1 argument")
		}
		cc.emitter.EmitOpcodeWithOperand(OpCall,
			Operand{Type: OperandImmediate32, Value: encodeBuiltinCall(builtinInt, len(call.Args))},
			call.Pos.Line, call.Pos.Column)
		return nil
	case "md5":
		if len(call.Args) != 1 && len(call.Args) != 2 {
			return fmt.Errorf("md5 requires 1 or 2 arguments")
		}
		cc.emitter.EmitOpcodeWithOperand(OpCall,
			Operand{Type: OperandImmediate32, Value: encodeBuiltinCall(builtinMD5, len(call.Args))},
			call.Pos.Line, call.Pos.Column)
		return nil
	case "sha1":
		if len(call.Args) != 1 && len(call.Args) != 2 {
			return fmt.Errorf("sha1 requires 1 or 2 arguments")
		}
		cc.emitter.EmitOpcodeWithOperand(OpCall,
			Operand{Type: OperandImmediate32, Value: encodeBuiltinCall(builtinSHA1, len(call.Args))},
			call.Pos.Line, call.Pos.Column)
		return nil
	case "sha256":
		if len(call.Args) != 1 && len(call.Args) != 2 {
			return fmt.Errorf("sha256 requires 1 or 2 arguments")
		}
		cc.emitter.EmitOpcodeWithOperand(OpCall,
			Operand{Type: OperandImmediate32, Value: encodeBuiltinCall(builtinSHA256, len(call.Args))},
			call.Pos.Line, call.Pos.Column)
		return nil
	default:
		return fmt.Errorf("unsupported function: %s", call.Function)
	}
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

	cc.emitter.EmitOpcodeWithOperand(OpPushRuleRef,
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

func (cc *ConditionCompiler) emitModuleFunctionCall(_ string, line, column int) {
	cc.emitter.EmitPush(0, line, column)
}
