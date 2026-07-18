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
	globalVariables   map[string]int
	ruleIndexMap      map[string]int
	labelCounter      int
	labels            map[string]int
	pendingJumps      []PendingJump
	stringSets        [][]string
	stringSetIndex    map[string]int
	anonymousStrings  []string
	textStringSets    [][]string
	moduleFunctions   map[string]compiledModuleFunction

	// loopVarSlots tracks the memory slot for the loop variable of each
	// enclosing for-loop. For "for any of them : ($)" the slot holds the
	// current iteration's string identifier, and "$" in the body must load
	// that slot (OpLoadVar + OpFound) instead of compiling as OpOf against
	// the whole rule's anonymous set. Without this, "for all of them : ($)"
	// returns true whenever any string matches, ignoring whether the *current*
	// string matched. Slots are pushed/popped around the loop body.
	loopVarSlots []int
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
		globalVariables:   make(map[string]int),
		ruleIndexMap:      make(map[string]int),
		moduleFunctions:   make(map[string]compiledModuleFunction),
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

//nolint:revive // argument-limit: internal helper
func (cc *ConditionCompiler) emitJumpWithLabel(opcode Opcode, label string, line, column int) {
	pos := cc.emitter.GetLength()
	cc.pendingJumps = append(cc.pendingJumps, PendingJump{
		Opcode:   opcode,
		Label:    label,
		Position: pos,
		Line:     line,
		Column:   column,
	})
	cc.emitter.EmitOpcodeWithOperand(opcode, Operand{Type: OperandRelative32, Value: 0}, line, column)
}

func (cc *ConditionCompiler) resolveJumps() error {
	for _, jump := range cc.pendingJumps {
		targetOffset, exists := cc.labels[jump.Label]
		if !exists {
			return fmt.Errorf("undefined label: %s", jump.Label)
		}

		// Find the instruction index corresponding to the byte offset
		instIndex, err := cc.emitter.FindInstructionIndexByOffset(jump.Position)
		if err != nil {
			return fmt.Errorf("failed to find instruction at offset %d: %w", jump.Position, err)
		}

		inst := cc.emitter.GetInstruction(instIndex)
		instEnd := jump.Position + inst.Size()
		relativeOffset := targetOffset - instEnd

		// #nosec G115 - safe conversion with explicit bounds checking
		if err := cc.emitter.UpdateOperandByIndex(instIndex, Operand{Type: OperandRelative32, Value: uint64(int64(relativeOffset))}); err != nil {
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

//nolint:revive // argument-limit: internal helper
func (cc *ConditionCompiler) emitStringIdentifier(offset int, identifier string, line, column int) {
	_ = offset
	if len(identifier) > 0 && identifier[0] != '$' {
		identifier = "$" + identifier
	}
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

// compileMatchesExpression compiles "<string_identifier> matches <regex>"
// For the left operand (string identifier), it pushes the identifier string directly.
// For the right operand (regex), it pushes the regex pattern string.
// Then it emits OpMatches.
func (cc *ConditionCompiler) compileMatchesExpression(binOp *ast.BinaryOp) error {
	// Left operand: string identifier
	leftIdent, ok := binOp.Left.(*ast.Identifier)
	if !ok {
		return fmt.Errorf("MATCHES requires a string identifier on the left")
	}

	// Look up the string identifier in stringOffsets
	offset, exists := cc.findStringOffset(leftIdent.Name)
	if !exists {
		return fmt.Errorf("undefined string identifier for MATCHES: %s", leftIdent.Name)
	}

	// Emit the string identifier (pushes the identifier string, not a boolean)
	cc.emitStringIdentifier(offset, leftIdent.Name, leftIdent.Pos.Line, leftIdent.Pos.Column)

	// Right operand: regex pattern
	switch right := binOp.Right.(type) {
	case *ast.Literal:
		if right.Type != token.RegexLit {
			return fmt.Errorf("MATCHES requires a regex pattern on the right")
		}
		cc.compileRegexLiteral(right)
	case *ast.Identifier:
		// Loop variable containing the regex pattern
		slot, exists := cc.variableMap[right.Name]
		if !exists {
			return fmt.Errorf("undefined identifier in MATCHES: %s", right.Name)
		}
		cc.emitter.EmitOpcodeWithOperand(OpLoadVar, Operand{Type: OperandImmediate32, Value: safeInt64ToUint64(safeMax(0, int64(slot)))}, right.Pos.Line, right.Pos.Column)
	default:
		return fmt.Errorf("MATCHES requires a regex pattern on the right")
	}

	// Emit the MATCHES operation
	cc.emitter.EmitOpcode(OpMatches, binOp.Pos.Line, binOp.Pos.Column)
	return nil
}

// compileBinaryOp compiles a binary operation expression
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
	case *ast.LengthOf:
		return cc.compileLengthOf(e)
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
		return
	}

	if strValue, ok := lit.Value.(string); ok {
		// Handle case where literal value is stored as string (parse it)
		intVal, err := parseIntLiteral(strValue)
		if err == nil {
			cc.emitter.EmitPush(safeInt64ToUint64(safeMax(0, intVal)), lit.Pos.Line, lit.Pos.Column)
			return
		}
	}

	cc.emitter.EmitPush(0, lit.Pos.Line, lit.Pos.Column)
}

// parseIntLiteral parses a string as an integer literal.
//
// Base 0 lets strconv auto-detect the prefix: "0x" -> hexadecimal, "0o" ->
// octal, otherwise decimal. The lexer preserves the prefix in the token
// literal for HexIntegerLit and OctalIntegerLit, so a fixed base-10 parse
// would silently fail and compile those literals to 0. This matches the
// convention used by the other literal-parsing call sites in the codebase
// (declaration_parser, quantifier_parser, rule_compiler).
func parseIntLiteral(s string) (int64, error) {
	return strconv.ParseInt(s, 0, 64)
}

// compileFloatLiteral compiles float literals
func (cc *ConditionCompiler) compileFloatLiteral(lit *ast.Literal) {
	if value, ok := lit.Value.(float64); ok {
		cc.emitter.EmitPushDouble(value, lit.Pos.Line, lit.Pos.Column)
		return
	}
	if value, ok := lit.Value.(string); ok {
		if parsed, err := strconv.ParseFloat(value, 64); err == nil {
			cc.emitter.EmitPushDouble(parsed, lit.Pos.Line, lit.Pos.Column)
		}
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
	// Inside a for-loop over strings, "$" is the loop placeholder: it must
	// resolve to the current iteration's string (held in the loop variable's
	// memory slot) and check whether that specific string matched. This check
	// must come before the stringOffsets lookup below, which has its own "$"
	// entry for the rule's anonymous strings and would otherwise capture it.
	if ident.Name == "$" && len(cc.loopVarSlots) > 0 && cc.loopVarSlots[len(cc.loopVarSlots)-1] >= 0 {
		slot := cc.loopVarSlots[len(cc.loopVarSlots)-1]
		cc.emitter.EmitOpcodeWithOperand(OpLoadVar, Operand{Type: OperandImmediate32, Value: uint64(slot)}, ident.Pos.Line, ident.Pos.Column)
		cc.emitter.EmitOpcode(OpFound, ident.Pos.Line, ident.Pos.Column)
		return nil
	}

	if offset, exists := cc.stringOffsets[ident.Name]; exists {
		cc.emitStringIdentifier(offset, ident.Name, ident.Pos.Line, ident.Pos.Column)
		cc.emitter.EmitOpcode(OpFound, ident.Pos.Line, ident.Pos.Column)
		return nil
	}

	if index, exists := cc.externalVariables[ident.Name]; exists {
		cc.emitter.EmitOpcodeWithOperand(OpPushM, Operand{Type: OperandImmediate32, Value: uint64(int64(index))}, ident.Pos.Line, ident.Pos.Column) // #nosec G115
		return nil
	}

	if index, exists := cc.globalVariables[ident.Name]; exists {
		cc.emitter.EmitOpcodeWithOperand(OpPushM, Operand{Type: OperandImmediate32, Value: uint64(int64(index))}, ident.Pos.Line, ident.Pos.Column) // #nosec G115
		return nil
	}

	if index, exists := cc.variableMap[ident.Name]; exists {
		cc.emitter.EmitOpcodeWithOperand(OpLoadVar, Operand{Type: OperandImmediate32, Value: safeInt64ToUint64(safeMax(0, int64(index)))}, ident.Pos.Line, ident.Pos.Column)
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

	if moduleName, ok := moduleNameFromDottedName(ident.Name); ok {
		return cc.emitModuleFunctionCall(moduleName, ident.Pos.Line, ident.Pos.Column)
	}

	cc.emitter.EmitOpcode(OpPushU, ident.Pos.Line, ident.Pos.Column)
	return fmt.Errorf("undefined identifier: %s", ident.Name)

}

func (cc *ConditionCompiler) compileAnonymousIdentifier(line, column int) error {
	// Inside a for-loop over strings, "$" is the loop placeholder: it must
	// resolve to the current iteration's string identifier (held in the
	// loop variable's memory slot) and check whether that specific string
	// matched. Compiling it as OpOf against the whole rule's anonymous set
	// is the bug: it asks "does any string match?" on every iteration,
	// inflating the count and making "for all of them : ($)" true whenever
	// a single string matches.
	if n := len(cc.loopVarSlots); n > 0 && cc.loopVarSlots[n-1] >= 0 {
		cc.emitter.EmitOpcodeWithOperand(OpLoadVar, Operand{Type: OperandImmediate32, Value: uint64(cc.loopVarSlots[n-1])}, line, column)
		cc.emitter.EmitOpcode(OpFound, line, column)
		return nil
	}

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

	// "$" as the left operand is the for-loop placeholder: it refers to the
	// current iteration's string, whose StringRef is held in the active loop
	// variable's memory slot. Load it directly instead of looking up a fixed
	// string offset ("$" has no fixed offset). This makes "$ at <offset>" and
	// "$ in (range)" work inside for-loop bodies, mirroring how "$" alone is
	// compiled in compileIdentifier.
	if id.Name == "$" && len(cc.loopVarSlots) > 0 && cc.loopVarSlots[len(cc.loopVarSlots)-1] >= 0 {
		slot := cc.loopVarSlots[len(cc.loopVarSlots)-1]
		cc.emitter.EmitOpcodeWithOperand(OpLoadVar, Operand{Type: OperandImmediate32, Value: uint64(slot)}, binOp.Pos.Line, binOp.Pos.Column)
	} else {
		offset, exists := cc.findStringOffset(id.Name)
		if !exists {
			return fmt.Errorf("undefined string identifier: %s", id.Name)
		}
		cc.emitStringIdentifier(offset, id.Name, binOp.Pos.Line, binOp.Pos.Column)
	}

	if err := cc.compileExpression(binOp.Right); err != nil {
		return err
	}

	opcodes := map[token.Type]Opcode{token.AT: OpFoundAt, token.IN: OpFoundIn}
	cc.emitter.EmitOpcode(opcodes[binOp.Op], binOp.Pos.Line, binOp.Pos.Column)
	return nil
}

// compileCountInRange compiles "#a in (min..max)" expressions.
// Stack layout (bottom to top): count, min, max → OpCountIn → result
func (cc *ConditionCompiler) compileCountInRange(binOp *ast.BinaryOp) error {
	// Compile the count expression (#a)
	if err := cc.compileExpression(binOp.Left); err != nil {
		return fmt.Errorf("compiling count expression: %w", err)
	}

	// The right side should be a range expression (min..max)
	rangeExpr, ok := binOp.Right.(*ast.BinaryOp)
	if !ok || rangeExpr.Op != token.DOT {
		return fmt.Errorf("IN operator with count requires a range expression (min..max)")
	}

	// Compile min (left side of ..)
	if err := cc.compileExpression(rangeExpr.Left); err != nil {
		return fmt.Errorf("compiling range minimum: %w", err)
	}

	// Compile max (right side of ..)
	if err := cc.compileExpression(rangeExpr.Right); err != nil {
		return fmt.Errorf("compiling range maximum: %w", err)
	}

	cc.emitter.EmitOpcode(OpCountIn, binOp.Pos.Line, binOp.Pos.Column)
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

	// The enclosing 'of' expression builds the string set from the AST, so the
	// comma node itself does not require a VM operation.
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
	case *ast.FunctionCall:
		function, ok := cc.moduleFunctions[e.Function]
		return ok && function.function.ReturnType == ModuleFloat
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
	if function, ok := cc.moduleFunctions[name]; ok {
		return function.function.ReturnType == ModuleString
	}
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

//nolint:revive // argument-limit: internal helper
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

//nolint:revive // argument-limit: internal helper
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

//nolint:revive // argument-limit: internal helper
func (cc *ConditionCompiler) handleFloatOperations(binOp *ast.BinaryOp, leftIsFloat, rightIsFloat, isComparison bool) error {
	// Logical operands are boolean even when a nested comparison contains
	// floating-point expressions. Promoting either result would turn a valid
	// boolean into a double before OpAnd/OpOr executes.
	if binOp.Op == token.AND || binOp.Op == token.OR {
		return nil
	}
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
	case token.AT:
		return true, cc.compileStringOffsetOperator(binOp)
	case token.IN:
		// Handle "#a in (min..max)" — count range check
		if _, ok := binOp.Left.(*ast.StringCount); ok {
			return true, cc.compileCountInRange(binOp)
		}
		return true, cc.compileStringOffsetOperator(binOp)
	case token.DOT:
		if moduleName, ok := moduleNameFromMemberAccess(binOp); ok {
			return true, unsupportedModuleError(moduleName)
		}
		return true, cc.compileExpressions(binOp.Left, binOp.Right)
	case token.COMMA:
		// COMMA creates a list for 'of' expressions
		return true, cc.compileCommaOperator(binOp)
	case token.MATCHES:
		if _, ok := binOp.Left.(*ast.Identifier); ok {
			return true, cc.compileMatchesExpression(binOp)
		}
		return false, nil // fall through to normal comparison path
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

// compileLengthOf compiles a "length of" expression.
// Stack: [setIndex] -> [totalLength]
func (cc *ConditionCompiler) compileLengthOf(lengthOf *ast.LengthOf) error {
	setIndex, pos := cc.resolveLengthOfTarget(lengthOf)
	if pos.Line == 0 {
		return fmt.Errorf("unsupported 'length of' target")
	}
	cc.emitter.EmitPush(safeInt64ToUint64(int64(setIndex)), lengthOf.Pos.Line, lengthOf.Pos.Column)
	cc.emitter.EmitOpcode(OpLengthOf, lengthOf.Pos.Line, lengthOf.Pos.Column)
	return nil
}

// resolveLengthOfTarget resolves the target of a "length of" expression to a string set index.
func (cc *ConditionCompiler) resolveLengthOfTarget(lengthOf *ast.LengthOf) (int, token.Position) {
	switch target := lengthOf.Target.(type) {
	case *ast.Identifier:
		// length of them [*/**] or length of ($a)
		if target.Name == "them" {
			return cc.internStringSet(cc.allStringIdentifiers()), target.Pos
		}
		// length of ($a) — the parenthesized expression unwraps to Identifier
		return cc.resolveStringSetIndex(target)
	default:
		return 0, token.Position{}
	}
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

	// "!" with no name is the for-loop placeholder: length of the current
	// iteration's string. Load its StringRef from the active loop variable
	// slot instead of looking up a fixed offset ("$" has none). Mirrors the
	// handling of "#"/"@" placeholders in compileStringCount/compileStringOffset.
	if id.Name == "$" && len(cc.loopVarSlots) > 0 && cc.loopVarSlots[len(cc.loopVarSlots)-1] >= 0 {
		slot := cc.loopVarSlots[len(cc.loopVarSlots)-1]
		cc.emitter.EmitOpcodeWithOperand(OpLoadVar, Operand{Type: OperandImmediate32, Value: uint64(slot)}, strLen.Pos.Line, strLen.Pos.Column)
	} else {
		offset, exists := cc.findStringOffset(id.Name)
		if !exists {
			return fmt.Errorf("undefined string identifier for string length operator: %s", id.Name)
		}
		cc.emitStringIdentifier(offset, id.Name, strLen.Pos.Line, strLen.Pos.Column)
	}

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

	// "@" with no name is the for-loop placeholder: first offset of the
	// current iteration's string. Load its StringRef from the active loop
	// variable slot instead of looking up a fixed offset ("$" has none).
	if id.Name == "$" && len(cc.loopVarSlots) > 0 && cc.loopVarSlots[len(cc.loopVarSlots)-1] >= 0 {
		slot := cc.loopVarSlots[len(cc.loopVarSlots)-1]
		cc.emitter.EmitOpcodeWithOperand(OpLoadVar, Operand{Type: OperandImmediate32, Value: uint64(slot)}, strOffset.Pos.Line, strOffset.Pos.Column)
	} else {
		offset, exists := cc.findStringOffset(id.Name)
		if !exists {
			return fmt.Errorf("undefined string identifier for string offset operator: %s", id.Name)
		}
		cc.emitStringIdentifier(offset, id.Name, strOffset.Pos.Line, strOffset.Pos.Column)
	}

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

	// "#" with no name is the for-loop placeholder: count occurrences of the
	// current iteration's string. Load its StringRef from the active loop
	// variable slot instead of looking up a fixed offset ("$" has none).
	if id.Name == "$" && len(cc.loopVarSlots) > 0 && cc.loopVarSlots[len(cc.loopVarSlots)-1] >= 0 {
		slot := cc.loopVarSlots[len(cc.loopVarSlots)-1]
		cc.emitter.EmitOpcodeWithOperand(OpLoadVar, Operand{Type: OperandImmediate32, Value: uint64(slot)}, strCount.Pos.Line, strCount.Pos.Column)
	} else {
		offset, exists := cc.findStringOffset(id.Name)
		if !exists {
			return fmt.Errorf("undefined string identifier for string count operator: %s", id.Name)
		}
		cc.emitStringIdentifier(offset, id.Name, strCount.Pos.Line, strCount.Pos.Column)
	}

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

// SetExternalVariables sets the memory slots for declared external variables.
func (cc *ConditionCompiler) SetExternalVariables(externalVariables map[string]int) {
	cc.externalVariables = externalVariables
}

// SetGlobalVariables sets the memory slots for declared global variables.
func (cc *ConditionCompiler) SetGlobalVariables(globalVariables map[string]int) {
	cc.globalVariables = globalVariables
}

// GetGlobalVariables returns the compiler's global variables map.
func (cc *ConditionCompiler) GetGlobalVariables() map[string]int {
	return cc.globalVariables
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

// ResetForRule clears per-rule state while preserving program-level maps.
func (cc *ConditionCompiler) ResetForRule() {
	cc.labelCounter = 0
	cc.labels = make(map[string]int)
	cc.pendingJumps = cc.pendingJumps[:0]
	cc.stringSets = cc.stringSets[:0]
	cc.stringSetIndex = make(map[string]int)
	cc.globalVariables = make(map[string]int)
}

func (cc *ConditionCompiler) SetModuleFunctions(functions map[string]compiledModuleFunction) {
	cc.moduleFunctions = functions
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

// EstimateComplexity returns a simple structural complexity score for an expression.
// Supported nodes contribute fixed weights: literals count as 1, identifiers as
// 2, and unary or binary operators add 1 plus their operands. Unsupported node
// types return 0. The score is a heuristic for relative diagnostics, not a
// runtime cost model.
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

func (cc *ConditionCompiler) allocateVariables(vars []string) ([]int, error) {
	if cc.variableMap == nil {
		cc.variableMap = make(map[string]int)
	}
	slots := make([]int, len(vars))
	for i, v := range vars {
		slot := len(cc.variableMap)
		if slot >= 256 {
			return nil, fmt.Errorf("too many variables")
		}
		cc.variableMap[v] = slot
		slots[i] = slot
	}
	return slots, nil
}

func (cc *ConditionCompiler) compileForLoop(forLoop *ast.ForLoop) error {
	if len(forLoop.Variables) == 0 {
		return cc.compileForLoopOverStrings(forLoop)
	}

	// Handle text string set iteration: for any s in ("text1", "text2") : (...)
	if tuple, ok := forLoop.Range.(*ast.StringTuple); ok {
		return cc.compileForLoopOverTextStrings(forLoop, tuple)
	}
	// Handle single string literal: for any s in ("text") : (...)
	if lit, ok := forLoop.Range.(*ast.Literal); ok && lit.Type == token.StringLit {
		return cc.compileForLoopOverTextStrings(forLoop, &ast.StringTuple{
			Elements: []ast.Expression{lit},
		})
	}
	// Handle string set iteration: for any s in ($*) or for any s in (them)
	if ident, ok := forLoop.Range.(*ast.Identifier); ok {
		_ = ident // handled by compileForLoopOverStrings
		return cc.compileForLoopOverStrings(forLoop)
	}

	rangeExpr, ok := forLoop.Range.(*ast.BinaryOp)
	if !ok || rangeExpr.Op != token.DOT {
		return fmt.Errorf("unsupported for-loop range type, expected binary range operator")
	}

	slots, err := cc.allocateVariables(forLoop.Variables)
	if err != nil {
		return err
	}

	// 1. Push start and end to stack dynamically
	if err := cc.compileExpression(rangeExpr.Left); err != nil {
		return fmt.Errorf("compiling range start: %w", err)
	}
	if err := cc.compileExpression(rangeExpr.Right); err != nil {
		return fmt.Errorf("compiling range end: %w", err)
	}

	// 2. Start Iterator
	cc.emitter.EmitOpcodeWithOperand(OpIterStartIntRange, Operand{Type: OperandImmediate32, Value: uint64(slots[0])}, forLoop.Pos.Line, forLoop.Pos.Column)

	return cc.compileForLoopBody(forLoop.Quantifier, forLoop.Condition, forLoop.Pos, -1)
}

// compileForLoopOverTextStrings compiles: for any s in ("text1", "text2") : (...)
func (cc *ConditionCompiler) compileForLoopOverTextStrings(forLoop *ast.ForLoop, tuple *ast.StringTuple) error {
	// Extract string literals from the tuple
	var literals []string
	for _, elem := range tuple.Elements {
		switch e := elem.(type) {
		case *ast.Literal:
			if e.Type != token.StringLit {
				return fmt.Errorf("text string set elements must be string literals")
			}
			literals = append(literals, e.Value.(string))
		default:
			return fmt.Errorf("text string set elements must be string literals")
		}
	}

	// Register the text string set and get its index
	idx := cc.registerTextStringSet(literals)

	slots, err := cc.allocateVariables(forLoop.Variables)
	if err != nil {
		return err
	}

	// Push text string set index and constraint marker (0 = no constraint) onto stack
	cc.emitter.EmitPush(uint64(idx), forLoop.Pos.Line, forLoop.Pos.Column)
	cc.emitter.EmitPush(0, forLoop.Pos.Line, forLoop.Pos.Column)

	// Start iterator with the variable slot
	cc.emitter.EmitOpcodeWithOperand(OpIterStartTextStringSet, Operand{Type: OperandImmediate32, Value: uint64(slots[0])}, forLoop.Pos.Line, forLoop.Pos.Column)

	return cc.compileForLoopBody(forLoop.Quantifier, forLoop.Condition, forLoop.Pos, slots[0])
}

// registerTextStringSet registers a text string set and returns its index.
func (cc *ConditionCompiler) registerTextStringSet(literals []string) int {
	cc.textStringSets = append(cc.textStringSets, literals)
	return len(cc.textStringSets) - 1
}

// GetTextStringSets returns the compiled text string sets for this condition.
func (cc *ConditionCompiler) GetTextStringSets() [][]string {
	sets := make([][]string, len(cc.textStringSets))
	for i, set := range cc.textStringSets {
		copied := make([]string, len(set))
		copy(copied, set)
		sets[i] = copied
	}
	return sets
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

	varName := "$"
	if len(forLoop.Variables) > 0 {
		varName = forLoop.Variables[0]
	}
	slots, err := cc.allocateVariables([]string{varName})
	if err != nil {
		return err
	}

	index := cc.internStringSet(ids)

	// Compile optional "in (range)" or "at offset" constraints
	// Stack layout (bottom to top): [args..., stringSetIndex, constraintMarker]
	// constraintMarker: 0=no constraint, 1=in range, 2=at offset
	var constraintMarker uint64
	switch {
	case forLoop.InRange != nil:
		rangeOp, ok := forLoop.InRange.(*ast.BinaryOp)
		if !ok || rangeOp.Op != token.DOT {
			return fmt.Errorf("invalid range expression for 'in' constraint")
		}
		if err := cc.compileExpression(rangeOp.Left); err != nil {
			return fmt.Errorf("compiling range min: %w", err)
		}
		if err := cc.compileExpression(rangeOp.Right); err != nil {
			return fmt.Errorf("compiling range max: %w", err)
		}
		constraintMarker = 1
	case forLoop.AtOffset != nil:
		if err := cc.compileExpression(forLoop.AtOffset); err != nil {
			return fmt.Errorf("compiling offset expression: %w", err)
		}
		constraintMarker = 2
	default:
		constraintMarker = 0
	}
	cc.emitter.EmitPush(uint64(index), forLoop.Pos.Line, forLoop.Pos.Column)
	cc.emitter.EmitPush(constraintMarker, forLoop.Pos.Line, forLoop.Pos.Column)
	cc.emitter.EmitOpcodeWithOperand(OpIterStartStringSet, Operand{Type: OperandImmediate32, Value: uint64(slots[0])}, forLoop.Pos.Line, forLoop.Pos.Column)

	return cc.compileForLoopBody(forLoop.Quantifier, forLoop.Condition, forLoop.Pos, slots[0])
}

// compileForLoopBody emits the shared loop body and quantifier check used by
// all for-loop variants. loopVarSlot is the memory slot holding the current
// iteration's value, or -1 for loops without a string variable (integer-range
// loops), in which case "$" in the body is invalid.
//
//nolint:revive // argument-limit: internal helper
func (cc *ConditionCompiler) compileForLoopBody(quantifier string, condition ast.Expression, pos token.Position, loopVarSlot int) error {
	// 1. Check if iterator is empty using OpIterPushTotal + OpJzP
	cc.emitter.EmitOpcode(OpIterPushTotal, pos.Line, pos.Column)
	jumpToEnd := cc.emitter.EmitJump(JumpConfig{Opcode: OpJzP, Line: pos.Line, Pos: pos.Column})

	// 2. First iteration: push target and call OpIterNext to initialize
	setupIndex := cc.emitter.GetInstructionCount()
	cc.emitter.EmitOpcodeWithOperand(OpPush32, Operand{Type: OperandImmediate32, Value: 0}, pos.Line, pos.Column) // Placeholder for loopBodyIP
	cc.emitter.EmitOpcode(OpIterNext, pos.Line, pos.Column)

	loopBodyIP := cc.emitter.GetSize()

	// Fixup the setup push with the loopBodyIP
	if err := cc.emitter.UpdateOperandByIndex(setupIndex, Operand{Type: OperandImmediate32, Value: uint64(loopBodyIP)}); err != nil {
		return err
	}

	// 3. Compile the condition expression
	// Push the loop variable slot so "$" in the body resolves to the current
	// iteration's string (OpLoadVar + OpFound) instead of the whole rule's
	// anonymous set. -1 means no string loop variable (e.g. integer-range
	// loops), in which case "$" is invalid.
	cc.loopVarSlots = append(cc.loopVarSlots, loopVarSlot)
	if err := cc.compileExpression(condition); err != nil {
		cc.loopVarSlots = cc.loopVarSlots[:len(cc.loopVarSlots)-1]
		return err
	}
	cc.loopVarSlots = cc.loopVarSlots[:len(cc.loopVarSlots)-1]

	// 4. Accumulate condition
	cc.emitter.EmitOpcode(OpIterCondition, pos.Line, pos.Column)

	// 5. Push jump target and iterate
	cc.emitter.EmitPush(uint64(loopBodyIP), pos.Line, pos.Column)
	cc.emitter.EmitOpcode(OpIterNext, pos.Line, pos.Column)

	// 6. End Iteration and evaluate target logic
	endLoopIP := cc.emitter.GetSize()
	cc.emitter.SetFixup(jumpToEnd, endLoopIP)

	if quantifier == QuantifierAll {
		cc.emitter.EmitOpcode(OpIterPushTotal, pos.Line, pos.Column)
	}

	cc.emitter.EmitOpcode(OpIterEnd, pos.Line, pos.Column) // Pushes final count to stack

	// 8. Quantifier checks
	switch quantifier {
	case QuantifierAny:
		cc.emitter.EmitPush(0, pos.Line, pos.Column)
		cc.emitter.EmitOpcode(OpIntGt, pos.Line, pos.Column)
	case QuantifierNone:
		cc.emitter.EmitPush(0, pos.Line, pos.Column)
		cc.emitter.EmitOpcode(OpIntEq, pos.Line, pos.Column)
	case QuantifierAll:
		cc.emitter.EmitOpcode(OpIntEq, pos.Line, pos.Column)
	default:
		count, ok := parseNumericQuantifier(quantifier)
		if !ok {
			return fmt.Errorf("unsupported for-loop quantifier: %s", quantifier)
		}
		cc.emitter.EmitPush(uint64(count), pos.Line, pos.Column) // #nosec G115
		cc.emitter.EmitOpcode(OpIntGe, pos.Line, pos.Column)
	}

	return nil
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

func (cc *ConditionCompiler) compileOfExpression(ofExpr *ast.OfExpression) error {
	var opcode Opcode

	// Special case: "#a in (min..max) of ($a*)" — count-in-range with string set.
	// We handle this before the general flow to avoid emitting OpOf which would
	// consume the setIndex we need for OpOfFoundIn.
	if _, ok := ofExpr.Count.(*ast.StringCount); ok && ofExpr.InRange != nil {
		// #a in (min..max) of ($str*)
		// Resolve the string set and emit OpCountInOf.
		// Stack: [setIndex, min, max] → OpCountInOf counts matched strings in set, checks if count is within [min, max].
		setIndex, pos := cc.resolveStringSetIndex(ofExpr.Strings)
		cc.emitter.EmitPush(uint64(setIndex), pos.Line, pos.Column)
		if err := cc.compileExpression(ofExpr.InRange); err != nil {
			return err
		}
		cc.emitter.EmitOpcode(OpCountInOf, ofExpr.Pos.Line, ofExpr.Pos.Column)
		return nil
	}

	// Check if the count is a percent expression ("N % of")
	if percentExpr, ok := ofExpr.Count.(*ast.PercentExpression); ok {
		if err := cc.compileExpression(percentExpr.Value); err != nil {
			return fmt.Errorf("compiling percent expression: %w", err)
		}
		opcode = OpOfPercent
	} else {
		if err := cc.compileCountExpression(ofExpr.Count); err != nil {
			return fmt.Errorf("compiling count expression in of-expression: %w", err)
		}
		opcode = OpOf
	}

	if err := cc.compileStringsExpression(ofExpr.Strings); err != nil {
		return fmt.Errorf("compiling strings expression in of-expression: %w", err)
	}

	// Compile optional constraint and adjust opcode
	isPercent := isPercentOpcode(opcode)
	if ofExpr.InRange != nil {
		opcode = cc.compileInRangeConstraint(ofExpr.InRange, ofExpr.Pos, opcode, isPercent)
	} else if ofExpr.AtOffset != nil {
		opcode = cc.compileAtOffsetConstraint(ofExpr.AtOffset, ofExpr.Pos, opcode, isPercent)
	}

	cc.emitter.EmitOpcode(opcode, ofExpr.Pos.Line, ofExpr.Pos.Column)
	return nil
}

func isPercentOpcode(op Opcode) bool {
	return op == OpOfPercent || op == OpOfPercentIn || op == OpOfPercentAt
}

//nolint:revive // argument-limit: internal helper
func (cc *ConditionCompiler) compileInRangeConstraint(
	expr ast.Expression,
	pos token.Position,
	baseOpcode Opcode,
	isPercent bool,
) Opcode {
	rangeOp, ok := expr.(*ast.BinaryOp)
	if !ok || rangeOp.Op != token.DOT {
		return baseOpcode // fallback; error will be caught elsewhere
	}
	if err := cc.compileExpression(rangeOp.Left); err != nil {
		return baseOpcode
	}
	if err := cc.compileExpression(rangeOp.Right); err != nil {
		return baseOpcode
	}
	if isPercent {
		return OpOfPercentIn
	}
	return OpOfFoundIn
}

//nolint:revive // argument-limit: internal helper
func (cc *ConditionCompiler) compileAtOffsetConstraint(
	expr ast.Expression,
	pos token.Position,
	baseOpcode Opcode,
	isPercent bool,
) Opcode {
	if err := cc.compileExpression(expr); err != nil {
		return baseOpcode
	}
	if isPercent {
		return OpOfPercentAt
	}
	return OpOfFoundAt
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

// resolveStringSetIndex resolves a string set expression to its interned index and position.
// It does NOT emit any bytecode — just returns the index for the caller to use.
func (cc *ConditionCompiler) resolveStringSetIndex(stringsExpr ast.Expression) (int, token.Position) {
	if ident, ok := stringsExpr.(*ast.Identifier); ok {
		switch ident.Name {
		case "them", "all":
			return cc.internStringSet(cc.allStringIdentifiers()), ident.Pos
		case "$":
			return cc.internStringSet(cc.anonymousStringIdentifiers()), ident.Pos
		default:
			if cc.isStringSetIdentifier(ident.Name) {
				ids, err := cc.expandStringSetIdentifier(ident.Name)
				if err != nil {
					ids = []string{ident.Name}
				}
				return cc.internStringSet(ids), ident.Pos
			}
		}
	}
	if binOp, ok := stringsExpr.(*ast.BinaryOp); ok && binOp.Op == token.COMMA {
		ids, err := cc.collectStringSetFromComma(binOp)
		if err != nil {
			return 0, binOp.Pos
		}
		return cc.internStringSet(ids), binOp.Pos
	}
	return 0, token.Position{}
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
	moduleFunction, isModuleFunction := cc.moduleFunctions[call.Function]
	if moduleName, dotted := moduleNameFromDottedName(call.Function); dotted && !isModuleFunction {
		return unsupportedModuleError(moduleName)
	}

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
	if isModuleFunction {
		cc.emitter.EmitOpcodeWithOperand(
			OpCall,
			Operand{Type: OperandImmediate32, Value: encodeBuiltinCall(moduleFunction.id, len(call.Args))},
			call.Pos.Line,
			call.Pos.Column,
		)
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

func (*ConditionCompiler) emitModuleFunctionCall(moduleName string, _, _ int) error {
	return unsupportedModuleError(moduleName)
}

func unsupportedModuleError(moduleName string) error {
	return fmt.Errorf("unsupported module: %s", moduleName)
}

func moduleNameFromDottedName(name string) (string, bool) {
	moduleName, _, found := strings.Cut(name, ".")
	if !found || moduleName == "" {
		return "", false
	}
	return moduleName, true
}

func moduleNameFromMemberAccess(expr ast.Expression) (string, bool) {
	binOp, ok := expr.(*ast.BinaryOp)
	if !ok || binOp.Op != token.DOT {
		return "", false
	}
	if _, ok := binOp.Right.(*ast.Identifier); !ok {
		return "", false
	}
	return leftmostIdentifierName(binOp.Left)
}

func leftmostIdentifierName(expr ast.Expression) (string, bool) {
	switch e := expr.(type) {
	case *ast.Identifier:
		if e.Name == "" {
			return "", false
		}
		if moduleName, ok := moduleNameFromDottedName(e.Name); ok {
			return moduleName, true
		}
		return e.Name, true
	case *ast.BinaryOp:
		if e.Op != token.DOT {
			return "", false
		}
		return leftmostIdentifierName(e.Left)
	default:
		return "", false
	}
}
