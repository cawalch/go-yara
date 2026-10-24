package compiler

import (
	"errors"
	"fmt"
	"maps"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/semantic"
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
type conditionCompiler struct {
	moduleSchemas     map[string]*ModuleSchema
	moduleTypes       map[string]*semantic.TypeInfo
	moduleAccessNames []string
	moduleIterations  []moduleIterationPlan
	emitter           *emitter
	stringOffsets     map[string]int
	variableMap       map[string]int
	externalVariables map[string]int
	globalVariables   map[string]int
	globalValues      map[string]compiledGlobalValue
	ruleIndexMap      map[string]int
	labelCounter      int
	labels            map[string]int
	pendingJumps      []pendingJump
	stringSets        [][]string
	stringSetIndex    map[string]int
	anonymousStrings  []string
	textStringSets    [][]string
	moduleFunctions   map[string]compiledModuleFunction
	assertions        []conditionAssertion
	disableAssertions bool // Test-only baseline for differential and performance checks.

	// loopVarSlots tracks the memory slot for the loop variable of each
	// enclosing for-loop. For "for any of them : ($)" the slot holds the
	// current iteration's string identifier, and "$" in the body must load
	// that slot (OpLoadVar + OpFound) instead of compiling as OpOf against
	// the whole rule's anonymous set. Without this, "for all of them : ($)"
	// returns true whenever any string matches, ignoring whether the *current*
	// string matched. Slots are pushed/popped around the loop body.
	loopVarSlots     []int
	patternLoopSlots map[int]bool
	nextVariableSlot int
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
		if num > math.MaxInt64/multiplier {
			return 0, fmt.Errorf("size literal exceeds int64 range: %s", literal)
		}
		return num * multiplier, nil
	}
	return 0, fmt.Errorf("unsupported size unit: %s", matches[2])
}

// pendingJump represents a pending jump operation in bytecode generation
type pendingJump struct {
	Opcode       Opcode
	Label        string
	Position     int
	Line, Column int
}

// newConditionCompiler creates a new condition compiler
func newConditionCompiler(emitter *emitter, stringOffsets map[string]int) *conditionCompiler {
	return &conditionCompiler{
		emitter:           emitter,
		stringOffsets:     maps.Clone(stringOffsets),
		variableMap:       make(map[string]int),
		patternLoopSlots:  make(map[int]bool),
		externalVariables: make(map[string]int),
		globalVariables:   make(map[string]int),
		ruleIndexMap:      make(map[string]int),
		moduleFunctions:   make(map[string]compiledModuleFunction),
		labels:            make(map[string]int),
		pendingJumps:      make([]pendingJump, 0),
		stringSets:        make([][]string, 0, 8),
		stringSetIndex:    make(map[string]int),
	}
}

func (cc *conditionCompiler) setRuleIndexMap(ruleIndexMap map[string]int) {
	cc.ruleIndexMap = ruleIndexMap
}

func (cc *conditionCompiler) generateLabel() string {
	cc.labelCounter++
	return fmt.Sprintf("L%d", cc.labelCounter)
}

func (cc *conditionCompiler) defineLabel(label string) {
	cc.labels[label] = cc.emitter.GetSize()
}

//nolint:revive // argument-limit: internal helper
func (cc *conditionCompiler) emitJumpWithLabel(opcode Opcode, label string, line, column int) {
	pos := cc.emitter.GetSize()
	cc.pendingJumps = append(cc.pendingJumps, pendingJump{
		Opcode:   opcode,
		Label:    label,
		Position: pos,
		Line:     line,
		Column:   column,
	})
	cc.emitter.EmitOpcodeWithOperand(opcode, Operand{Type: OperandRelative32, Value: 0}, line, column)
}

func (cc *conditionCompiler) resolveJumps() error {
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

func (cc *conditionCompiler) compileExpressions(exprs ...ast.Expression) error {
	for _, expr := range exprs {
		if err := cc.compileExpression(expr); err != nil {
			return err
		}
	}
	return nil
}

func (cc *conditionCompiler) findStringOffset(name string) (int, bool) {
	if offset, exists := cc.stringOffsets[name]; exists {
		return offset, true
	}
	if offset, exists := cc.stringOffsets["$"+name]; exists {
		return offset, true
	}
	return 0, false
}

//nolint:revive // argument-limit: internal helper
func (cc *conditionCompiler) emitStringIdentifier(offset int, identifier string, line, column int) {
	_ = offset
	if len(identifier) > 0 && identifier[0] != '$' {
		identifier = "$" + identifier
	}
	cc.emitter.EmitPushString(identifier, line, column)
}

func (cc *conditionCompiler) compileMatchesExpression(expr *ast.BinaryOp) error {
	op, err := cc.compileMatchesOperand(expr.Left)
	if err != nil {
		return err
	}
	if err := cc.compileExpression(expr.Right); err != nil {
		return err
	}
	cc.emitter.EmitOpcode(op, expr.Pos.Line, expr.Pos.Column)
	return nil
}

func (cc *conditionCompiler) compileMatchesOperand(expr ast.Expression) (Opcode, error) {
	id, ok := expr.(*ast.Identifier)
	if !ok {
		return OpMatchesValue, cc.compileExpression(expr)
	}
	slot, loop := cc.variableMap[id.Name]
	if id.Name == "$" && len(cc.loopVarSlots) > 0 {
		slot = cc.loopVarSlots[len(cc.loopVarSlots)-1]
		loop = slot >= 0
	}
	if loop {
		cc.emitter.EmitOpcodeWithOperand(OpLoadVar, Operand{Type: OperandImmediate32, Value: uint64(slot)}, id.Pos.Line, id.Pos.Column)
		if cc.patternLoopSlots[slot] {
			return OpMatches, nil
		}
		return OpMatchesValue, nil
	}
	_, external := cc.externalVariables[id.Name]
	_, global := cc.globalVariables[id.Name]
	if external || global {
		return OpMatchesValue, cc.compileExpression(expr)
	}
	if offset, exists := cc.findStringOffset(id.Name); exists {
		cc.emitStringIdentifier(offset, id.Name, id.Pos.Line, id.Pos.Column)
		return OpMatches, nil
	}
	return OpMatchesValue, cc.compileExpression(expr)
}

// compileBinaryOp compiles a binary operation expression
func (cc *conditionCompiler) compileExpression(expr ast.Expression) error {
	switch e := expr.(type) {
	case *ast.MemberAccess:
		return cc.compileModuleMember(e)
	case *ast.IndexAccess:
		return cc.compileModuleIndex(e)
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

func (cc *conditionCompiler) compileLiteral(lit *ast.Literal) error {
	switch lit.Type {
	case token.IntegerLit, token.HexIntegerLit, token.OctalIntegerLit:
		return cc.compileIntegerLiteral(lit)
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
func (cc *conditionCompiler) compileSimpleLiteral(lit *ast.Literal) bool {
	switch lit.Type {
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
func (cc *conditionCompiler) compileIntegerLiteral(lit *ast.Literal) error {
	value, err := globalLiteralInt(lit)
	if err != nil {
		return fmt.Errorf("invalid integer literal %v: %w", lit.Value, err)
	}
	cc.emitter.EmitPush(uint64(value), lit.Pos.Line, lit.Pos.Column) // #nosec G115 -- preserve signed integer bits
	return nil
}

func parseIntLiteral(s string) (int64, error) {
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		bits, err := strconv.ParseUint(s, 0, 64)
		if err != nil {
			return 0, err
		}
		if bits <= math.MaxInt64 {
			return int64(bits), nil
		}
		// Negative two's-complement value for 64-bit hex literals with high bit set (e.g. 0xffffffffffffffff -> -1).
		return int64(bits-math.MaxInt64-1) - math.MaxInt64 - 1, nil //checkednarrow:ignore bounded within [0, math.MaxInt64]
	}
	return strconv.ParseInt(s, 0, 64)
}

// compileFloatLiteral compiles float literals
func (cc *conditionCompiler) compileFloatLiteral(lit *ast.Literal) {
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
func (cc *conditionCompiler) compileStringLiteral(lit *ast.Literal) {
	if value, ok := lit.Value.(string); ok {
		cc.emitter.EmitPushString(value, lit.Pos.Line, lit.Pos.Column)
	}
}

// compileRegexLiteral compiles regex literals
func (cc *conditionCompiler) compileRegexLiteral(lit *ast.Literal) {
	if value, ok := lit.Value.(string); ok {
		// Push the regex literal; OpMatches will handle compilation and matching.
		cc.emitter.EmitPushString(value, lit.Pos.Line, lit.Pos.Column)
	}
}

// compileBooleanLiteral compiles boolean literals
func (cc *conditionCompiler) compileBooleanLiteral(lit *ast.Literal) {
	if lit.Type == token.TRUE {
		cc.emitter.EmitPush(1, lit.Pos.Line, lit.Pos.Column)
	} else {
		cc.emitter.EmitPush(0, lit.Pos.Line, lit.Pos.Column)
	}
}

func (cc *conditionCompiler) compileSizeLiteral(lit *ast.Literal) error {
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
func (cc *conditionCompiler) compileIdentifier(ident *ast.Identifier) error {
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

	if index, exists := cc.variableMap[ident.Name]; exists {
		cc.emitter.EmitOpcodeWithOperand(OpLoadVar, Operand{Type: OperandImmediate32, Value: safeInt64ToUint64(safeMax(0, int64(index)))}, ident.Pos.Line, ident.Pos.Column)
		return nil
	}

	if cc.moduleSchemas[ident.Name] != nil {
		cc.emitModuleName(OpModuleLoad, ident.Name, ident.Pos)
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

	if ruleIndex, exists := cc.ruleIndexMap[ident.Name]; exists {
		if ruleIndex < 0 || ruleIndex > math.MaxUint8 {
			return fmt.Errorf("rule reference index %d exceeds bytecode capacity", ruleIndex)
		}
		cc.emitter.EmitOpcodeWithOperand(
			OpPushRule,
			Operand{Type: OperandImmediate8, Value: uint64(ruleIndex)},
			ident.Pos.Line,
			ident.Pos.Column,
		)
		return nil
	}

	specialIdentifiers := map[string]func(){
		"filesize":   func() { cc.emitter.EmitOpcode(OpFilesize, ident.Pos.Line, ident.Pos.Column) },
		"entrypoint": func() { cc.emitter.EmitOpcode(OpEntrypoint, ident.Pos.Line, ident.Pos.Column) },
		"them":       func() { cc.emitter.EmitPush(stringSetAll, ident.Pos.Line, ident.Pos.Column) },
		"flags":      func() { cc.emitter.EmitPush(0, ident.Pos.Line, ident.Pos.Column) },
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

func (cc *conditionCompiler) compileAnonymousIdentifier(line, column int) error {
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

// CompileBooleanExpression compiles a boolean expression to bytecode
func (cc *conditionCompiler) CompileBooleanExpression(expr ast.Expression, shortCircuit bool) error {
	expr = FoldConstants(expr)
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

func (cc *conditionCompiler) compileShortCircuitBinary(binOp *ast.BinaryOp, jumpOpcode, resultOpcode Opcode) error {
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

func (cc *conditionCompiler) setExternalVariables(externalVariables map[string]int) {
	cc.externalVariables = externalVariables
}

func (cc *conditionCompiler) setGlobalVariables(globalVariables map[string]int) {
	cc.globalVariables = globalVariables
}

func (cc *conditionCompiler) setStringOffsets(offsets map[string]int) {
	cc.stringOffsets = offsets
}

// SetAnonymousStrings sets the anonymous string identifiers for the current rule.
func (cc *conditionCompiler) SetAnonymousStrings(ids []string) {
	cc.anonymousStrings = nil
	if len(ids) == 0 {
		return
	}
	cc.anonymousStrings = make([]string, len(ids))
	copy(cc.anonymousStrings, ids)
}

// GetStringSets returns the compiled string sets for this condition.
func (cc *conditionCompiler) GetStringSets() [][]string {
	if len(cc.stringSets) == 0 {
		return nil
	}
	sets := make([][]string, len(cc.stringSets))
	for i, set := range cc.stringSets {
		copied := make([]string, len(set))
		copy(copied, set)
		sets[i] = copied
	}
	return sets
}

// ResetForRule clears per-rule state while preserving program-level maps.
func (cc *conditionCompiler) ResetForRule() {
	cc.moduleAccessNames = nil
	cc.moduleIterations = nil
	cc.assertions = cc.assertions[:0]
	cc.labelCounter = 0
	clear(cc.labels)
	cc.pendingJumps = cc.pendingJumps[:0]
	cc.stringSets = cc.stringSets[:0]
	clear(cc.stringSetIndex)
	clear(cc.globalVariables)
}

func (cc *conditionCompiler) setModuleFunctions(functions map[string]compiledModuleFunction) {
	cc.moduleFunctions = functions
}

func (cc *conditionCompiler) allocateVariables(vars []string) ([]int, error) {
	if cc.variableMap == nil {
		cc.variableMap = make(map[string]int)
	}
	used := make(map[int]bool)
	for _, bindings := range []map[string]int{cc.variableMap, cc.externalVariables, cc.globalVariables} {
		for _, slot := range bindings {
			used[slot] = true
		}
	}
	slots := make([]int, len(vars))
	for i, v := range vars {
		slot := cc.nextVariableSlot
		for used[slot] {
			slot++
		}
		if slot >= 256 {
			return nil, errors.New("too many variables")
		}
		cc.variableMap[v] = slot
		used[slot] = true
		cc.nextVariableSlot = slot + 1
		slots[i] = slot
	}
	return slots, nil
}

func (cc *conditionCompiler) compileFunctionCall(call *ast.FunctionCall) error {
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
			return errors.New("concat requires at least 2 arguments")
		}
		cc.emitter.EmitOpcodeWithOperand(OpCall,
			Operand{Type: OperandImmediate32, Value: encodeBuiltinCall(builtinConcat, len(call.Args))},
			call.Pos.Line, call.Pos.Column)
		return nil
	case "tostring":
		if len(call.Args) != 1 {
			return errors.New("tostring requires exactly 1 argument")
		}
		cc.emitter.EmitOpcodeWithOperand(OpCall,
			Operand{Type: OperandImmediate32, Value: encodeBuiltinCall(builtinToString, len(call.Args))},
			call.Pos.Line, call.Pos.Column)
		return nil
	case "int":
		if len(call.Args) != 1 {
			return errors.New("int requires exactly 1 argument")
		}
		cc.emitter.EmitOpcodeWithOperand(OpCall,
			Operand{Type: OperandImmediate32, Value: encodeBuiltinCall(builtinInt, len(call.Args))},
			call.Pos.Line, call.Pos.Column)
		return nil
	case "md5":
		if len(call.Args) != 1 && len(call.Args) != 2 {
			return errors.New("md5 requires 1 or 2 arguments")
		}
		cc.emitter.EmitOpcodeWithOperand(OpCall,
			Operand{Type: OperandImmediate32, Value: encodeBuiltinCall(builtinMD5, len(call.Args))},
			call.Pos.Line, call.Pos.Column)
		return nil
	case "sha1":
		if len(call.Args) != 1 && len(call.Args) != 2 {
			return errors.New("sha1 requires 1 or 2 arguments")
		}
		cc.emitter.EmitOpcodeWithOperand(OpCall,
			Operand{Type: OperandImmediate32, Value: encodeBuiltinCall(builtinSHA1, len(call.Args))},
			call.Pos.Line, call.Pos.Column)
		return nil
	case "sha256":
		if len(call.Args) != 1 && len(call.Args) != 2 {
			return errors.New("sha256 requires 1 or 2 arguments")
		}
		cc.emitter.EmitOpcodeWithOperand(OpCall,
			Operand{Type: OperandImmediate32, Value: encodeBuiltinCall(builtinSHA256, len(call.Args))},
			call.Pos.Line, call.Pos.Column)
		return nil
	default:
		return fmt.Errorf("unsupported function: %s", call.Function)
	}
}

func (cc *conditionCompiler) isRuleReference(name string) bool {
	_, exists := cc.ruleIndexMap[name]
	return exists
}

func (cc *conditionCompiler) compileRuleReference(ruleName string, line, column int) error {
	ruleIndex, exists := cc.ruleIndexMap[ruleName]
	if !exists {
		return fmt.Errorf("undefined rule reference: %s", ruleName)
	}
	if ruleIndex < 0 || ruleIndex > math.MaxUint8 {
		return fmt.Errorf("rule reference index %d exceeds bytecode capacity", ruleIndex)
	}

	cc.emitter.EmitOpcodeWithOperand(OpPushRuleRef,
		Operand{Type: OperandImmediate8, Value: uint64(ruleIndex)},
		line, column)
	return nil
}

func (*conditionCompiler) emitModuleFunctionCall(moduleName string, _, _ int) error {
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
