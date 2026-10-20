package compiler

import (
	"errors"
	"fmt"
	"slices"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

func (cc *conditionCompiler) compileStringOffsetOperator(binOp *ast.BinaryOp) error {
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
func (cc *conditionCompiler) compileCountInRange(binOp *ast.BinaryOp) error {
	// Compile the count expression (#a)
	if err := cc.compileExpression(binOp.Left); err != nil {
		return fmt.Errorf("compiling count expression: %w", err)
	}

	// The right side should be a range expression (min..max)
	rangeExpr, ok := binOp.Right.(*ast.BinaryOp)
	if !ok || rangeExpr.Op != token.DOT {
		return errors.New("IN operator with count requires a range expression (min..max)")
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
func (cc *conditionCompiler) compileCommaOperator(binOp *ast.BinaryOp) error {
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

func (cc *conditionCompiler) isFloatExpression(expr ast.Expression) bool {
	switch e := expr.(type) {
	case *ast.Identifier:
		_, loop := cc.variableMap[e.Name]
		return !loop && cc.globalValues[e.Name].valueType == ValueTypeDouble
	case *ast.Literal:
		return e.Type == token.FloatLit
	case *ast.BinaryOp:
		switch e.Op {
		case token.PLUS, token.MINUS, token.MULTIPLY, token.DIVIDE, token.IntDivide:
			return cc.isFloatExpression(e.Left) || cc.isFloatExpression(e.Right)
		}
		return false
	case *ast.UnaryOp:
		return e.Op == token.MINUS && cc.isFloatExpression(e.Right)
	case *ast.FunctionCall:
		function, ok := cc.moduleFunctions[e.Function]
		return ok && function.function.ReturnType == ModuleFloat
	default:
		return false
	}
}

func (cc *conditionCompiler) isStringExpression(expr ast.Expression) bool {
	switch e := expr.(type) {
	case *ast.Identifier:
		if slot, loop := cc.variableMap[e.Name]; loop {
			return e.Name != "$" && slices.Contains(cc.loopVarSlots, slot)
		}
		return cc.globalValues[e.Name].valueType == ValueTypeString
	case *ast.Literal:
		return e.Type == token.StringLit || e.Type == token.RegexLit
	case *ast.FunctionCall:
		return cc.isStringFunction(e.Function)
	default:
		return false
	}
}

func (cc *conditionCompiler) isStringFunction(name string) bool {
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

func (cc *conditionCompiler) isComparisonOperator(op token.Type) bool {
	return slices.Contains([]token.Type{
		token.EQ, token.NEQ, token.LT, token.LE, token.GT, token.GE,
		token.LeftShift, token.RightShift, token.MODULO,
		token.CONTAINS, token.ICONTAINS, token.STARTSWITH, token.ISTARTSWITH,
		token.ENDSWITH, token.IENDSWITH, token.IEQUALS, token.MATCHES,
	}, op)
}

func (cc *conditionCompiler) isStringComparisonOperator(op token.Type) bool {
	switch op {
	case token.EQ, token.NEQ, token.LT, token.LE, token.GT, token.GE:
		return true
	default:
		return false
	}
}

func (cc *conditionCompiler) isNonCommutativeOperator(op token.Type) bool {
	return op == token.MINUS || op == token.DIVIDE || op == token.IntDivide
}

func (cc *conditionCompiler) compileOperands(binOp *ast.BinaryOp) error {
	left, right := binOp.Left, binOp.Right
	if !cc.isComparisonOperator(binOp.Op) && !cc.isNonCommutativeOperator(binOp.Op) {
		left, right = right, left
	}
	promote := binOp.Op != token.AND && binOp.Op != token.OR &&
		(cc.isFloatExpression(left) || cc.isFloatExpression(right))
	for _, operand := range []ast.Expression{left, right} {
		if err := cc.compileExpression(operand); err != nil {
			return err
		}
		if promote && !cc.isFloatExpression(operand) {
			cc.emitter.EmitOpcode(OpIntToDbl, binOp.Pos.Line, binOp.Pos.Column)
		}
	}
	return nil
}

type opcodeMapping struct {
	intOp, dblOp Opcode
}

func (cc *conditionCompiler) selectOpcode(binOp *ast.BinaryOp, isFloatOp, isStringCompare bool) (Opcode, error) {
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
		token.IntDivide:   {OpIntDiv, OpDblDiv},
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

func (cc *conditionCompiler) handleSpecialOperators(binOp *ast.BinaryOp) (bool, error) {
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
		return true, cc.compileMatchesExpression(binOp)
	}
	return false, nil
}

func (cc *conditionCompiler) compileBinaryOp(binOp *ast.BinaryOp) error {
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
	isFloatOp := leftIsFloat || rightIsFloat

	if isStringCompare {
		opcode, err := cc.selectOpcode(binOp, false, true)
		if err != nil {
			return err
		}
		cc.emitter.EmitOpcode(opcode, binOp.Pos.Line, binOp.Pos.Column)
		return nil
	}

	opcode, err := cc.selectOpcode(binOp, isFloatOp, false)
	if err != nil {
		return err
	}

	cc.emitter.EmitOpcode(opcode, binOp.Pos.Line, binOp.Pos.Column)
	return nil
}

func (cc *conditionCompiler) compileUnaryOp(unaryOp *ast.UnaryOp) error {
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

func (cc *conditionCompiler) compileHashOperator(unaryOp *ast.UnaryOp) error {
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

func (cc *conditionCompiler) compileAtOperator(unaryOp *ast.UnaryOp) error {
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

func (cc *conditionCompiler) compileStringLengthOperator(unaryOp *ast.UnaryOp) error {
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

func (cc *conditionCompiler) compileNotOperator(unaryOp *ast.UnaryOp) error {
	if err := cc.compileExpression(unaryOp.Right); err != nil {
		return err
	}
	cc.emitter.EmitOpcode(OpNot, unaryOp.Pos.Line, unaryOp.Pos.Column)
	return nil
}

func (cc *conditionCompiler) compileBitwiseNotOperator(unaryOp *ast.UnaryOp) error {
	if err := cc.compileExpression(unaryOp.Right); err != nil {
		return err
	}
	cc.emitter.EmitOpcode(OpBitwiseNot, unaryOp.Pos.Line, unaryOp.Pos.Column)
	return nil
}

// compileLengthOf compiles a "length of" expression.
// Stack: [setIndex] -> [totalLength]
func (cc *conditionCompiler) compileLengthOf(lengthOf *ast.LengthOf) error {
	setIndex, pos := cc.resolveLengthOfTarget(lengthOf)
	if pos.Line == 0 {
		return errors.New("unsupported 'length of' target")
	}
	cc.emitter.EmitPush(safeInt64ToUint64(int64(setIndex)), lengthOf.Pos.Line, lengthOf.Pos.Column)
	cc.emitter.EmitOpcode(OpLengthOf, lengthOf.Pos.Line, lengthOf.Pos.Column)
	return nil
}

// resolveLengthOfTarget resolves the target of a "length of" expression to a string set index.
func (cc *conditionCompiler) resolveLengthOfTarget(lengthOf *ast.LengthOf) (int, token.Position) {
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

func (cc *conditionCompiler) compileMinusOperator(unaryOp *ast.UnaryOp) error {
	if lit, ok := unaryOp.Right.(*ast.Literal); ok && lit.Type == token.IntegerLit {
		if text, ok := lit.Value.(string); ok && text == "9223372036854775808" {
			cc.emitter.EmitPush(uint64(1)<<63, lit.Pos.Line, lit.Pos.Column)
			return nil
		}
	}
	if err := cc.compileExpression(unaryOp.Right); err != nil {
		return err
	}

	if cc.isFloatExpression(unaryOp.Right) {
		cc.emitter.EmitOpcode(OpDblMinus, unaryOp.Pos.Line, unaryOp.Pos.Column)
	} else {
		cc.emitter.EmitOpcode(OpIntMinus, unaryOp.Pos.Line, unaryOp.Pos.Column)
	}
	return nil
}

func (cc *conditionCompiler) compileDefinedOperator(unaryOp *ast.UnaryOp) error {
	if err := cc.compileExpression(unaryOp.Right); err != nil {
		return err
	}
	cc.emitter.EmitOpcode(OpDefined, unaryOp.Pos.Line, unaryOp.Pos.Column)
	return nil
}

// compileStringLength compiles string length expressions (!a or !a[i])
func (cc *conditionCompiler) compileStringLength(strLen *ast.StringLength) error {
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
func (cc *conditionCompiler) compileStringOffset(strOffset *ast.StringOffset) error {
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
func (cc *conditionCompiler) compileStringCount(strCount *ast.StringCount) error {
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
