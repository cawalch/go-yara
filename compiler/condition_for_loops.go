package compiler

import (
	"errors"
	"fmt"
	"maps"
	"strconv"
	"strings"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

func (cc *conditionCompiler) compileForLoop(forLoop *ast.ForLoop) error {
	if plan, ok := cc.tryParseProximityLoop(forLoop); ok {
		return cc.compileProximity(plan, forLoop.Pos)
	}

	outerVariables, outerSlot := cc.variableMap, cc.nextVariableSlot
	cc.variableMap = maps.Clone(outerVariables)
	defer func() { cc.variableMap, cc.nextVariableSlot = outerVariables, outerSlot }()

	if len(forLoop.Variables) == 0 {
		return cc.compileForLoopOverStrings(forLoop)
	}

	// Handle tuple iteration: string set, integer enumeration, or text strings
	if tuple, ok := forLoop.Range.(*ast.StringTuple); ok {
		if isStringSetTuple(tuple) {
			return cc.compileForLoopOverStrings(forLoop)
		}
		if isIntegerTuple(tuple) {
			return cc.compileForLoopOverIntEnum(forLoop, tuple)
		}
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

	var startExpr, endExpr ast.Expression
	if rangeExpr, ok := forLoop.Range.(*ast.BinaryOp); ok && rangeExpr.Op == token.DOT {
		startExpr = rangeExpr.Left
		endExpr = rangeExpr.Right
	} else if forLoop.Range != nil {
		startExpr = forLoop.Range
		endExpr = forLoop.Range
	} else {
		return errors.New("unsupported for-loop range type, expected binary range operator")
	}

	slots, err := cc.allocateVariables(forLoop.Variables)
	if err != nil {
		return err
	}

	// 1. Push start and end to stack dynamically
	if err := cc.compileExpression(startExpr); err != nil {
		return fmt.Errorf("compiling range start: %w", err)
	}
	if err := cc.compileExpression(endExpr); err != nil {
		return fmt.Errorf("compiling range end: %w", err)
	}

	// 2. Start Iterator
	cc.emitter.EmitOpcodeWithOperand(OpIterStartIntRange, Operand{Type: OperandImmediate32, Value: uint64(slots[0])}, forLoop.Pos.Line, forLoop.Pos.Column)

	return cc.compileForLoopBody(forLoop.Quantifier, forLoop.Condition, forLoop.Pos, -1)
}

// compileForLoopOverTextStrings compiles: for any s in ("text1", "text2") : (...)
func (cc *conditionCompiler) compileForLoopOverTextStrings(forLoop *ast.ForLoop, tuple *ast.StringTuple) error {
	// Extract string literals from the tuple
	var literals []string
	for _, elem := range tuple.Elements {
		switch e := elem.(type) {
		case *ast.Literal:
			if e.Type != token.StringLit {
				return errors.New("text string set elements must be string literals")
			}
			literals = append(literals, e.Value.(string))
		default:
			return errors.New("text string set elements must be string literals")
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
func (cc *conditionCompiler) registerTextStringSet(literals []string) int {
	cc.textStringSets = append(cc.textStringSets, literals)
	return len(cc.textStringSets) - 1
}

// GetTextStringSets returns the compiled text string sets for this condition.
func (cc *conditionCompiler) GetTextStringSets() [][]string {
	sets := make([][]string, len(cc.textStringSets))
	for i, set := range cc.textStringSets {
		copied := make([]string, len(set))
		copy(copied, set)
		sets[i] = copied
	}
	return sets
}

// compileForLoopOverIntEnum compiles an integer enumeration loop: for any i in (1, 2, 3) : (...)
func (cc *conditionCompiler) compileForLoopOverIntEnum(forLoop *ast.ForLoop, tuple *ast.StringTuple) error {
	if len(tuple.Elements) == 0 {
		return errors.New("integer enumeration cannot be empty")
	}

	slots, err := cc.allocateVariables(forLoop.Variables)
	if err != nil {
		return err
	}

	// 1. Evaluate and push each integer expression onto the stack
	for _, elem := range tuple.Elements {
		if err := cc.compileExpression(elem); err != nil {
			return fmt.Errorf("compiling integer enumeration element: %w", err)
		}
	}

	// 2. Push total number of elements in the enumeration
	cc.emitter.EmitPush(uint64(len(tuple.Elements)), forLoop.Pos.Line, forLoop.Pos.Column)

	// 3. Emit OpIterStartIntEnum with the variable slot operand
	cc.emitter.EmitOpcodeWithOperand(OpIterStartIntEnum, Operand{Type: OperandImmediate32, Value: uint64(slots[0])}, forLoop.Pos.Line, forLoop.Pos.Column)

	// 4. Compile loop body with loopVarSlot = -1 (integer variable, not string variable)
	return cc.compileForLoopBody(forLoop.Quantifier, forLoop.Condition, forLoop.Pos, -1)
}

func isStringSetTuple(tuple *ast.StringTuple) bool {
	if len(tuple.Elements) == 0 {
		return false
	}
	for _, elem := range tuple.Elements {
		ident, ok := elem.(*ast.Identifier)
		if !ok || (!strings.HasPrefix(ident.Name, "$") && ident.Name != "them") {
			return false
		}
	}
	return true
}

func isIntegerTuple(tuple *ast.StringTuple) bool {
	if len(tuple.Elements) == 0 {
		return false
	}
	for _, elem := range tuple.Elements {
		switch e := elem.(type) {
		case *ast.Literal:
			if e.Type == token.IntegerLit {
				return true
			}
			if e.Type == token.StringLit {
				return false
			}
		case *ast.Identifier:
			if strings.HasPrefix(e.Name, "$") || e.Name == "them" {
				return false
			}
			return true
		default:
			return true
		}
	}
	return false
}

func (cc *conditionCompiler) compileForLoopOverStrings(forLoop *ast.ForLoop) error {
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

	cc.patternLoopSlots[slots[0]] = true
	defer delete(cc.patternLoopSlots, slots[0])

	index := cc.internStringSet(ids)

	// Compile optional "in (range)" or "at offset" constraints
	// Stack layout (bottom to top): [args..., stringSetIndex, constraintMarker]
	// constraintMarker: 0=no constraint, 1=in range, 2=at offset
	var constraintMarker uint64
	switch {
	case forLoop.InRange != nil:
		rangeOp, ok := forLoop.InRange.(*ast.BinaryOp)
		if !ok || rangeOp.Op != token.DOT {
			return errors.New("invalid range expression for 'in' constraint")
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
func (cc *conditionCompiler) compileForLoopBody(quantifier string, condition ast.Expression, pos token.Position, loopVarSlot int) error {
	// 1. Check if iterator is empty using OpIterPushTotal + OpJzP
	cc.emitter.EmitOpcode(OpIterPushTotal, pos.Line, pos.Column)
	jumpToEnd := cc.emitter.EmitJump(jumpConfig{Opcode: OpJzP, Line: pos.Line, Pos: pos.Column})

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
