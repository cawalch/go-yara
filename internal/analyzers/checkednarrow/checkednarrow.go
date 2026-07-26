// Package checkednarrow defines an analyzer for risky integer conversions.
package checkednarrow

import (
	"go/constant"
	"go/token"
	"go/types"
	"math/big"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

const ignoreDirective = "checkednarrow:ignore"

// Analyzer reports integer conversions that may lose value unless their SSA
// input is range-checked, masked, shifted into range, or locally suppressed.
var Analyzer = &analysis.Analyzer{
	Name:     "checkednarrow",
	Doc:      "checks potentially lossy integer conversions for range proofs",
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
	Run:      run,
}

type integerType struct {
	bits   uint
	signed bool
	name   string
}

type integerRange struct {
	min *big.Int
	max *big.Int
}

type checker struct {
	pass         *analysis.Pass
	suppressions map[string]map[int]bool
	reported     map[token.Pos]bool
}

type phiEdge struct {
	index int
	value ssa.Value
}

type rangeCondition struct {
	value     ssa.Value
	condition ssa.Value
	truth     bool
}

func run(pass *analysis.Pass) (any, error) {
	if pass.Pkg.Name() != "compiler" && pass.Pkg.Name() != "regex" {
		return nil, nil
	}
	checker := checker{
		pass:         pass,
		suppressions: collectSuppressions(pass),
		reported:     make(map[token.Pos]bool),
	}
	ssaResult := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA)
	for _, function := range ssaResult.SrcFuncs {
		checker.checkFunction(function)
	}
	return nil, nil
}

func (checker *checker) checkFunction(function *ssa.Function) {
	for _, block := range function.Blocks {
		for _, instruction := range block.Instrs {
			conversion, ok := instruction.(*ssa.Convert)
			if !ok || conversion.Pos() == token.NoPos || checker.isTestPosition(conversion.Pos()) {
				continue
			}
			source, sourceOK := checker.integerType(conversion.X.Type())
			destination, destinationOK := checker.integerType(conversion.Type())
			if !sourceOK || !destinationOK || conversionSafeByType(source, destination) {
				continue
			}
			valueRange := checker.valueRange(conversion.X, make(map[ssa.Value]bool))
			checker.applyDominatingConditions(conversion.X, block, &valueRange)
			checker.applyInductionBounds(conversion.X, block, &valueRange)
			if rangeFits(valueRange, destination) || checker.isSuppressed(conversion.Pos()) {
				continue
			}
			if checker.reported[conversion.Pos()] {
				continue
			}
			checker.reported[conversion.Pos()] = true
			checker.pass.Reportf(
				conversion.Pos(),
				"conversion from %s to %s may lose value; guard, mask, or add //%s with a reason",
				source.name,
				destination.name,
				ignoreDirective,
			)
		}
	}
}

func (checker *checker) integerType(valueType types.Type) (integerType, bool) {
	basic, ok := valueType.Underlying().(*types.Basic)
	if !ok || basic.Info()&types.IsInteger == 0 {
		return integerType{}, false
	}
	size := checker.pass.TypesSizes.Sizeof(valueType)
	if size <= 0 {
		return integerType{}, false
	}
	return integerType{
		bits:   uint(size * 8),
		signed: basic.Info()&types.IsUnsigned == 0,
		name:   types.TypeString(valueType, nil),
	}, true
}

func conversionSafeByType(source, destination integerType) bool {
	if destination.bits > source.bits {
		return true
	}
	if destination.bits == source.bits {
		return source.signed || !destination.signed
	}
	return false
}

func (checker *checker) valueRange(value ssa.Value, seen map[ssa.Value]bool) integerRange {
	valueType, ok := checker.integerType(value.Type())
	if !ok {
		return integerRange{}
	}
	typeRange := rangeForType(valueType)
	if seen[value] {
		return typeRange
	}
	seen[value] = true
	defer delete(seen, value)

	switch value := value.(type) {
	case *ssa.Const:
		if exact, ok := constantToBigInt(value.Value); ok {
			return integerRange{min: exact, max: new(big.Int).Set(exact)}
		}
	case *ssa.Convert:
		sourceType, sourceOK := checker.integerType(value.X.Type())
		destinationType, destinationOK := checker.integerType(value.Type())
		if sourceOK && destinationOK && conversionSafeByType(sourceType, destinationType) {
			return checker.valueRange(value.X, seen)
		}
	case *ssa.Phi:
		if valueRange, ok := checker.phiInitialRange(value, seen); ok {
			return valueRange
		}
	case *ssa.BinOp:
		switch value.Op {
		case token.AND:
			if mask, ok := integerConstantOperand(value); ok && mask.Sign() >= 0 {
				return integerRange{min: new(big.Int), max: mask}
			}
		case token.ADD:
			if addedRange, ok := checker.offsetRange(value, seen, false); ok {
				return boundedArithmeticRange(addedRange, typeRange)
			}
		case token.SUB:
			if subtractedRange, ok := checker.offsetRange(value, seen, true); ok {
				return boundedArithmeticRange(subtractedRange, typeRange)
			}
		case token.SHR:
			if shift, ok := unsignedConstant(value.Y); ok && typeRange.min.Sign() >= 0 {
				maximum := new(big.Int).Rsh(new(big.Int).Set(typeRange.max), uint(shift))
				return integerRange{min: new(big.Int), max: maximum}
			}
		case token.SHL:
			if shift, ok := unsignedConstant(value.Y); ok {
				inputRange := checker.valueRange(value.X, seen)
				if inputRange.min.Sign() >= 0 {
					shiftedRange := integerRange{
						min: new(big.Int).Lsh(new(big.Int).Set(inputRange.min), uint(shift)),
						max: new(big.Int).Lsh(new(big.Int).Set(inputRange.max), uint(shift)),
					}
					return boundedArithmeticRange(shiftedRange, typeRange)
				}
			}
		}
	case *ssa.Call:
		if isNonNegativeBuiltin(value.Common()) {
			typeRange.min = new(big.Int)
		}
	}
	return typeRange
}

func (checker *checker) offsetRange(
	operation *ssa.BinOp,
	seen map[ssa.Value]bool,
	subtract bool,
) (integerRange, bool) {
	constantOffset, ok := operation.Y.(*ssa.Const)
	if !ok {
		if subtract {
			return integerRange{}, false
		}
		constantOffset, ok = operation.X.(*ssa.Const)
		if !ok {
			return integerRange{}, false
		}
	}
	offset, ok := constantToBigInt(constantOffset.Value)
	if !ok {
		return integerRange{}, false
	}
	input := operation.X
	if input == constantOffset {
		input = operation.Y
	}
	inputRange := checker.valueRange(input, seen)
	if subtract {
		offset.Neg(offset)
	}
	return integerRange{
		min: new(big.Int).Add(inputRange.min, offset),
		max: new(big.Int).Add(inputRange.max, offset),
	}, true
}

func boundedArithmeticRange(candidate, typeRange integerRange) integerRange {
	if candidate.min.Cmp(typeRange.min) < 0 || candidate.max.Cmp(typeRange.max) > 0 {
		return typeRange
	}
	return candidate
}

func (checker *checker) phiInitialRange(
	phi *ssa.Phi,
	seen map[ssa.Value]bool,
) (integerRange, bool) {
	var combined integerRange
	var cyclicEdges []phiEdge
	found := false
	for index, edge := range phi.Edges {
		if dependsOn(edge, phi, make(map[ssa.Value]bool)) {
			cyclicEdges = append(cyclicEdges, phiEdge{index: index, value: edge})
			continue
		}
		edgeRange := checker.valueRange(edge, seen)
		checker.applyPhiEdgeCondition(
			phi,
			phiEdge{index: index, value: edge},
			&edgeRange,
		)
		if !found {
			combined = edgeRange
			found = true
			continue
		}
		combined.min = minBig(combined.min, edgeRange.min)
		combined.max = maxBig(combined.max, edgeRange.max)
	}
	if !found {
		return integerRange{}, false
	}
	for _, edge := range cyclicEdges {
		step, ok := inductionStep(edge.value, phi)
		if !ok || step.Sign() == 0 {
			return integerRange{}, false
		}
		edgeRange, ok := checker.guardedCycleEdgeRange(phi, edge)
		if !ok {
			return integerRange{}, false
		}
		typeRange := rangeForType(checker.mustIntegerType(edge.value.Type()))
		switch step.Sign() {
		case 1:
			lastSafeValue := new(big.Int).Sub(typeRange.max, step)
			if edgeRange.max.Cmp(lastSafeValue) > 0 {
				return integerRange{}, false
			}
			edgeRange.min = maxBig(edgeRange.min, combined.min)
		case -1:
			lastSafeValue := new(big.Int).Sub(typeRange.min, step)
			if edgeRange.min.Cmp(lastSafeValue) < 0 {
				return integerRange{}, false
			}
			edgeRange.max = minBig(edgeRange.max, combined.max)
		}
		combined.min = minBig(combined.min, edgeRange.min)
		combined.max = maxBig(combined.max, edgeRange.max)
	}
	return combined, true
}

func (checker *checker) guardedCycleEdgeRange(
	phi *ssa.Phi,
	edge phiEdge,
) (integerRange, bool) {
	if edge.index >= len(phi.Block().Preds) {
		return integerRange{}, false
	}
	predecessor := phi.Block().Preds[edge.index]
	if len(predecessor.Instrs) == 0 || len(predecessor.Succs) != 2 {
		return integerRange{}, false
	}
	branch, ok := predecessor.Instrs[len(predecessor.Instrs)-1].(*ssa.If)
	if !ok {
		return integerRange{}, false
	}

	edgeRange := rangeForType(checker.mustIntegerType(edge.value.Type()))
	switch {
	case predecessor.Succs[0] == phi.Block():
		if blockCanReachPhiCycle(predecessor.Succs[1], phi, make(map[*ssa.BasicBlock]bool)) {
			return integerRange{}, false
		}
		checker.applyCondition(
			rangeCondition{value: edge.value, condition: branch.Cond, truth: true},
			&edgeRange,
		)
	case predecessor.Succs[1] == phi.Block():
		if blockCanReachPhiCycle(predecessor.Succs[0], phi, make(map[*ssa.BasicBlock]bool)) {
			return integerRange{}, false
		}
		checker.applyCondition(
			rangeCondition{value: edge.value, condition: branch.Cond},
			&edgeRange,
		)
	default:
		return integerRange{}, false
	}
	return edgeRange, true
}

func (checker *checker) applyPhiEdgeCondition(
	phi *ssa.Phi,
	edge phiEdge,
	edgeRange *integerRange,
) {
	if edge.index >= len(phi.Block().Preds) {
		return
	}
	predecessor := phi.Block().Preds[edge.index]
	if len(predecessor.Instrs) == 0 || len(predecessor.Succs) != 2 {
		return
	}
	branch, ok := predecessor.Instrs[len(predecessor.Instrs)-1].(*ssa.If)
	if !ok {
		return
	}
	switch {
	case predecessor.Succs[0] == phi.Block():
		checker.applyCondition(
			rangeCondition{value: edge.value, condition: branch.Cond, truth: true},
			edgeRange,
		)
	case predecessor.Succs[1] == phi.Block():
		checker.applyCondition(
			rangeCondition{value: edge.value, condition: branch.Cond},
			edgeRange,
		)
	}
}

func dependsOn(value, target ssa.Value, seen map[ssa.Value]bool) bool {
	if value == target {
		return true
	}
	if seen[value] {
		return false
	}
	seen[value] = true
	instruction, ok := value.(ssa.Instruction)
	if !ok {
		return false
	}
	for _, operand := range instruction.Operands(nil) {
		if operand != nil && *operand != nil && dependsOn(*operand, target, seen) {
			return true
		}
	}
	return false
}

func (checker *checker) applyDominatingConditions(
	value ssa.Value,
	conversionBlock *ssa.BasicBlock,
	valueRange *integerRange,
) {
	for _, block := range conversionBlock.Parent().Blocks {
		if len(block.Instrs) == 0 || len(block.Succs) != 2 {
			continue
		}
		branch, ok := block.Instrs[len(block.Instrs)-1].(*ssa.If)
		if !ok {
			continue
		}
		switch {
		case block.Succs[0].Dominates(conversionBlock):
			checker.applyCondition(
				rangeCondition{value: value, condition: branch.Cond, truth: true},
				valueRange,
			)
		case block.Succs[1].Dominates(conversionBlock):
			checker.applyCondition(
				rangeCondition{value: value, condition: branch.Cond},
				valueRange,
			)
		}
	}
}

func (checker *checker) applyInductionBounds(
	value ssa.Value,
	conversionBlock *ssa.BasicBlock,
	valueRange *integerRange,
) {
	phi, offset, ok := inductionSource(value)
	if !ok {
		return
	}
	header := phi.Block()
	if len(header.Instrs) == 0 || len(header.Succs) != 2 {
		return
	}
	branch, ok := header.Instrs[len(header.Instrs)-1].(*ssa.If)
	if !ok {
		return
	}

	guardRange := rangeForType(checker.mustIntegerType(phi.Type()))
	var exit *ssa.BasicBlock
	switch {
	case header.Succs[0].Dominates(conversionBlock):
		exit = header.Succs[1]
		checker.applyCondition(
			rangeCondition{value: value, condition: branch.Cond, truth: true},
			&guardRange,
		)
	case header.Succs[1].Dominates(conversionBlock):
		exit = header.Succs[0]
		checker.applyCondition(
			rangeCondition{value: value, condition: branch.Cond},
			&guardRange,
		)
	default:
		return
	}
	if blockCanReachPhiCycle(exit, phi, make(map[*ssa.BasicBlock]bool)) {
		return
	}

	initialRange, step, ok := checker.induction(phi)
	if !ok {
		return
	}
	initialRange.min.Add(initialRange.min, offset)
	initialRange.max.Add(initialRange.max, offset)
	typeRange := rangeForType(checker.mustIntegerType(phi.Type()))
	switch step.Sign() {
	case 1:
		lastSafeValue := new(big.Int).Sub(typeRange.max, step)
		if guardRange.max.Cmp(lastSafeValue) <= 0 {
			valueRange.min = maxBig(valueRange.min, initialRange.min)
		}
	case -1:
		lastSafeValue := new(big.Int).Sub(typeRange.min, step)
		if guardRange.min.Cmp(lastSafeValue) >= 0 {
			valueRange.max = minBig(valueRange.max, initialRange.max)
		}
	}
}

func inductionSource(value ssa.Value) (*ssa.Phi, *big.Int, bool) {
	if phi, ok := value.(*ssa.Phi); ok {
		return phi, new(big.Int), true
	}
	operation, ok := value.(*ssa.BinOp)
	if !ok {
		return nil, nil, false
	}
	switch operation.Op {
	case token.ADD:
		if phi, ok := operation.X.(*ssa.Phi); ok {
			offset, constantOK := ssaIntegerConstant(operation.Y)
			return phi, offset, constantOK
		}
		if phi, ok := operation.Y.(*ssa.Phi); ok {
			offset, constantOK := ssaIntegerConstant(operation.X)
			return phi, offset, constantOK
		}
	case token.SUB:
		if phi, ok := operation.X.(*ssa.Phi); ok {
			offset, constantOK := ssaIntegerConstant(operation.Y)
			if constantOK {
				offset.Neg(offset)
			}
			return phi, offset, constantOK
		}
	}
	return nil, nil, false
}

func (checker *checker) induction(phi *ssa.Phi) (integerRange, *big.Int, bool) {
	var initialRange integerRange
	var step *big.Int
	foundInitial := false
	foundCycle := false
	for _, edge := range phi.Edges {
		if dependsOn(edge, phi, make(map[ssa.Value]bool)) {
			edgeStep, ok := inductionStep(edge, phi)
			if !ok || edgeStep.Sign() == 0 || step != nil && step.Cmp(edgeStep) != 0 {
				return integerRange{}, nil, false
			}
			step = edgeStep
			foundCycle = true
			continue
		}
		edgeRange := checker.valueRange(edge, make(map[ssa.Value]bool))
		if !foundInitial {
			initialRange = edgeRange
			foundInitial = true
			continue
		}
		initialRange.min = minBig(initialRange.min, edgeRange.min)
		initialRange.max = maxBig(initialRange.max, edgeRange.max)
	}
	return initialRange, step, foundInitial && foundCycle
}

func inductionStep(value, phi ssa.Value) (*big.Int, bool) {
	operation, ok := value.(*ssa.BinOp)
	if !ok {
		return nil, false
	}
	switch operation.Op {
	case token.ADD:
		switch {
		case operation.X == phi:
			return ssaIntegerConstant(operation.Y)
		case operation.Y == phi:
			return ssaIntegerConstant(operation.X)
		}
	case token.SUB:
		if operation.X == phi {
			step, ok := ssaIntegerConstant(operation.Y)
			if ok {
				return step.Neg(step), true
			}
		}
	}
	return nil, false
}

func ssaIntegerConstant(value ssa.Value) (*big.Int, bool) {
	constantValue, ok := value.(*ssa.Const)
	if !ok {
		return nil, false
	}
	return constantToBigInt(constantValue.Value)
}

func blockCanReachPhiCycle(
	start *ssa.BasicBlock,
	phi *ssa.Phi,
	seen map[*ssa.BasicBlock]bool,
) bool {
	if seen[start] {
		return false
	}
	seen[start] = true
	for _, successor := range start.Succs {
		if successor == phi.Block() {
			for index, predecessor := range phi.Block().Preds {
				if predecessor == start {
					return index < len(phi.Edges) &&
						dependsOn(phi.Edges[index], phi, make(map[ssa.Value]bool))
				}
			}
			continue
		}
		if blockCanReachPhiCycle(successor, phi, seen) {
			return true
		}
	}
	return false
}

func (checker *checker) applyCondition(
	condition rangeCondition,
	valueRange *integerRange,
) {
	if negation, ok := condition.condition.(*ssa.UnOp); ok && negation.Op == token.NOT {
		condition.condition = negation.X
		condition.truth = !condition.truth
		checker.applyCondition(condition, valueRange)
		return
	}
	comparison, ok := condition.condition.(*ssa.BinOp)
	if !ok || !isComparison(comparison.Op) {
		return
	}

	operator := comparison.Op
	other := comparison.Y
	switch {
	case comparison.X == condition.value:
	case comparison.Y == condition.value:
		operator = reverseComparison(operator)
		other = comparison.X
	default:
		return
	}
	if !condition.truth {
		operator = negateComparison(operator)
	}
	otherRange := checker.valueRange(other, make(map[ssa.Value]bool))
	applyRangeComparison(valueRange, operator, otherRange)
}

func (checker *checker) mustIntegerType(valueType types.Type) integerType {
	result, ok := checker.integerType(valueType)
	if !ok {
		panic("checkednarrow: induction variable is not an integer")
	}
	return result
}

func applyRangeComparison(target *integerRange, operator token.Token, other integerRange) {
	switch operator {
	case token.LSS:
		upper := new(big.Int).Sub(other.max, big.NewInt(1))
		target.max = minBig(target.max, upper)
	case token.LEQ:
		target.max = minBig(target.max, other.max)
	case token.GTR:
		lower := new(big.Int).Add(other.min, big.NewInt(1))
		target.min = maxBig(target.min, lower)
	case token.GEQ:
		target.min = maxBig(target.min, other.min)
	case token.EQL:
		target.min = maxBig(target.min, other.min)
		target.max = minBig(target.max, other.max)
	}
}

func rangeForType(valueType integerType) integerRange {
	if valueType.signed {
		maximum := new(big.Int).Sub(
			new(big.Int).Lsh(big.NewInt(1), valueType.bits-1),
			big.NewInt(1),
		)
		minimum := new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), valueType.bits-1))
		return integerRange{min: minimum, max: maximum}
	}
	maximum := new(big.Int).Sub(
		new(big.Int).Lsh(big.NewInt(1), valueType.bits),
		big.NewInt(1),
	)
	return integerRange{min: new(big.Int), max: maximum}
}

func rangeFits(valueRange integerRange, destination integerType) bool {
	destinationRange := rangeForType(destination)
	return valueRange.min.Cmp(destinationRange.min) >= 0 &&
		valueRange.max.Cmp(destinationRange.max) <= 0
}

func integerConstantOperand(operation *ssa.BinOp) (*big.Int, bool) {
	if value, ok := operation.X.(*ssa.Const); ok {
		return constantToBigInt(value.Value)
	}
	if value, ok := operation.Y.(*ssa.Const); ok {
		return constantToBigInt(value.Value)
	}
	return nil, false
}

func constantToBigInt(value constant.Value) (*big.Int, bool) {
	if value == nil || value.Kind() != constant.Int {
		return nil, false
	}
	integer := new(big.Int)
	_, ok := integer.SetString(value.ExactString(), 10)
	return integer, ok
}

func unsignedConstant(value ssa.Value) (uint64, bool) {
	constantValue, ok := value.(*ssa.Const)
	if !ok {
		return 0, false
	}
	return constant.Uint64Val(constant.ToInt(constantValue.Value))
}

func isNonNegativeBuiltin(call *ssa.CallCommon) bool {
	builtin, ok := call.Value.(*ssa.Builtin)
	return ok && (builtin.Name() == "len" || builtin.Name() == "cap")
}

func isComparison(operator token.Token) bool {
	switch operator {
	case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ:
		return true
	default:
		return false
	}
}

func reverseComparison(operator token.Token) token.Token {
	switch operator {
	case token.LSS:
		return token.GTR
	case token.LEQ:
		return token.GEQ
	case token.GTR:
		return token.LSS
	case token.GEQ:
		return token.LEQ
	default:
		return operator
	}
}

func negateComparison(operator token.Token) token.Token {
	switch operator {
	case token.EQL:
		return token.NEQ
	case token.NEQ:
		return token.EQL
	case token.LSS:
		return token.GEQ
	case token.LEQ:
		return token.GTR
	case token.GTR:
		return token.LEQ
	case token.GEQ:
		return token.LSS
	default:
		return operator
	}
}

func minBig(left, right *big.Int) *big.Int {
	if left.Cmp(right) <= 0 {
		return left
	}
	return right
}

func maxBig(left, right *big.Int) *big.Int {
	if left.Cmp(right) >= 0 {
		return left
	}
	return right
}

func collectSuppressions(pass *analysis.Pass) map[string]map[int]bool {
	suppressions := make(map[string]map[int]bool)
	for _, file := range pass.Files {
		for _, group := range file.Comments {
			for _, comment := range group.List {
				index := strings.Index(comment.Text, ignoreDirective)
				if index < 0 || strings.TrimSpace(comment.Text[index+len(ignoreDirective):]) == "" {
					continue
				}
				position := pass.Fset.PositionFor(comment.Slash, false)
				if suppressions[position.Filename] == nil {
					suppressions[position.Filename] = make(map[int]bool)
				}
				suppressions[position.Filename][position.Line] = true
				suppressions[position.Filename][position.Line+1] = true
			}
		}
	}
	return suppressions
}

func (checker *checker) isSuppressed(position token.Pos) bool {
	source := checker.pass.Fset.PositionFor(position, false)
	return checker.suppressions[source.Filename][source.Line]
}

func (checker *checker) isTestPosition(position token.Pos) bool {
	filename := checker.pass.Fset.PositionFor(position, false).Filename
	return strings.HasSuffix(filepath.Base(filename), "_test.go")
}
