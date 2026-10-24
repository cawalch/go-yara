package compiler

import (
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/semantic"
	"github.com/cawalch/go-yara/token"
)

type moduleIterationPlan struct {
	Kind       ModuleValueType
	ValueSlot  int
	KeySlot    int
	Quantifier string
	Target     int64
}

func (cc *conditionCompiler) emitModuleName(op Opcode, name string, pos token.Position) {
	index := slices.Index(cc.moduleAccessNames, name)
	if index < 0 {
		index = len(cc.moduleAccessNames)
		cc.moduleAccessNames = append(cc.moduleAccessNames, name)
	}
	cc.emitter.EmitOpcodeWithOperand(op, Operand{Type: OperandImmediate32, Value: uint64(index)}, pos.Line, pos.Column)
}

func (cc *conditionCompiler) compileModuleMember(expr *ast.MemberAccess) error {
	if value := cc.moduleConstant(expr); value != nil {
		return cc.compileModuleConstant(*value, expr.Pos)
	}
	if err := cc.compileExpression(expr.Object); err != nil {
		return err
	}
	cc.emitModuleName(OpModuleGetField, expr.Member, expr.Pos)
	return nil
}

func (cc *conditionCompiler) compileModuleIndex(expr *ast.IndexAccess) error {
	if err := cc.compileExpression(expr.Object); err != nil {
		return err
	}
	if err := cc.compileExpression(expr.Index); err != nil {
		return err
	}
	cc.emitter.EmitOpcode(OpModuleGetIndex, expr.Pos.Line, expr.Pos.Column)
	return nil
}

func (cc *conditionCompiler) moduleConstant(expr ast.Expression) *ModuleValue {
	var path []string
	for {
		switch e := expr.(type) {
		case *ast.MemberAccess:
			path = append(path, e.Member)
			expr = e.Object
		case *ast.Identifier:
			if _, variable := cc.variableMap[e.Name]; variable {
				return nil
			}
			schema := cc.moduleSchemas[e.Name]
			for index := len(path) - 1; index >= 0; index-- {
				if schema == nil {
					return nil
				}
				field, ok := schema.Fields[path[index]]
				if !ok {
					return nil
				}
				if index == 0 {
					return field.Constant
				}
				schema = field.Struct
			}
			return nil
		default:
			return nil
		}
	}
}

func (cc *conditionCompiler) compileModuleConstant(value ModuleValue, pos token.Position) error {
	switch value.Type {
	case ModuleInteger:
		cc.emitter.EmitPush(uint64(value.Integer), pos.Line, pos.Column) // #nosec G115 -- preserve signed bits
	case ModuleFloat:
		cc.emitter.EmitPushDouble(value.Float, pos.Line, pos.Column)
	case ModuleString:
		cc.emitter.EmitPushString(value.String, pos.Line, pos.Column)
	case ModuleBoolean:
		cc.emitter.EmitPush(uint64(boolToInt(value.Boolean)), pos.Line, pos.Column)
	default:
		return errors.New("invalid module constant")
	}
	return nil
}

func (cc *conditionCompiler) compileModuleLoop(loop *ast.ForLoop, collection *semantic.TypeInfo) error {
	if err := cc.compileExpression(loop.Range); err != nil {
		return err
	}
	slots, err := cc.allocateVariables(loop.Variables)
	if err != nil {
		return err
	}
	plan := moduleIterationPlan{Kind: ModuleArray, ValueSlot: slots[len(slots)-1], KeySlot: -1, Quantifier: loop.Quantifier}
	if collection.DataType == semantic.TypeDictionary {
		plan.KeySlot = slots[0]
		plan.Kind = ModuleDictionary
	}
	switch loop.Quantifier {
	case QuantifierAny, QuantifierAll, QuantifierNone:
	default:
		var ok bool
		plan.Target, ok = parseNumericQuantifier(loop.Quantifier)
		if !ok || plan.Target < 0 {
			return fmt.Errorf("invalid collection quantifier %q", loop.Quantifier)
		}
	}
	index := len(cc.moduleIterations)
	cc.moduleIterations = append(cc.moduleIterations, plan)
	cc.emitter.EmitOpcodeWithOperand(OpIterStartModuleArray, Operand{Type: OperandImmediate32, Value: uint64(index)}, loop.Pos.Line, loop.Pos.Column)
	outer := cc.moduleTypes
	cc.moduleTypes = maps.Clone(outer)
	defer func() { cc.moduleTypes = outer }()
	for index, name := range loop.Variables {
		cc.moduleTypes[name] = collection.Element
		if collection.DataType == semantic.TypeDictionary && index == 0 {
			cc.moduleTypes[name] = &semantic.TypeInfo{DataType: semantic.TypeString}
		}
	}
	return cc.compileForLoopBody(loop.Quantifier, loop.Condition, loop.Pos, -1)
}

func (plan moduleIterationPlan) validate() error {
	if plan.ValueSlot < 0 || plan.ValueSlot >= interpreterMemorySlotCount {
		return errors.New("invalid module value slot")
	}
	switch plan.Kind {
	case ModuleArray:
		if plan.KeySlot != -1 {
			return errors.New("array iterator has a key slot")
		}
	case ModuleDictionary:
		if plan.KeySlot < 0 || plan.KeySlot >= interpreterMemorySlotCount || plan.KeySlot == plan.ValueSlot {
			return errors.New("invalid module key slot")
		}
	default:
		return errors.New("invalid module collection kind")
	}
	switch plan.Quantifier {
	case QuantifierAny, QuantifierAll, QuantifierNone:
		return nil
	default:
		target, ok := parseNumericQuantifier(plan.Quantifier)
		if !ok || target < 0 || target != plan.Target {
			return errors.New("invalid module quantifier")
		}
	}
	return nil
}
