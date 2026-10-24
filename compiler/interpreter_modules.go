package compiler

import "encoding/binary"

func (i *Interpreter) moduleNameOperand(opcode Opcode) (string, error) {
	if err := i.validateBytecodeBounds(opcode, 4); err != nil {
		return "", err
	}
	index := uint64(binary.LittleEndian.Uint32(i.bytecode[i.ip : i.ip+4]))
	i.ip += 4
	if i.currentCompiledRule == nil || index >= uint64(len(i.currentCompiledRule.moduleAccessNames)) {
		return "", &InterpreterError{Type: ErrorInvalidBytecode, Opcode: opcode, Message: "invalid module name operand"}
	}
	return i.currentCompiledRule.moduleAccessNames[index], nil
}

func (i *Interpreter) executeModuleLoad() error {
	name, err := i.moduleNameOperand(OpModuleLoad)
	if err != nil {
		return err
	}
	return i.pushModuleValue(i.moduleData[name])
}

func (i *Interpreter) executeModuleGetField() error {
	name, err := i.moduleNameOperand(OpModuleGetField)
	if err != nil {
		return err
	}
	if err := i.validateStackUnderflow(OpModuleGetField); err != nil {
		return err
	}
	value := i.stack[len(i.stack)-1]
	i.stack = i.stack[:len(i.stack)-1]
	if value.Type == ValueTypeUndefined {
		return i.push(value)
	}
	if value.Type != ValueTypeObject || value.object == nil || value.object.kind != ModuleStruct {
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpModuleGetField, Message: "module field requires a structure"}
	}
	return i.pushModuleValue(value.object.fields[name])
}

func (i *Interpreter) executeModuleGetIndex() error {
	if err := i.validateStackUnderflowN(OpModuleGetIndex, 2); err != nil {
		return err
	}
	key, value := i.stack[len(i.stack)-1], i.stack[len(i.stack)-2]
	i.stack = i.stack[:len(i.stack)-2]
	if key.Type == ValueTypeUndefined || value.Type == ValueTypeUndefined {
		return i.push(Value{Type: ValueTypeUndefined})
	}
	if value.Type != ValueTypeObject || value.object == nil {
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpModuleGetIndex, Message: "index requires a module collection"}
	}
	var result ModuleValue
	switch {
	case value.object.kind == ModuleArray && key.Type == ValueTypeInt:
		if key.IntVal >= 0 && key.IntVal < int64(len(value.object.elements)) {
			result = value.object.elements[key.IntVal]
		}
	case value.object.kind == ModuleDictionary && key.Type == ValueTypeString:
		result = value.object.fields[i.getString(key)]
	default:
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpModuleGetIndex, Message: "invalid module collection index"}
	}
	return i.pushModuleValue(result)
}

func (i *Interpreter) executeIterStartModuleArray() error {
	if err := i.validateBytecodeBounds(OpIterStartModuleArray, 4); err != nil {
		return err
	}
	index := uint64(binary.LittleEndian.Uint32(i.bytecode[i.ip : i.ip+4]))
	i.ip += 4
	if i.currentCompiledRule == nil || index >= uint64(len(i.currentCompiledRule.moduleIterations)) {
		return &InterpreterError{Type: ErrorInvalidBytecode, Opcode: OpIterStartModuleArray, Message: "invalid module iterator operand"}
	}
	plan := i.currentCompiledRule.moduleIterations[index]
	if err := plan.validate(); err != nil {
		return &InterpreterError{Type: ErrorInvalidBytecode, Opcode: OpIterStartModuleArray, Message: err.Error()}
	}
	if err := i.validateStackUnderflow(OpIterStartModuleArray); err != nil {
		return err
	}
	value := i.stack[len(i.stack)-1]
	i.stack = i.stack[:len(i.stack)-1]
	iter := Iterator{Type: OpIterStartModuleArray, modulePlan: plan}
	if value.Type != ValueTypeUndefined {
		if value.Type != ValueTypeObject || value.object == nil || value.object.kind != plan.Kind {
			return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpIterStartModuleArray, Message: "invalid module iterator collection"}
		}
		iter.moduleObject = value.object
		iter.Total = len(value.object.elements)
		if plan.Kind == ModuleDictionary {
			iter.Total = len(value.object.keys)
		}
	}
	if plan.Quantifier != QuantifierAny && plan.Quantifier != QuantifierAll && plan.Quantifier != QuantifierNone && plan.Target == 0 {
		iter.Total = 0
	}
	i.iterators = append(i.iterators, iter)
	return nil
}

func (i *Interpreter) nextModuleElement(iter *Iterator) error {
	var value ModuleValue
	if iter.modulePlan.Kind == ModuleDictionary {
		key := iter.moduleObject.keys[iter.Index]
		value = iter.moduleObject.fields[key]
		if err := i.pushString(key); err != nil {
			return err
		}
		i.memory[iter.modulePlan.KeySlot] = i.stack[len(i.stack)-1]
		i.stack = i.stack[:len(i.stack)-1]
	} else {
		value = iter.moduleObject.elements[iter.Index]
	}
	if err := i.pushModuleValue(value); err != nil {
		return err
	}
	i.memory[iter.modulePlan.ValueSlot] = i.stack[len(i.stack)-1]
	i.stack = i.stack[:len(i.stack)-1]
	return nil
}

func (iter *Iterator) moduleQuantifierDecided(truth bool) bool {
	switch iter.modulePlan.Quantifier {
	case QuantifierAny, QuantifierNone:
		return truth
	case QuantifierAll:
		return !truth
	default:
		return int64(iter.Count) >= iter.modulePlan.Target
	}
}
