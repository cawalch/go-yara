package compiler

// executeIterStartIntRange starts an integer range iterator.
func (i *Interpreter) executeIterStartIntRange() error {
	if err := i.validateStackUnderflowN(OpIterStartIntRange, 2); err != nil {
		return err
	}

	endVal := i.stack[len(i.stack)-1]
	startVal := i.stack[len(i.stack)-2]
	i.stack = i.stack[:len(i.stack)-2]

	if startVal.Type != ValueTypeInt || endVal.Type != ValueTypeInt {
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpIterStartIntRange, Message: "range bounds must be integers"}
	}

	slot1, err := i.readAndValidateMemorySlot(OpIterStartIntRange)
	if err != nil {
		return err
	}

	iter := Iterator{
		Type:       OpIterStartIntRange,
		Variables:  []int{slot1},
		StartValue: startVal.IntVal,
		EndValue:   endVal.IntVal,
		Index:      0,
		Total:      int(endVal.IntVal - startVal.IntVal + 1),
	}

	if iter.Total <= 0 {
		iter.Total = 0
	}

	i.iterators = append(i.iterators, iter)
	return nil
}

// executeIterStartStringSet starts a string set iterator.
// Stack layout (bottom to top): [min?, max?, offset?, stringSetIndex, constraintMarker]
// constraintMarker: 0=no constraint, 1=in range (min, max on stack), 2=at offset
func (i *Interpreter) executeIterStartStringSet() error {
	if err := i.validateStackUnderflowN(OpIterStartStringSet, 2); err != nil {
		return err
	}

	// Pop constraint marker
	markerVal := i.stack[len(i.stack)-1]
	i.stack = i.stack[:len(i.stack)-1]

	// Pop string set index
	stringIDVal := i.stack[len(i.stack)-1]
	i.stack = i.stack[:len(i.stack)-1]

	var inRange, atOffset bool
	var offsetMin, offsetMax, atOffsetValue int64

	if markerVal.Type == ValueTypeInt {
		var err error
		inRange, atOffset, offsetMin, offsetMax, atOffsetValue, err = i.parseConstraintMarker(markerVal.IntVal)
		if err != nil {
			return err
		}
	}

	var ids []string
	switch stringIDVal.Type {
	case ValueTypeInt:
		switch stringIDVal.IntVal {
		case stringSetAll:
			ids = i.allStringIdentifiers()
		case stringSetAnonymous:
			ids = i.anonymousStringIdentifiers()
		default:
			if stringIDVal.IntVal < 0 || int(stringIDVal.IntVal) >= len(i.stringSets) {
				return &InterpreterError{Type: ErrorRuntime, Opcode: OpIterStartStringSet, Message: "invalid string set reference"}
			}
			ids = i.stringSets[stringIDVal.IntVal]
		}
	case ValueTypeString:
		ids = []string{i.getString(stringIDVal)}
	default:
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpIterStartStringSet, Message: "invalid string set type"}
	}

	// Filter string IDs based on constraints
	if (inRange || atOffset) && i.matchContext != nil {
		filtered := make([]string, 0, len(ids))
		for _, id := range ids {
			matches, exists := i.matchContext.Matches[id]
			if !exists {
				continue
			}
			for _, m := range matches {
				if inRange && m.Offset >= offsetMin && m.Offset <= offsetMax {
					filtered = append(filtered, id)
					break
				}
				if atOffset && m.Offset == atOffsetValue {
					filtered = append(filtered, id)
					break
				}
			}
		}
		ids = filtered
	}

	slot1, err := i.readAndValidateMemorySlot(OpIterStartStringSet)
	if err != nil {
		return err
	}

	iter := Iterator{
		Type:      OpIterStartStringSet,
		Variables: []int{slot1},
		StringIDs: ids,
		Index:     0,
		Total:     len(ids),
	}

	i.iterators = append(i.iterators, iter)
	return nil
}

// executeIterStartTextStringSet starts iterating over a set of literal text strings.
// Used for: for any s in ("text1", "text2") : (condition)
// Stack: [textStringSetRef, constraintMarker]
func (i *Interpreter) executeIterStartTextStringSet() error {
	if err := i.validateStackUnderflowN(OpIterStartTextStringSet, 2); err != nil {
		return err
	}

	// Pop constraint marker
	markerVal := i.stack[len(i.stack)-1]
	i.stack = i.stack[:len(i.stack)-1]

	// Pop text string set index (index into textStringSets)
	textSetVal := i.stack[len(i.stack)-1]
	i.stack = i.stack[:len(i.stack)-1]

	var inRange, atOffset bool
	var offsetMin, offsetMax, atOffsetValue int64

	if markerVal.Type == ValueTypeInt {
		var err error
		inRange, atOffset, offsetMin, offsetMax, atOffsetValue, err = i.parseConstraintMarker(markerVal.IntVal)
		if err != nil {
			return err
		}
	}

	var textStrings []string
	switch textSetVal.Type {
	case ValueTypeInt:
		if textSetVal.IntVal < 0 || int(textSetVal.IntVal) >= len(i.textStringSets) {
			return &InterpreterError{Type: ErrorRuntime, Opcode: OpIterStartTextStringSet, Message: "invalid text string set reference"}
		}
		textStrings = i.textStringSets[textSetVal.IntVal]
	case ValueTypeString:
		textStrings = []string{i.getString(textSetVal)}
	default:
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpIterStartTextStringSet, Message: "invalid text string set type"}
	}

	// Text string sets don't have offset constraints (they're not YARA strings),
	// so inRange/atOffset constraints are ignored.
	_ = inRange
	_ = atOffset
	_ = offsetMin
	_ = offsetMax
	_ = atOffsetValue

	// Read the loop variable slot from the operand
	slot1, err := i.readAndValidateMemorySlot(OpIterStartTextStringSet)
	if err != nil {
		return err
	}

	iter := Iterator{
		Type:        OpIterStartTextStringSet,
		Variables:   []int{slot1},
		TextStrings: textStrings,
		Index:       0,
		Total:       len(textStrings),
	}

	i.iterators = append(i.iterators, iter)
	return nil
}

// parseConstraintMarker interprets the constraint marker value and pops
// the necessary operands from the stack.
func (i *Interpreter) parseConstraintMarker(
	marker int64,
) (inRange, atOffset bool, offsetMin, offsetMax, atOffsetValue int64, err error) {
	switch marker {
	case 0:
		// No constraint
	case 1:
		// In range: pop max, then min
		if err := i.validateStackUnderflowN(OpIterStartStringSet, 2); err != nil {
			return false, false, 0, 0, 0, err
		}
		offsetMaxVal := i.stack[len(i.stack)-1]
		offsetMinVal := i.stack[len(i.stack)-2]
		i.stack = i.stack[:len(i.stack)-2]
		if offsetMinVal.Type != ValueTypeInt || offsetMaxVal.Type != ValueTypeInt {
			return false, false, 0, 0, 0, &InterpreterError{
				Type: ErrorTypeMismatch, Opcode: OpIterStartStringSet,
				Message: "range bounds must be integers",
			}
		}
		return true, false, offsetMinVal.IntVal, offsetMaxVal.IntVal, 0, nil
	case 2:
		// At offset: pop offset
		if err := i.validateStackUnderflow(OpIterStartStringSet); err != nil {
			return false, false, 0, 0, 0, err
		}
		offsetVal := i.stack[len(i.stack)-1]
		i.stack = i.stack[:len(i.stack)-1]
		if offsetVal.Type != ValueTypeInt {
			return false, false, 0, 0, 0, &InterpreterError{
				Type: ErrorTypeMismatch, Opcode: OpIterStartStringSet,
				Message: "offset must be integer",
			}
		}
		return false, true, 0, 0, offsetVal.IntVal, nil
	default:
		return false, false, 0, 0, 0, &InterpreterError{
			Type: ErrorRuntime, Opcode: OpIterStartStringSet,
			Message: "invalid constraint marker",
		}
	}
	return false, false, 0, 0, 0, nil
}

// executeIterNext advances the current iterator to the next element.
func (i *Interpreter) executeIterNext() error {
	if len(i.iterators) == 0 {
		return &InterpreterError{Type: ErrorRuntime, Opcode: OpIterNext, Message: "no active iterator"}
	}
	if err := i.validateStackUnderflow(OpIterNext); err != nil {
		return err
	}
	targetIPVal := i.stack[len(i.stack)-1]
	i.stack = i.stack[:len(i.stack)-1]

	iter := &i.iterators[len(i.iterators)-1]

	if iter.Index < iter.Total {
		switch iter.Type {
		case OpIterStartIntRange:
			i.memory[iter.Variables[0]] = Value{Type: ValueTypeInt, IntVal: iter.StartValue + int64(iter.Index)}
		case OpIterStartStringSet:
			id := iter.StringIDs[iter.Index]
			i.memory[iter.Variables[0]] = Value{Type: ValueTypeString, StringRef: i.resolveStringRef(id)}
		case OpIterStartTextStringSet:
			text := iter.TextStrings[iter.Index]
			if err := i.pushString(text); err != nil {
				return err
			}
			i.memory[iter.Variables[0]] = Value{Type: ValueTypeString, StringRef: int64(len(i.stringArena) - 1)}
		}

		iter.Index++
		i.ip = int(targetIPVal.IntVal)
		return nil
	}

	return nil
}

// resolveStringRef resolves a string to a StringRef for the interpreter stack.
func (i *Interpreter) resolveStringRef(str string) int64 {
	if i.currentCompiledRule != nil && i.currentCompiledRule.StringNameToRef != nil {
		if ref, ok := i.currentCompiledRule.StringNameToRef[str]; ok {
			return ref
		}
	}

	for idx, s := range i.stringLiterals {
		if s == str {
			return int64(-1 - idx)
		}
	}

	if err := i.pushString(str); err == nil {
		val := i.stack[len(i.stack)-1]
		i.stack = i.stack[:len(i.stack)-1]
		return val.StringRef
	}
	return -1
}

// executeIterCondition evaluates the condition for the current iteration.
func (i *Interpreter) executeIterCondition() error {
	if len(i.iterators) == 0 {
		return &InterpreterError{Type: ErrorRuntime, Opcode: OpIterCondition, Message: "no active iterator"}
	}
	if err := i.validateStackUnderflow(OpIterCondition); err != nil {
		return err
	}

	condVal := i.stack[len(i.stack)-1]
	i.stack = i.stack[:len(i.stack)-1]

	iter := &i.iterators[len(i.iterators)-1]
	if i.isTruthy(condVal) {
		iter.Count++
	}

	return nil
}

// executeIterPushTotal pushes the total count of the current iterator.
func (i *Interpreter) executeIterPushTotal() error {
	if len(i.iterators) == 0 {
		return &InterpreterError{Type: ErrorRuntime, Opcode: OpIterPushTotal, Message: "no active iterator"}
	}

	iter := i.iterators[len(i.iterators)-1]
	return i.push(Value{Type: ValueTypeInt, IntVal: int64(iter.Total)})
}

// executeIterEnd ends the current iterator and pushes the match count.
func (i *Interpreter) executeIterEnd() error {
	if len(i.iterators) == 0 {
		return &InterpreterError{Type: ErrorRuntime, Opcode: OpIterEnd, Message: "no active iterator"}
	}

	iter := i.iterators[len(i.iterators)-1]
	i.iterators = i.iterators[:len(i.iterators)-1]

	return i.push(Value{Type: ValueTypeInt, IntVal: int64(iter.Count)})
}

// executeIterUnimplemented returns an error for iterator types not yet implemented.
func (i *Interpreter) executeIterUnimplemented() error {
	return &InterpreterError{
		Type:    ErrorUnsupportedOpcode,
		Opcode:  OpIterStartArray,
		Message: "iterator type not yet implemented",
	}
}
