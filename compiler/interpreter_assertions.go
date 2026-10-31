package compiler

import "encoding/binary"

type assertionResult uint8

const (
	assertionUnknown assertionResult = iota
	assertionFalse
	assertionTrue
	assertionInvalidRead
	assertionUndefined
	assertionTypeMismatch
)

func compareAssertion(left, right int64, comparison Opcode) bool {
	switch comparison {
	case OpIntEq:
		return left == right
	case OpIntNeq:
		return left != right
	case OpIntLt:
		return left < right
	case OpIntLe:
		return left <= right
	case OpIntGt:
		return left > right
	case OpIntGe:
		return left >= right
	default:
		return false
	}
}

func evaluateInputAssertion(assertion *conditionAssertion, ctx *MatchContext) assertionResult {
	var value int64
	switch assertion.Opcode {
	case OpAssertExternal:
		if ctx == nil {
			return assertionUndefined
		}
		return evaluateExternalAssertion(assertion, ctx.externalValues)
	case OpAssertFilesize:
		if ctx != nil {
			value = ctx.FileSize
		}
	case OpAssertUint16Eq, OpAssertUint32Eq:
		if ctx == nil {
			return assertionInvalidRead
		}
		width := int64(2)
		if assertion.Opcode == OpAssertUint32Eq {
			width = 4
		}
		data, ok := ctx.dataRange(assertion.Offset, width)
		if !ok {
			return assertionUndefined
		}
		if width == 2 {
			value = int64(binary.LittleEndian.Uint16(data))
		} else {
			value = int64(binary.LittleEndian.Uint32(data))
		}
	}
	if compareAssertion(value, assertion.Value, assertion.Comparison) {
		return assertionTrue
	}
	return assertionFalse
}

func cachedInputAssertion(assertion *conditionAssertion, ctx *MatchContext, index int) assertionResult {
	if ctx == nil || index < 0 || index >= len(ctx.assertionResults) {
		return evaluateInputAssertion(assertion, ctx)
	}
	if result := ctx.assertionResults[index]; result != assertionUnknown {
		return result
	}
	result := evaluateInputAssertion(assertion, ctx)
	ctx.assertionResults[index] = result
	return result
}

func (i *Interpreter) executeAssertExternal() error { return i.executeAssertion(OpAssertExternal) }

func (i *Interpreter) executeAssertUint16Eq() error { return i.executeAssertion(OpAssertUint16Eq) }
func (i *Interpreter) executeAssertUint32Eq() error { return i.executeAssertion(OpAssertUint32Eq) }
func (i *Interpreter) executeAssertFilesize() error { return i.executeAssertion(OpAssertFilesize) }
func (i *Interpreter) executeAssertStringAt() error { return i.executeAssertion(OpAssertStringAt) }
func (i *Interpreter) executeAssertStringCount() error {
	return i.executeAssertion(OpAssertStringCount)
}

func (i *Interpreter) executeAssertion(opcode Opcode) error {
	if err := i.validateBytecodeBounds(opcode, 4); err != nil {
		return err
	}
	index := uint64(binary.LittleEndian.Uint32(i.bytecode[i.ip : i.ip+4]))
	i.ip += 4
	rule := i.currentCompiledRule
	if rule == nil || index >= uint64(len(rule.assertions)) || rule.assertions[index].Opcode != opcode {
		return &InterpreterError{Type: ErrorInvalidBytecode, Opcode: opcode, Message: "invalid condition assertion index"}
	}

	result, err := i.evaluateAssertion(int(index))
	if err != nil {
		return err
	}
	if result == assertionUndefined {
		return i.push(Value{Type: ValueTypeUndefined})
	}
	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(result == assertionTrue)})
}

func (i *Interpreter) evaluateAssertion(index int) (assertionResult, error) {
	rule := i.currentCompiledRule
	assertion := &rule.assertions[index]
	var matched bool
	switch assertion.Opcode {
	case OpAssertStringAt:
		matched = i.matchContext != nil && i.matchContext.hasMatchAt(assertion.String, assertion.Offset)
	case OpAssertStringCount:
		count := int64(0)
		if i.matchContext != nil {
			count = int64(i.matchContext.matchCount(assertion.String))
		}
		matched = compareAssertion(count, assertion.Value, assertion.Comparison)
	case OpAssertExternal, OpAssertUint16Eq, OpAssertUint32Eq, OpAssertFilesize:
		cacheIndex := -1
		if index < len(rule.assertionCacheIndices) {
			cacheIndex = rule.assertionCacheIndices[index]
		}
		result := cachedInputAssertion(assertion, i.matchContext, cacheIndex)
		if result == assertionInvalidRead {
			width := 2
			if assertion.Opcode == OpAssertUint32Eq {
				width = 4
			}
			_, err := i.executeReadInt(assertion.Offset, width, false)
			return result, err
		}
		if result == assertionTypeMismatch {
			return result, i.externalAssertionError(assertion)
		}
		return result, nil
	default:
		return assertionUnknown, &InterpreterError{Type: ErrorInvalidBytecode, Opcode: assertion.Opcode, Message: "invalid assertion opcode"}
	}
	if matched {
		return assertionTrue, nil
	}
	return assertionFalse, nil
}
