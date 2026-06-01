package compiler

import (
	"crypto/md5"  // #nosec G501 -- required for YARA hash compatibility
	"crypto/sha1" // #nosec G505 -- required for YARA hash compatibility
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// executePush8 pushes an 8-bit unsigned integer.
func (i *Interpreter) executePush8() error {
	if err := i.validateBytecodeBounds(OpPush8, 1); err != nil {
		return err
	}
	val := int64(i.bytecode[i.ip])
	i.ip++
	return i.push(Value{Type: ValueTypeInt, IntVal: val})
}

// executePush16 pushes a 16-bit unsigned integer.
func (i *Interpreter) executePush16() error {
	if err := i.validateBytecodeBounds(OpPush16, 2); err != nil {
		return err
	}
	val := int64(i.bytecode[i.ip]) | int64(i.bytecode[i.ip+1])<<8
	i.ip += 2
	return i.push(Value{Type: ValueTypeInt, IntVal: val})
}

// executePush32 pushes a 32-bit unsigned integer.
func (i *Interpreter) executePush32() error {
	if err := i.validateBytecodeBounds(OpPush32, 4); err != nil {
		return err
	}
	val := int64(i.bytecode[i.ip]) | int64(i.bytecode[i.ip+1])<<8 |
		int64(i.bytecode[i.ip+2])<<16 | int64(i.bytecode[i.ip+3])<<24
	i.ip += 4
	return i.push(Value{Type: ValueTypeInt, IntVal: val})
}

// executePushU pushes an undefined value or a 32-bit integer.
func (i *Interpreter) executePushU() error {
	if i.ip+3 >= len(i.bytecode) {
		return i.push(Value{Type: ValueTypeUndefined})
	}
	val := int64(i.bytecode[i.ip]) | int64(i.bytecode[i.ip+1])<<8 |
		int64(i.bytecode[i.ip+2])<<16 | int64(i.bytecode[i.ip+3])<<24
	i.ip += 4
	return i.push(Value{Type: ValueTypeInt, IntVal: val})
}

// executePushDouble pushes a 64-bit floating-point value.
func (i *Interpreter) executePushDouble() error {
	if err := i.validateBytecodeBounds(OpPushDbl, 8); err != nil {
		return err
	}
	bits := uint64(i.bytecode[i.ip]) | uint64(i.bytecode[i.ip+1])<<8 |
		uint64(i.bytecode[i.ip+2])<<16 | uint64(i.bytecode[i.ip+3])<<24 |
		uint64(i.bytecode[i.ip+4])<<32 | uint64(i.bytecode[i.ip+5])<<40 |
		uint64(i.bytecode[i.ip+6])<<48 | uint64(i.bytecode[i.ip+7])<<56
	i.ip += 8
	val := math.Float64frombits(bits)
	return i.push(Value{Type: ValueTypeDouble, DoubleVal: val})
}

// executePushRuleRef pushes a rule reference value.
func (i *Interpreter) executePushRuleRef() error {
	if err := i.validateBytecodeBounds(OpPushRuleRef, 1); err != nil {
		return err
	}
	ruleIdx := int(i.bytecode[i.ip])
	i.ip++
	if ruleIdx >= len(i.compiledRules) {
		return &InterpreterError{Type: ErrorInvalidBytecode, Opcode: OpPushRuleRef, Message: fmt.Sprintf("rule index %d out of range", ruleIdx)}
	}
	ruleName := i.compiledRules[ruleIdx].Name
	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(i.ruleResults[ruleName])})
}

// executePushString pushes a string literal reference.
func (i *Interpreter) executePushString() error {
	if err := i.validateBytecodeBounds(OpPushStr, 4); err != nil {
		return err
	}
	idx := int(uint32(i.bytecode[i.ip]) |
		uint32(i.bytecode[i.ip+1])<<8 |
		uint32(i.bytecode[i.ip+2])<<16 |
		uint32(i.bytecode[i.ip+3])<<24)
	i.ip += 4
	if idx < 0 || idx >= len(i.stringLiterals) {
		return i.push(Value{Type: ValueTypeUndefined})
	}
	return i.push(Value{Type: ValueTypeString, StringRef: int64(-1 - idx)})
}

// executePop removes the top value from the stack.
func (i *Interpreter) executePop() error {
	if err := i.validateStackUnderflow(OpPop); err != nil {
		return err
	}
	i.stack = i.stack[:len(i.stack)-1]
	return nil
}

// executeCall handles OpCall opcode for built-in functions.
func (i *Interpreter) executeCall() error {
	if err := i.validateBytecodeBounds(OpCall, 4); err != nil {
		return err
	}
	encoded := uint32(i.bytecode[i.ip]) |
		uint32(i.bytecode[i.ip+1])<<8 |
		uint32(i.bytecode[i.ip+2])<<16 |
		uint32(i.bytecode[i.ip+3])<<24
	i.ip += 4

	fn, argc := decodeBuiltinCall(encoded)
	if argc <= 0 {
		return &InterpreterError{Type: ErrorInvalidBytecode, Opcode: OpCall, Message: "invalid argument count"}
	}
	if err := i.validateStackUnderflowN(OpCall, argc); err != nil {
		return err
	}

	args := make([]Value, argc)
	for idx := argc - 1; idx >= 0; idx-- {
		args[idx] = i.stack[len(i.stack)-1]
		i.stack = i.stack[:len(i.stack)-1]
	}

	switch fn {
	case builtinConcat:
		return i.executeBuiltinConcat(args)
	case builtinToString:
		return i.executeBuiltinToString(args)
	case builtinInt:
		return i.executeBuiltinInt(args)
	case builtinMD5:
		return i.executeBuiltinMD5(args)
	case builtinSHA1:
		return i.executeBuiltinSHA1(args)
	case builtinSHA256:
		return i.executeBuiltinSHA256(args)
	default:
		return &InterpreterError{Type: ErrorInvalidBytecode, Opcode: OpCall, Message: "unknown builtin"}
	}
}

// executeBuiltinConcat concatenates string arguments.
func (i *Interpreter) executeBuiltinConcat(args []Value) error {
	if len(args) < 2 {
		return &InterpreterError{Type: ErrorRuntime, Opcode: OpCall, Message: "concat requires at least 2 arguments"}
	}
	var sb strings.Builder
	for _, arg := range args {
		str, err := i.valueToString(arg)
		if err != nil {
			return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpCall, Message: err.Error()}
		}
		sb.WriteString(str)
	}
	return i.pushString(sb.String())
}

// executeBuiltinToString converts a value to string.
func (i *Interpreter) executeBuiltinToString(args []Value) error {
	if len(args) != 1 {
		return &InterpreterError{Type: ErrorRuntime, Opcode: OpCall, Message: "tostring requires exactly 1 argument"}
	}
	str, err := i.valueToString(args[0])
	if err != nil {
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpCall, Message: err.Error()}
	}
	return i.pushString(str)
}

// executeBuiltinInt converts a value to integer.
func (i *Interpreter) executeBuiltinInt(args []Value) error {
	if len(args) != 1 {
		return &InterpreterError{Type: ErrorRuntime, Opcode: OpCall, Message: "int requires exactly 1 argument"}
	}
	switch v := args[0]; v.Type {
	case ValueTypeInt:
		return i.push(v)
	case ValueTypeDouble:
		return i.push(Value{Type: ValueTypeInt, IntVal: int64(v.DoubleVal)})
	case ValueTypeString:
		s := i.getString(v)
		if s == "" {
			return i.push(Value{Type: ValueTypeInt, IntVal: 0})
		}
		if parsed, err := strconv.ParseInt(strings.TrimSpace(s), 0, 64); err == nil {
			return i.push(Value{Type: ValueTypeInt, IntVal: parsed})
		}
		return i.push(Value{Type: ValueTypeInt, IntVal: 0})
	case ValueTypeUndefined:
		return i.push(Value{Type: ValueTypeInt, IntVal: 0})
	default:
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpCall, Message: "unsupported int() argument type"}
	}
}

// executeBuiltinMD5 computes MD5 hash.
func (i *Interpreter) executeBuiltinMD5(args []Value) error {
	data, err := i.extractHashInput(args)
	if err != nil {
		return &InterpreterError{Type: ErrorRuntime, Opcode: OpCall, Message: err.Error()}
	}
	sum := md5.Sum(data) // #nosec G401 -- YARA defines md5() for compatibility
	return i.pushString(hex.EncodeToString(sum[:]))
}

// executeBuiltinSHA1 computes SHA1 hash.
func (i *Interpreter) executeBuiltinSHA1(args []Value) error {
	data, err := i.extractHashInput(args)
	if err != nil {
		return &InterpreterError{Type: ErrorRuntime, Opcode: OpCall, Message: err.Error()}
	}
	sum := sha1.Sum(data) // #nosec G401 -- YARA defines sha1() for compatibility
	return i.pushString(hex.EncodeToString(sum[:]))
}

// executeBuiltinSHA256 computes SHA256 hash.
func (i *Interpreter) executeBuiltinSHA256(args []Value) error {
	data, err := i.extractHashInput(args)
	if err != nil {
		return &InterpreterError{Type: ErrorRuntime, Opcode: OpCall, Message: err.Error()}
	}
	sum := sha256.Sum256(data)
	return i.pushString(hex.EncodeToString(sum[:]))
}

// extractHashInput extracts the data for hash functions from arguments.
func (i *Interpreter) extractHashInput(args []Value) ([]byte, error) {
	switch len(args) {
	case 1:
		if args[0].Type != ValueTypeString {
			return nil, fmt.Errorf("hash functions expect string or (offset,size)")
		}
		return []byte(i.getString(args[0])), nil
	case 2:
		if args[0].Type != ValueTypeInt || args[1].Type != ValueTypeInt {
			return nil, fmt.Errorf("hash functions expect integer offset and size")
		}
		if args[0].IntVal < 0 || args[1].IntVal < 0 {
			return nil, fmt.Errorf("hash range must be non-negative")
		}
		if i.matchContext == nil || i.matchContext.Data == nil {
			return nil, fmt.Errorf("hash functions require data context")
		}
		start := int(args[0].IntVal)
		size := int(args[1].IntVal)
		if start > len(i.matchContext.Data) || start+size > len(i.matchContext.Data) {
			return nil, fmt.Errorf("hash range out of bounds")
		}
		return i.matchContext.Data[start : start+size], nil
	default:
		return nil, fmt.Errorf("hash functions expect 1 or 2 arguments")
	}
}

// valueToString converts a Value to a string representation.
func (i *Interpreter) valueToString(v Value) (string, error) {
	switch v.Type {
	case ValueTypeString:
		return i.getString(v), nil
	case ValueTypeInt:
		return strconv.FormatInt(v.IntVal, 10), nil
	case ValueTypeDouble:
		return strconv.FormatFloat(v.DoubleVal, 'g', -1, 64), nil
	case ValueTypeUndefined:
		return "", nil
	default:
		return "", fmt.Errorf("unsupported string conversion")
	}
}

// readAndValidateMemorySlot reads and validates a memory slot from bytecode.
// Memory slot operands are stored as OperandImmediate32 (4 bytes, little-endian).
func (i *Interpreter) readAndValidateMemorySlot(opcode Opcode) (int, error) {
	if err := i.validateBytecodeBounds(opcode, 4); err != nil {
		return 0, err
	}
	slot := int(i.bytecode[i.ip]) | int(i.bytecode[i.ip+1])<<8 |
		int(i.bytecode[i.ip+2])<<16 | int(i.bytecode[i.ip+3])<<24
	i.ip += 4
	if slot < 0 || slot >= 256 {
		return 0, &InterpreterError{Type: ErrorInvalidBytecode, Opcode: opcode, Message: fmt.Sprintf("memory slot %d out of range", slot)}
	}
	return slot, nil
}

// executeLoadVarOperation loads a value from a memory slot.
func (i *Interpreter) executeLoadVarOperation() error {
	slot, err := i.readAndValidateMemorySlot(OpLoadVar)
	if err != nil {
		return err
	}
	return i.push(i.memory[slot])
}

// executeSwapUndefined handles SWAPUNDEF operation
func (i *Interpreter) executeSwapUndefined() error {
	if err := i.validateStackUnderflowN(OpSwapundef, 2); err != nil {
		return err
	}
	top := i.stack[len(i.stack)-1]
	second := i.stack[len(i.stack)-2]
	if top.Type == ValueTypeUndefined && second.Type != ValueTypeUndefined {
		i.stack[len(i.stack)-1] = second
		i.stack[len(i.stack)-2] = top
	}
	return nil
}

// executePushMemory handles PUSH_M operation
func (i *Interpreter) executePushMemory() error {
	slot, err := i.readAndValidateMemorySlot(OpPushM)
	if err != nil {
		return err
	}
	return i.push(i.memory[slot])
}

// executePopMemory handles POP_M operation
func (i *Interpreter) executePopMemory() error {
	if err := i.validateStackUnderflow(OpPopM); err != nil {
		return err
	}
	slot, err := i.readAndValidateMemorySlot(OpPopM)
	if err != nil {
		return err
	}
	i.memory[slot] = i.stack[len(i.stack)-1]
	i.stack = i.stack[:len(i.stack)-1]
	return nil
}

// executeClearMemory handles CLEAR_M operation
func (i *Interpreter) executeClearMemory() error {
	slot, err := i.readAndValidateMemorySlot(OpClearM)
	if err != nil {
		return err
	}
	i.memory[slot] = Value{Type: ValueTypeUndefined}
	return nil
}

// executeIncrementMemory handles INCR_M operation
func (i *Interpreter) executeIncrementMemory() error {
	slot, err := i.readAndValidateMemorySlot(OpIncrM)
	if err != nil {
		return err
	}
	switch i.memory[slot].Type {
	case ValueTypeInt:
		i.memory[slot].IntVal++
	case ValueTypeUndefined:
		i.memory[slot] = Value{Type: ValueTypeInt, IntVal: 1}
	default:
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpIncrM, Message: "memory slot contains non-integer value"}
	}
	return nil
}
