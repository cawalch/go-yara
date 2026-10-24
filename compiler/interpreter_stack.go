package compiler

import (
	"crypto/md5"  // #nosec G501 -- required for YARA hash compatibility
	"crypto/sha1" // #nosec G505 -- required for YARA hash compatibility
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"slices"
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

// executePushU pushes an undefined value.
func (i *Interpreter) executePushU() error {
	return i.push(Value{Type: ValueTypeUndefined})
}

// executePush64 pushes a 64-bit integer.
func (i *Interpreter) executePush64() error {
	if err := i.validateBytecodeBounds(OpPush64, 8); err != nil {
		return err
	}
	value := int64(uint64(i.bytecode[i.ip]) | //checkednarrow:ignore uint64 bits encode the signed VM integer
		uint64(i.bytecode[i.ip+1])<<8 |
		uint64(i.bytecode[i.ip+2])<<16 |
		uint64(i.bytecode[i.ip+3])<<24 |
		uint64(i.bytecode[i.ip+4])<<32 |
		uint64(i.bytecode[i.ip+5])<<40 |
		uint64(i.bytecode[i.ip+6])<<48 |
		uint64(i.bytecode[i.ip+7])<<56)
	i.ip += 8
	return i.push(Value{Type: ValueTypeInt, IntVal: value})
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
	if ruleIdx < len(i.ruleResultsDense) {
		return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(i.ruleResultsDense[ruleIdx])})
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
	if argc == 0 && fn < firstModuleFunctionID {
		return &InterpreterError{Type: ErrorInvalidBytecode, Opcode: OpCall, Message: "invalid argument count"}
	}
	if err := i.validateStackUnderflowN(OpCall, argc); err != nil {
		return err
	}

	var argBuffer [4]Value
	args := argBuffer[:]
	if argc <= len(argBuffer) {
		args = args[:argc]
	} else {
		args = make([]Value, argc)
	}
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
		if i.currentCompiledRule != nil {
			if moduleFunction, ok := i.currentCompiledRule.ModuleFunctions[fn]; ok {
				return i.executeModuleCall(fn, moduleFunction, args)
			}
		}
		return &InterpreterError{Type: ErrorInvalidBytecode, Opcode: OpCall, Message: "unknown builtin"}
	}
}

func (i *Interpreter) executeModuleCall(id builtinFunction, function ModuleFunction, args []Value) error {
	// Cache hits need no callback argument allocation.
	var buffer [3]ModuleValue
	moduleArgs := buffer[:]
	if len(args) <= len(buffer) {
		moduleArgs = moduleArgs[:len(args)]
	} else {
		moduleArgs = make([]ModuleValue, len(args))
	}
	for index, arg := range args {
		switch arg.Type {
		case ValueTypeInt:
			moduleArgs[index] = IntegerValue(arg.IntVal)
		case ValueTypeDouble:
			moduleArgs[index] = FloatValue(arg.DoubleVal)
		case ValueTypeString:
			moduleArgs[index] = StringValue(i.getString(arg))
		case ValueTypeUndefined:
			return i.push(Value{Type: ValueTypeUndefined})
		default:
			return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpCall, Message: "unsupported module argument type"}
		}
	}

	if !normalizeModuleArguments(function.Signatures, moduleArgs) {
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpCall, Message: "invalid module arguments"}
	}
	var cache *moduleCallCache
	var key moduleCallCacheEntry
	if function.Cacheable && i.matchContext != nil && i.matchContext.moduleCache != nil {
		if candidate, ok := moduleCallKey(i.currentCompiledRule.ModuleNames[id], moduleArgs); ok {
			cache, key = i.matchContext.moduleCache, candidate
			if result, hit := cache.lookup(key); hit {
				return i.pushModuleValue(result)
			}
		}
	}
	ctx := ModuleContext{RuleName: i.currentRule}
	if i.matchContext != nil {
		ctx.Data = i.matchContext.Data
		ctx.Blocks = i.matchContext.Blocks
	}
	result, err := function.Evaluate(ctx, slices.Clone(moduleArgs))
	if err != nil {
		return &InterpreterError{Type: ErrorRuntime, Opcode: OpCall, Message: err.Error()}
	}
	if result.Type != ModuleUndefined && result.Type != moduleResultType(function, moduleArgs) {
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpCall, Message: "module returned an unexpected value type"}
	}
	if cache != nil {
		cache.put(key, result)
	}
	return i.pushModuleValue(result)
}

func normalizeModuleArguments(signatures []ModuleSignature, args []ModuleValue) bool {
	for _, signature := range signatures {
		if len(signature.Arguments) != len(args) {
			continue
		}
		matches := true
		for index, expected := range signature.Arguments {
			actual := args[index].Type
			if actual != expected && (actual != ModuleInteger || (expected != ModuleFloat && expected != ModuleBoolean)) {
				matches = false
				break
			}
		}
		if !matches {
			continue
		}
		for index, expected := range signature.Arguments {
			if args[index].Type == ModuleInteger && expected == ModuleFloat {
				args[index] = FloatValue(float64(args[index].Integer))
			}
			if args[index].Type == ModuleInteger && expected == ModuleBoolean {
				args[index] = BooleanValue(args[index].Integer != 0)
			}
		}
		return true
	}
	return false
}

func (i *Interpreter) pushModuleValue(result ModuleValue) error {
	switch result.Type {
	case ModuleStruct, ModuleArray, ModuleDictionary:
		return i.push(Value{Type: ValueTypeObject, object: result.object})
	case ModuleInteger:
		return i.push(Value{Type: ValueTypeInt, IntVal: result.Integer})
	case ModuleFloat:
		return i.push(Value{Type: ValueTypeDouble, DoubleVal: result.Float})
	case ModuleString:
		return i.pushString(result.String)
	case ModuleBoolean:
		if result.Boolean {
			return i.push(Value{Type: ValueTypeInt, IntVal: 1})
		}
		return i.push(Value{Type: ValueTypeInt, IntVal: 0})
	case ModuleUndefined:
		return i.push(Value{Type: ValueTypeUndefined})
	default:
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpCall, Message: "unsupported module return type"}
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
			return nil, errors.New("hash functions expect string or (offset,size)")
		}
		return []byte(i.getString(args[0])), nil
	case 2:
		if args[0].Type != ValueTypeInt || args[1].Type != ValueTypeInt {
			return nil, errors.New("hash functions expect integer offset and size")
		}
		if args[0].IntVal < 0 || args[1].IntVal < 0 {
			return nil, errors.New("hash range must be non-negative")
		}
		if i.matchContext == nil {
			return nil, errors.New("hash functions require data context")
		}
		data, ok := i.matchContext.dataRange(args[0].IntVal, args[1].IntVal)
		if !ok {
			return nil, errors.New("hash range out of bounds")
		}
		return data, nil
	default:
		return nil, errors.New("hash functions expect 1 or 2 arguments")
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
		return "", errors.New("unsupported string conversion")
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

func moduleResultType(function ModuleFunction, args []ModuleValue) ModuleValueType {
	for _, signature := range function.Signatures {
		if len(signature.Arguments) != len(args) {
			continue
		}
		matches := true
		for index, expected := range signature.Arguments {
			if args[index].Type != expected {
				matches = false
				break
			}
		}
		if matches {
			return signature.resultType(function.ReturnType)
		}
	}
	return function.ReturnType
}
