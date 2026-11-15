package compiler

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

type bytecodeJumpCheck struct {
	instStart int
	target    int
}

func validateRuleCrossReferences(cr *CompiledRule) error {
	if err := validateRuleStringKinds(cr); err != nil {
		return err
	}
	if err := validateRuleHeaderConstraints(cr); err != nil {
		return err
	}
	if err := validateRuleStringLists(cr); err != nil {
		return err
	}
	if err := validateRuleHexPatterns(cr); err != nil {
		return err
	}
	return validateRuleBytecode(cr)
}

func validateRuleHexPatterns(cr *CompiledRule) error {
	for id, pattern := range cr.HexPatterns {
		if pattern == nil {
			continue
		}
		if err := validateHexPatternTokens(pattern.Tokens); err != nil {
			return fmt.Errorf("hex string %q: %w", id, err)
		}
	}
	return nil
}

func validateHexPatternTokens(tokens []HexPatternToken) error {
	for _, tok := range tokens {
		switch tok.Kind {
		case HexTokenJump:
			if tok.Min < 0 || tok.Min > math.MaxInt32 {
				return errors.New("jump length too large")
			}
			if tok.Max < -1 || tok.Max > math.MaxInt32 {
				return errors.New("jump length too large")
			}
			if tok.Max >= 0 && tok.Min > tok.Max {
				return errors.New("invalid jump range")
			}
		case HexTokenAlt:
			for _, alt := range tok.Alternatives {
				if err := validateHexPatternTokens(alt); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func validateRuleStringKinds(cr *CompiledRule) error {
	for id, kind := range cr.StringKinds {
		if kind > StringKindRegex {
			return fmt.Errorf("string %q has invalid kind %d", id, kind)
		}
		if cr.IsStringDead(id) {
			continue
		}
		if err := validateLiveStringBacking(cr, id, kind); err != nil {
			return err
		}
	}
	return nil
}

func validateLiveStringBacking(cr *CompiledRule, id string, kind StringKind) error {
	switch kind {
	case StringKindText:
		if cr.automaton == nil {
			return fmt.Errorf("text string %q has no automaton", id)
		}
	case StringKindRegex:
		if _, exists := cr.RegexPatterns[id]; !exists {
			return fmt.Errorf("regex string %q has no compiled pattern", id)
		}
	case StringKindHex:
		if pattern, exists := cr.HexPatterns[id]; !exists || pattern == nil {
			return fmt.Errorf("hex string %q has no compiled pattern", id)
		}
	}
	return nil
}

func validateRuleHeaderConstraints(cr *CompiledRule) error {
	for _, hc := range cr.HeaderConstraints {
		if hc.Offset < 0 {
			return fmt.Errorf("header constraint has negative offset %d", hc.Offset)
		}
		switch hc.Kind {
		case HeaderIntegerEquals:
			if hc.Width != 1 && hc.Width != 2 && hc.Width != 4 && hc.Width != 8 {
				return fmt.Errorf("header integer constraint has invalid width %d", hc.Width)
			}
		case HeaderStringAt:
			kind, exists := cr.StringKinds[hc.String]
			if !exists || kind > StringKindRegex {
				return fmt.Errorf("header constraint refers to unknown string %q", hc.String)
			}
			if err := validateLiveStringBacking(cr, hc.String, kind); err != nil {
				return fmt.Errorf("header constraint: %w", err)
			}
		default:
			return fmt.Errorf("unknown header constraint kind %d", hc.Kind)
		}
	}
	return nil
}

func validateRuleStringLists(cr *CompiledRule) error {
	if err := validateDeclaredStringIDs(cr, "anonymous strings", cr.AnonymousStrings); err != nil {
		return err
	}
	if err := validateDeclaredStringIDs(cr, "required strings", cr.requiredStrings); err != nil {
		return err
	}
	if err := validateDeclaredStringIDs(cr, "forbidden strings", cr.forbiddenStrings); err != nil {
		return err
	}
	for i, set := range cr.StringSets {
		if err := validateDeclaredStringIDs(cr, fmt.Sprintf("string set %d", i), set); err != nil {
			return err
		}
	}
	return nil
}

func validateDeclaredStringIDs(cr *CompiledRule, label string, ids []string) error {
	for _, id := range ids {
		kind, exists := cr.StringKinds[id]
		if !exists || kind > StringKindRegex {
			return fmt.Errorf("%s refers to unknown string %q", label, id)
		}
	}
	return nil
}

func validateRuleBytecode(cr *CompiledRule) error {
	bc := cr.Bytecode
	boundaries := make([]bool, len(bc))
	var jumps []bytecodeJumpCheck

	for ip := 0; ip < len(bc); {
		boundaries[ip] = true
		op := Opcode(bc[ip])
		operandSize, valid := bytecodeOperandSize(op)
		if !valid {
			return fmt.Errorf("unsupported opcode %d at bytecode offset %d", op, ip)
		}
		operandStart := ip + 1
		nextIP := operandStart + operandSize
		if nextIP > len(bc) {
			return fmt.Errorf("truncated %s operand at bytecode offset %d", op, ip)
		}
		if err := validateInstructionOperand(cr, op, bc[operandStart:nextIP]); err != nil {
			return fmt.Errorf("invalid %s operand at bytecode offset %d: %w", op, ip, err)
		}
		if isConditionalJumpOpcode(op) {
			rel := int32(bc[operandStart]) | int32(bc[operandStart+1])<<8 |
				int32(bc[operandStart+2])<<16 | int32(bc[operandStart+3])<<24
			jumps = append(jumps, bytecodeJumpCheck{instStart: ip, target: nextIP + int(rel)})
		}
		ip = nextIP
	}

	for _, jump := range jumps {
		if jump.target <= jump.instStart || jump.target > len(bc) {
			return fmt.Errorf("invalid jump target %d from offset %d", jump.target, jump.instStart)
		}
		if jump.target < len(bc) && !boundaries[jump.target] {
			return fmt.Errorf("unaligned jump target %d from offset %d", jump.target, jump.instStart)
		}
	}
	return nil
}

func validateInstructionOperand(cr *CompiledRule, op Opcode, operand []byte) error {
	switch op {
	case OpEvalAssertions:
		if len(cr.assertionProgram) == 0 {
			return errors.New("empty assertion program")
		}
	case OpPushStr:
		idx := int(binary.LittleEndian.Uint32(operand))
		if idx < 0 || idx >= len(cr.StringLiterals) {
			return fmt.Errorf("string literal index %d out of range", idx)
		}
	case OpPushRegex:
		idx := int(binary.LittleEndian.Uint32(operand))
		if idx < 0 || idx >= len(cr.moduleRegexes) || cr.moduleRegexes[idx] == nil || len(cr.moduleRegexes[idx].code) == 0 {
			return fmt.Errorf("module regex index %d out of range", idx)
		}
	case OpModuleLoad, OpModuleGetField:
		idx := int(binary.LittleEndian.Uint32(operand))
		if idx < 0 || idx >= len(cr.moduleAccessNames) {
			return fmt.Errorf("module access index %d out of range", idx)
		}
	case OpIterStartModuleArray:
		idx := int(binary.LittleEndian.Uint32(operand))
		if idx < 0 || idx >= len(cr.moduleIterations) {
			return fmt.Errorf("module iterator index %d out of range", idx)
		}
	case OpAssertUint16Eq, OpAssertUint32Eq, OpAssertFilesize, OpAssertStringAt, OpAssertStringCount, OpAssertExternal:
		idx := int(binary.LittleEndian.Uint32(operand))
		if idx < 0 || idx >= len(cr.assertions) || cr.assertions[idx].Opcode != op {
			return fmt.Errorf("assertion index %d out of range", idx)
		}
	case OpPushM, OpPopM, OpClearM, OpIncrM, OpLoadVar,
		OpIterStartIntRange, OpIterStartStringSet, OpIterStartTextStringSet, OpIterStartIntEnum:
		slot := int(binary.LittleEndian.Uint32(operand))
		if slot < 0 || slot >= interpreterMemorySlotCount {
			return fmt.Errorf("memory slot %d out of range", slot)
		}
	case OpCall:
		fn, argc := decodeBuiltinCall(binary.LittleEndian.Uint32(operand))
		if fn < firstModuleFunctionID {
			if fn > builtinSHA256 || argc == 0 {
				return fmt.Errorf("invalid builtin call (%d, %d)", fn, argc)
			}
			return nil
		}
		if _, exists := cr.ModuleNames[fn]; !exists {
			return fmt.Errorf("unknown module function ID %d", fn)
		}
	}
	return nil
}

func validateProgramBytecodeRuleRefs(cp *CompiledProgram) error {
	for i, rule := range cp.Rules {
		bc := rule.Bytecode
		for ip := 0; ip < len(bc); {
			op := Opcode(bc[ip])
			operandSize, valid := bytecodeOperandSize(op)
			if !valid || ip+1+operandSize > len(bc) {
				return fmt.Errorf("rule %d (%s): invalid bytecode at offset %d", i, rule.Name, ip)
			}
			if op == OpPushRuleRef || op == OpPushRule || op == OpInitRule {
				ruleIdx := int(bc[ip+1])
				if ruleIdx >= len(cp.Rules) {
					return fmt.Errorf("rule %d (%s): rule reference %d out of range", i, rule.Name, ruleIdx)
				}
			}
			ip += 1 + operandSize
		}
	}
	return nil
}

func isConditionalJumpOpcode(op Opcode) bool {
	return op == OpJz || op == OpJzP || op == OpJtrue || op == OpJfalse
}

func bytecodeOperandSize(op Opcode) (int, bool) {
	if opcodeTable[op] == nil {
		return 0, false
	}
	switch op {
	case OpPush8, OpPushRuleRef, OpPushRule, OpInitRule:
		return 1, true
	case OpPush16:
		return 2, true
	case OpPush32, OpPushStr, OpPushRegex, OpCall,
		OpJz, OpJzP, OpJtrue, OpJfalse,
		OpPushM, OpPopM, OpClearM, OpIncrM, OpLoadVar,
		OpModuleLoad, OpModuleGetField, OpIterStartModuleArray,
		OpAssertExternal, OpAssertUint16Eq, OpAssertUint32Eq, OpAssertFilesize, OpAssertStringAt, OpAssertStringCount,
		OpIterStartIntRange, OpIterStartStringSet, OpIterStartTextStringSet, OpIterStartIntEnum:
		return 4, true
	case OpPush64, OpPushDbl:
		return 8, true
	default:
		return 0, true
	}
}
