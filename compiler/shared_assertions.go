package compiler

// assignSharedAssertions interns only payload predicates. String occurrences
// belong to individual rules and must never be shared merely by identifier.
func (cp *CompiledProgram) assignSharedAssertions() {
	cp.sharedAssertions = nil
	indices := make(map[conditionAssertion]int)
	intern := func(assertion conditionAssertion) int {
		if index, ok := indices[assertion]; ok {
			return index
		}
		index := len(cp.sharedAssertions)
		indices[assertion] = index
		cp.sharedAssertions = append(cp.sharedAssertions, assertion)
		return index
	}
	for _, rule := range cp.Rules {
		rule.assertionCacheIndices = make([]int, len(rule.assertions))
		for index, assertion := range rule.assertions {
			rule.assertionCacheIndices[index] = -1
			switch assertion.Opcode {
			case OpAssertUint16Eq, OpAssertUint32Eq, OpAssertFilesize:
				rule.assertionCacheIndices[index] = intern(assertion)
			}
		}
		rule.headerCacheIndices = make([]int, len(rule.HeaderConstraints))
		for index, header := range rule.HeaderConstraints {
			rule.headerCacheIndices[index] = -1
			if assertion, ok := assertionFromHeader(header); ok {
				rule.headerCacheIndices[index] = intern(assertion)
			}
		}
	}
}

func assertionFromHeader(header HeaderConstraint) (conditionAssertion, bool) {
	if header.Kind != HeaderIntegerEquals || header.BigEndian {
		return conditionAssertion{}, false
	}
	assertion := conditionAssertion{Comparison: OpIntEq, Offset: header.Offset}
	switch header.Width {
	case 2:
		if header.Value > 0xffff {
			return conditionAssertion{}, false
		}
		assertion.Opcode = OpAssertUint16Eq
	case 4:
		if header.Value > 0xffffffff {
			return conditionAssertion{}, false
		}
		assertion.Opcode = OpAssertUint32Eq
	default:
		return conditionAssertion{}, false
	}
	assertion.Value = int64(header.Value) // checkednarrow:ignore bounded to uint32 above
	return assertion, true
}

func (s *Scanner) ruleConstraintsMatchContext(rule *CompiledRule, ctx *MatchContext, pruneFilesize bool) bool {
	ctx.assertionResults = s.assertionResults
	for index, constraint := range rule.HeaderConstraints {
		if index < len(rule.headerCacheIndices) && rule.headerCacheIndices[index] >= 0 {
			sharedIndex := rule.headerCacheIndices[index]
			if cachedInputAssertion(&s.program.sharedAssertions[sharedIndex], ctx, sharedIndex) != assertionTrue {
				return false
			}
			continue
		}
		switch constraint.Kind {
		case HeaderIntegerEquals:
			if !headerIntegerEquals(ctx, constraint) {
				return false
			}
		case HeaderStringAt:
			if !compiledPatternMatchesAtContext(rule, constraint.String, ctx, constraint.Offset) {
				return false
			}
		}
	}
	if !pruneFilesize {
		return true
	}
	for _, index := range rule.mandatoryAssertions {
		if cachedInputAssertion(&rule.assertions[index], ctx, rule.assertionCacheIndices[index]) != assertionTrue {
			return false
		}
	}
	return true
}
