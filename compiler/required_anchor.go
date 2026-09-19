package compiler

type anchorPattern struct {
	class      prefilterStringClass
	text       string
	cacheIndex int
}

func ruleAnchorPattern(rule *CompiledRule, index int) anchorPattern {
	info := rule.prefilterStrings[index]
	key := anchorPattern{class: info.class, cacheIndex: info.cacheIndex}
	if info.class == prefilterStringText {
		key.text = string(rule.TextPatterns[rule.IndexToStringID[index]])
	}
	return key
}

func (cp *CompiledProgram) buildRequiredAnchorRoutes() {
	type frequency struct{ rules, lastRule int }
	frequencies := make(map[anchorPattern]frequency)
	for ruleIndex, rule := range cp.Rules {
		for index := range rule.prefilterStrings {
			key := ruleAnchorPattern(rule, index)
			value := frequencies[key]
			if value.lastRule != ruleIndex+1 {
				value.rules++
				value.lastRule = ruleIndex + 1
				frequencies[key] = value
			}
		}
	}
	anchors := make([]int, len(cp.Rules))
	for ruleIndex, rule := range cp.Rules {
		anchors[ruleIndex] = -1
		if !cp.ruleHasCompleteSharedPrefilter(rule) {
			continue
		}
		bestFrequency, bestLength := len(cp.Rules)+1, -1
		for _, id := range rule.requiredStrings {
			index, ok := rule.StringIDToIndex[id]
			if !ok {
				continue
			}
			count := frequencies[ruleAnchorPattern(rule, index)].rules
			length := len(rule.Strings[id])
			if count < bestFrequency || count == bestFrequency && length > bestLength {
				anchors[ruleIndex], bestFrequency, bestLength = index, count, length
			}
		}
	}
	for i := range cp.SharedLookup {
		entry := &cp.SharedLookup[i]
		anchor := anchors[entry.RuleIndex]
		entry.skipCompactCandidate = anchor >= 0 && entry.StringIdx != anchor
	}
	cp.compactNonTextCacheRules = make([][]int, len(cp.sharedNonTextCacheRules))
	for cacheIndex, rules := range cp.sharedNonTextCacheRules {
		for _, ruleIndex := range rules {
			anchor := anchors[ruleIndex]
			if anchor >= 0 {
				info := cp.Rules[ruleIndex].prefilterStrings[anchor]
				if info.class != prefilterStringNonText || info.cacheIndex != cacheIndex {
					continue
				}
			}
			cp.compactNonTextCacheRules[cacheIndex] = append(cp.compactNonTextCacheRules[cacheIndex], ruleIndex)
		}
	}
}
