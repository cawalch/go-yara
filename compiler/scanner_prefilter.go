package compiler

import "context"

type ruleEvaluation struct {
	matched bool
	pruned  bool
}

type rulePrefilterStatus uint8

const (
	rulePrefilterUnknown rulePrefilterStatus = iota
	rulePrefilterRejected
	rulePrefilterCandidate
)

func (s *Scanner) evaluateRuleCondition(
	rule *CompiledRule,
	data []byte,
	useSharedAutomaton bool,
) (ruleEvaluation, error) {
	if !ruleHeaderConstraintsMatch(rule, data) {
		s.ruleResults[rule.Name] = false
		return ruleEvaluation{pruned: true}, nil
	}

	s.populateRuleMatchContext(rule, data, useSharedAutomaton)
	if !s.prefilterDisabled && rule.RequiresStringMatch && len(s.matchCtx.spans) == 0 {
		s.ruleResults[rule.Name] = false
		return ruleEvaluation{}, nil
	}

	s.prepareInterpreter(rule)
	s.interp.SetItersmax(s.itersmax)
	if err := s.interp.Execute(); err != nil {
		return ruleEvaluation{}, err
	}
	matched := s.interp.GetRuleResults()[rule.Name]
	s.ruleResults[rule.Name] = matched
	return ruleEvaluation{matched: matched}, nil
}

func (s *Scanner) preparePatternScan(ctx context.Context, data []byte) (bool, error) {
	s.nonTextCache.reset(s.program.nonTextCacheSize)
	s.populateFixedRegexCache(data, &s.nonTextCache)
	s.regexByteSetCache.reset()
	s.resetGlobalMatches(len(s.program.Rules))
	s.resetPrefilterCandidates(len(s.program.SharedLookup))

	useSharedAutomaton := shouldUseSharedPatternAutomaton(data, s.program)
	if !useSharedAutomaton {
		return false, nil
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.extractGlobalMatchesInt(data, s.globalMatches, &s.nonTextCache)
	return true, nil
}

func (s *Scanner) populateRuleMatchContext(rule *CompiledRule, data []byte, useSharedAutomaton bool) {
	s.matchCtx.Reset(data)
	s.matchCtx.maxMatchesPerPattern = 0
	if s.fastScan && rule.FastScanSafe {
		s.matchCtx.maxMatchesPerPattern = 1
	}
	if useSharedAutomaton {
		s.addStaticMatchesInt(rule, data, s.globalMatches[rule.Index])
	} else {
		s.addLocalTextMatches(rule, data)
	}
	s.addLocalNonTextMatches(rule, data, &s.nonTextCache)
}

func (s *Scanner) allEvaluatedRulesPrefilterRejected(data []byte, useSharedAutomaton bool) bool {
	for _, rule := range s.program.Rules {
		if !rule.IsGlobal && !s.hasMatchingTag(rule) {
			continue
		}
		if !ruleHeaderConstraintsMatch(rule, data) {
			continue
		}
		if !rule.RequiresStringMatch {
			return false
		}
		if s.rulePrefilterStatus(rule, useSharedAutomaton) != rulePrefilterRejected {
			return false
		}
	}
	return true
}

func (s *Scanner) rulePrefilterStatus(rule *CompiledRule, useSharedAutomaton bool) rulePrefilterStatus {
	if !useSharedAutomaton || rule.Index < 0 || rule.Index >= len(s.globalMatches) {
		return rulePrefilterUnknown
	}
	if len(rule.IndexToStringID) == 0 {
		return rulePrefilterUnknown
	}
	if len(s.globalMatches[rule.Index]) != 0 {
		return rulePrefilterCandidate
	}

	complete := true
	for _, identifier := range rule.IndexToStringID {
		kind, exists := rule.StringKinds[identifier]
		if !exists {
			return rulePrefilterUnknown
		}
		switch kind {
		case StringKindText:
			// Text strings are always represented in the shared automaton.
		case StringKindRegex:
			pattern, exists := rule.RegexPatterns[identifier]
			if !exists {
				return rulePrefilterUnknown
			}
			matches, ready := s.nonTextCache.get(pattern.cacheIndex)
			if !ready {
				complete = false
				continue
			}
			if len(matches) != 0 {
				return rulePrefilterCandidate
			}
		case StringKindHex:
			pattern, exists := rule.HexPatterns[identifier]
			if !exists || pattern == nil {
				return rulePrefilterUnknown
			}
			matches, ready := s.nonTextCache.get(pattern.cacheIndex)
			if !ready {
				complete = false
				continue
			}
			if len(matches) != 0 {
				return rulePrefilterCandidate
			}
		default:
			return rulePrefilterUnknown
		}
	}
	if !complete {
		return rulePrefilterUnknown
	}
	return rulePrefilterRejected
}

func (s *Scanner) resetGlobalMatches(size int) {
	if cap(s.globalMatches) < size {
		s.globalMatches = make([][]globalMatchEntry, size)
		return
	}
	s.globalMatches = s.globalMatches[:size]
	for index := range s.globalMatches {
		s.globalMatches[index] = s.globalMatches[index][:0]
	}
}
