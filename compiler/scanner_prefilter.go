package compiler

import "context"

type ruleEvaluation struct {
	matched bool
	pruned  bool
}

type ruleScanInput struct {
	data               []byte
	useSharedAutomaton bool
}

type rulePrefilterStatus uint8

const (
	rulePrefilterUnknown rulePrefilterStatus = iota
	rulePrefilterRejected
	rulePrefilterCandidate
)

func (s *Scanner) evaluateRuleCondition(
	ctx context.Context,
	rule *CompiledRule,
	input ruleScanInput,
) (ruleEvaluation, error) {
	if !ruleHeaderConstraintsMatch(rule, input.data) {
		s.ruleResults[rule.Name] = false
		return ruleEvaluation{pruned: true}, nil
	}

	if err := s.populateRuleMatchContext(ctx, rule, input); err != nil {
		return ruleEvaluation{}, err
	}
	if !s.prefilterDisabled && rule.RequiresStringMatch && len(s.matchCtx.spans) == 0 {
		s.ruleResults[rule.Name] = false
		return ruleEvaluation{}, nil
	}

	s.prepareInterpreter(rule)
	s.interp.SetItersmax(s.itersmax)
	if err := s.interp.Execute(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ruleEvaluation{}, ctxErr
		}
		return ruleEvaluation{}, err
	}
	matched := s.interp.ruleResult(rule.Name)
	s.ruleResults[rule.Name] = matched
	return ruleEvaluation{matched: matched}, nil
}

func (s *Scanner) preparePatternScan(ctx context.Context, data []byte) (bool, error) {
	s.sharedNonTextMatched = false
	s.nonTextCache.reset(s.program.nonTextCacheSize)
	if err := s.populateFixedRegexCache(ctx, data, &s.nonTextCache); err != nil {
		return false, err
	}
	s.regexByteSetCache.reset()
	s.resetGlobalMatches(len(s.program.Rules))
	s.resetPrefilterCandidates(len(s.program.SharedLookup))
	s.resetCandidateRules(len(s.program.Rules))

	useSharedAutomaton := shouldUseSharedPatternAutomaton(data, s.program)
	if !useSharedAutomaton {
		return false, nil
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := s.extractGlobalMatchesInt(ctx, data); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Scanner) populateRuleMatchContext(
	ctx context.Context,
	rule *CompiledRule,
	input ruleScanInput,
) error {
	s.matchCtx.Reset(input.data)
	s.matchCtx.cancelDone = ctx.Done()
	s.matchCtx.maxMatchesPerPattern = 0
	if s.fastScan && rule.FastScanSafe {
		s.matchCtx.maxMatchesPerPattern = 1
	}
	if input.useSharedAutomaton {
		if err := s.addStaticMatchesInt(ctx, rule, input.data, s.globalMatches[rule.Index]); err != nil {
			return err
		}
	} else {
		if err := s.addLocalTextMatches(ctx, rule, input.data); err != nil {
			return err
		}
	}
	return s.addLocalNonTextMatches(ctx, rule, input.data, &s.nonTextCache, input.useSharedAutomaton)
}

func (s *Scanner) allEvaluatedRulesPrefilterRejected(data []byte, useSharedAutomaton bool) bool {
	if useSharedAutomaton && s.allEvaluatedRulesRequireSharedPatterns &&
		len(s.touchedGlobalMatches) == 0 && !s.sharedNonTextMatched {
		return true
	}
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
	if len(rule.prefilterStrings) == 0 {
		return rulePrefilterUnknown
	}
	if len(s.globalMatches[rule.Index]) != 0 {
		return rulePrefilterCandidate
	}

	// rule.prefilterStrings resolves kind and cache index at compile time. This
	// loop runs for every evaluated rule on every event, so it deliberately does
	// no map lookups: hashing each string identifier here dominated the reject
	// path, costing far more than the automaton scan it is meant to protect.
	complete := true
	for i := range rule.prefilterStrings {
		info := &rule.prefilterStrings[i]
		switch info.class {
		case prefilterStringText:
			// Text strings are always represented in the shared automaton.
		case prefilterStringNonText:
			matches, ready := s.getNonTextMatches(&s.nonTextCache, info.cacheIndex, useSharedAutomaton)
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
		s.touchedGlobalMatches = s.touchedGlobalMatches[:0]
		return
	}
	for _, index := range s.touchedGlobalMatches {
		if index >= 0 && index < len(s.globalMatches) {
			s.globalMatches[index] = s.globalMatches[index][:0]
		}
	}
	s.touchedGlobalMatches = s.touchedGlobalMatches[:0]
	s.globalMatches = s.globalMatches[:size]
}
