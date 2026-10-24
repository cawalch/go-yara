package compiler

import (
	"context"
	"time"
)

type ruleEvaluation struct {
	matched bool
	pruned  bool
}

type ruleScanInput struct {
	data                 []byte
	usesharedAutomaton   bool
	skipUnmatchedContext bool
	booleanMatchOnly     bool
}

type rulePrefilterStatus uint8

const (
	rulePrefilterUnknown rulePrefilterStatus = iota
	rulePrefilterRejected
	rulePrefilterCandidate
)

func (s *Scanner) recordRuleResult(rule *CompiledRule, matched bool) {
	if rule.Index >= 0 && rule.Index < len(s.ruleResultsDense) {
		s.ruleResultsDense[rule.Index] = matched
	}
}

func (s *Scanner) evaluateRuleCondition(
	ctx context.Context,
	rule *CompiledRule,
	input ruleScanInput,
) (ruleEvaluation, error) {
	var ruleStart time.Time
	if s.hookMask&hookBitRuleProfile != 0 {
		ruleStart = time.Now()
	}

	if !s.ruleHeaderConstraintsMatchInput(ctx, rule, input) {
		if err := ctx.Err(); err != nil {
			return ruleEvaluation{}, err
		}
		s.recordRuleResult(rule, false)
		if s.hookMask&hookBitRuleProfile != 0 {
			s.dispatchRuleEvaluated(RuleProfile{
				RuleName:  rule.Name,
				RuleIndex: rule.Index,
				Duration:  time.Since(ruleStart),
				Pruned:    true,
			})
		}
		if s.hookMask&hookBitTelemetry != 0 && s.telemetrySink != nil {
			s.telemetrySink.RulesPruned++
		}
		return ruleEvaluation{pruned: true}, nil
	}

	if !s.prefilterDisabled && input.skipUnmatchedContext && input.usesharedAutomaton && s.missingRequiredString(rule) {
		s.recordRuleResult(rule, false)
		if s.hookMask&(hookBitTelemetry|hookBitRuleProfile) != 0 {
			s.recordRuleEvaluatedHooks(rule, false, ruleStart)
		}
		return ruleEvaluation{}, nil
	}

	if err := s.populateRuleMatchContext(ctx, rule, input); err != nil {
		return ruleEvaluation{}, err
	}
	if !s.prefilterDisabled && input.skipUnmatchedContext && s.hasForbiddenStringMatch(rule, input.usesharedAutomaton) {
		s.recordRuleResult(rule, false)
		if s.hookMask&(hookBitTelemetry|hookBitRuleProfile) != 0 {
			s.recordRuleEvaluatedHooks(rule, false, ruleStart)
		}
		return ruleEvaluation{}, nil
	}
	if !s.prefilterDisabled && rule.RequiresStringMatch && len(s.matchCtx.spans) == 0 {
		s.recordRuleResult(rule, false)
		if s.hookMask&(hookBitTelemetry|hookBitRuleProfile) != 0 {
			s.recordRuleEvaluatedHooks(rule, false, ruleStart)
		}
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
	matched := s.interp.ruleResultByIndex(rule.Index, rule.Name)
	s.recordRuleResult(rule, matched)

	if s.hookMask&(hookBitTelemetry|hookBitRuleProfile) != 0 {
		s.recordRuleEvaluatedHooks(rule, matched, ruleStart)
	}

	return ruleEvaluation{matched: matched}, nil
}

func (s *Scanner) recordRuleEvaluatedHooks(
	rule *CompiledRule,
	matched bool,
	ruleStart time.Time,
) {
	candidates := 0
	if rule.Index < len(s.globalMatches) {
		candidates = len(s.globalMatches[rule.Index])
	}
	matches := 0
	for _, spans := range s.matchCtx.spans {
		matches += len(spans)
	}

	if s.hookMask&hookBitTelemetry != 0 && s.telemetrySink != nil {
		s.telemetrySink.RulesEvaluated++
		s.telemetrySink.CandidateHits += uint64(candidates)
		s.telemetrySink.VerifiedMatches += uint64(matches)
		if candidates > matches {
			s.telemetrySink.FalseCandidateHits += uint64(candidates - matches)
		}
	}

	if s.hookMask&hookBitRuleProfile != 0 {
		s.dispatchRuleEvaluated(RuleProfile{
			RuleName:        rule.Name,
			RuleIndex:       rule.Index,
			Duration:        time.Since(ruleStart),
			ConditionSteps:  s.interp.iterations,
			Matched:         matched,
			Pruned:          false,
			CandidateHits:   candidates,
			VerifiedMatches: matches,
		})
	}
}

func (s *Scanner) ruleHeaderConstraintsMatchInput(ctx context.Context, rule *CompiledRule, input ruleScanInput) bool {
	if !s.blockScan {
		return ruleHeaderConstraintsMatchContext(rule, &MatchContext{Data: input.data, cancelDone: ctx.Done()})
	}
	return ruleHeaderConstraintsMatchContext(rule, &MatchContext{
		cancelDone: ctx.Done(),
		Blocks:     s.blockContext[:],
		FileSize:   s.blockFileSize,
	})
}

func (s *Scanner) preparePatternScan(ctx context.Context, data []byte) (bool, error) {
	s.moduleCache.reset()
	s.sharedNonTextMatched = false
	s.nonTextCache.reset(s.program.nonTextCacheSize)
	if err := s.populateFixedRegexCache(ctx, data, &s.nonTextCache); err != nil {
		return false, err
	}
	s.regexByteSetCache.reset()
	s.resetGlobalMatches(len(s.program.Rules))
	s.resetPrefilterCandidates(len(s.program.sharedLookup))
	s.resetCandidateRules(len(s.program.Rules))

	usesharedAutomaton := shouldUseSharedPatternAutomaton(data, s.program)
	if !usesharedAutomaton {
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
	s.matchCtx.moduleCache = &s.moduleCache
	s.matchCtx.cancelDone = ctx.Done()
	s.matchCtx.maxMatchesPerPattern = 0
	if s.fastScan && rule.FastScanSafe {
		s.matchCtx.maxMatchesPerPattern = 1
	}
	s.matchCtx.maxMatchSpan = s.maxMatchSpan
	if input.usesharedAutomaton {
		if err := s.addStaticMatchesInt(ctx, rule, input.data, s.globalMatches[rule.Index]); err != nil {
			return err
		}
	} else {
		if err := s.addLocalTextMatches(ctx, rule, input.data); err != nil {
			return err
		}
	}

	if !s.prefilterDisabled && input.skipUnmatchedContext && s.hasForbiddenStringMatch(rule, input.usesharedAutomaton) {
		return nil
	}

	canShortCircuit := rule.ConditionMonotonic &&
		input.booleanMatchOnly &&
		(len(rule.RegexPatterns) > 0 || len(rule.HexPatterns) > 0)

	if canShortCircuit && len(s.matchCtx.spans) > 0 && s.isRuleConditionSatisfied(rule) {
		s.matchCtx.normalizeMatches()
		if s.blockScan {
			base := s.blockContext[0].Base
			for _, spans := range s.matchCtx.spans {
				for index := range spans {
					spans[index].Offset += base
				}
			}
			s.matchCtx.Data = nil
			s.matchCtx.Blocks = s.blockContext[:]
			s.matchCtx.FileSize = s.blockFileSize
		}
		return nil
	}

	if err := s.addLocalNonTextMatches(ctx, rule, input.data, &s.nonTextCache, input.usesharedAutomaton, canShortCircuit); err != nil {
		return err
	}
	s.matchCtx.normalizeMatches()
	if s.blockScan {
		base := s.blockContext[0].Base
		for _, spans := range s.matchCtx.spans {
			for index := range spans {
				spans[index].Offset += base
			}
		}
		s.matchCtx.Data = nil
		s.matchCtx.Blocks = s.blockContext[:]
		s.matchCtx.FileSize = s.blockFileSize
	}
	return nil
}

func (s *Scanner) isRuleConditionSatisfied(rule *CompiledRule) bool {
	s.prepareInterpreter(rule)
	s.interp.SetItersmax(s.itersmax)
	if err := s.interp.Execute(); err != nil {
		return false
	}
	return s.interp.ruleResultByIndex(rule.Index, rule.Name)
}

func (s *Scanner) allEvaluatedRulesPrefilterRejected(ctx context.Context, data []byte, usesharedAutomaton bool) bool {
	if usesharedAutomaton && s.allEvaluatedRulesRequireSharedPatterns &&
		len(s.touchedGlobalMatches) == 0 && !s.sharedNonTextMatched {
		return true
	}
	for _, rule := range s.program.Rules {
		if !s.shouldEvaluateRule(rule) {
			continue
		}
		if !s.ruleHeaderConstraintsMatchInput(ctx, rule, ruleScanInput{data: data}) {
			continue
		}
		if !rule.RequiresStringMatch {
			return false
		}
		if s.rulePrefilterStatus(rule, usesharedAutomaton) != rulePrefilterRejected {
			return false
		}
	}
	return true
}

func (s *Scanner) rulePrefilterStatus(rule *CompiledRule, usesharedAutomaton bool) rulePrefilterStatus {
	if !usesharedAutomaton || rule.Index < 0 || rule.Index >= len(s.globalMatches) {
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
		case prefilterStringText, prefilterStringDead:
			// Text strings are represented in shared automaton; dead strings cannot match.
		case prefilterStringNonText:
			matches, ready := s.getNonTextMatches(&s.nonTextCache, info.cacheIndex, usesharedAutomaton)
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
