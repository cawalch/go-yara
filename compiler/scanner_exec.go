package compiler

import (
	"context"
	"slices"

	"github.com/cawalch/go-yara/internal/wordmatch"
)

type publicRuleEvaluation struct {
	scanInput              ruleScanInput
	allGlobalMatched       bool
	matchedPublicGlobal    bool
	matchedPublicNonGlobal bool
	matchedRuleIndices     *[]int
}

func (s *Scanner) scanError() error {
	if s.moduleErr != nil {
		return s.moduleErr
	}
	if s.program.preparationErr != nil {
		return s.program.preparationErr
	}
	return s.externalErr
}

func (s *Scanner) selectEvaluatedRules() {
	if s.program == nil || s.program.preparationErr != nil || len(s.tagsFilter) == 0 ||
		len(s.program.dependencies) < len(s.program.Rules) {
		return
	}
	s.evaluatedRules = make(map[string]bool)
	pending := make([]string, 0)
	for _, rule := range s.program.Rules {
		if rule.IsGlobal || s.hasMatchingTag(rule) {
			pending = append(pending, rule.Name)
		}
	}
	for len(pending) > 0 {
		name := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if !s.evaluatedRules[name] {
			s.evaluatedRules[name] = true
			pending = append(pending, s.program.dependencies[name]...)
		}
	}
}

func (s *Scanner) shouldEvaluateRule(rule *CompiledRule) bool {
	if s != nil && s.hookMask&hookBitRuleGate != 0 && s.ruleGate != nil && !s.ruleGate(rule) {
		return false
	}
	return s.evaluatedRules == nil || s.evaluatedRules[rule.Name]
}

// hasMatchingTag returns true if the rule has at least one tag in the filter.
func (s *Scanner) hasMatchingTag(rule *CompiledRule) bool {
	if len(s.tagsFilter) == 0 {
		return true
	}
	for _, tag := range rule.Tags {
		if s.tagsFilter[tag] {
			return true
		}
	}
	return false
}

func (s *Scanner) recordSkippedCandidateRule(
	rule *CompiledRule,
	result *ScanResult,
	pruned bool,
) {
	if result.RuleResults != nil {
		result.RuleResults[rule.Name] = false
	}
	if pruned {
		result.PrunedRules = append(result.PrunedRules, rule.Name)
		if s.hookMask&hookBitRuleProfile != 0 {
			s.dispatchRuleEvaluated(RuleProfile{
				RuleName:  rule.Name,
				RuleIndex: rule.Index,
				Pruned:    true,
			})
		}
		if s.hookMask&hookBitTelemetry != 0 && s.telemetrySink != nil {
			s.telemetrySink.RulesPruned++
		}
	}
}

func (s *Scanner) recordAllRulesRejected(ctx context.Context, result *ScanResult, scanInput ruleScanInput) error {
	done := ctx.Done()
	if scanCanceled(done) {
		return ctx.Err()
	}
	if s.omitRuleResults && !s.program.hasHeaderOrMandatoryAssertions {
		return nil
	}
	checkHeaders := s.program.hasHeaderOrMandatoryAssertions
	for i, rule := range s.program.Rules {
		if i&63 == 63 && scanCanceled(done) {
			return ctx.Err()
		}
		if !s.shouldEvaluateRule(rule) {
			continue
		}
		if result.RuleResults != nil {
			result.RuleResults[rule.Name] = false
		}
		if checkHeaders && !s.ruleHeaderConstraintsMatchInput(ctx, rule, scanInput) {
			s.recordSkippedCandidateRule(rule, result, true)
		}
	}
	if scanCanceled(done) {
		return ctx.Err()
	}
	return nil
}

func (s *Scanner) rejectAllRules(ctx context.Context, result *ScanResult, scanInput ruleScanInput) error {
	s.clearRuleResultsIfDirty()
	if err := s.recordAllRulesRejected(ctx, result, scanInput); err != nil {
		s.clearRuleResultsIfDirty()
		return err
	}
	s.recordScanRejection(result)
	return nil
}

func (s *Scanner) markChunkCandidateRules() {
	for _, ruleIndex := range s.touchedGlobalMatches {
		s.markCandidateRule(ruleIndex)
	}
	for _, rule := range s.program.Rules {
		if !s.shouldEvaluateRule(rule) || s.isCandidateRule(rule.Index) {
			continue
		}
		if !s.program.ruleAllStringsInSharedPrefilter(rule) || s.ruleHasMatchedSharedNonText(rule) {
			s.markCandidateRule(rule.Index)
		}
	}
}

func (s *Scanner) resetBorrowedEvidence() {
	if s.evidenceBorrowed {
		fieldsLimit := min(s.borrowedFieldsMapIdx, len(s.borrowedFieldsMaps))
		for i := range fieldsLimit {
			clear(s.borrowedFieldsMaps[i])
		}
		s.borrowedFieldsMapIdx = 0

		findingsLimit := min(s.borrowedFindingsIdx, len(s.borrowedFindings))
		clear(s.borrowedFindings[:findingsLimit])
		s.borrowedFindingsIdx = 0

		planLimit := min(s.borrowedPlanMapIdx, len(s.borrowedPlanMaps))
		for i := range planLimit {
			clear(s.borrowedPlanMaps[i])
		}
		s.borrowedPlanMapIdx = 0

		clear(s.borrowedCaptureSlab)
		s.borrowedCaptureSlab = s.borrowedCaptureSlab[:0]
		clear(s.borrowedEvidenceRuleMap)
	}
}

func (s *Scanner) resetScanState() {
	if s.matchBudgets != nil {
		s.resetMatchLimits()
	}
	s.populatedMatchCtxRuleIndex = -1
	clear(s.assertionResults)
	s.resetBorrowedEvidence()
}

func (s *Scanner) recordScanRejection(
	result *ScanResult,
) {
	if s.hookMask&hookBitTelemetry != 0 && s.telemetrySink != nil {
		s.telemetrySink.PrefilterRejects++
	}
}

// ScanWithContext scans the provided byte slice against the compiled rules.
func (s *Scanner) ScanWithContext(ctx context.Context, data []byte) (result *ScanResult, err error) {
	ctx, ready, err := s.prepareScanCall(ctx)
	var ruleResults map[string]bool
	if s == nil || !s.omitRuleResults {
		ruleCount := 0
		if s != nil && s.program != nil {
			ruleCount = len(s.program.Rules)
		}
		ruleResults = make(map[string]bool, ruleCount)
	}
	result = &ScanResult{
		MatchedRules: make([]RuleMatch, 0),
		PrunedRules:  make([]string, 0),
		RuleResults:  ruleResults,
	}
	if s == nil || (!s.reportedMatchesOnly && !s.omitMatches) {
		result.Matches = make(map[string]map[string][]Match)
	}
	if !ready || err != nil {
		if err != nil {
			return nil, err
		}
		return result, nil
	}

	if s.hookMask&(hookBitTelemetry|hookBitScanLifecycle) != 0 {
		scanStart := s.beginScan(ctx, int64(len(data)))
		defer func() {
			matches := 0
			if result != nil {
				matches = len(result.MatchedRules)
			}
			scanStart.finish(result, matches, err)
		}()
	}

	s.resetScanState()
	if (s.reportedMatchesOnly || s.omitMatches) && s.compactPrefilterFanoutRejects(ctx, data) {
		scanInput := ruleScanInput{data: data, usesharedAutomaton: false, skipUnmatchedContext: true}
		if err := s.rejectAllRules(ctx, result, scanInput); err != nil {
			return nil, err
		}
		return result, nil
	}

	s.skipUnmatchedNonText = s.reportedMatchesOnly
	usesharedAutomaton, err := s.preparePatternScan(ctx, data)
	if err != nil {
		return nil, err
	}
	if !s.reportedMatchesOnly {
		s.markChunkCandidateRules()
	}
	scanInput := ruleScanInput{data: data, usesharedAutomaton: usesharedAutomaton, skipUnmatchedContext: s.reportedMatchesOnly}

	allRejected := false
	if !s.prefilterDisabled {
		if usesharedAutomaton {
			allRejected = len(s.candidateRuleIndices) == 0
		} else {
			allRejected = s.allEvaluatedRulesPrefilterRejected(ctx, data, false)
		}
	}
	if allRejected {
		if err := s.rejectAllRules(ctx, result, scanInput); err != nil {
			return nil, err
		}
		return result, nil
	}
	s.clearRuleResultsIfDirty()
	defer s.clearRuleResultsIfDirty()

	// YARA spec: global rules are evaluated first and ALL must match
	// before non-global rules are evaluated.
	// Private rules are never reported in MatchedRules.
	// Tag filtering includes dependencies during evaluation, but not reporting.
	//
	// Two-pass approach:
	// 1. Evaluate all rules to populate match context and rule results.
	// 2. Build MatchedRules, skipping non-global rules if any global rule failed.

	done := ctx.Done()
	// Pass 1: evaluate candidate rules and retain the full result map.
	s.matchedRuleIndices = s.matchedRuleIndices[:0]
	s.interp.ResetIterationCount()
	for ruleIdx, rule := range s.program.Rules {
		if scanCanceled(done) {
			return nil, ctx.Err()
		}
		// Evaluation includes dependencies of selected and global rules.
		if !s.shouldEvaluateRule(rule) {
			continue
		}
		if s.hookMask&hookBitPoll != 0 {
			if err := s.dispatchPoll(ctx, PollProgress{
				BytesScanned:   int64(len(data)),
				TotalBytes:     int64(len(data)),
				Phase:          PhaseRuleCondition,
				CurrentRule:    rule.Name,
				RulesEvaluated: ruleIdx,
				TotalRules:     len(s.program.Rules),
			}); err != nil {
				return nil, err
			}
		}
		if usesharedAutomaton && !s.prefilterDisabled && !s.isCandidateRule(rule.Index) {
			pruned := !s.ruleHeaderConstraintsMatchInput(ctx, rule, scanInput)
			s.recordSkippedCandidateRule(rule, result, pruned)
			continue
		}
		evaluation, err := s.evaluateRuleCondition(ctx, rule, scanInput)
		if err != nil {
			return nil, err
		}
		if evaluation.pruned {
			result.PrunedRules = append(result.PrunedRules, rule.Name)
			if result.RuleResults != nil {
				result.RuleResults[rule.Name] = false
			}
			continue
		}

		// The default preserves the historical all-evaluated-rules result shape.
		// The opt-in compact result mode materializes only matching public rules.
		materialize := !s.omitMatches && (!s.reportedMatchesOnly || (evaluation.matched && !rule.IsPrivate && s.hasMatchingTag(rule)))
		if materialize && s.matchCtx.hasSpans() {
			if err := s.recordRuleMatches(ctx, data, rule, result); err != nil {
				return nil, err
			}
		}
		s.recordRuleOutcome(result, rule, evaluation.matched)
	}

	if scanCanceled(done) {
		return nil, ctx.Err()
	}

	if err := s.finalizeMatchedRules(ctx, result, func(rule *CompiledRule) (map[string][]Match, map[string][]EvidenceFinding, error) {
		var matches map[string][]Match
		if !s.omitMatches && result.Matches != nil {
			matches = result.Matches[rule.Name]
		}
		if s.omitMatches {
			return matches, nil, nil
		}
		evidence, err := s.populatePublicRuleEvidence(ctx, rule, publicRuleMaterialization{
			data:    data,
			matches: matches,
		})
		return matches, evidence, err
	}); err != nil {
		return nil, err
	}
	s.clearRuleResultsIfDirty()
	return result, nil
}

func (s *Scanner) allEvaluatedGlobalsMatched(ruleResults map[string]bool) bool {
	for _, ruleIndex := range s.evaluatedGlobalRules {
		if ruleIndex >= 0 && ruleIndex < len(s.ruleResultsDense) {
			if !s.ruleResultsDense[ruleIndex] {
				return false
			}
		} else if ruleResults != nil && !ruleResults[s.program.Rules[ruleIndex].Name] {
			return false
		}
	}
	return true
}

//nolint:nestif // security-sensitive result boundary mirrors private/global filtering
func (s *Scanner) finalizeMatchedRules(
	ctx context.Context,
	result *ScanResult,
	extract func(*CompiledRule) (map[string][]Match, map[string][]EvidenceFinding, error),
) error {
	return s.finalizeMatchedRulesCore(ctx, result, false, extract)
}

//nolint:nestif,revive // argument-limit,nestif: security-sensitive result boundary mirrors private/global filtering
func (s *Scanner) finalizeMatchedRulesCore(
	ctx context.Context,
	result *ScanResult,
	streamingEarlyStop bool,
	extract func(*CompiledRule) (map[string][]Match, map[string][]EvidenceFinding, error),
) error {
	done := ctx.Done()
	allGlobalMatched := s.allEvaluatedGlobalsMatched(result.RuleResults)
	if len(s.matchedRuleIndices) > 0 {
		result.MatchedRules = make([]RuleMatch, 0, len(s.matchedRuleIndices))
	}
	for _, ruleIndex := range s.matchedRuleIndices {
		rule := s.program.Rules[ruleIndex]
		if scanCanceled(done) {
			return ctx.Err()
		}
		if (!rule.IsGlobal && !allGlobalMatched) || !s.hasMatchingTag(rule) {
			if s.reportedMatchesOnly && !s.omitMatches && result.Matches != nil {
				delete(result.Matches, rule.Name)
			}
			continue
		}
		if rule.IsPrivate {
			continue
		}
		matches, evidence, err := extract(rule)
		if err != nil {
			return err
		}
		ruleMatch := newPublicRuleMatch(rule, matches, evidence)
		if s.hookMask&hookBitMatch != 0 && s.matchHook != nil {
			switch s.matchHook(rule, ruleMatch) {
			case MatchActionStopScan:
				s.recordRuleEvidence(result, rule.Name, evidence)
				result.MatchedRules = append(result.MatchedRules, ruleMatch)
				return nil
			case MatchActionSkipRule:
				continue
			case MatchActionContinue:
			}
		}
		s.recordRuleEvidence(result, rule.Name, evidence)
		result.MatchedRules = append(result.MatchedRules, ruleMatch)
		if streamingEarlyStop {
			return nil
		}
	}
	return nil
}

func (s *Scanner) recordRuleEvidence(result *ScanResult, ruleName string, evidence map[string][]EvidenceFinding) {
	if len(evidence) == 0 {
		return
	}
	if result.Evidence == nil {
		switch {
		case s.evidenceBorrowed && s.borrowedEvidenceRuleMap != nil:
			result.Evidence = s.borrowedEvidenceRuleMap
			clear(result.Evidence)
		case s.evidenceBorrowed:
			s.borrowedEvidenceRuleMap = make(map[string]map[string][]EvidenceFinding)
			result.Evidence = s.borrowedEvidenceRuleMap
		default:
			result.Evidence = make(map[string]map[string][]EvidenceFinding)
		}
	}
	result.Evidence[ruleName] = evidence
}

func (s *Scanner) evaluatePublicRules(
	ctx context.Context,
	data []byte,
	matchedRuleIndices *[]int,
) (publicRuleEvaluation, error) {
	if s.compactPrefilterFanoutRejects(ctx, data) {
		if s.hookMask&hookBitTelemetry != 0 && s.telemetrySink != nil {
			s.telemetrySink.PrefilterRejects++
		}
		if scanCanceled(ctx.Done()) {
			return publicRuleEvaluation{}, ctx.Err()
		}
		return publicRuleEvaluation{}, nil
	}
	return s.evaluatePublicRulesAfterCompact(ctx, data, matchedRuleIndices)
}

func (s *Scanner) evaluatePublicRulesAfterCompact(
	ctx context.Context,
	data []byte,
	matchedRuleIndices *[]int,
) (publicRuleEvaluation, error) {
	done := ctx.Done()
	s.resetScanState()
	s.skipUnmatchedNonText = true
	usesharedAutomaton, err := s.preparePatternScan(ctx, data)
	if err != nil {
		return publicRuleEvaluation{}, err
	}
	result := publicRuleEvaluation{
		scanInput: ruleScanInput{
			data:                 data,
			usesharedAutomaton:   usesharedAutomaton,
			skipUnmatchedContext: true,
			booleanMatchOnly:     matchedRuleIndices == nil,
		},
		allGlobalMatched:   true,
		matchedRuleIndices: matchedRuleIndices,
	}
	s.interp.ResetIterationCount()
	if !s.prefilterDisabled && usesharedAutomaton {
		return s.evaluateSharedPublicRules(ctx, result)
	}
	if !s.prefilterDisabled && s.allEvaluatedRulesPrefilterRejected(ctx, data, usesharedAutomaton) {
		if s.hookMask&hookBitTelemetry != 0 && s.telemetrySink != nil {
			s.telemetrySink.PrefilterRejects++
		}
		if scanCanceled(done) {
			return result, ctx.Err()
		}
		return result, nil
	}
	for _, rule := range s.program.Rules {
		if err := s.evaluatePublicRule(ctx, rule, &result); err != nil {
			return publicRuleEvaluation{}, err
		}
	}
	if scanCanceled(done) {
		return result, ctx.Err()
	}
	return result, nil
}

func (s *Scanner) evaluateSharedPublicRules(
	ctx context.Context,
	result publicRuleEvaluation,
) (publicRuleEvaluation, error) {
	if len(s.candidateRuleIndices) == 0 {
		if s.hookMask&hookBitTelemetry != 0 && s.telemetrySink != nil {
			s.telemetrySink.PrefilterRejects++
		}
		return result, nil
	}
	slices.Sort(s.candidateRuleIndices)
	for _, ruleIndex := range s.evaluatedGlobalRules {
		if !s.isCandidateRule(ruleIndex) {
			result.allGlobalMatched = false
			break
		}
	}
	for _, ruleIndex := range s.candidateRuleIndices {
		if ruleIndex < 0 || ruleIndex >= len(s.program.Rules) {
			continue
		}
		if err := s.evaluatePublicRule(ctx, s.program.Rules[ruleIndex], &result); err != nil {
			return publicRuleEvaluation{}, err
		}
	}
	return result, nil
}

func (s *Scanner) evaluatePublicRule(
	ctx context.Context,
	rule *CompiledRule,
	result *publicRuleEvaluation,
) error {
	if scanCanceled(ctx.Done()) {
		return ctx.Err()
	}
	if !s.shouldEvaluateRule(rule) {
		return nil
	}
	evaluation, err := s.evaluateRuleCondition(ctx, rule, result.scanInput)
	if err != nil {
		return err
	}
	if rule.IsGlobal && !evaluation.matched {
		result.allGlobalMatched = false
	}
	if rule.IsPrivate || !s.hasMatchingTag(rule) || !evaluation.matched {
		return nil
	}
	if rule.IsGlobal {
		result.matchedPublicGlobal = true
	} else {
		result.matchedPublicNonGlobal = true
	}
	if result.matchedRuleIndices != nil {
		*result.matchedRuleIndices = append(*result.matchedRuleIndices, rule.Index)
	}
	return nil
}

func (s *Scanner) matchBooleanRouting(ctx context.Context, data []byte) (bool, bool, error) {
	if s.booleanRouting == nil || len(data) > 1024 || s.prefilterDisabled {
		return false, false, nil
	}
	if s.hookMask&hookBitTelemetryLatency != 0 {
		previous := s.enterScanPhase(PhasePrefilter)
		defer s.leaveScanPhase(previous)
	}
	started := s.prefilterStart()
	decision := s.booleanRouting.Match(data)
	if err := ctx.Err(); err != nil {
		return false, false, err
	}
	if decision == wordmatch.Unknown {
		return false, false, nil
	}
	candidates := 0
	if decision == wordmatch.Match {
		candidates = 1
	}
	s.finishPrefilter(PrefilterDecision{Stage: PrefilterStageWordRouting, Rejected: decision == wordmatch.NoMatch, CandidateCount: candidates}, started)

	matched := decision == wordmatch.Match
	if s.hookMask&hookBitTelemetry != 0 && s.telemetrySink != nil {
		if !matched {
			s.telemetrySink.PrefilterRejects++
		}
	}
	return matched, true, nil
}

//nolint:revive // argument-limit: internal helper
func (s *Scanner) recordRuleMatches(
	ctx context.Context,
	data []byte,
	rule *CompiledRule,
	result *ScanResult,
) error {
	ruleMatches := materializeRuleMatchesAt(rule, s.matchCtx, 0)
	if ruleMatches == nil {
		return nil
	}
	if err := s.populateMatchEvidence(ctx, data, ruleMatches); err != nil {
		return err
	}
	if result.Matches == nil {
		result.Matches = make(map[string]map[string][]Match)
	}
	result.Matches[rule.Name] = ruleMatches
	return nil
}
