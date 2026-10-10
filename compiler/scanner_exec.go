package compiler

import (
	"context"
	"io"
	"os"
	"slices"
	"time"

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
	result.RuleResults[rule.Name] = false
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
	for _, rule := range s.program.Rules {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !s.shouldEvaluateRule(rule) {
			continue
		}
		result.RuleResults[rule.Name] = false
		if !s.ruleHeaderConstraintsMatchInput(ctx, rule, scanInput) {
			result.PrunedRules = append(result.PrunedRules, rule.Name)
		}
	}
	return ctx.Err()
}

func (s *Scanner) recordScanRejection(
	ctx context.Context,
	result *ScanResult,
	scanStart time.Time,
) {
	if s.hookMask&hookBitTelemetry != 0 && s.telemetrySink != nil {
		s.telemetrySink.PrefilterRejects++
		s.telemetrySink.RulesPruned += uint64(len(result.PrunedRules))
	}
	if s.hookMask&(hookBitScanLifecycle|hookBitTelemetryLatency) != 0 {
		dur := time.Since(scanStart)
		s.dispatchScanComplete(ctx, result, dur)
		if s.hookMask&hookBitTelemetryLatency != 0 && s.telemetrySink != nil {
			s.telemetrySink.TotalScanDurationNs += uint64(dur.Nanoseconds())
		}
	}
}

// Scan scans the provided byte slice against the compiled rules.
func (s *Scanner) Scan(data []byte) (*ScanResult, error) {
	return s.ScanWithContext(context.Background(), data)
}

// ScanWithContext scans the provided byte slice against the compiled rules.
func (s *Scanner) ScanWithContext(ctx context.Context, data []byte) (*ScanResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ruleCount := 0
	if s != nil && s.program != nil {
		ruleCount = len(s.program.Rules)
	}
	result := &ScanResult{
		MatchedRules: make([]RuleMatch, 0),
		PrunedRules:  make([]string, 0),
		RuleResults:  make(map[string]bool, ruleCount),
	}
	if s == nil || !s.reportedMatchesOnly {
		result.Matches = make(map[string]map[string][]Match)
	}
	if s == nil || s.program == nil {
		return result, nil
	}
	if err := s.scanError(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var scanStart time.Time
	if s.hookMask&(hookBitScanLifecycle|hookBitTelemetryLatency) != 0 {
		scanStart = time.Now()
		s.dispatchScanStart(ctx, int64(len(data)))
	}
	if s.hookMask&hookBitTelemetry != 0 && s.telemetrySink != nil {
		s.telemetrySink.TotalScans++
		s.telemetrySink.BytesScanned += int64(len(data))
	}

	if s.reportedMatchesOnly && s.compactPrefilterRejects(ctx, data) {
		if s.hookMask&hookBitPrefilter != 0 {
			s.dispatchPrefilter(PrefilterDecision{Stage: PrefilterStageCompactMask, Rejected: true})
		}
		scanInput := ruleScanInput{data: data, useSharedAutomaton: false, skipUnmatchedContext: true}
		clear(s.ruleResults)
		if err := s.recordAllRulesRejected(ctx, result, scanInput); err != nil {
			return nil, err
		}
		s.recordScanRejection(ctx, result, scanStart)
		return result, nil
	}

	useSharedAutomaton, err := s.preparePatternScan(ctx, data)
	if err != nil {
		return nil, err
	}
	scanInput := ruleScanInput{data: data, useSharedAutomaton: useSharedAutomaton, skipUnmatchedContext: s.reportedMatchesOnly}

	clear(s.ruleResults)
	allRejected := false
	if !s.prefilterDisabled {
		if useSharedAutomaton {
			allRejected = len(s.candidateRuleIndices) == 0
		} else {
			allRejected = s.allEvaluatedRulesPrefilterRejected(ctx, data, false)
		}
	}
	//nolint:nestif // cancellation and result materialization share the rejection boundary
	if allRejected {
		if s.hookMask&hookBitPrefilter != 0 {
			s.dispatchPrefilter(PrefilterDecision{Stage: PrefilterStageSharedAutomaton, Rejected: true})
		}
		if err := s.recordAllRulesRejected(ctx, result, scanInput); err != nil {
			return nil, err
		}
		s.recordScanRejection(ctx, result, scanStart)
		return result, nil
	}

	// YARA spec: global rules are evaluated first and ALL must match
	// before non-global rules are evaluated.
	// Private rules are never reported in MatchedRules.
	// Tag filtering includes dependencies during evaluation, but not reporting.
	//
	// Two-pass approach:
	// 1. Evaluate all rules to populate match context and rule results.
	// 2. Build MatchedRules, skipping non-global rules if any global rule failed.

	// Pass 1: evaluate candidate rules and retain the full result map.
	s.matchedRuleIndices = s.matchedRuleIndices[:0]
	s.interp.ResetIterationCount()
	for _, rule := range s.program.Rules {
		if err := ctx.Err(); err != nil {
			return nil, err
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
				RulesEvaluated: len(result.RuleResults),
				TotalRules:     len(s.program.Rules),
			}); err != nil {
				return nil, err
			}
		}
		if useSharedAutomaton && !s.prefilterDisabled && !s.candidateRuleSeen[rule.Index] {
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
			result.RuleResults[rule.Name] = false
			continue
		}

		// The default preserves the historical all-evaluated-rules result shape.
		// The opt-in compact result mode materializes only matching public rules.
		materialize := !s.reportedMatchesOnly || evaluation.matched && !rule.IsPrivate
		if materialize && len(s.matchCtx.spans) > 0 {
			ruleMatches := materializeMatches(s.matchCtx.spans)
			ruleMatches = filterPrivateStrings(rule, ruleMatches)
			if err := s.populateMatchEvidence(ctx, data, ruleMatches); err != nil {
				return nil, err
			}
			if result.Matches == nil {
				result.Matches = make(map[string]map[string][]Match)
			}
			result.Matches[rule.Name] = ruleMatches
		}
		result.RuleResults[rule.Name] = evaluation.matched
		if evaluation.matched {
			s.matchedRuleIndices = append(s.matchedRuleIndices, rule.Index)
		}
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Check if all global rules matched
	allGlobalMatched := true
	for _, ruleIndex := range s.evaluatedGlobalRules {
		if !result.RuleResults[s.program.Rules[ruleIndex].Name] {
			allGlobalMatched = false
			break
		}
	}

	// Pass 2: build MatchedRules
	for _, ruleIndex := range s.matchedRuleIndices {
		rule := s.program.Rules[ruleIndex]
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// Skip non-global rules if not all global rules matched
		if !rule.IsGlobal && !allGlobalMatched {
			if s.reportedMatchesOnly {
				delete(result.Matches, rule.Name)
			}
			continue
		}
		// Skip rules not matching the tag filter
		if !s.hasMatchingTag(rule) {
			if s.reportedMatchesOnly {
				delete(result.Matches, rule.Name)
			}
			continue
		}
		// Private rules are not reported in results
		if rule.IsPrivate {
			continue
		}
		// Evidence extraction is deliberately colocated with final public-rule
		// reporting so private or globally filtered matches cannot expose bytes.
		//nolint:nestif // the nested gates mirror that security-sensitive result boundary
		if result.RuleResults[rule.Name] {
			matches := result.Matches[rule.Name]
			evidence, err := s.populatePublicRuleEvidence(ctx, rule, publicRuleMaterialization{
				data:    data,
				matches: matches,
			})
			if err != nil {
				return nil, err
			}
			if len(evidence) != 0 {
				if result.Evidence == nil {
					result.Evidence = make(map[string]map[string][]EvidenceFinding)
				}
				result.Evidence[rule.Name] = evidence
			}
			ruleMatch := newPublicRuleMatch(rule, matches, evidence)
			if s.hookMask&hookBitMatch != 0 && s.matchHook != nil {
				action := s.matchHook(rule, ruleMatch)
				switch action {
				case MatchActionStopScan:
					result.MatchedRules = append(result.MatchedRules, ruleMatch)
					clear(s.ruleResults)
					if s.hookMask&(hookBitScanLifecycle|hookBitTelemetry) != 0 {
						dur := time.Since(scanStart)
						s.dispatchScanComplete(ctx, result, dur)
						if s.telemetrySink != nil {
							s.telemetrySink.TotalScanDurationNs += uint64(dur.Nanoseconds())
							s.telemetrySink.TotalMatches += uint64(len(result.MatchedRules))
						}
					}
					return result, nil
				case MatchActionSkipRule:
					continue
				case MatchActionContinue:
				}
			}
			result.MatchedRules = append(result.MatchedRules, ruleMatch)
		}
	}

	clear(s.ruleResults)
	if s.hookMask&hookBitTelemetry != 0 && s.telemetrySink != nil {
		s.telemetrySink.TotalMatches += uint64(len(result.MatchedRules))
	}
	if s.hookMask&(hookBitScanLifecycle|hookBitTelemetryLatency) != 0 {
		dur := time.Since(scanStart)
		s.dispatchScanComplete(ctx, result, dur)
		if s.hookMask&hookBitTelemetryLatency != 0 && s.telemetrySink != nil {
			s.telemetrySink.TotalScanDurationNs += uint64(dur.Nanoseconds())
		}
	}
	return result, nil
}

func (s *Scanner) Matches(data []byte) (bool, error) {
	return s.MatchesWithContext(context.Background(), data)
}

// MatchesWithContext reports whether at least one public rule matches data.
func (s *Scanner) MatchesWithContext(ctx context.Context, data []byte) (bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s == nil || s.program == nil {
		return false, nil
	}
	if err := s.scanError(); err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	clear(s.ruleResults)
	defer clear(s.ruleResults)
	if s.hookMask&hookBitTelemetry != 0 && s.telemetrySink != nil {
		s.telemetrySink.TotalScans++
		s.telemetrySink.BytesScanned += int64(len(data))
	}
	if matched, handled, err := s.matchBooleanRouting(ctx, data); handled || err != nil {
		return matched, err
	}
	evaluation, err := s.evaluatePublicRules(ctx, data, nil)
	if err != nil {
		return false, err
	}
	hasMatch := evaluation.matchedPublicGlobal ||
		evaluation.allGlobalMatched && evaluation.matchedPublicNonGlobal
	if s.hookMask&hookBitTelemetry != 0 && s.telemetrySink != nil && hasMatch {
		s.telemetrySink.TotalMatches++
	}
	return hasMatch, nil
}

// MatchingRules returns detailed public rule matches without constructing the
// all-rules maps in ScanResult. The returned slice and RuleMatch values are
// owned by the caller and remain valid across later scanner calls.
func (s *Scanner) MatchingRules(data []byte) ([]RuleMatch, error) {
	return s.MatchingRulesWithContext(context.Background(), data)
}

// MatchingRulesWithContext returns detailed public rule matches without
// constructing the all-rules maps in ScanResult.
func (s *Scanner) MatchingRulesWithContext(ctx context.Context, data []byte) ([]RuleMatch, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s == nil || s.program == nil {
		return nil, nil
	}
	if err := s.scanError(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	clear(s.ruleResults)
	defer clear(s.ruleResults)
	s.matchedRuleIndices = s.matchedRuleIndices[:0]
	evaluation, err := s.evaluatePublicRules(ctx, data, &s.matchedRuleIndices)
	if err != nil {
		return nil, err
	}
	return s.materializeMatchingRules(ctx, data, evaluation)
}

func (s *Scanner) evaluatePublicRules(
	ctx context.Context,
	data []byte,
	matchedRuleIndices *[]int,
) (publicRuleEvaluation, error) {
	if s.compactPrefilterRejects(ctx, data) {
		if s.hookMask&hookBitPrefilter != 0 {
			s.dispatchPrefilter(PrefilterDecision{Stage: PrefilterStageCompactMask, Rejected: true})
		}
		if s.hookMask&hookBitTelemetry != 0 && s.telemetrySink != nil {
			s.telemetrySink.PrefilterRejects++
		}
		return publicRuleEvaluation{}, ctx.Err()
	}
	useSharedAutomaton, err := s.preparePatternScan(ctx, data)
	if err != nil {
		return publicRuleEvaluation{}, err
	}
	result := publicRuleEvaluation{
		scanInput:          ruleScanInput{data: data, useSharedAutomaton: useSharedAutomaton, skipUnmatchedContext: true},
		allGlobalMatched:   true,
		matchedRuleIndices: matchedRuleIndices,
	}
	s.interp.ResetIterationCount()
	if !s.prefilterDisabled && useSharedAutomaton {
		return s.evaluateSharedPublicRules(ctx, result)
	}
	if !s.prefilterDisabled && s.allEvaluatedRulesPrefilterRejected(ctx, data, useSharedAutomaton) {
		if s.hookMask&hookBitPrefilter != 0 {
			s.dispatchPrefilter(PrefilterDecision{Stage: PrefilterStageSharedAutomaton, Rejected: true})
		}
		if s.hookMask&hookBitTelemetry != 0 && s.telemetrySink != nil {
			s.telemetrySink.PrefilterRejects++
		}
		return result, ctx.Err()
	}
	for _, rule := range s.program.Rules {
		if err := s.evaluatePublicRule(ctx, rule, &result); err != nil {
			return publicRuleEvaluation{}, err
		}
	}
	return result, ctx.Err()
}

func (s *Scanner) evaluateSharedPublicRules(
	ctx context.Context,
	result publicRuleEvaluation,
) (publicRuleEvaluation, error) {
	if len(s.candidateRuleIndices) == 0 {
		if s.hookMask&hookBitPrefilter != 0 {
			s.dispatchPrefilter(PrefilterDecision{Stage: PrefilterStageSharedAutomaton, Rejected: true})
		}
		if s.hookMask&hookBitTelemetry != 0 && s.telemetrySink != nil {
			s.telemetrySink.PrefilterRejects++
		}
		return result, nil
	}
	slices.Sort(s.candidateRuleIndices)
	for _, ruleIndex := range s.evaluatedGlobalRules {
		if !s.candidateRuleSeen[ruleIndex] {
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
	if err := ctx.Err(); err != nil {
		return err
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
	decision := s.booleanRouting.Match(data)
	if err := ctx.Err(); err != nil {
		return false, false, err
	}
	if decision == wordmatch.Unknown {
		return false, false, nil
	}
	if s.hookMask&hookBitPrefilter != 0 {
		s.dispatchPrefilter(PrefilterDecision{
			Stage:    PrefilterStageWordRouting,
			Rejected: decision == wordmatch.NoMatch,
		})
	}
	matched := decision == wordmatch.Match
	if s.hookMask&hookBitTelemetry != 0 && s.telemetrySink != nil {
		if !matched {
			s.telemetrySink.PrefilterRejects++
		} else {
			s.telemetrySink.TotalMatches++
		}
	}
	return matched, true, nil
}

// ScanReader reads from the reader and scans the data.
func (s *Scanner) ScanReader(r io.Reader) (*ScanResult, error) {
	return s.ScanReaderWithContext(context.Background(), r)
}

// ScanReaderWithContext reads from the reader and scans the data.
// Cancellation is checked between reads; it cannot interrupt a blocked Read.
func (s *Scanner) ScanReaderWithContext(ctx context.Context, r io.Reader) (*ScanResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(contextReader{ctx, r})
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.ScanWithContext(ctx, data)
}

// ScanFile scans the given file.
func (s *Scanner) ScanFile(filename string) (*ScanResult, error) {
	return s.ScanFileWithContext(context.Background(), filename)
}

// ScanFileWithContext scans the given file.
func (s *Scanner) ScanFileWithContext(ctx context.Context, filename string) (*ScanResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if ctx.Done() == nil {
		data, err := os.ReadFile(filename) // #nosec G304 - caller intentionally scans this path
		if err != nil {
			return nil, err
		}
		return s.ScanWithContext(ctx, data)
	}
	file, err := os.Open(filename) // #nosec G304 - caller intentionally scans this path
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return s.ScanReaderWithContext(ctx, file)
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(data)
}
