package compiler

import (
	"context"
	"time"
)

// Phase timers are exclusive: speculative conditions executed during pattern
// search suspend that timer rather than charging both phases for the same work.
func (s *Scanner) enterScanPhase(phase ScanPhase) ScanPhase {
	if s.hookMask&hookBitTelemetryLatency == 0 {
		return PhaseUnknown
	}
	now := time.Now()
	previous := s.timingPhase
	s.recordPhaseTime(now)
	s.timingPhase, s.timingStart = phase, now
	return previous
}

func (s *Scanner) leaveScanPhase(previous ScanPhase) {
	if s.hookMask&hookBitTelemetryLatency == 0 {
		return
	}
	now := time.Now()
	s.recordPhaseTime(now)
	s.timingPhase, s.timingStart = previous, now
}

func (s *Scanner) recordPhaseTime(now time.Time) {
	if s.telemetrySink == nil || s.timingPhase == PhaseUnknown {
		return
	}
	elapsed := uint64(now.Sub(s.timingStart).Nanoseconds())
	switch s.timingPhase {
	case PhasePrefilter:
		s.telemetrySink.PrefilterDurationNs += elapsed
	case PhasePatternSearch:
		s.telemetrySink.PatternSearchNs += elapsed
	case PhaseRuleCondition:
		s.telemetrySink.ConditionEvalNs += elapsed
	}
}

type scanObservation struct {
	scanner *Scanner
	ctx     context.Context
	started time.Time
}

func (s *Scanner) beginScan(ctx context.Context, size int64) scanObservation {
	var start time.Time
	if s.hookMask&(hookBitScanLifecycle|hookBitTelemetryLatency) != 0 {
		start = time.Now()
	}
	if s.telemetrySink != nil {
		s.telemetrySink.TotalScans++
		s.telemetrySink.BytesScanned += size
	}
	s.dispatchScanStart(ctx, size)
	return scanObservation{scanner: s, ctx: ctx, started: start}
}

// Completion is successful-return-only. Failed attempts still contribute time,
// but never count partial matches as a successful result.
func (observation scanObservation) finish(result *ScanResult, matches int, err error) {
	s := observation.scanner
	start := observation.started
	var duration time.Duration
	if !start.IsZero() {
		duration = time.Since(start)
	}
	if s.telemetrySink != nil {
		if s.trackTelemetryLatency {
			s.telemetrySink.TotalScanDurationNs += uint64(duration.Nanoseconds())
		}
		if err == nil {
			s.telemetrySink.TotalMatches += uint64(matches)
		}
	}
	if err == nil {
		s.dispatchScanComplete(observation.ctx, result, duration)
	}
}

func (observation scanObservation) finishRuleList(matches []RuleMatch, err error) {
	s := observation.scanner
	var result *ScanResult
	if s.hookMask&hookBitScanLifecycle != 0 {
		result = &ScanResult{MatchedRules: matches}
	}
	observation.finish(result, len(matches), err)
}

func (s *Scanner) executeCondition(rule *CompiledRule) error {
	if s.hookMask&hookBitTelemetryLatency != 0 {
		previous := s.enterScanPhase(PhaseRuleCondition)
		defer s.leaveScanPhase(previous)
	}
	s.prepareInterpreter(rule)
	s.interp.SetItersmax(s.itersmax)
	return s.interp.Execute()
}

// Candidate counts describe retained automaton hits, not individual verifier
// invocations. Fallback regex/hex paths do not expose a comparable hit count.
func (s *Scanner) patternCandidateCount(rule *CompiledRule, id string, shared bool) (int, bool) {
	if !shared {
		if rule.StringKinds[id] == StringKindText {
			return s.localProfileCandidates[id], true
		}
		return 0, false
	}
	if rule.StringKinds[id] == StringKindText {
		count := 0
		for _, match := range s.globalMatches[rule.Index] {
			if match.strID == id {
				count++
			}
		}
		return count, true
	}
	cacheIndex := -1
	if pattern, ok := rule.RegexPatterns[id]; ok {
		cacheIndex = pattern.cacheIndex
	}
	if pattern := rule.HexPatterns[id]; pattern != nil {
		cacheIndex = pattern.cacheIndex
	}
	if cacheIndex >= 0 && cacheIndex < len(s.sharedProfileCandidates) && cacheIndex < len(s.program.sharedNonTextCaches) && s.program.sharedNonTextCaches[cacheIndex] {
		return s.sharedProfileCandidates[cacheIndex], true
	}
	return 0, false
}

func (s *Scanner) recordPatternProfiles(rule *CompiledRule, shared bool) {
	if s.hookMask&hookBitPatternProfile == 0 {
		return
	}
	// Compilation assigns stable IDs; no map ordering or per-scan sorting needed.
	for _, id := range rule.IndexToStringID {
		if rule.IsStringDead(id) {
			continue
		}
		candidates, known := s.patternCandidateCount(rule, id, shared)
		verified := len(s.matchCtx.spans[id])
		selectivity := 0.0
		if known && candidates > 0 {
			selectivity = float64(verified) / float64(candidates)
		}
		s.hooks.OnPatternProfile(PatternProfile{RuleName: rule.Name, StringID: id,
			Kind: rule.StringKinds[id], CandidateHits: candidates, CandidateHitsKnown: known,
			VerifiedMatches: verified, Selectivity: selectivity})
	}
}

func (s *Scanner) recordLocalCandidate(id string) {
	if s.hookMask&(hookBitPatternProfile|hookBitTelemetry|hookBitRuleProfile) == 0 {
		return
	}
	if s.localProfileCandidates == nil {
		s.localProfileCandidates = make(map[string]int)
	}
	s.localProfileCandidates[id]++
}

func (s *Scanner) prefilterStart() time.Time {
	if s.hookMask&hookBitPrefilter != 0 {
		return time.Now()
	}
	return time.Time{}
}

func (s *Scanner) finishPrefilter(decision PrefilterDecision, start time.Time) {
	if start.IsZero() {
		return
	}
	decision.DurationNs = time.Since(start).Nanoseconds()
	s.dispatchPrefilter(decision)
}

// Aggregate once per shared search, rather than walking the entire atom lookup
// for each consuming rule/pattern on large instrumented rule sets.
func (s *Scanner) collectSharedProfileCandidates() {
	size := s.program.nonTextCacheSize
	if cap(s.sharedProfileCandidates) < size {
		s.sharedProfileCandidates = make([]int, size)
	}
	s.sharedProfileCandidates = s.sharedProfileCandidates[:size]
	clear(s.sharedProfileCandidates)
	for _, index := range s.touchedPrefilterCandidates {
		entry := s.program.sharedLookup[index]
		if entry.CacheIndex >= 0 && entry.CacheIndex < size {
			s.sharedProfileCandidates[entry.CacheIndex] += len(s.prefilterCandidates[index])
		}
	}
}
