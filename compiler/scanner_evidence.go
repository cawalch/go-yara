package compiler

import (
	"context"
	"maps"
	"slices"
)

type publicRuleMaterialization struct {
	data    []byte
	matches map[string][]Match
	base    int64
}

func newPublicRuleMatch(
	rule *CompiledRule,
	matches map[string][]Match,
	evidence map[string][]EvidenceFinding,
) RuleMatch {
	var tags []string
	if len(rule.Tags) > 0 {
		tags = slices.Clone(rule.Tags)
	}
	var meta map[string]any
	if len(rule.Meta) > 0 {
		meta = maps.Clone(rule.Meta)
	}
	return RuleMatch{
		Rule:     rule.Name,
		Tags:     tags,
		Meta:     meta,
		Matches:  matches,
		Evidence: evidence,
	}
}

func (s *Scanner) materializeMatchingRules(
	ctx context.Context,
	data []byte,
	evaluation publicRuleEvaluation,
) ([]RuleMatch, error) {
	resultCount := 0
	for _, ruleIndex := range s.matchedRuleIndices {
		if ruleIndex < 0 || ruleIndex >= len(s.program.Rules) {
			continue
		}
		if s.program.Rules[ruleIndex].IsGlobal || evaluation.allGlobalMatched {
			resultCount++
		}
	}
	if resultCount == 0 {
		return nil, nil
	}

	matchBase := int64(0)
	if s.blockScan {
		matchBase = s.blockContext[0].Base
	}
	result := make([]RuleMatch, 0, resultCount)
	for _, ruleIndex := range s.matchedRuleIndices {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if ruleIndex < 0 || ruleIndex >= len(s.program.Rules) {
			continue
		}
		rule := s.program.Rules[ruleIndex]
		if !rule.IsGlobal && !evaluation.allGlobalMatched {
			continue
		}
		var publicMatches map[string][]Match
		var evidence map[string][]EvidenceFinding
		if !s.omitMatches {
			var err error
			publicMatches, evidence, err = s.extractPublicMatchesAndEvidence(ctx, rule, data, evaluation.scanInput, matchBase)
			if err != nil {
				return nil, err
			}
		}
		ruleMatch := newPublicRuleMatch(rule, publicMatches, evidence)
		if s.hookMask&hookBitMatch != 0 && s.matchHook != nil {
			action := s.matchHook(rule, ruleMatch)
			switch action {
			case MatchActionStopScan:
				result = append(result, ruleMatch)
				return result, nil
			case MatchActionSkipRule:
				continue
			case MatchActionContinue:
			}
		}
		result = append(result, ruleMatch)
	}
	return result, nil
}

//nolint:revive // argument-limit: internal helper coordinates rule match extraction
func (s *Scanner) extractPublicMatchesAndEvidence(
	ctx context.Context,
	rule *CompiledRule,
	data []byte,
	scanInput ruleScanInput,
	matchBase int64,
) (map[string][]Match, map[string][]EvidenceFinding, error) {
	scanInput.booleanMatchOnly = false
	if err := s.populateRuleMatchContext(ctx, rule, scanInput); err != nil {
		return nil, nil, err
	}

	var publicMatches map[string][]Match
	if len(s.matchCtx.spans) > 0 {
		publicMatches = materializeRuleMatchesAt(rule, s.matchCtx.spans, matchBase)
		if publicMatches != nil {
			if err := s.populateMatchEvidenceFrom(ctx, publicRuleMaterialization{
				data:    data,
				matches: publicMatches,
				base:    matchBase,
			}); err != nil {
				return nil, nil, err
			}
		}
	}
	evidence, err := s.populatePublicRuleEvidence(ctx, rule, publicRuleMaterialization{
		data:    data,
		matches: publicMatches,
		base:    matchBase,
	})
	if err != nil {
		return nil, nil, err
	}
	return publicMatches, evidence, nil
}

func (s *Scanner) populatePublicRuleEvidence(
	ctx context.Context,
	rule *CompiledRule,
	materialization publicRuleMaterialization,
) (map[string][]EvidenceFinding, error) {
	if s.evidenceMax <= 0 {
		return nil, nil
	}
	return s.populateRuleEvidence(ctx, rule, materialization.matches, func(match Match) (captureInput, bool) {
		relativeOffset := match.Offset - materialization.base
		if relativeOffset < 0 || match.Length < 0 || relativeOffset > int64(len(materialization.data)) {
			return captureInput{}, false
		}
		end := relativeOffset + int64(match.Length)
		if end < relativeOffset || end > int64(len(materialization.data)) {
			return captureInput{}, false
		}
		return captureInput{
			data:  materialization.data,
			start: int(relativeOffset),
			end:   int(end),
			base:  materialization.base,
		}, true
	})
}

func (s *Scanner) populateMatchEvidence(ctx context.Context, data []byte, matches map[string][]Match) error {
	return s.populateMatchEvidenceFrom(ctx, publicRuleMaterialization{data: data, matches: matches})
}

func (s *Scanner) populateMatchEvidenceFrom(ctx context.Context, materialization publicRuleMaterialization) error {
	if s.matchDataMax <= 0 && !s.matchContextEnabled {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for id, perStringMatches := range materialization.matches {
		if err := ctx.Err(); err != nil {
			return err
		}
		for i := range perStringMatches {
			if err := ctx.Err(); err != nil {
				return err
			}
			s.populateSingleMatchEvidenceAt(materialization.data, materialization.base, &perStringMatches[i])
		}
		materialization.matches[id] = perStringMatches
	}
	return nil
}

func (s *Scanner) populateSingleMatchEvidenceAt(data []byte, base int64, match *Match) {
	relativeOffset := match.Offset - base
	if relativeOffset < 0 || match.Length < 0 || relativeOffset > int64(len(data)) {
		return
	}
	endOffset := relativeOffset + int64(match.Length)
	if endOffset < relativeOffset || endOffset > int64(len(data)) {
		return
	}

	start := int(relativeOffset)
	end := int(endOffset)
	if s.matchDataMax > 0 {
		copyLength := match.Length
		if copyLength > s.matchDataMax {
			copyLength = s.matchDataMax
			match.MatchedDataTruncated = true
		}
		match.MatchedData = copyBytes(data[start : start+copyLength])
	}
	if s.matchContextEnabled {
		beforeStart := start - s.matchContextBefore
		if beforeStart < 0 {
			beforeStart = 0
		}
		afterEnd := end + s.matchContextAfter
		if afterEnd > len(data) {
			afterEnd = len(data)
		}
		match.ContextBefore = copyBytes(data[beforeStart:start])
		match.ContextAfter = copyBytes(data[end:afterEnd])
	}
}

func copyBytes(src []byte) []byte {
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

func materializeRuleMatchesAt(rule *CompiledRule, src map[string][]matchSpan, base int64) map[string][]Match {
	if len(src) == 0 {
		return nil
	}
	if len(src) == 1 {
		for id, spans := range src {
			if len(spans) == 0 || (rule != nil && rule.IsPrivateString(id)) {
				return nil
			}
			dst := make([]Match, len(spans))
			for index, span := range spans {
				dst[index] = Match{Pattern: id, Offset: span.Offset, Length: span.Length, Base: base}
			}
			return map[string][]Match{id: dst}
		}
	}
	totalSpans := 0
	validIDs := 0
	for id, spans := range src {
		if len(spans) == 0 || (rule != nil && rule.IsPrivateString(id)) {
			continue
		}
		totalSpans += len(spans)
		validIDs++
	}
	if totalSpans == 0 {
		return nil
	}
	matches := make(map[string][]Match, validIDs)
	slab := make([]Match, totalSpans)
	for id, spans := range src {
		if len(spans) == 0 || (rule != nil && rule.IsPrivateString(id)) {
			continue
		}
		n := len(spans)
		dst := slab[:n:n]
		slab = slab[n:]
		for index, span := range spans {
			dst[index] = Match{Pattern: id, Offset: span.Offset, Length: span.Length, Base: base}
		}
		matches[id] = dst
	}
	return matches
}
