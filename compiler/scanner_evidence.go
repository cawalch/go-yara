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
	return RuleMatch{
		Rule:     rule.Name,
		Tags:     slices.Clone(rule.Tags),
		Meta:     maps.Clone(rule.Meta),
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
		if err := s.populateRuleMatchContext(ctx, rule, evaluation.scanInput); err != nil {
			return nil, err
		}

		var publicMatches map[string][]Match
		if len(s.matchCtx.spans) > 0 {
			publicMatches = filterPrivateStrings(
				rule,
				materializeMatchesAt(s.matchCtx.spans, matchBase),
			)
			if err := s.populateMatchEvidenceFrom(ctx, publicRuleMaterialization{
				data:    data,
				matches: publicMatches,
				base:    matchBase,
			}); err != nil {
				return nil, err
			}
		}
		evidence, err := s.populatePublicRuleEvidence(ctx, rule, publicRuleMaterialization{
			data:    data,
			matches: publicMatches,
			base:    matchBase,
		})
		if err != nil {
			return nil, err
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

func materializeMatches(src map[string][]matchSpan) map[string][]Match {
	return materializeMatchesAt(src, 0)
}

func materializeMatchesAt(src map[string][]matchSpan, base int64) map[string][]Match {
	matches := make(map[string][]Match, len(src))
	for id, spans := range src {
		if len(spans) == 0 {
			continue
		}
		dst := make([]Match, len(spans))
		for index, span := range spans {
			dst[index] = Match{Pattern: id, Offset: span.Offset, Length: span.Length, Base: base}
		}
		matches[id] = dst
	}
	return matches
}

// filterPrivateStrings removes private strings from the matches map.
func filterPrivateStrings(rule *CompiledRule, matches map[string][]Match) map[string][]Match {
	for id := range matches {
		if rule.IsPrivateString(id) {
			delete(matches, id)
		}
	}
	return matches
}
