package compiler

// A limit spans all patterns and input windows for one rule. Keys are absolute
// offsets within each pattern, so replaying evidence or an overlapping block
// doesn't consume the budget twice. A nonzero value is a one-based index into
// retained matches for that pattern in a block scan, or marks a committed reader match.
type ruleMatchBudget struct {
	positions map[string]map[int64]int
	count     int
	exceeded  bool
}

func (s *Scanner) resetMatchLimits() {
	clear(s.matchBudgets)
	s.matchLimitErr = nil
}

// limitRuleMatches attaches the opt-in budget at the point verified occurrences
// enter the match context. The filter is removed by the next context reset.
func (s *Scanner) limitRuleMatches(rule *CompiledRule, base int64, window *streamMatchWindow) {
	budget := s.matchBudgets[rule.Index]
	if budget == nil {
		budget = &ruleMatchBudget{positions: make(map[string]map[int64]int)}
		s.matchBudgets[rule.Index] = budget
	}
	s.matchCtx.matchFilter = func(id string, span matchSpan) bool {
		offset := base + span.Offset
		if fixed, ok := rule.fixedOffsets[id]; ok && fixed != offset {
			return false
		}
		if window != nil {
			horizon := -1
			if pattern, ok := rule.RegexPatterns[id]; ok {
				horizon = s.streamRegexHorizon(pattern)
			}
			if !window.owns(span, horizon) {
				return false
			}
		}
		positions := budget.positions[id]
		if index, retained := positions[offset]; retained {
			// A reader may revisit a start when its explicit overlap is shorter
			// than the regex horizon. Only the first owned occurrence is retained.
			return window == nil || index == 0
		}
		if s.fastScan && rule.FastScanSafe && len(positions) > 0 {
			return false
		}
		if budget.count >= s.maxMatchesLimit {
			if budget.exceeded {
				return false
			}
			budget.exceeded = true
			if s.onMaxMatchesExceeded == nil {
				s.matchLimitErr = ErrMatchLimitExceeded
				return false
			}
			s.onMaxMatchesExceeded(rule.Name, budget.count+1)
			return false
		}
		if positions == nil {
			positions = make(map[int64]int)
			budget.positions[id] = positions
		}
		positions[offset] = 0
		budget.count++
		return true
	}
}
