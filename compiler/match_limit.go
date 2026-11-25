package compiler

// Keys are absolute offsets within each pattern. In block scans, a nonzero
// value indexes the retained occurrence (one-based) so overlaps can update it.
type ruleMatchBudget struct {
	rule      *CompiledRule
	positions map[string]map[int64]int
	count     int
	exceeded  bool
}

func (s *Scanner) resetMatchLimits() {
	clear(s.matchBudgets)
	s.matchLimitErr = nil
}

func (s *Scanner) ruleMatchBudget(rule *CompiledRule) *ruleMatchBudget {
	budget := s.matchBudgets[rule.Index]
	if budget == nil {
		budget = &ruleMatchBudget{rule: rule, positions: make(map[string]map[int64]int)}
		s.matchBudgets[rule.Index] = budget
	}
	return budget
}

// limitRuleMatches filters before storing a span. Repeated starts still enter
// the context so normalization and evidence replay see the retained occurrence.
func (s *Scanner) limitRuleMatches(rule *CompiledRule, base int64) {
	budget := s.ruleMatchBudget(rule)
	s.matchCtx.matchFilter = func(id string, span matchSpan) bool {
		offset := base + span.Offset
		if fixed, ok := rule.fixedOffsets[id]; ok && fixed != offset {
			return false
		}
		if _, retained := budget.positions[id][offset]; retained {
			return true
		}
		return budget.reserve(s, id, offset)
	}
}

// reserve charges a previously unseen start to the rule.
func (budget *ruleMatchBudget) reserve(s *Scanner, id string, offset int64) bool {
	positions := budget.positions[id]
	if budget.exceeded || s.fastScan && budget.rule.FastScanSafe && len(positions) > 0 {
		return false
	}
	if budget.count >= s.maxMatchesLimit {
		budget.exceeded = true
		if s.onMaxMatchesExceeded == nil {
			s.matchLimitErr = ErrMatchLimitExceeded
		} else {
			s.onMaxMatchesExceeded(budget.rule.Name, budget.count+1)
		}
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
