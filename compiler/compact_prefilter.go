package compiler

import (
	"context"
	"strconv"

	"github.com/cawalch/go-yara/regex"
)

type compactPatternKey struct {
	data  string
	flags regex.Flags
}

// The compact pass needs only a necessary pattern cover, not match spans.
func (cp *CompiledProgram) buildCompactPrefilter() (*ACAutomaton, error) {
	frequencies := make(map[string]int)
	for _, rule := range cp.Rules {
		for _, data := range rule.TextPatterns {
			frequencies[string(data)]++
		}
	}
	anchors := make([]string, len(cp.Rules))
	nonText := make([]bool, cp.nonTextCacheSize)
	hasAnchor := false
	for i, rule := range cp.Rules {
		best := len(cp.SharedLookup) + 1
		for _, id := range rule.requiredStrings {
			data, ok := rule.TextPatterns[id]
			if ok && len(data) > 0 && frequencies[string(data)] < best {
				anchors[i], best = id, frequencies[string(data)]
			}
		}
		if anchors[i] != "" {
			hasAnchor = true
			continue
		}
		if !cp.ruleHasCompleteSharedPrefilter(rule) {
			return nil, nil
		}
		for _, info := range rule.prefilterStrings {
			if info.class == prefilterStringNonText {
				nonText[info.cacheIndex] = true
			}
		}
	}
	if !hasAnchor {
		return nil, nil
	}

	counts := make(map[compactPatternKey]int)
	selected := make(map[compactPatternKey]bool)
	for i, entry := range cp.SharedLookup {
		info := cp.SharedAutomaton.strings[i]
		key := compactPatternKey{string(info.Data), info.Flags}
		counts[key]++
		anchor := anchors[entry.RuleIndex]
		if entry.Kind == StringKindText {
			if anchor == "" || cp.Rules[entry.RuleIndex].IndexToStringID[entry.StringIdx] == anchor {
				selected[key] = true
			}
		} else if nonText[entry.CacheIndex] {
			selected[key] = true
		}
	}
	useful := false
	for key, count := range counts {
		if count > 1 && !selected[key] {
			useful = true
		}
	}
	if !useful {
		return nil, nil
	}
	var sensitive, folded bool
	for key := range selected {
		if key.flags&regex.FlagsNoCase != 0 {
			folded = true
		} else {
			sensitive = true
		}
	}
	// Rebuilding mixed-case tries can split existing case-folded transitions.
	if sensitive && folded {
		return nil, nil
	}
	gate := NewACAutomaton()
	for _, info := range cp.SharedAutomaton.strings {
		key := compactPatternKey{string(info.Data), info.Flags}
		if !selected[key] {
			continue
		}
		if len(info.Data) == 0 {
			return nil, nil
		}
		delete(selected, key)
		if err := gate.AddStringWithFlags(strconv.Itoa(len(gate.strings)), info.Data, false, false, info.Flags); err != nil {
			return nil, err
		}
	}
	if err := gate.Compile(); err != nil {
		return nil, err
	}
	return gate, nil
}

func (s *Scanner) compactPrefilterRejects(ctx context.Context, data []byte) bool {
	gate := s.program.compactPrefilter
	// Large positive records would pay for two full passes.
	if gate == nil || s.prefilterDisabled || len(data) > 1024 {
		return false
	}
	if done := ctx.Done(); done != nil {
		for range gate.searchIterWithCancel(data, done) {
			return false
		}
	} else {
		for range gate.SearchIter(data) {
			return false
		}
	}
	return true
}
