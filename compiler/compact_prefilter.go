package compiler

import (
	"context"

	"github.com/cawalch/go-yara/regex"
)

type compactPatternKey struct {
	data  string
	flags regex.Flags
}

type compactPrefilter struct {
	automaton *ACAutomaton
	accepting []bool
}

// The compact pass needs only a necessary pattern cover, not match spans.
func (cp *CompiledProgram) buildCompactPrefilter() *compactPrefilter {
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
			return nil
		}
		for _, info := range rule.prefilterStrings {
			if info.class == prefilterStringNonText {
				nonText[info.cacheIndex] = true
			}
		}
	}
	if !hasAnchor {
		return nil
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
	if !useful || len(selected) == 0 {
		return nil
	}
	ac := cp.SharedAutomaton
	patterns := make([]bool, len(ac.strings))
	for i, info := range ac.strings {
		if selected[compactPatternKey{string(info.Data), info.Flags}] {
			if len(info.Data) == 0 {
				return nil
			}
			patterns[i] = true
		}
	}
	gate := &compactPrefilter{automaton: ac, accepting: make([]bool, len(ac.states))}
	for i := range ac.states {
		state := &ac.states[i]
		for _, pattern := range ac.outputs[state.outputStart:state.outputEnd] {
			if patterns[pattern] {
				gate.accepting[i] = true
				break
			}
		}
	}
	return gate
}

//nolint:nestif // the sparse-root and general loops are intentionally separate hot paths
func (s *Scanner) compactPrefilterRejects(ctx context.Context, data []byte) bool {
	gate := s.program.compactPrefilter
	// Large positive records would pay for two full passes.
	if gate == nil || s.prefilterDisabled || len(data) > 1024 || s.program.SharedAutomaton != gate.automaton {
		return false
	}
	if ctx.Err() != nil {
		return true
	}
	ac, state := gate.automaton, int32(0)
	if len(data) >= 256 && len(ac.rootBytes) > 0 && len(ac.rootBytes) <= maxSparseRootTransitions {
		cursor := newRootCandidateCursor(ac.rootBytes)
		for i := 0; i < len(data); i++ {
			if state == 0 && len(data)-i >= 256 {
				i = cursor.next(data, i)
				if i < 0 {
					return true
				}
			}
			state = ac.states[state].transitions[data[i]]
			if gate.accepting[state] {
				return false
			}
		}
		return true
	}
	rootTransitions := &ac.states[0].transitions
	for _, b := range data {
		if state == 0 {
			state = rootTransitions[b]
			if state == 0 {
				continue
			}
		} else {
			state = ac.states[state].transitions[b]
		}
		if gate.accepting[state] {
			return false
		}
	}
	return true
}
