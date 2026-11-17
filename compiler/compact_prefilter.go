package compiler

import (
	"context"

	"github.com/cawalch/go-yara/regex"
)

const minCompactFanout = 8

type compactPatternKey struct {
	data  string
	flags regex.Flags
}

type compactPrefilter struct {
	automaton    *acAutomaton
	accepting    []bool
	fanoutUseful bool
}

// The compact pass needs only a necessary pattern cover, not match spans.
func (cp *CompiledProgram) buildCompactPrefilter() *compactPrefilter {
	frequencies := make(map[string]int, len(cp.Rules)*2)
	for _, rule := range cp.Rules {
		for _, data := range rule.TextPatterns {
			frequencies[string(data)]++
		}
	}
	anchors := make([]string, len(cp.Rules))
	nonText := make([]bool, cp.nonTextCacheSize)
	hasAnchor := false
	for i, rule := range cp.Rules {
		best := len(cp.sharedLookup) + 1
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
			if info.class == prefilterStringNonText && info.cacheIndex >= 0 && info.cacheIndex < len(nonText) {
				nonText[info.cacheIndex] = true
			}
		}
	}
	if !hasAnchor && len(cp.Rules) < minSharedNonTextEntries {
		return nil
	}

	counts := make(map[compactPatternKey]int, len(cp.sharedLookup))
	selected := make(map[compactPatternKey]bool, len(cp.sharedLookup))
	for i, entry := range cp.sharedLookup {
		info := cp.sharedAutomaton.strings[i]
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
	fanoutUseful := false
	for key, count := range counts {
		// The extra pass needs enough avoided fanout to amortize its cost.
		if count >= minCompactFanout && !selected[key] {
			fanoutUseful = true
		}
	}
	useful := fanoutUseful
	if !useful && len(cp.Rules) >= minSharedNonTextEntries && len(selected) > 0 {
		useful = true
	}
	if !useful || len(selected) == 0 {
		return nil
	}
	ac := cp.sharedAutomaton
	patterns := make([]bool, len(ac.strings))
	for i, info := range ac.strings {
		if selected[compactPatternKey{string(info.Data), info.Flags}] {
			if len(info.Data) == 0 {
				return nil
			}
			patterns[i] = true
		}
	}
	gate := &compactPrefilter{
		automaton:    ac,
		accepting:    make([]bool, len(ac.states)),
		fanoutUseful: fanoutUseful,
	}
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

func (s *Scanner) compactPrefilterFanoutRejects(ctx context.Context, data []byte) bool {
	gate := s.program.compactPrefilter
	// Non-fanout gates only amortize preparePatternScan setup on short (<256B)
	// inputs with 16-bit tables; >=256B inputs go straight to sharedAutomaton
	// where Teddy SIMD and single-pass candidate routing apply.
	if gate == nil || (!gate.fanoutUseful && (len(data) >= 256 || len(gate.automaton.transitions16) == 0)) {
		return false
	}
	return s.compactPrefilterRejects(ctx, data)
}

func (s *Scanner) compactPrefilterRejects(ctx context.Context, data []byte) bool {
	gate := s.program.compactPrefilter
	// Large positive records would pay for two full passes.
	if gate == nil || s.prefilterDisabled || len(data) > 1024 || s.program.sharedAutomaton != gate.automaton {
		return false
	}
	if s.hookMask&(hookBitPrefilter|hookBitTelemetryLatency) != 0 {
		return s.compactPrefilterRejectsWithHooks(ctx, data, gate)
	}
	if scanCanceled(ctx.Done()) {
		return true
	}
	return compactPrefilterMatchesAbsent(data, gate)
}

func (s *Scanner) compactPrefilterRejectsWithHooks(ctx context.Context, data []byte, gate *compactPrefilter) (rejected bool) {
	if s.hookMask&hookBitPrefilter != 0 {
		started := s.prefilterStart()
		defer func() {
			if ctx.Err() == nil {
				s.finishPrefilter(PrefilterDecision{Stage: PrefilterStageCompactMask, Rejected: rejected}, started)
			}
		}()
	}
	if s.hookMask&hookBitTelemetryLatency != 0 {
		previous := s.enterScanPhase(PhasePrefilter)
		defer s.leaveScanPhase(previous)
	}
	if scanCanceled(ctx.Done()) {
		return true
	}
	return compactPrefilterMatchesAbsent(data, gate)
}

func compactPrefilterMatchesAbsent(data []byte, gate *compactPrefilter) bool {
	ac := gate.automaton
	if teddySIMDEnabled && ac.teddyGate != nil && len(data) >= 256 && !ac.teddyGate.mayMatch(data, nil) {
		return true
	}
	if len(ac.transitions16) > 0 {
		if len(data) < 256 {
			return compactPrefilterRejectsShort16(data, ac.transitions16, gate.accepting)
		}
		return compactPrefilterRejectsTable(data, gate, ac.transitions16)
	}
	if len(ac.transitions32) > 0 {
		return compactPrefilterRejectsTable(data, gate, ac.transitions32)
	}

	state := int32(0)
	rootTransitions := &ac.states[0].transitions
	for _, b := range data {
		if state == 0 {
			state = rootTransitions[b]
			if state == 0 {
				continue
			}
		} else {
			state = ac.findNextState(state, b)
		}
		if gate.accepting[state] {
			return false
		}
	}
	return true
}

// Keep the short-input kernel separate from the mixed-width dispatcher.
// Inlining made AMD64 reject throughput sensitive to unrelated binary layout
// changes; a standalone kernel preserves the tight root-miss loop.
//
//go:noinline
func compactPrefilterRejectsShort16(data []byte, trans [][256]uint16, accepting []bool) bool {
	rootTransitions := &trans[0]
	var state uint16
	for _, b := range data {
		if state == 0 {
			state = rootTransitions[b]
			if state == 0 {
				continue
			}
		} else {
			state = trans[state][b]
		}
		if accepting[state] {
			return false
		}
	}
	return true
}

//nolint:nestif // the sparse-root and general loops are intentionally separate hot paths
func compactPrefilterRejectsTable[S ~uint16 | ~int32](data []byte, gate *compactPrefilter, trans [][256]S) bool {
	ac := gate.automaton
	accepting := gate.accepting
	rootTransitions := &trans[0]
	var state S

	if len(data) > 256 && len(ac.rootLanes) > 0 && len(ac.rootLanes) <= maxSparseRootTransitions {
		cursor := newRootCandidateCursor(ac.rootLanes)
		for i := 0; i < len(data); i++ {
			if state == 0 && len(data)-i >= 256 {
				i = cursor.next(data, i)
				if i < 0 {
					return true
				}
			}
			if state == 0 {
				state = rootTransitions[data[i]]
				if state == 0 {
					continue
				}
			} else {
				state = trans[state][data[i]]
			}
			if accepting[state] {
				return false
			}
		}
		return true
	}
	for _, b := range data {
		if state == 0 {
			state = rootTransitions[b]
			if state == 0 {
				continue
			}
		} else {
			state = trans[state][b]
		}
		if accepting[state] {
			return false
		}
	}
	return true
}
