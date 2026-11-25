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
		counts[key] += 1 + len(entry.fanout)
		anchor := anchors[entry.RuleIndex]
		if entry.Kind == StringKindText {
			if anchor == "" || cp.Rules[entry.RuleIndex].IndexToStringID[entry.StringIdx] == anchor {
				selected[key] = true
			}
		} else if compactEntryUsesNonTextCache(entry, nonText) {
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
		accepting:    make([]bool, len(ac.outputRanges)),
		fanoutUseful: fanoutUseful,
	}
	for i := range ac.outputRanges {
		outputRange := ac.outputRanges[i]
		for _, pattern := range ac.outputs[outputRange[0]:outputRange[1]] {
			if patterns[pattern] {
				gate.accepting[i] = true
				break
			}
		}
	}
	return gate
}

func compactEntryUsesNonTextCache(entry sharedAutomatonEntry, nonText []bool) bool {
	if nonText[entry.CacheIndex] {
		return true
	}
	for _, extra := range entry.fanout {
		if nonText[extra.CacheIndex] {
			return true
		}
	}
	return false
}

func (s *Scanner) compactPrefilterFanoutRejects(ctx context.Context, data []byte) bool {
	rejected, _ := s.checkCompactPrefilterFanout(ctx, data, true)
	return rejected
}

func (s *Scanner) checkCompactPrefilterFanout(ctx context.Context, data []byte, checkCancellation bool) (bool, <-chan struct{}) {
	gate := s.program.compactPrefilter
	if gate == nil {
		return false, nil
	}
	// Non-fanout gates only amortize preparePatternScan setup on short (<256B)
	// inputs with 16-bit tables; >=256B inputs go straight to sharedAutomaton
	// where Teddy SIMD and single-pass candidate routing apply.
	has16 := len(gate.automaton.transitions16) > 0 || len(gate.automaton.flatClass16) > 0
	if !gate.fanoutUseful && (len(data) >= 256 || !has16) {
		// Test the same whole-corpus cover used by shared search before
		// allocating or resetting its candidate state. Positive inputs go
		// straight to exact matching without repeating the SIMD test.
		if teddySIMDEnabled && gate.automaton.teddyGate != nil && len(data) >= 256 && len(data) <= 512 &&
			!s.prefilterDisabled && s.program.sharedAutomaton == gate.automaton &&
			s.hookMask&(hookBitPrefilter|hookBitTelemetryLatency) == 0 {
			done := compactPrefilterCancellation(ctx, checkCancellation)
			if !gate.automaton.teddyGate.mayMatch(data, done) || scanCanceled(done) {
				return true, done
			}
			s.skipSharedTeddyGate = true
		}
		return false, nil
	}
	return s.checkCompactPrefilter(ctx, data, gate, checkCancellation)
}

func (s *Scanner) compactPrefilterRejects(ctx context.Context, data []byte) bool {
	rejected, _ := s.checkCompactPrefilter(ctx, data, s.program.compactPrefilter, true)
	return rejected
}

func compactPrefilterCancellation(ctx context.Context, checkCancellation bool) <-chan struct{} {
	if checkCancellation {
		return ctx.Done()
	}
	return nil
}

//nolint:revive // keep the prepared gate and cancellation policy explicit
func (s *Scanner) checkCompactPrefilter(ctx context.Context, data []byte, gate *compactPrefilter, checkCancellation bool) (bool, <-chan struct{}) {
	s.skipSharedTeddyGate = false
	// Large positive records would pay for two full passes.
	if gate == nil || s.prefilterDisabled || len(data) > 1024 || s.program.sharedAutomaton != gate.automaton {
		return false, nil
	}
	done := compactPrefilterCancellation(ctx, checkCancellation)
	var rejected bool
	if s.hookMask&(hookBitPrefilter|hookBitTelemetryLatency) != 0 {
		rejected = s.compactPrefilterRejectsWithHooks(ctx, data, gate, done)
	} else {
		if scanCanceled(done) {
			return true, done
		}
		rejected = compactPrefilterMatchesAbsent(data, gate)
	}
	if !rejected && teddySIMDEnabled && gate.automaton.teddyGate != nil && len(data) >= 256 {
		s.skipSharedTeddyGate = true
	}
	return rejected, done
}

//nolint:revive // reuse the cancellation channel already obtained by the prefilter
func (s *Scanner) compactPrefilterRejectsWithHooks(ctx context.Context, data []byte, gate *compactPrefilter, done <-chan struct{}) (rejected bool) {
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
	if scanCanceled(done) {
		return true
	}
	return compactPrefilterMatchesAbsent(data, gate)
}

func compactPrefilterMatchesAbsent(data []byte, gate *compactPrefilter) bool {
	ac := gate.automaton
	if teddySIMDEnabled && ac.teddyGate != nil && len(data) >= 256 && len(data) <= 512 && !ac.teddyGate.mayMatch(data, nil) {
		return true
	}
	if len(ac.transitions16) > 0 {
		if len(data) < 256 {
			return compactPrefilterRejectsShort16(data, ac.transitions16, gate.accepting)
		}
		return compactPrefilterRejectsTable(data, gate, ac.transitions16)
	}
	if len(ac.flatClass16) > 0 {
		if len(data) < 256 {
			return compactPrefilterRejectsShortClass16(data, ac, gate.accepting)
		}
		return compactPrefilterRejectsClassTable(data, gate, ac.classRoot16, ac.flatClass16)
	}
	if len(ac.flatClass32) > 0 {
		return compactPrefilterRejectsClassTable(data, gate, ac.classRoot32, ac.flatClass32)
	}
	if len(ac.transitions32) > 0 {
		return compactPrefilterRejectsTable(data, gate, ac.transitions32)
	}
	return false
}

//go:noinline
func compactPrefilterRejectsShortClass16(data []byte, ac *acAutomaton, accepting []bool) bool {
	rootTransitions := ac.classRoot16
	var state uint32
	for i := 0; i < len(data); i++ {
		if state == 0 {
			for {
				state = uint32(rootTransitions[data[i]])
				if state != 0 {
					break
				}
				i++
				if i == len(data) {
					return true
				}
			}
		} else {
			state = uint32(ac.flatClass16[(int(state)<<ac.classShift)+int(ac.classMap[data[i]])])
		}
		if accepting[state] {
			return false
		}
	}
	return true
}

//nolint:nestif,revive // mirrors compactPrefilterRejectsTable for byte-class compressed tables
func compactPrefilterRejectsClassTable[S ~uint16 | ~int32](data []byte, gate *compactPrefilter, rootTransitions *[256]S, flat []S) bool {
	ac := gate.automaton
	accepting := gate.accepting
	classMap := &ac.classMap
	shift := ac.classShift
	var state S

	if !accepting[0] && ac.teddy != nil && len(data) >= 256 {
		tailBytes := ac.teddy.tailBytes()
		linearUntil := 0
		for i := 0; i < len(data); i++ {
			if state == 0 && i >= linearUntil && len(data)-i > tailBytes {
				candidate := ac.teddy.findCandidate(data, i)
				if candidate < 0 {
					i = max(i, len(data)-tailBytes)
					if i >= len(data) {
						return true
					}
				} else {
					if candidate-i < 64 {
						linearUntil = candidate + 256
					}
					i = candidate
				}
			}
			if state == 0 {
				state = rootTransitions[data[i]]
				if state == 0 {
					continue
				}
			} else {
				state = flat[(int(state)<<shift)+int(classMap[data[i]])]
			}
			if accepting[state] {
				return false
			}
		}
		return true
	}

	if len(data) > 256 && len(ac.rootLanes) > 0 && len(ac.rootLanes) <= maxSparseRootTransitions {
		rootCursor := newRootCandidateCursor(ac.rootLanes)
		linearUntil := 0
		for i := 0; i < len(data); i++ {
			if state == 0 && i >= linearUntil && len(data)-i >= 256 {
				candidate := rootCursor.next(data, i)
				if candidate < 0 {
					return true
				}
				if candidate-i < 64 {
					linearUntil = candidate + 256
				}
				i = candidate
			}
			if state == 0 {
				state = rootTransitions[data[i]]
				if state == 0 {
					continue
				}
			} else {
				state = flat[(int(state)<<shift)+int(classMap[data[i]])]
			}
			if accepting[state] {
				return false
			}
		}
		return true
	}

	for i := 0; i < len(data); i++ {
		if state == 0 {
			for {
				state = rootTransitions[data[i]]
				if state != 0 {
					break
				}
				i++
				if i == len(data) {
					return true
				}
			}
		} else {
			state = flat[(int(state)<<shift)+int(classMap[data[i]])]
		}
		if accepting[state] {
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
	// Keep state arithmetic in a full register; the transition table stays 16-bit.
	var state uint32
	for i := 0; i < len(data); i++ {
		if state == 0 {
			// Consecutive root misses need neither a state branch nor an
			// accepting-state lookup for each byte.
			for {
				state = uint32(rootTransitions[data[i]])
				if state != 0 {
					break
				}
				i++
				if i == len(data) {
					return true
				}
			}
		} else {
			state = uint32(trans[state][data[i]])
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

	if !accepting[0] && ac.teddy != nil && len(data) >= 256 {
		tailBytes := ac.teddy.tailBytes()
		linearUntil := 0
		for i := 0; i < len(data); i++ {
			if state == 0 && i >= linearUntil && len(data)-i > tailBytes {
				candidate := ac.teddy.findCandidate(data, i)
				if candidate < 0 {
					i = max(i, len(data)-tailBytes)
					if i >= len(data) {
						return true
					}
				} else {
					if candidate-i < 64 {
						linearUntil = candidate + 256
					}
					i = candidate
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
