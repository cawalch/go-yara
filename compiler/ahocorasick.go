package compiler

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"sync"

	"github.com/cawalch/go-yara/regex"
)

// acState represents a state in the Aho-Corasick automaton
// Using struct-of-arrays layout for better cache locality
type acState struct {
	// Transition table (256 possible byte values)
	transitions [256]int32 // -1 means no transition, >=0 is state index
	// Failure link
	failure int32
	// Output information
	outputStart int32
	outputEnd   int32
}

// acAutomaton represents the high-performance Aho-Corasick automaton
type acAutomaton struct {
	// States with cache-friendly layout
	states []acState

	// Output storage (flattened)
	outputs []int32

	// String information
	strings []acStringInfo

	// Explicit bytes reachable from the root before failure links are built.
	// Small sets can use SIMD-optimized byte search to skip root misses.
	rootBytes []byte
	rootLanes []rootLane
	teddy     teddyPrefilter
	teddyGate *corpusTeddyPrefilter

	// Flattened transition table. If len(states) <= 65536, transitions16 is populated
	// and transitions32 is nil. If len(states) > 65536, transitions32 is populated.
	transitions16 [][256]uint16
	transitions32 [][256]int32

	// hasOutput indicates whether a state has any outputs. 1 byte per state.
	hasOutput []bool

	// Compilation state
	compiledOnce  sync.Once
	compiled      bool
	compactStates bool

	// Exported metadata retained for compatibility with existing callers.
	StringCount int
	Strings     []acStringInfo
}

// newacAutomaton creates a new Aho-Corasick automaton with compact initial capacity.
func newacAutomaton() *acAutomaton {
	return newacAutomatonWithCapacity(1, 8, 16)
}

// newacAutomatonWithCapacity creates a new Aho-Corasick automaton with pre-allocated capacities.
func newacAutomatonWithCapacity(stateCap, stringCap, outputCap int) *acAutomaton {
	if stateCap < 1 {
		stateCap = 1
	}
	states := make([]acState, 1, stateCap)
	for i := range states[0].transitions {
		states[0].transitions[i] = -1 // No transitions initially
	}
	states[0].failure = -1 // Root has no failure
	states[0].outputStart = 0
	states[0].outputEnd = 0

	if outputCap < 16 {
		outputCap = 16
	}
	if stringCap < 8 {
		stringCap = 8
	}

	return &acAutomaton{
		states:      states,
		outputs:     make([]int32, 0, outputCap),
		strings:     make([]acStringInfo, 0, stringCap),
		compiled:    false,
		StringCount: 0,
		Strings:     make([]acStringInfo, 0, stringCap),
	}
}

// AddString adds a string pattern to the automaton
//
//nolint:revive // argument-limit: API surface
func (ac *acAutomaton) AddString(identifier string, data []byte, isHex, isRegex bool) error {
	config := stringConfig{
		Identifier: identifier,
		Data:       data,
		IsHex:      isHex,
		IsRegex:    isRegex,
		Flags:      0, // Default flags
	}
	return ac.addStringToAutomaton(config)
}

// addStringToAutomaton implements the core string addition logic
func (ac *acAutomaton) addStringToAutomaton(config stringConfig) error {
	if ac.compiled {
		return errors.New("cannot add strings to compiled automaton")
	}

	// Keep private and compatibility metadata in disjoint slices while using a
	// single allocation. Restrict each slice's capacity so an append cannot
	// cross into the other copy.
	patternLength := len(config.Data)
	patternCopies := make([]byte, patternLength*2)
	copy(patternCopies[:patternLength], config.Data)
	copy(patternCopies[patternLength:], config.Data)
	stringInfo := acStringInfo{
		Identifier: config.Identifier,
		Length:     patternLength,
		IsHex:      config.IsHex,
		IsRegex:    config.IsRegex,
		Data:       patternCopies[:patternLength:patternLength],
		Flags:      config.Flags,
	}
	compatibilityInfo := stringInfo
	compatibilityInfo.Data = patternCopies[patternLength : patternLength*2 : patternLength*2]

	// Add string to collection
	ac.strings = append(ac.strings, stringInfo)
	ac.StringCount = len(ac.strings)
	ac.Strings = append(ac.Strings, compatibilityInfo)
	stringIndex := mustACIndex(len(ac.strings) - 1)

	// Build trie for pattern matching
	currentState := int32(0) // Start at root
	noCase := config.Flags&regex.FlagsNoCase != 0

	for _, b := range config.Data {
		// For nocase strings the pattern is already lowercased; register both
		// ASCII cases of each alphabetic byte so the shared automaton fires on
		// any case. Case-sensitive strings keep a single transition. Because
		// trie states are shared, a case-sensitive string can end up reachable
		// via a nocase string's dual transitions; PopulateMatchContext re-verifies
		// the matched bytes (case-sensitively for case-sensitive strings) to
		// reject those false candidates.
		var variants [2]byte
		n := 1
		variants[0] = b
		if noCase {
			if flipped := flipASCIICase(b); flipped != b {
				variants[1] = flipped
				n = 2
			}
		}

		// Reuse an existing transition across any variant if present.
		nextState := int32(-1)
		for k := 0; k < n; k++ {
			if t := ac.states[currentState].transitions[variants[k]]; t != -1 {
				nextState = t
				break
			}
		}
		if nextState == -1 {
			// Create new state
			newState := acState{
				transitions: [256]int32{},
				failure:     -1,
				outputStart: 0,
				outputEnd:   0,
			}
			for i := range newState.transitions {
				newState.transitions[i] = -1
			}
			// Dense rows exceed 1 KiB each. Above 32 MiB, double capacity
			// to avoid repeated copies at the slice runtime's smaller growth
			// factor. Compile releases the unused capacity.
			if len(ac.states) == cap(ac.states) && len(ac.states) >= 32768 {
				states := make([]acState, len(ac.states), len(ac.states)*2)
				copy(states, ac.states)
				ac.states = states
				ac.compactStates = true
			}
			ac.states = append(ac.states, newState)
			nextState = mustACIndex(len(ac.states) - 1)
		}
		// Point every variant at the resolved state (skip those already bound).
		for k := 0; k < n; k++ {
			if ac.states[currentState].transitions[variants[k]] == -1 {
				ac.states[currentState].transitions[variants[k]] = nextState
			}
		}
		currentState = nextState
	}

	// Add output for the final state. Multiple patterns can share the same
	// terminal state (for example, identical strings in different rules).
	// Preserve the existing range by copying it to a new contiguous range.
	existingStart := ac.states[currentState].outputStart
	existingEnd := ac.states[currentState].outputEnd
	switch {
	case existingStart == existingEnd:
		ac.states[currentState].outputStart = mustACIndex(len(ac.outputs))
	case int(existingEnd) != len(ac.outputs):
		ac.states[currentState].outputStart = mustACIndex(len(ac.outputs))
		ac.outputs = append(ac.outputs, ac.outputs[existingStart:existingEnd]...)
	}
	ac.outputs = append(ac.outputs, stringIndex)
	ac.states[currentState].outputEnd = mustACIndex(len(ac.outputs))

	return nil
}

// Compile compiles the optimized automaton
func (ac *acAutomaton) Compile() error {
	var compileErr error

	ac.compiledOnce.Do(func() {
		if ac.compiled {
			compileErr = errors.New("already compiled")
			return
		}
		// Compact doubled construction buffers before allocating the flat scan
		// table. Keep small buffers reusable without another allocation.
		if ac.compactStates && cap(ac.states) > len(ac.states) {
			states := make([]acState, len(ac.states))
			copy(states, ac.states)
			ac.states = states
		}
		ac.compactStates = false
		ac.collectRootBytes()

		// Build failure links using BFS
		if err := ac.buildFailureLinks(); err != nil {
			compileErr = fmt.Errorf("building failure links: %w", err)
			return
		}
		// Fold the failure links into the goto table so the scan never walks them.
		ac.closeTransitions()
		ac.buildFlatTransitions()
		filter := newTeddyPrefilter(ac.strings)
		if gate, ok := filter.(*corpusTeddyPrefilter); ok {
			ac.teddyGate = gate
		} else {
			ac.teddy = filter
		}
		ac.compiled = true
	})

	return compileErr
}

func (ac *acAutomaton) collectRootBytes() {
	ac.rootBytes = ac.rootBytes[:0]
	ac.rootLanes = ac.rootLanes[:0]
	for byteVal, nextState := range ac.states[0].transitions {
		if nextState != -1 {
			ac.rootBytes = append(ac.rootBytes, byte(byteVal))
		}
	}
	var visited [256]bool
	for _, b := range ac.rootBytes {
		if visited[b] {
			continue
		}
		visited[b] = true
		other := flipASCIICase(b)
		if other != b && ac.states[0].transitions[other] != -1 {
			visited[other] = true
			ac.rootLanes = append(ac.rootLanes, rootLane{value: toLowerTable[b], isFold: true})
		} else {
			ac.rootLanes = append(ac.rootLanes, rootLane{value: b, isFold: false})
		}
	}
}

func (ac *acAutomaton) failureState(current int32, byteVal byte) int32 {
	failure := ac.states[current].failure
	for failure != -1 && ac.states[failure].transitions[byteVal] == -1 {
		failure = ac.states[failure].failure
	}
	if failure != -1 {
		return ac.states[failure].transitions[byteVal]
	}
	return 0
}

// mergeFailureOutput merges output from the failure state to the current state.
func (ac *acAutomaton) mergeFailureOutput(state int32) {
	failState := ac.states[ac.states[state].failure]
	if failState.outputStart != failState.outputEnd {
		// Copy both ranges into a new contiguous range. Output ranges for other
		// states may have been appended between this state's original range and
		// the current end of the flat output storage.
		stateOutput := slices.Clone(ac.outputs[ac.states[state].outputStart:ac.states[state].outputEnd])
		failOutput := ac.outputs[failState.outputStart:failState.outputEnd]
		ac.states[state].outputStart = mustACIndex(len(ac.outputs))
		ac.outputs = append(ac.outputs, stateOutput...)
		ac.outputs = append(ac.outputs, failOutput...)
		ac.states[state].outputEnd = mustACIndex(len(ac.outputs))
	}
}

func mustACIndex(value int) int32 {
	if value < 0 || value > math.MaxInt32 {
		panic("Aho-Corasick index exceeds int32 capacity")
	}
	return int32(value)
}

// buildFailureLinks builds failure links for the optimized automaton
func (ac *acAutomaton) buildFailureLinks() error {
	if len(ac.states) == 0 {
		return errors.New("no states in automaton")
	}

	queue := make([]int32, 0, len(ac.states))
	seen := make([]bool, len(ac.states))
	seen[0] = true
	for _, nextState := range &ac.states[0].transitions {
		if nextState != -1 && !seen[nextState] {
			seen[nextState] = true
			ac.states[nextState].failure = 0
			queue = append(queue, nextState)
		}
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		ac.mergeFailureOutput(current)
		for byteVal, nextState := range ac.states[current].transitions {
			if nextState == -1 {
				continue
			}
			ac.states[nextState].failure = ac.failureState(current, byte(byteVal))
			if !seen[nextState] {
				seen[nextState] = true
				queue = append(queue, nextState)
			}
		}
	}

	return nil
}

// findNextState returns the next state for b. closeTransitions has already
// folded every failure-link hop into the goto table, so this is one load with no
// loop and no branch.
func (ac *acAutomaton) findNextState(currentState int32, b byte) int32 {
	if len(ac.transitions16) > 0 {
		return int32(ac.transitions16[currentState][b])
	}
	if len(ac.transitions32) > 0 {
		return ac.transitions32[currentState][b]
	}
	return ac.states[currentState].transitions[b]
}

// closeTransitions converts the goto table from the sparse Aho-Corasick form,
// where a missing edge is -1 and the scan follows failure links at run time, to
// the full deterministic form, where every (state, byte) pair has an explicit
// target.
//
// The scan is the whole cost on large inputs — on a 16KB event it was 99% of
// Matches(), split between the SearchIter loop and findNextState's failure
// walk — so paying once at compile time to make the per-byte step a single
// indexed load is a large win. This costs no extra memory: acState.transitions
// is already a dense [256]int32.
//
// Must run after buildFailureLinks, and after collectRootBytes, which
// distinguishes real root edges by their -1 absence.
func (ac *acAutomaton) closeTransitions() {
	// Breadth-first from the root so a state's failure target, which is always
	// strictly shallower, is closed before the state itself.
	//
	// The seen guard is required, not defensive: case-insensitive strings point
	// several byte values at the same next state, so a state is reachable more
	// than once and an unguarded walk re-enqueues it without bound.
	queue := make([]int32, 0, len(ac.states))
	seen := make([]bool, len(ac.states))
	seen[0] = true
	for b := range ac.states[0].transitions {
		next := ac.states[0].transitions[b]
		if next == -1 {
			// A miss at the root restarts the scan at the root.
			ac.states[0].transitions[b] = 0
			continue
		}
		if !seen[next] {
			seen[next] = true
			queue = append(queue, next)
		}
	}
	for head := 0; head < len(queue); head++ {
		state := queue[head]
		failure := ac.states[state].failure
		if failure < 0 {
			failure = 0
		}
		for b := range ac.states[state].transitions {
			next := ac.states[state].transitions[b]
			if next == -1 {
				ac.states[state].transitions[b] = ac.states[failure].transitions[b]
				continue
			}
			if !seen[next] {
				seen[next] = true
				queue = append(queue, next)
			}
		}
	}
}

func (ac *acAutomaton) buildFlatTransitions() {
	numStates := len(ac.states)
	if numStates == 0 {
		return
	}
	ac.hasOutput = make([]bool, numStates)
	for i := range ac.states {
		if ac.states[i].outputStart != ac.states[i].outputEnd {
			ac.hasOutput[i] = true
		}
	}

	if numStates <= 65536 {
		flat := make([][256]uint16, numStates)
		for s := range ac.states {
			transitions := &ac.states[s].transitions
			row := &flat[s]
			for b := range 256 {
				row[b] = uint16(transitions[b]) //checkednarrow:ignore guarded by numStates <= 65536
			}
		}
		ac.transitions16 = flat
	} else {
		flat := make([][256]int32, numStates)
		for s := range ac.states {
			flat[s] = ac.states[s].transitions
		}
		ac.transitions32 = flat
	}
}

// AddStringWithFlags adds a string and records regex VM flags alongside metadata
//
//nolint:revive // argument-limit: API surface
func (ac *acAutomaton) AddStringWithFlags(
	identifier string,
	data []byte,
	isHex, isRegex bool,
	flags regex.Flags,
) error {
	config := stringConfig{
		Identifier: identifier,
		Data:       data,
		IsHex:      isHex,
		IsRegex:    isRegex,
		Flags:      flags,
	}
	return ac.addStringToAutomaton(config)
}

// ReserveStrings ensures capacity for at least n string infos to avoid slice growth
func (ac *acAutomaton) ReserveStrings(n int) {
	if n > 0 && cap(ac.strings) < n {
		ac.strings = slices.Grow(ac.strings, n-len(ac.strings))
	}
	if n > 0 && cap(ac.Strings) < n {
		ac.Strings = slices.Grow(ac.Strings, n-len(ac.Strings))
	}
}

// ReserveStates ensures capacity for at least n states to avoid slice growth
func (ac *acAutomaton) ReserveStates(n int) {
	if n > 0 && cap(ac.states) < n {
		ac.states = slices.Grow(ac.states, n-len(ac.states))
	}
}

// BuildFailureLinks builds the failure links for the automaton
func (ac *acAutomaton) BuildFailureLinks() error {
	return ac.buildFailureLinks()
}

// Validate checks if the automaton is correctly constructed
func (ac *acAutomaton) Validate() error {
	if len(ac.states) == 0 {
		return errors.New("automaton has no states")
	}

	if len(ac.states) > 0 && len(ac.strings) == 0 && ac.compiled {
		return errors.New("inconsistent automaton state")
	}

	return nil
}

// Clone creates a copy of the automaton
func (ac *acAutomaton) Clone() *acAutomaton {
	internalStrings := cloneacStringInfos(ac.strings)
	newAC := &acAutomaton{
		states:        slices.Clone(ac.states),
		outputs:       slices.Clone(ac.outputs),
		strings:       internalStrings,
		rootBytes:     slices.Clone(ac.rootBytes),
		rootLanes:     slices.Clone(ac.rootLanes),
		teddy:         ac.teddy,
		teddyGate:     ac.teddyGate,
		transitions16: slices.Clone(ac.transitions16),
		transitions32: slices.Clone(ac.transitions32),
		hasOutput:     slices.Clone(ac.hasOutput),
		compiled:      ac.compiled,
		StringCount:   len(internalStrings),
		Strings:       cloneacStringInfos(internalStrings),
	}
	if ac.compiled {
		newAC.compiledOnce.Do(func() {})
	}

	return newAC
}

func cloneacStringInfos(in []acStringInfo) []acStringInfo {
	out := slices.Clone(in)
	for index := range out {
		out[index].Data = slices.Clone(out[index].Data)
	}
	return out
}

// acMatch represents a pattern match found by the automaton
type acMatch struct {
	StringIndex int    // Index of the matched string
	StringID    string // Identifier of the matched string
	Backtrack   int    // Backtrack distance
}

// acStringInfo contains information about a registered string pattern
type acStringInfo struct {
	Data       []byte
	Identifier string
	Length     int
	Flags      regex.Flags
	IsHex      bool
	IsRegex    bool
}

type stringConfig struct {
	Identifier string
	Data       []byte
	IsHex      bool
	IsRegex    bool
	Flags      regex.Flags
}

// GetStateCount returns the number of states in the automaton
func (ac *acAutomaton) GetStateCount() int {
	return len(ac.states)
}

// GetStringCount returns the number of strings in the automaton
func (ac *acAutomaton) GetStringCount() int {
	return len(ac.strings)
}

// GetStrings returns an owned snapshot of all string information.
func (ac *acAutomaton) GetStrings() []acStringInfo {
	return cloneacStringInfos(ac.strings)
}

// GetPatternData returns owned pattern data keyed by string identifier.
func (ac *acAutomaton) GetPatternData() map[string][]byte {
	// Pre-allocate map with known capacity for better performance
	result := make(map[string][]byte, len(ac.strings))
	for _, strInfo := range ac.strings {
		result[strInfo.Identifier] = slices.Clone(strInfo.Data)
	}
	return result
}

// EstimateMemoryUsage returns a deterministic heuristic byte estimate for the automaton.
// It is intended for relative sizing and diagnostics, not exact Go heap accounting.
func (ac *acAutomaton) EstimateMemoryUsage() int {
	stateMemory := len(ac.states) * (256*4 + 8) // transitions + failure + output indices
	if len(ac.transitions16) > 0 {
		stateMemory += len(ac.transitions16) * 256 * 2
	} else if len(ac.transitions32) > 0 {
		stateMemory += len(ac.transitions32) * 256 * 4
	}
	stateMemory += len(ac.hasOutput)
	outputMemory := len(ac.outputs) * 4
	stringMemory := len(ac.strings) * 64 // Approximate

	return stateMemory + outputMemory + stringMemory
}

// Reset clears the automaton for reuse
func (ac *acAutomaton) Reset() {
	ac.compactStates = false
	// Clear states but keep capacity
	ac.states = ac.states[:1] // Keep root state
	for i := range ac.states[0].transitions {
		ac.states[0].transitions[i] = -1
	}
	ac.states[0].failure = -1
	ac.states[0].outputStart = 0
	ac.states[0].outputEnd = 0

	// Clear outputs and strings
	ac.outputs = ac.outputs[:0]
	ac.strings = ac.strings[:0]
	ac.rootBytes = ac.rootBytes[:0]
	ac.rootLanes = ac.rootLanes[:0]
	ac.teddy = nil
	ac.teddyGate = nil
	ac.StringCount = 0
	ac.Strings = ac.Strings[:0]
	ac.transitions16 = nil
	ac.transitions32 = nil
	ac.hasOutput = nil

	// Reset compilation state
	ac.compiledOnce = sync.Once{}
	ac.compiled = false
}

// flipASCIICase returns the opposite-ASCII-case equivalent of b for letters,
// and b unchanged otherwise. Used to register dual trie transitions for
// nocase strings (whose pattern bytes are already lowercased).
func flipASCIICase(b byte) byte {
	switch {
	case b >= 'a' && b <= 'z':
		return b - 32
	case b >= 'A' && b <= 'Z':
		return b + 32
	default:
		return b
	}
}
