package compiler

import (
	"bytes"
	"errors"
	"fmt"
	"iter"
	"slices"
	"sync"

	"github.com/cawalch/go-yara/regex"
)

// ACState represents a state in the Aho-Corasick automaton
// Using struct-of-arrays layout for better cache locality
type ACState struct {
	// Transition table (256 possible byte values)
	transitions [256]int32 // -1 means no transition, >=0 is state index
	// Failure link
	failure int32
	// Output information
	outputStart int32
	outputEnd   int32
}

// ACAutomaton represents the high-performance Aho-Corasick automaton
type ACAutomaton struct {
	// States with cache-friendly layout
	states []ACState

	// Output storage (flattened)
	outputs []int32

	// String information
	strings []ACStringInfo

	// Explicit bytes reachable from the root before failure links are built.
	// Small sets can use SIMD-optimized byte search to skip root misses.
	rootBytes []byte

	// Performance optimization: matchBuffer removed, matching is now iterator-based

	// Compilation state
	compiledOnce sync.Once
	compiled     bool

	// Backward compatibility fields
	StringCount int
	Strings     []ACStringInfo
}

// NewACAutomaton creates a new Aho-Corasick automaton
func NewACAutomaton() *ACAutomaton {
	// Start with root state
	states := make([]ACState, 1, 256) // Pre-allocate capacity
	for i := range states[0].transitions {
		states[0].transitions[i] = -1 // No transitions initially
	}
	states[0].failure = -1 // Root has no failure
	states[0].outputStart = 0
	states[0].outputEnd = 0

	return &ACAutomaton{
		states:      states,
		outputs:     make([]int32, 0, 64),
		strings:     make([]ACStringInfo, 0, 16),
		compiled:    false,
		StringCount: 0,
		Strings:     make([]ACStringInfo, 0, 16),
	}
}

// AddString adds a string pattern to the automaton
//
//nolint:revive // argument-limit: API surface
func (ac *ACAutomaton) AddString(identifier string, data []byte, isHex, isRegex bool) error {
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
func (ac *ACAutomaton) addStringToAutomaton(config stringConfig) error {
	if ac.compiled {
		return errors.New("cannot add strings to compiled automaton")
	}

	// Create string info
	stringInfo := ACStringInfo{
		Identifier: config.Identifier,
		Length:     len(config.Data),
		IsHex:      config.IsHex,
		IsRegex:    config.IsRegex,
		Data:       make([]byte, len(config.Data)),
		Flags:      config.Flags,
	}
	copy(stringInfo.Data, config.Data)

	// Add string to collection
	ac.strings = append(ac.strings, stringInfo)
	ac.StringCount = len(ac.strings)

	// Update backward compatibility field
	ac.Strings = slices.Clone(ac.strings)
	stringIndex := int32(len(ac.strings) - 1) // #nosec G115

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
			newState := ACState{
				transitions: [256]int32{},
				failure:     -1,
				outputStart: 0,
				outputEnd:   0,
			}
			for i := range newState.transitions {
				newState.transitions[i] = -1
			}
			ac.states = append(ac.states, newState)
			nextState = int32(len(ac.states) - 1) // #nosec G115
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
		ac.states[currentState].outputStart = int32(len(ac.outputs)) // #nosec G115
	case int(existingEnd) != len(ac.outputs):
		ac.states[currentState].outputStart = int32(len(ac.outputs)) // #nosec G115
		ac.outputs = append(ac.outputs, ac.outputs[existingStart:existingEnd]...)
	}
	ac.outputs = append(ac.outputs, stringIndex)
	ac.states[currentState].outputEnd = int32(len(ac.outputs)) // #nosec G115

	return nil
}

// Compile compiles the optimized automaton
func (ac *ACAutomaton) Compile() error {
	var compileErr error

	ac.compiledOnce.Do(func() {
		if ac.compiled {
			compileErr = errors.New("already compiled")
			return
		}
		ac.collectRootBytes()

		// Build failure links using BFS
		if err := ac.buildFailureLinks(); err != nil {
			compileErr = fmt.Errorf("building failure links: %w", err)
			return
		}

		ac.compiled = true
	})

	return compileErr
}

func (ac *ACAutomaton) collectRootBytes() {
	ac.rootBytes = ac.rootBytes[:0]
	for byteVal, nextState := range ac.states[0].transitions {
		if nextState != -1 {
			ac.rootBytes = append(ac.rootBytes, byte(byteVal))
		}
	}
}

func (ac *ACAutomaton) failureState(current int32, byteVal byte) int32 {
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
func (ac *ACAutomaton) mergeFailureOutput(state int32) {
	failState := ac.states[ac.states[state].failure]
	if failState.outputStart != failState.outputEnd {
		// Copy both ranges into a new contiguous range. Output ranges for other
		// states may have been appended between this state's original range and
		// the current end of the flat output storage.
		stateOutput := slices.Clone(ac.outputs[ac.states[state].outputStart:ac.states[state].outputEnd])
		failOutput := ac.outputs[failState.outputStart:failState.outputEnd]
		ac.states[state].outputStart = int32(len(ac.outputs)) // #nosec G115
		ac.outputs = append(ac.outputs, stateOutput...)
		ac.outputs = append(ac.outputs, failOutput...)
		ac.states[state].outputEnd = int32(len(ac.outputs)) // #nosec G115
	}
}

// buildFailureLinks builds failure links for the optimized automaton
func (ac *ACAutomaton) buildFailureLinks() error {
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

// findNextState follows failure links until a transition is available.
func (ac *ACAutomaton) findNextState(currentState int32, b byte) int32 {
	for {
		nextState := ac.states[currentState].transitions[b]
		if nextState != -1 {
			return nextState
		}
		if currentState == 0 {
			return 0
		}
		currentState = ac.states[currentState].failure
	}
}

const (
	maxSparseRootTransitions = 4
	rootCandidateExhausted   = -1
	rootCandidateUnsearched  = -2
)

// rootCandidateCursor keeps one next-occurrence cursor per root transition.
// Every lane advances monotonically, so an absent root byte is searched once
// instead of rescanning the remaining input at every candidate from another
// lane.
type rootCandidateCursor struct {
	values    []byte
	positions [maxSparseRootTransitions]int
}

func newRootCandidateCursor(values []byte) rootCandidateCursor {
	cursor := rootCandidateCursor{values: values}
	for index := range cursor.positions {
		cursor.positions[index] = rootCandidateUnsearched
	}
	return cursor
}

func (cursor *rootCandidateCursor) next(data []byte, from int) int {
	best := -1
	for index, value := range cursor.values {
		position := cursor.positions[index]
		if position == rootCandidateExhausted {
			continue
		}
		if position < from {
			relative := bytes.IndexByte(data[from:], value)
			if relative < 0 {
				cursor.positions[index] = rootCandidateExhausted
				continue
			}
			position = from + relative
			cursor.positions[index] = position
		}
		if best < 0 || position < best {
			best = position
		}
	}
	return best
}

func (ac *ACAutomaton) yieldMatches(state int32, offset int, yield func(ACMatch) bool) bool {
	outputStart := ac.states[state].outputStart
	outputEnd := ac.states[state].outputEnd
	for idx := outputStart; idx < outputEnd; idx++ {
		stringIndex := ac.outputs[idx]
		if stringIndex < 0 || int(stringIndex) >= len(ac.strings) {
			continue
		}
		stringInfo := ac.strings[stringIndex]
		if !yield(ACMatch{
			StringIndex: int(stringIndex),
			StringID:    stringInfo.Identifier,
			Backtrack:   offset + 1 - stringInfo.Length,
		}) {
			return false
		}
	}
	return true
}

func indexSinglePattern(data []byte, pattern []byte, noCase bool) int {
	if len(pattern) == 0 || len(pattern) > len(data) {
		return -1
	}
	if !noCase {
		return bytes.Index(data, pattern)
	}

	last := len(data) - len(pattern)
	for pos := 0; pos <= last; {
		rel := indexASCIIFoldByte(data[pos:last+1], pattern[0])
		if rel < 0 {
			return -1
		}
		candidate := pos + rel
		matched := true
		for idx := 1; idx < len(pattern); idx++ {
			if toLowerTable[data[candidate+idx]] != toLowerTable[pattern[idx]] {
				matched = false
				break
			}
		}
		if matched {
			return candidate
		}
		pos = candidate + 1
	}
	return -1
}

func singlePatternIsDense(data []byte, pattern []byte, noCase bool) bool {
	const sampleSize = 256
	if len(data) > sampleSize {
		data = data[:sampleSize]
	}
	matches := 0
	for pos := 0; pos <= len(data)-len(pattern); {
		rel := indexSinglePattern(data[pos:], pattern, noCase)
		if rel < 0 {
			return false
		}
		matches++
		if matches == 8 {
			return true
		}
		pos += rel + 1
	}
	return false
}

// searchSinglePattern uses the platform byte-search primitives when an
// automaton contains only one concrete pattern. This avoids walking the AC
// state machine for the common one-rule/one-string case while preserving
// overlapping matches and nocase semantics.
func (ac *ACAutomaton) searchSinglePattern(data []byte, yield func(ACMatch) bool) {
	info := ac.strings[0]
	noCase := info.Flags&regex.FlagsNoCase != 0
	for pos := 0; pos <= len(data)-len(info.Data); {
		rel := indexSinglePattern(data[pos:], info.Data, noCase)
		if rel < 0 {
			return
		}
		start := pos + rel
		if !yield(ACMatch{
			StringIndex: 0,
			StringID:    info.Identifier,
			Backtrack:   start,
		}) {
			return
		}
		pos = start + 1
	}
}

// SearchIter performs optimized pattern matching without allocating a slice, yielding matches via an iterator
//
//nolint:nestif // the sparse-root and general loops are intentionally separate hot paths
func (ac *ACAutomaton) SearchIter(data []byte) iter.Seq[ACMatch] {
	return func(yield func(ACMatch) bool) {
		if !ac.compiled {
			return
		}

		if len(data) == 0 {
			return
		}
		if len(ac.strings) == 1 {
			info := ac.strings[0]
			if len(info.Data) > 0 {
				noCase := info.Flags&regex.FlagsNoCase != 0
				if !singlePatternIsDense(data, info.Data, noCase) {
					ac.searchSinglePattern(data, yield)
					return
				}
			}
		}

		currentState := int32(0) // Start at root

		// When the automaton has only a few root transitions, skip root misses
		// with the platform byte-search routine. Keep the tight range loop for
		// small inputs and wider roots where repeated byte searches cost more.
		rootHasNoOutput := ac.states[0].outputStart == ac.states[0].outputEnd
		if rootHasNoOutput && len(data) >= 256 && len(ac.rootBytes) > 0 && len(ac.rootBytes) <= maxSparseRootTransitions {
			rootCursor := newRootCandidateCursor(ac.rootBytes)
			for i := 0; i < len(data); i++ {
				if currentState == 0 && len(data)-i >= 256 {
					candidate := rootCursor.next(data, i)
					if candidate < 0 {
						return
					}
					i = candidate
				}
				currentState = ac.findNextState(currentState, data[i])
				if ac.states[currentState].outputStart != ac.states[currentState].outputEnd &&
					!ac.yieldMatches(currentState, i, yield) {
					return
				}
			}
			return
		}

		rootTransitions := &ac.states[0].transitions
		for i, b := range data {
			if currentState == 0 {
				currentState = rootTransitions[b]
				if currentState == -1 {
					currentState = 0
					continue
				}
			} else {
				currentState = ac.findNextState(currentState, b)
			}
			outputStart := ac.states[currentState].outputStart
			outputEnd := ac.states[currentState].outputEnd
			for idx := outputStart; idx < outputEnd; idx++ {
				stringIndex := ac.outputs[idx]
				if stringIndex < 0 || int(stringIndex) >= len(ac.strings) {
					continue
				}
				stringInfo := ac.strings[stringIndex]
				if !yield(ACMatch{
					StringIndex: int(stringIndex),
					StringID:    stringInfo.Identifier,
					Backtrack:   i + 1 - stringInfo.Length,
				}) {
					return
				}
			}
		}
	}
}

// AddStringWithFlags adds a string and records regex VM flags alongside metadata
//
//nolint:revive // argument-limit: API surface
func (ac *ACAutomaton) AddStringWithFlags(
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
func (ac *ACAutomaton) ReserveStrings(n int) {
	if n > 0 && cap(ac.strings) < n {
		ac.strings = slices.Grow(ac.strings, n-len(ac.strings))
	}
}

// ReserveStates ensures capacity for at least n states to avoid slice growth
func (ac *ACAutomaton) ReserveStates(n int) {
	if n > 0 && cap(ac.states) < n {
		ac.states = slices.Grow(ac.states, n-len(ac.states))
	}
}

// BuildFailureLinks builds the failure links for the automaton
func (ac *ACAutomaton) BuildFailureLinks() error {
	return ac.buildFailureLinks()
}

// PrintDebug prints debug information about the automaton
func (ac *ACAutomaton) PrintDebug() {
	fmt.Printf("Aho-Corasick Automaton Debug Information:\n")
	fmt.Printf("States: %d\n", len(ac.states))
	fmt.Printf("Strings: %d\n", len(ac.strings))
	fmt.Printf("\nStates:\n")
	for i := range ac.states {
		state := &ac.states[i]
		// Count children
		childCount := 0
		for _, transition := range &state.transitions {
			if transition != -1 {
				childCount++
			}
		}

		fmt.Printf("  State %d: failure=%d, children=%d, output=%d-%d\n",
			i, state.failure, childCount, state.outputStart, state.outputEnd)
	}
}

// Validate checks if the automaton is correctly constructed
func (ac *ACAutomaton) Validate() error {
	if len(ac.states) == 0 {
		return errors.New("automaton has no states")
	}

	if len(ac.states) > 0 && len(ac.strings) == 0 && ac.compiled {
		return errors.New("inconsistent automaton state")
	}

	return nil
}

// Clone creates a copy of the automaton
func (ac *ACAutomaton) Clone() *ACAutomaton {
	newAC := &ACAutomaton{
		states:      slices.Clone(ac.states),
		outputs:     slices.Clone(ac.outputs),
		strings:     slices.Clone(ac.strings),
		StringCount: ac.StringCount,
		Strings:     slices.Clone(ac.Strings),
	}

	return newAC
}

// ACMatch represents a pattern match found by the automaton
type ACMatch struct {
	StringIndex int    // Index of the matched string
	StringID    string // Identifier of the matched string
	Backtrack   int    // Backtrack distance
}

// ACStringInfo contains information about a registered string pattern
type ACStringInfo struct {
	Identifier string
	Length     int
	IsHex      bool
	IsRegex    bool
	Data       []byte
	Flags      regex.Flags
}

type stringConfig struct {
	Identifier string
	Data       []byte
	IsHex      bool
	IsRegex    bool
	Flags      regex.Flags
}

// GetStateCount returns the number of states in the automaton
func (ac *ACAutomaton) GetStateCount() int {
	return len(ac.states)
}

// GetStringCount returns the number of strings in the automaton
func (ac *ACAutomaton) GetStringCount() int {
	return len(ac.strings)
}

// GetStrings returns all string information from the automaton
func (ac *ACAutomaton) GetStrings() []ACStringInfo {
	return ac.strings
}

// GetPatternData returns a map of string identifiers to their pattern data
func (ac *ACAutomaton) GetPatternData() map[string][]byte {
	// Pre-allocate map with known capacity for better performance
	result := make(map[string][]byte, len(ac.strings))
	for _, strInfo := range ac.strings {
		result[strInfo.Identifier] = strInfo.Data
	}
	return result
}

// EstimateMemoryUsage returns a deterministic heuristic byte estimate for the automaton.
// It is intended for relative sizing and diagnostics, not exact Go heap accounting.
func (ac *ACAutomaton) EstimateMemoryUsage() int {
	stateMemory := len(ac.states) * (256*4 + 8) // transitions + failure + output indices
	outputMemory := len(ac.outputs) * 4
	stringMemory := len(ac.strings) * 64 // Approximate

	return stateMemory + outputMemory + stringMemory
}

// Reset clears the automaton for reuse
func (ac *ACAutomaton) Reset() {
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

	// Reset compilation state
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
