package compiler

import (
	"errors"
	"fmt"
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

	// Performance optimization: pre-allocated match buffer
	matchBuffer []ACMatch

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
		matchBuffer: make([]ACMatch, 0, 32), // Pre-allocate reasonable capacity
		compiled:    false,
		StringCount: 0,
		Strings:     make([]ACStringInfo, 0, 16),
	}
}

// AddString adds a string pattern to the automaton
func (ac *ACAutomaton) AddString(identifier string, data []byte, isHex, isRegex bool) error {
	config := StringConfig{
		Identifier: identifier,
		Data:       data,
		IsHex:      isHex,
		IsRegex:    isRegex,
		Flags:      0, // Default flags
	}
	return ac.addStringToAutomaton(config)
}

// addStringToAutomaton implements the core string addition logic
func (ac *ACAutomaton) addStringToAutomaton(config StringConfig) error {
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
	ac.Strings = make([]ACStringInfo, len(ac.strings))
	copy(ac.Strings, ac.strings)
	stringIndex := int32(len(ac.strings) - 1)

	// Build trie for pattern matching
	currentState := int32(0) // Start at root

	for _, b := range config.Data {
		// Check if transition exists
		nextState := ac.states[currentState].transitions[b]
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
			nextState = int32(len(ac.states) - 1)
			ac.states[currentState].transitions[b] = nextState
		}
		currentState = nextState
	}

	// Add output for final state
	ac.outputs = append(ac.outputs, stringIndex)
	ac.states[currentState].outputEnd = int32(len(ac.outputs))

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

		// Build failure links using BFS
		if err := ac.buildFailureLinks(); err != nil {
			compileErr = fmt.Errorf("building failure links: %w", err)
			return
		}

		ac.compiled = true
	})

	return compileErr
}

// buildFailureLinks builds failure links for the optimized automaton
func (ac *ACAutomaton) buildFailureLinks() error {
	if len(ac.states) == 0 {
		return errors.New("no states in automaton")
	}

	// Queue for BFS
	queue := make([]int32, 0, len(ac.states))

	// Initialize root's children
	for _, nextState := range &ac.states[0].transitions {
		if nextState != -1 {
			ac.states[nextState].failure = 0 // Root's children fail to root
			queue = append(queue, nextState)
		}
	}

	// Process remaining states
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		// Process all transitions from current state
		for byteVal, nextState := range &ac.states[current].transitions {
			if nextState == -1 {
				continue // No transition
			}

			queue = append(queue, nextState)

			// Find failure link for this transition
			failure := ac.states[current].failure

			// Follow failure links to find a state that has this transition
			for failure != -1 && ac.states[failure].transitions[byteVal] == -1 {
				failure = ac.states[failure].failure
			}

			if failure != -1 {
				ac.states[nextState].failure = ac.states[failure].transitions[byteVal]

				// Merge output from failure state
				failState := ac.states[ac.states[nextState].failure]
				if failState.outputStart != failState.outputEnd {
					// Append failure state's output to current state's output
					_ = ac.outputs[ac.states[nextState].outputStart:ac.states[nextState].outputEnd]
					failOutput := ac.outputs[failState.outputStart:failState.outputEnd]

					// This is simplified - real implementation would handle this more efficiently
					ac.outputs = append(ac.outputs, failOutput...)
					ac.states[nextState].outputEnd = int32(len(ac.outputs))
				}
			} else {
				ac.states[nextState].failure = 0 // Fail to root
			}
		}
	}

	return nil
}

// Search performs optimized pattern matching
func (ac *ACAutomaton) Search(data []byte) []ACMatch {
	if !ac.compiled {
		return nil
	}

	if len(data) == 0 {
		return nil
	}

	// Reset match buffer
	ac.matchBuffer = ac.matchBuffer[:0]

	currentState := int32(0) // Start at root

	// Optimized search loop
	for i, b := range data {
		// Follow transitions, using failure links when needed
		for {
			nextState := ac.states[currentState].transitions[b]
			if nextState != -1 {
				currentState = nextState
				break
			}

			if currentState == 0 {
				break // At root, no transition found
			}

			currentState = ac.states[currentState].failure
		}

		// Check for outputs at current state
		outputStart := ac.states[currentState].outputStart
		outputEnd := ac.states[currentState].outputEnd

		if outputStart != outputEnd {
			// Process all matches
			for idx := outputStart; idx < outputEnd; idx++ {
				stringIndex := ac.outputs[idx]
				if stringIndex >= 0 && int(stringIndex) < len(ac.strings) {
					stringInfo := ac.strings[stringIndex]
					ac.matchBuffer = append(ac.matchBuffer, ACMatch{
						StringIndex: int(stringIndex),
						StringID:    stringInfo.Identifier,
						Backtrack:   i + 1 - stringInfo.Length,
					})
				}
			}
		}
	}

	// Return a copy of matches (to avoid caller modifying internal buffer)
	result := make([]ACMatch, len(ac.matchBuffer))
	copy(result, ac.matchBuffer)
	return result
}

// AddStringWithFlags adds a string and records regex VM flags alongside metadata
func (ac *ACAutomaton) AddStringWithFlags(
	identifier string,
	data []byte,
	isHex, isRegex bool,
	flags regex.Flags,
) error {
	config := StringConfig{
		Identifier: identifier,
		Data:       data,
		IsHex:      isHex,
		IsRegex:    isRegex,
		Flags:      flags,
	}
	return ac.addStringToAutomaton(config)
}

// AddStringWithConfig adds a string using configuration
func (ac *ACAutomaton) AddStringWithConfig(config StringConfig) error {
	return ac.addStringToAutomaton(config)
}

// AddStringWithFlagsAndConfig adds a string with flags using configuration
func (ac *ACAutomaton) AddStringWithFlagsAndConfig(config StringConfigWithFlags) error {
	if err := ac.AddStringWithConfig(config.StringConfig); err != nil {
		return err
	}
	// Store flags if needed in the future
	return nil
}

// ReserveStrings ensures capacity for at least n string infos to avoid slice growth
func (ac *ACAutomaton) ReserveStrings(n int) {
	if n <= 0 {
		return
	}
	if cap(ac.strings) < n {
		newSlice := make([]ACStringInfo, len(ac.strings), n)
		copy(newSlice, ac.strings)
		ac.strings = newSlice
	}
}

// ReserveStates ensures capacity for at least n states to avoid slice growth
func (ac *ACAutomaton) ReserveStates(n int) {
	if n <= 0 {
		return
	}
	if cap(ac.states) < n {
		newSlice := make([]ACState, len(ac.states), n)
		copy(newSlice, ac.states)
		ac.states = newSlice
	}
}

// BuildFailureLinks builds the failure links for the automaton
func (ac *ACAutomaton) BuildFailureLinks() error {
	return ac.buildFailureLinks()
}

// GetTransitionTable returns the compiled transition table
func (ac *ACAutomaton) GetTransitionTable() []ACTransition {
	return nil // Transition table not used in optimized implementation
}

// GetMatchTable returns the compiled match table
func (ac *ACAutomaton) GetMatchTable() []uint32 {
	return nil // Match table not used in optimized implementation
}

// GetTableSize returns the size of the transition table
func (ac *ACAutomaton) GetTableSize() int {
	return 0 // No transition table in optimized implementation
}

// PrintDebug prints debug information about the automaton
func (ac *ACAutomaton) PrintDebug() {
	fmt.Printf("Aho-Corasick Automaton Debug Information:\n")
	fmt.Printf("States: %d\n", len(ac.states))
	fmt.Printf("Strings: %d\n", len(ac.strings))
	fmt.Printf("Table Size: %d\n", 0) // No transition table

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
		states:      make([]ACState, len(ac.states)),
		outputs:     make([]int32, len(ac.outputs)),
		strings:     make([]ACStringInfo, len(ac.strings)),
		matchBuffer: make([]ACMatch, 0, cap(ac.matchBuffer)),
		StringCount: ac.StringCount,
		Strings:     make([]ACStringInfo, len(ac.Strings)),
	}

	// Copy states
	copy(newAC.states, ac.states)

	// Copy outputs
	copy(newAC.outputs, ac.outputs)

	// Copy strings
	copy(newAC.strings, ac.strings)

	// Copy backward compatibility strings
	copy(newAC.Strings, ac.Strings)

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

// ACTransition represents a state transition in the automaton
type ACTransition uint32

// ACMakeTransition creates a transition with state index and offset
func ACMakeTransition(stateIndex, offset int) ACTransition {
	return ACTransition((stateIndex << 16) | offset)
}

// GetStateIndex returns the state index from a transition
func (t ACTransition) GetStateIndex() int {
	return int(t >> 16)
}

// GetOffset returns the offset from a transition
func (t ACTransition) GetOffset() int {
	return int(t & 0xFFFF)
}

// StringConfig contains configuration for adding a string to the automaton
type StringConfig struct {
	Identifier string
	Data       []byte
	IsHex      bool
	IsRegex    bool
	Flags      regex.Flags
}

// StringConfigWithFlags extends StringConfig with regex flags
type StringConfigWithFlags struct {
	StringConfig
	Flags regex.Flags
}

// GetStateCount returns the number of states in the automaton
func (ac *ACAutomaton) GetStateCount() int {
	return len(ac.states)
}

// GetStringCount returns the number of strings in the automaton
func (ac *ACAutomaton) GetStringCount() int {
	return len(ac.strings)
}

// EstimateMemoryUsage estimates memory usage
func (ac *ACAutomaton) EstimateMemoryUsage() int {
	stateMemory := len(ac.states) * (256*4 + 8) // transitions + failure + output indices
	outputMemory := len(ac.outputs) * 4
	stringMemory := len(ac.strings) * 64     // Approximate
	bufferMemory := cap(ac.matchBuffer) * 16 // Approximate

	return stateMemory + outputMemory + stringMemory + bufferMemory
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
