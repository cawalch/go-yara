package compiler

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cawalch/go-yara/regex"
)

// ACState represents a state in the Aho-Corasick automaton
type ACState struct {
	Depth      int      // Depth in the trie
	Input      byte     // Input symbol that leads to this state
	FirstChild *ACState // First child in linked list (replaces map)
	Siblings   *ACState // Next sibling in linked list
	Failure    *ACState // Failure link for fallback
	Output     []int    // String indices that match at this state (nil until needed)
	TableSlot  int      // Slot in transition table
}

// ACMatch represents a match found in the automaton
type ACMatch struct {
	StringIndex int    // Index of the matched string
	StringID    string // Identifier of the matched string
	Backtrack   int    // Backtrack distance
}

// ACAutomaton represents the complete Aho-Corasick automaton
type ACAutomaton struct {
	Root        *ACState       // Root state
	States      []*ACState     // All states in the automaton
	StringCount int            // Number of strings added
	Transitions []ACTransition // Transition table
	MatchTable  []uint32       // Match table
	TableSize   int            // Size of transition table
	Bitmask     []uint32       // Bitmask for transition table optimization
	Strings     []ACStringInfo // Information about added strings

	// Performance optimization fields
	searchPool   sync.Pool // Pool for match slices to reduce allocations
	compiledOnce sync.Once // Ensure compilation happens only once
}

// ACStringInfo holds information about a string added to the automaton
type ACStringInfo struct {
	Identifier string
	Length     int
	IsHex      bool
	IsRegex    bool
	Data       []byte
	Flags      regex.Flags
}

// ACTransition represents a transition in the transition table
type ACTransition uint32

const (
	// ACStateIndexBits is the number of bits used for state index encoding
	ACStateIndexBits = 23
	// ACOffsetBits is the number of bits used for offset encoding
	ACOffsetBits = 9
	// ACSlotOffsetBits is the number of bits used for slot offset encoding
	ACSlotOffsetBits = 9

	// ACStateIndexMask is the mask for extracting state index
	ACStateIndexMask = (1 << ACStateIndexBits) - 1
	// ACOffsetMask is the mask for extracting offset
	ACOffsetMask = (1 << ACOffsetBits) - 1

	// ACMaxTableSize is the maximum size of the transition table
	ACMaxTableSize = 1 << 16
)

// ACMakeTransition creates a transition table entry
func ACMakeTransition(stateIndex, offset uint32) ACTransition {
	return ACTransition((stateIndex & ACStateIndexMask) |
		((offset & ACOffsetMask) << ACStateIndexBits))
}

// GetStateIndex extracts the state index from a transition
func (t ACTransition) GetStateIndex() uint32 {
	return uint32(t) & ACStateIndexMask
}

// GetOffset extracts the offset from a transition
func (t ACTransition) GetOffset() uint32 {
	return (uint32(t) >> ACStateIndexBits) & ACOffsetMask
}

// NewACAutomaton creates a new Aho-Corasick automaton
func NewACAutomaton() *ACAutomaton {
	root := &ACState{
		Depth:      0,
		Input:      0,
		FirstChild: nil,
		Siblings:   nil,
		Failure:    nil,
		Output:     nil, // Lazy allocation - only allocate when needed
		TableSlot:  0,
	}

	ac := &ACAutomaton{
		Root:        root,
		States:      []*ACState{root},
		StringCount: 0,
		Transitions: make([]ACTransition, 0),
		MatchTable:  make([]uint32, 0),
		TableSize:   0,
		Bitmask:     make([]uint32, 0),
		Strings:     make([]ACStringInfo, 0),
	}

	// Initialize search pool for performance optimization
	ac.searchPool = sync.Pool{
		New: func() any {
			return make([]ACMatch, 0, 8) // Pre-allocate reasonable capacity
		},
	}

	return ac
}

// ReserveStrings ensures capacity for at least n string infos to avoid slice growth
func (ac *ACAutomaton) ReserveStrings(n int) {
	if n <= 0 {
		return
	}
	if cap(ac.Strings) < n {
		newSlice := make([]ACStringInfo, len(ac.Strings), n)
		copy(newSlice, ac.Strings)
		ac.Strings = newSlice
	}
}

// ReserveStates ensures capacity for at least n states to avoid slice growth
func (ac *ACAutomaton) ReserveStates(n int) {
	if n <= 0 {
		return
	}
	if cap(ac.States) < n {
		newSlice := make([]*ACState, len(ac.States), n)
		copy(newSlice, ac.States)
		ac.States = newSlice
	}
}

// findChild finds a child state with the given input byte
func (state *ACState) findChild(input byte) *ACState {
	child := state.FirstChild
	for child != nil {
		if child.Input == input {
			return child
		}
		child = child.Siblings
	}
	return nil
}

// addChild adds a new child state with the given input byte
func (state *ACState) addChild(newChild *ACState) {
	newChild.Siblings = state.FirstChild
	state.FirstChild = newChild
}

// StringConfig holds configuration for adding a string to the automaton
type StringConfig struct {
	Identifier string
	Data       []byte
	IsHex      bool
	IsRegex    bool
}

// AddString adds a string pattern to the automaton (backwards-compatible signature).
func (ac *ACAutomaton) AddString(identifier string, data []byte, isHex, isRegex bool) error {
	config := StringConfig{
		Identifier: identifier,
		Data:       data,
		IsHex:      isHex,
		IsRegex:    isRegex,
	}
	return ac.AddStringWithConfig(config)
}

// AddStringWithConfig adds a string pattern to the automaton using configuration.
func (ac *ACAutomaton) AddStringWithConfig(config StringConfig) error {
	if len(config.Data) == 0 {
		return errors.New("empty pattern")
	}

	// Ensure we have enough capacity in strings slice to avoid reallocations
	if ac.StringCount >= cap(ac.Strings) {
		newCap := max(cap(ac.Strings)*2, 16)
		ac.ReserveStrings(newCap)
	}

	// Store string information with copy to avoid data races
	dataCopy := make([]byte, len(config.Data))
	copy(dataCopy, config.Data)

	ac.Strings = append(ac.Strings, ACStringInfo{
		Identifier: config.Identifier,
		Length:     len(dataCopy),
		IsHex:      config.IsHex,
		IsRegex:    config.IsRegex,
		Data:       dataCopy,
		Flags:      0,
	})

	stringIndex := ac.StringCount
	ac.StringCount++

	// Add the string to the trie
	current := ac.Root
	depth := 0

	for _, b := range config.Data {
		depth++
		next := current.findChild(b)
		if next != nil {
			current = next
		} else {
			// Create new state (Output is nil until needed)
			newState := &ACState{
				Depth:      depth,
				Input:      b,
				FirstChild: nil,
				Siblings:   nil,
				Failure:    nil,
				Output:     nil, // Lazy allocation
				TableSlot:  0,
			}
			current.addChild(newState)
			ac.States = append(ac.States, newState)
			current = newState
		}
	}

	// Add string index to output at final state (allocate on first use)
	if current.Output == nil {
		current.Output = make([]int, 0, 1) // Pre-allocate with capacity 1
	}
	current.Output = append(current.Output, stringIndex)

	return nil
}

// StringConfigWithFlags holds configuration for adding a string with regex flags
type StringConfigWithFlags struct {
	StringConfig
	Flags regex.Flags
}

// AddStringWithFlags adds a string and records regex VM flags alongside metadata.
func (ac *ACAutomaton) AddStringWithFlags(
	identifier string,
	data []byte,
	isHex, isRegex bool,
	flags regex.Flags,
) error {
	config := StringConfigWithFlags{
		StringConfig: StringConfig{
			Identifier: identifier,
			Data:       data,
			IsHex:      isHex,
			IsRegex:    isRegex,
		},
		Flags: flags,
	}
	return ac.AddStringWithFlagsAndConfig(config)
}

// AddStringWithFlagsAndConfig adds a string with flags using configuration.
func (ac *ACAutomaton) AddStringWithFlagsAndConfig(config StringConfigWithFlags) error {
	if err := ac.AddStringWithConfig(config.StringConfig); err != nil {
		return err
	}
	idx := ac.StringCount - 1
	if idx >= 0 && idx < len(ac.Strings) {
		ac.Strings[idx].Flags = config.Flags
	}
	return nil
}

// BuildFailureLinks builds the failure links for the automaton
func (ac *ACAutomaton) BuildFailureLinks() error {
	// Use BFS to build failure links
	queue := make([]*ACState, 0, len(ac.States))

	// Start with root's children
	child := ac.Root.FirstChild
	for child != nil {
		child.Failure = ac.Root
		queue = append(queue, child)
		child = child.Siblings
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		// Process children of current state
		childNode := current.FirstChild
		for childNode != nil {
			queue = append(queue, childNode)

			// Find failure link for this child
			failure := current.Failure
			for failure != nil {
				next := failure.findChild(childNode.Input)
				if next != nil {
					childNode.Failure = next

					// Inherit output from failure state (only if failure state has output)
					if next.Output != nil {
						if childNode.Output == nil {
							childNode.Output = make([]int, 0, len(next.Output))
						}
						childNode.Output = append(childNode.Output, next.Output...)
					}
					break
				}
				failure = failure.Failure
			}

			// If no failure link found, point to root
			if childNode.Failure == nil {
				childNode.Failure = ac.Root
			}

			childNode = childNode.Siblings
		}
	}

	return nil
}

// OptimizeFailureLinks removes unnecessary failure links for better performance
func (ac *ACAutomaton) OptimizeFailureLinks() error {
	queue := make([]*ACState, 0, len(ac.States))

	// Start with root's children
	child := ac.Root.FirstChild
	for child != nil {
		queue = append(queue, child)
		child = child.Siblings
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if current.Failure != ac.Root {
			// Check if current state's transitions are a subset of failure state's transitions
			if ac.transitionsSubset(current.Failure, current) {
				current.Failure = current.Failure.Failure
			}
		}

		// Add children to queue
		childNode := current.FirstChild
		for childNode != nil {
			queue = append(queue, childNode)
			childNode = childNode.Siblings
		}
	}

	return nil
}

// transitionsSubset checks if s2's transitions are a subset of s1's transitions
func (ac *ACAutomaton) transitionsSubset(s1, s2 *ACState) bool {
	// Create a bitmask for s1's inputs (more efficient than map)
	s1Inputs := [32]byte{} // 256 bits for all possible byte values

	child := s1.FirstChild
	for child != nil {
		byteIdx := child.Input / 8
		bitIdx := child.Input % 8
		s1Inputs[byteIdx] |= 1 << bitIdx
		child = child.Siblings
	}

	// Check if all s2 inputs exist in s1
	child = s2.FirstChild
	for child != nil {
		byteIdx := child.Input / 8
		bitIdx := child.Input % 8
		if (s1Inputs[byteIdx] & (1 << bitIdx)) == 0 {
			return false
		}
		child = child.Siblings
	}

	return true
}

// BuildTransitionTable builds the optimized transition table
// NOTE: This is now a no-op as the transition table is not used at runtime.
// The method is kept for backward compatibility.
func (ac *ACAutomaton) BuildTransitionTable() error {
	if len(ac.States) == 0 {
		return errors.New("no states in automaton")
	}
	// No-op: transition table is not used at runtime
	return nil
}

// OLD IMPLEMENTATION (kept for reference, disabled):
// The following code was the original implementation that built the transition table.
// It is no longer used at runtime, but kept for reference.
// To re-enable, uncomment the code below and remove the no-op implementation above.
/*
func (ac *ACAutomaton) BuildTransitionTable() error {
	// Calculate and validate table size
	if err := ac.calculateTableSize(); err != nil {
		return err
	}

	// Allocate transition and match tables
	ac.Transitions = make([]ACTransition, ac.TableSize)
	ac.MatchTable = make([]uint32, ac.TableSize)

	// Assign state indices
	stateSlots := ac.assignStateSlots()

	// Build transition entries for each state
	if err := ac.buildStateTransitions(stateSlots); err != nil {
		return err
	}

	return nil
}
*/

// Compile compiles the automaton into an optimized form
func (ac *ACAutomaton) Compile() error {
	var compileErr error

	// Use sync.Once to ensure we only compile once
	ac.compiledOnce.Do(func() {
		// Pre-allocate capacity for states if we can estimate it
		if ac.StringCount > 0 {
			// Rough estimate: average string length of 10 chars = 10 states per string
			estimatedStates := min(ac.StringCount*10,
				// Cap to prevent over-allocation
				1000)
			ac.ReserveStates(estimatedStates)
		}

		// Build failure links
		if err := ac.BuildFailureLinks(); err != nil {
			compileErr = fmt.Errorf("building failure links: %w", err)
			return
		}

		// Optimize failure links
		if err := ac.OptimizeFailureLinks(); err != nil {
			compileErr = fmt.Errorf("optimizing failure links: %w", err)
			return
		}

		// Build transition table (no-op for runtime optimization)
		if err := ac.BuildTransitionTable(); err != nil {
			compileErr = fmt.Errorf("building transition table: %w", err)
			return
		}
	})

	return compileErr
}

// Search searches for all patterns in the given data
func (ac *ACAutomaton) Search(data []byte) []ACMatch {
	// Validate that the automaton is properly compiled
	if err := ac.Validate(); err != nil {
		// Return empty matches if automaton is not valid
		return nil
	}

	// Get match slice from pool
	matchesInterface := ac.searchPool.Get()
	if matchesInterface == nil {
		// Fallback to direct allocation if pool returns nil
		return ac.searchDirect(data)
	}

	// Type assertion with safety check
	matches, ok := matchesInterface.([]ACMatch)
	if !ok {
		// Fallback to direct allocation if type assertion fails
		return ac.searchDirect(data)
	}
	matches = matches[:0] // Reset length but keep capacity
	defer func() {
		// Return slice to pool if it's not too large
		if cap(matches) <= 1024 { // Prevent memory bloat
			ac.searchPool.Put(&matches)
		}
	}()

	state := ac.Root

	// Optimized search loop with reduced bounds checking
	for i := range data {
		b := data[i]

		// Follow transitions until we can
		for {
			next := state.findChild(b)
			if next != nil {
				state = next
				break
			}
			if state == ac.Root {
				break
			}
			state = state.Failure
		}

		// Check for matches at current state
		if state.Output != nil {
			for _, stringIndex := range state.Output {
				if stringIndex >= 0 && stringIndex < len(ac.Strings) {
					matches = append(matches, ACMatch{
						StringIndex: stringIndex,
						StringID:    ac.Strings[stringIndex].Identifier,
						Backtrack:   i + 1 - ac.Strings[stringIndex].Length,
					})
				}
			}
		}
	}

	// Return a copy of matches since we're returning the slice to the pool
	result := make([]ACMatch, len(matches))
	copy(result, matches)
	return result
}

// searchDirect performs the search without memory pooling (fallback)
func (ac *ACAutomaton) searchDirect(data []byte) []ACMatch {
	var matches []ACMatch
	state := ac.Root

	for i, b := range data {
		// Follow transitions until we can
		for {
			next := state.findChild(b)
			if next != nil {
				state = next
				break
			}
			if state == ac.Root {
				break
			}
			state = state.Failure
		}

		// Check for matches at current state
		if state.Output != nil {
			for _, stringIndex := range state.Output {
				if stringIndex >= 0 && stringIndex < len(ac.Strings) {
					matches = append(matches, ACMatch{
						StringIndex: stringIndex,
						StringID:    ac.Strings[stringIndex].Identifier,
						Backtrack:   i + 1 - ac.Strings[stringIndex].Length,
					})
				}
			}
		}
	}

	return matches
}

// GetTransitionTable returns the compiled transition table
// NOTE: Returns nil as transition table is not used at runtime
func (ac *ACAutomaton) GetTransitionTable() []ACTransition {
	return nil
}

// GetMatchTable returns the compiled match table
// NOTE: Returns nil as match table is not used at runtime
func (ac *ACAutomaton) GetMatchTable() []uint32 {
	return nil
}

// GetTableSize returns the size of the transition table
func (ac *ACAutomaton) GetTableSize() int {
	return ac.TableSize
}

// GetStateCount returns the number of states in the automaton
func (ac *ACAutomaton) GetStateCount() int {
	return len(ac.States)
}

// PrintDebug prints debug information about the automaton
func (ac *ACAutomaton) PrintDebug() {
	fmt.Printf("Aho-Corasick Automaton Debug Information:\n")
	fmt.Printf("States: %d\n", len(ac.States))
	fmt.Printf("Strings: %d\n", ac.StringCount)
	fmt.Printf("Table Size: %d\n", ac.TableSize)

	fmt.Printf("\nTransition Table:\n")
	for i, trans := range ac.Transitions {
		if trans != 0 {
			fmt.Printf("  [%d]: state=%d, offset=%d\n",
				i, trans.GetStateIndex(), trans.GetOffset())
		}
	}

	fmt.Printf("\nStates:\n")
	for i, state := range ac.States {
		// Count children
		childCount := 0
		child := state.FirstChild
		for child != nil {
			childCount++
			child = child.Siblings
		}

		fmt.Printf("  State %d: depth=%d, children=%d, output=%v\n",
			i, state.Depth, childCount, state.Output)
		if state.Failure != nil {
			// Find failure state index
			failureIndex := -1
			for j, s := range ac.States {
				if s == state.Failure {
					failureIndex = j
					break
				}
			}
			fmt.Printf("    Failure: %d\n", failureIndex)
		}
	}
}

// EstimateMemoryUsage estimates the memory usage of the automaton
func (ac *ACAutomaton) EstimateMemoryUsage() int {
	// Rough estimate of memory usage
	stateMemory := len(ac.States) * 64 // Approximate size per state
	transitionMemory := len(ac.Transitions) * 4
	matchMemory := len(ac.MatchTable) * 4
	bitmaskMemory := len(ac.Bitmask) * 4

	return stateMemory + transitionMemory + matchMemory + bitmaskMemory
}

// Validate checks if the automaton is correctly constructed
func (ac *ACAutomaton) Validate() error {
	if ac.Root == nil {
		return errors.New("automaton has no root")
	}

	// Quick validation - check state count and string count consistency
	if len(ac.States) == 0 && ac.StringCount > 0 {
		return errors.New("inconsistent automaton state")
	}

	// For performance optimization, skip full reachability test unless specifically requested
	// The full validation is expensive and primarily for debugging
	return nil
}

// Reset clears the automaton for reuse
func (ac *ACAutomaton) Reset() {
	ac.Root.FirstChild = nil
	ac.Root.Siblings = nil
	ac.States = []*ACState{ac.Root}
	ac.StringCount = 0
	ac.Strings = ac.Strings[:0]
	ac.TableSize = 0
	ac.Transitions = ac.Transitions[:0]
	ac.MatchTable = ac.MatchTable[:0]
	ac.Bitmask = ac.Bitmask[:0]

	// Reset compilation state for reuse
	ac.compiledOnce = sync.Once{}
}

// Clone creates a copy of the automaton
func (ac *ACAutomaton) Clone() *ACAutomaton {
	newAC := &ACAutomaton{
		Root: &ACState{
			Depth:      ac.Root.Depth,
			Input:      ac.Root.Input,
			FirstChild: nil,
			Siblings:   nil,
			Failure:    nil, // Will be set during compilation
			Output:     make([]int, len(ac.Root.Output)),
			TableSlot:  ac.Root.TableSlot,
		},
		States:      make([]*ACState, 0),
		StringCount: ac.StringCount,
		Strings:     make([]ACStringInfo, len(ac.Strings)),
	}

	// Copy string information
	copy(newAC.Strings, ac.Strings)

	// Copy root output
	copy(newAC.Root.Output, ac.Root.Output)

	// Deep copy would be needed for full clone
	// This is a simplified version

	return newAC
}
