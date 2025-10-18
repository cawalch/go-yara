// Package compiler provides bytecode generation and compilation for YARA rules.
package compiler

import (
	"fmt"
)

// ACState represents a state in the Aho-Corasick automaton
type ACState struct {
	Depth      int               // Depth in the trie
	Input      byte              // Input symbol that leads to this state
	Children   map[byte]*ACState // Child states (input -> state)
	Failure    *ACState          // Failure link for fallback
	Output     []int             // String indices that match at this state
	TableSlot  int               // Slot in transition table
}

// ACMatch represents a match found in the automaton
type ACMatch struct {
	StringIndex int    // Index of the matched string
	StringID    string // Identifier of the matched string
	Backtrack   int    // Backtrack distance
}

// ACAutomaton represents the complete Aho-Corasick automaton
type ACAutomaton struct {
	Root         *ACState          // Root state
	States       []*ACState        // All states in the automaton
	StringCount  int               // Number of strings added
	Transitions  []ACTransition    // Transition table
	MatchTable   []uint32          // Match table
	TableSize    int               // Size of transition table
	Bitmask      []uint32          // Bitmask for transition table optimization
	Strings      []ACStringInfo    // Information about added strings
}

// ACStringInfo holds information about a string added to the automaton
type ACStringInfo struct {
	Identifier string
	Length     int
	IsHex      bool
	IsRegex    bool
	Data       []byte
}

// ACTransition represents a transition in the transition table
type ACTransition uint32

const (
	// Transition encoding bits
	ACStateIndexBits  = 23
	ACOffsetBits      = 9
	ACSlotOffsetBits  = 9

	// Masks
	ACStateIndexMask = (1 << ACStateIndexBits) - 1
	ACOffsetMask     = (1 << ACOffsetBits) - 1

	// Maximum table size
	ACMaxTableSize = 1 << 16
)

// ACMakeTransition creates a transition table entry
func ACMakeTransition(stateIndex, offset uint32) ACTransition {
	return ACTransition((stateIndex & ACStateIndexMask) |
		((offset & ACOffsetMask) << ACStateIndexBits))
}

// ACGetStateIndex extracts the state index from a transition
func (t ACTransition) GetStateIndex() uint32 {
	return uint32(t) & ACStateIndexMask
}

// ACGetOffset extracts the offset from a transition
func (t ACTransition) GetOffset() uint32 {
	return (uint32(t) >> ACStateIndexBits) & ACOffsetMask
}

// NewACAutomaton creates a new Aho-Corasick automaton
func NewACAutomaton() *ACAutomaton {
	root := &ACState{
		Depth:    0,
		Input:    0,
		Children: make(map[byte]*ACState),
		Failure:  nil,
		Output:   make([]int, 0),
		TableSlot: 0,
	}

	return &ACAutomaton{
		Root:        root,
		States:      []*ACState{root},
		StringCount: 0,
		Transitions: make([]ACTransition, 0),
		MatchTable:  make([]uint32, 0),
		TableSize:   0,
		Bitmask:     make([]uint32, 0),
		Strings:     make([]ACStringInfo, 0),
	}
}

// AddString adds a string pattern to the automaton
func (ac *ACAutomaton) AddString(identifier string, data []byte, isHex, isRegex bool) error {
	if len(data) == 0 {
		return fmt.Errorf("empty pattern")
	}

	// Store string information
	ac.Strings = append(ac.Strings, ACStringInfo{
		Identifier: identifier,
		Length:     len(data),
		IsHex:      isHex,
		IsRegex:    isRegex,
		Data:       make([]byte, len(data)),
	})
	copy(ac.Strings[ac.StringCount].Data, data)

	stringIndex := ac.StringCount
	ac.StringCount++

	// Add the string to the trie
	current := ac.Root
	depth := 0

	for _, b := range data {
		depth++
		if next, exists := current.Children[b]; exists {
			current = next
		} else {
			// Create new state
			newState := &ACState{
				Depth:    depth,
				Input:    b,
				Children: make(map[byte]*ACState),
				Failure:  nil,
				Output:   make([]int, 0),
				TableSlot: 0,
			}
			current.Children[b] = newState
			ac.States = append(ac.States, newState)
			current = newState
		}
	}

	// Add string index to output at final state
	current.Output = append(current.Output, stringIndex)

	return nil
}

// BuildFailureLinks builds the failure links for the automaton
func (ac *ACAutomaton) BuildFailureLinks() error {
	// Use BFS to build failure links
	queue := make([]*ACState, 0)

	// Start with root's children
	for _, child := range ac.Root.Children {
		child.Failure = ac.Root
		queue = append(queue, child)
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		// Process children of current state
		for input, child := range current.Children {
			queue = append(queue, child)

			// Find failure link for this child
			failure := current.Failure
			for failure != nil {
				if next, exists := failure.Children[input]; exists {
					child.Failure = next

					// Inherit output from failure state
					child.Output = append(child.Output, next.Output...)
					break
				}
				failure = failure.Failure
			}

			// If no failure link found, point to root
			if child.Failure == nil {
				child.Failure = ac.Root
			}
		}
	}

	return nil
}

// OptimizeFailureLinks removes unnecessary failure links for better performance
func (ac *ACAutomaton) OptimizeFailureLinks() error {
	queue := make([]*ACState, 0)

	// Start with root's children
	for _, child := range ac.Root.Children {
		queue = append(queue, child)
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
		for _, child := range current.Children {
			queue = append(queue, child)
		}
	}

	return nil
}

// transitionsSubset checks if s2's transitions are a subset of s1's transitions
func (ac *ACAutomaton) transitionsSubset(s1, s2 *ACState) bool {
	// Create a set of inputs for s1
	s1Inputs := make(map[byte]bool)
	for input := range s1.Children {
		s1Inputs[input] = true
	}

	// Check if all s2 inputs exist in s1
	for input := range s2.Children {
		if !s1Inputs[input] {
			return false
		}
	}

	return true
}

// BuildTransitionTable builds the optimized transition table
func (ac *ACAutomaton) BuildTransitionTable() error {
	// Calculate required table size based on number of states
	// Each state needs space for up to 256 transitions (one per byte value)
	requiredSize := len(ac.States) * 256
	if requiredSize < 512 {
		requiredSize = 512
	}
	if requiredSize > ACMaxTableSize {
		requiredSize = ACMaxTableSize
	}

	ac.TableSize = requiredSize
	ac.Transitions = make([]ACTransition, ac.TableSize)
	ac.MatchTable = make([]uint32, ac.TableSize)

	// Track which slots are used (simple allocation strategy)
	usedSlots := make([]bool, ac.TableSize)
	usedSlots[0] = true // Root is at slot 0

	// Assign slots to all states
	stateSlots := make(map[*ACState]int)
	stateSlots[ac.Root] = 0

	// Allocate slots for all states sequentially
	nextSlot := 1
	for _, state := range ac.States {
		if state == ac.Root {
			continue
		}
		if nextSlot >= ac.TableSize {
			return fmt.Errorf("transition table too small: need %d slots, have %d", nextSlot, ac.TableSize)
		}
		stateSlots[state] = nextSlot
		usedSlots[nextSlot] = true
		nextSlot++
	}

	// Build transition entries for each state
	for state, slot := range stateSlots {
		// Set failure link
		var failureSlot int
		if state.Failure != nil {
			if fs, ok := stateSlots[state.Failure]; ok {
				failureSlot = fs
			}
		}
		ac.Transitions[slot] = ACMakeTransition(uint32(failureSlot), 0)

		// Set match table entry
		if len(state.Output) > 0 {
			ac.MatchTable[slot] = uint32(state.Output[0]) + 1
		} else {
			ac.MatchTable[slot] = 0
		}

		// Set up transitions for children
		for input, child := range state.Children {
			childSlot, ok := stateSlots[child]
			if !ok {
				return fmt.Errorf("child state not allocated")
			}

			// Store transition: input byte -> child slot
			transitionIndex := slot*256 + int(input)
			if transitionIndex >= ac.TableSize {
				return fmt.Errorf("transition index out of bounds: %d >= %d", transitionIndex, ac.TableSize)
			}

			ac.Transitions[transitionIndex] = ACMakeTransition(uint32(childSlot), uint32(input))
		}
	}

	return nil
}



// Compile compiles the automaton into an optimized form
func (ac *ACAutomaton) Compile() error {
	// Build failure links
	if err := ac.BuildFailureLinks(); err != nil {
		return fmt.Errorf("building failure links: %w", err)
	}

	// Optimize failure links
	if err := ac.OptimizeFailureLinks(); err != nil {
		return fmt.Errorf("optimizing failure links: %w", err)
	}

	// Build transition table
	if err := ac.BuildTransitionTable(); err != nil {
		return fmt.Errorf("building transition table: %w", err)
	}

	return nil
}

// Search searches for all patterns in the given data
func (ac *ACAutomaton) Search(data []byte) []ACMatch {
	var matches []ACMatch
	state := ac.Root

	for i, b := range data {
		// Follow transitions until we can
		for {
			if next, exists := state.Children[b]; exists {
				state = next
				break
			} else if state == ac.Root {
				break
			} else {
				state = state.Failure
			}
		}

		// Check for matches at current state
		for _, stringIndex := range state.Output {
			if stringIndex < len(ac.Strings) {
				matches = append(matches, ACMatch{
					StringIndex: stringIndex,
					StringID:    ac.Strings[stringIndex].Identifier,
					Backtrack:   i + 1 - ac.Strings[stringIndex].Length,
				})
			}
		}
	}

	return matches
}

// GetTransitionTable returns the compiled transition table
func (ac *ACAutomaton) GetTransitionTable() []ACTransition {
	return ac.Transitions
}

// GetMatchTable returns the compiled match table
func (ac *ACAutomaton) GetMatchTable() []uint32 {
	return ac.MatchTable
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
		fmt.Printf("  State %d: depth=%d, children=%d, output=%v\n",
			i, state.Depth, len(state.Children), state.Output)
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
		return fmt.Errorf("automaton has no root")
	}

	// Check that all states are reachable
	visited := make(map[*ACState]bool)
	queue := []*ACState{ac.Root}

	for len(queue) > 0 {
		state := queue[0]
		queue = queue[1:]

		if visited[state] {
			continue
		}
		visited[state] = true

		for _, child := range state.Children {
			queue = append(queue, child)
		}
	}

	if len(visited) != len(ac.States) {
		return fmt.Errorf("not all states are reachable")
	}

	// Check that transition table is properly sized
	if len(ac.Transitions) == 0 && ac.StringCount > 0 {
		return fmt.Errorf("transition table not built")
	}

	return nil
}

// Reset clears the automaton for reuse
func (ac *ACAutomaton) Reset() {
	ac.Root.Children = make(map[byte]*ACState)
	ac.States = []*ACState{ac.Root}
	ac.StringCount = 0
	ac.Strings = ac.Strings[:0]
	ac.TableSize = 0
	ac.Transitions = ac.Transitions[:0]
	ac.MatchTable = ac.MatchTable[:0]
	ac.Bitmask = ac.Bitmask[:0]
}

// Clone creates a copy of the automaton
func (ac *ACAutomaton) Clone() *ACAutomaton {
	newAC := &ACAutomaton{
		Root: &ACState{
			Depth:    ac.Root.Depth,
			Input:    ac.Root.Input,
			Children: make(map[byte]*ACState),
			Failure:  nil, // Will be set during compilation
			Output:   make([]int, len(ac.Root.Output)),
			TableSlot: ac.Root.TableSlot,
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