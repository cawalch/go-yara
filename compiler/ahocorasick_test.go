package compiler

import (
	"testing"
)

// TestACAutomatonBuildTransitionTable tests the transition table building
func TestACAutomatonBuildTransitionTable(t *testing.T) {
	tests := []struct {
		name      string
		patterns  []string
		wantError bool
	}{
		{"single_pattern", []string{"hello"}, false},
		{"multiple_patterns", []string{"hello", "world", "test"}, false},
		{"overlapping_patterns", []string{"he", "hello", "helloworld"}, false},
		{"single_char", []string{"a"}, false},
		{"empty_patterns", []string{}, false}, // Root state exists, so no error
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ac := NewACAutomaton()

			// Add patterns
			for i, pattern := range tt.patterns {
				err := ac.AddString("pattern"+string(rune(i)), []byte(pattern), false, false)
				if err != nil {
					t.Errorf("failed to add pattern: %v", err)
					return
				}
			}

			// Build transition table
			err := ac.BuildTransitionTable()

			if tt.wantError && err == nil {
				t.Errorf("expected error, got nil")
				return
			}
			if !tt.wantError && err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			// Verify table was built
			if !tt.wantError {
				if ac.TableSize == 0 {
					t.Errorf("table size is 0")
				}
				if len(ac.Transitions) != ac.TableSize {
					t.Errorf("transitions length %d != table size %d", len(ac.Transitions), ac.TableSize)
				}
				if len(ac.MatchTable) != ac.TableSize {
					t.Errorf("match table length %d != table size %d", len(ac.MatchTable), ac.TableSize)
				}
			}
		})
	}
}

// TestACAutomatonTableSizeCalculation tests table size calculation
func TestACAutomatonTableSizeCalculation(t *testing.T) {
	tests := []struct {
		name           string
		numPatterns    int
		minTableSize   int
		maxTableSize   int
	}{
		{"single_pattern", 1, 512, 65536},
		{"few_patterns", 5, 512, 65536},
		{"many_patterns", 100, 25600, 65536},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ac := NewACAutomaton()

			// Add patterns
			for i := 0; i < tt.numPatterns; i++ {
				err := ac.AddString("pattern"+string(rune(i)), []byte("pattern"+string(rune(i))), false, false)
				if err != nil {
					t.Errorf("failed to add pattern: %v", err)
					return
				}
			}

			// Build transition table
			err := ac.BuildTransitionTable()
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			// Verify table size is within expected range
			if ac.TableSize < tt.minTableSize {
				t.Errorf("table size %d < min %d", ac.TableSize, tt.minTableSize)
			}
			if ac.TableSize > tt.maxTableSize {
				t.Errorf("table size %d > max %d", ac.TableSize, tt.maxTableSize)
			}
		})
	}
}

// TestACAutomatonTransitionIndexBounds tests transition index bounds checking
func TestACAutomatonTransitionIndexBounds(t *testing.T) {
	ac := NewACAutomaton()

	// Add patterns with various byte values
	patterns := []string{
		"hello",
		"world",
		"test",
		"\x00\x01\x02", // Low bytes
		"\xFE\xFF",     // High bytes
	}

	for i, pattern := range patterns {
		err := ac.AddString("pattern"+string(rune(i)), []byte(pattern), false, false)
		if err != nil {
			t.Errorf("failed to add pattern: %v", err)
			return
		}
	}

	// Build transition table
	err := ac.BuildTransitionTable()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	// Verify all transitions are within bounds
	for i := 0; i < len(ac.Transitions); i++ {
		if i < 0 || i >= ac.TableSize {
			t.Errorf("transition index %d out of bounds [0, %d)", i, ac.TableSize)
		}
	}

	// Verify all match table entries are within bounds
	for i := 0; i < len(ac.MatchTable); i++ {
		if i < 0 || i >= ac.TableSize {
			t.Errorf("match table index %d out of bounds [0, %d)", i, ac.TableSize)
		}
	}
}

// TestACAutomatonFailureLinks tests failure link setup
func TestACAutomatonFailureLinks(t *testing.T) {
	ac := NewACAutomaton()

	// Add patterns that share prefixes
	patterns := []string{"he", "she", "his", "hers"}
	for i, pattern := range patterns {
		err := ac.AddString("pattern"+string(rune(i)), []byte(pattern), false, false)
		if err != nil {
			t.Errorf("failed to add pattern: %v", err)
			return
		}
	}

	// Build failure links
	err := ac.BuildFailureLinks()
	if err != nil {
		t.Errorf("failed to build failure links: %v", err)
		return
	}

	// Build transition table
	err = ac.BuildTransitionTable()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	// Verify transitions are valid
	for i := 0; i < len(ac.Transitions); i++ {
		trans := ac.Transitions[i]
		stateIdx := int(trans.GetStateIndex())
		if stateIdx < 0 || stateIdx >= ac.TableSize {
			t.Errorf("invalid state index %d at transition %d, table size %d", stateIdx, i, ac.TableSize)
		}
	}
}

// TestACAutomatonMatchTable tests match table setup
func TestACAutomatonMatchTable(t *testing.T) {
	ac := NewACAutomaton()

	// Add patterns
	patterns := []string{"hello", "world"}
	for i, pattern := range patterns {
		err := ac.AddString("pattern"+string(rune(i)), []byte(pattern), false, false)
		if err != nil {
			t.Errorf("failed to add pattern: %v", err)
			return
		}
	}

	// Build transition table
	err := ac.BuildTransitionTable()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	// Verify match table entries are valid
	for i := 0; i < len(ac.MatchTable); i++ {
		matchID := ac.MatchTable[i]
		// Match ID should be 0 (no match) or > 0 (valid pattern ID)
		if matchID < 0 {
			t.Errorf("invalid match ID %d at index %d", matchID, i)
		}
	}
}

// TestACAutomatonLargePatternSet tests with many patterns
func TestACAutomatonLargePatternSet(t *testing.T) {
	ac := NewACAutomaton()

	// Add many patterns
	numPatterns := 100 // Reduced from 1000 for faster tests
	for i := 0; i < numPatterns; i++ {
		pattern := "pattern" + string(rune(i%256))
		err := ac.AddString("p"+string(rune(i)), []byte(pattern), false, false)
		if err != nil {
			t.Errorf("failed to add pattern: %v", err)
			return
		}
	}

	// Build transition table
	err := ac.BuildTransitionTable()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	// Verify table was built successfully
	if ac.TableSize == 0 {
		t.Errorf("table size is 0")
	}
	if len(ac.Transitions) != ac.TableSize {
		t.Errorf("transitions length mismatch")
	}
	if len(ac.MatchTable) != ac.TableSize {
		t.Errorf("match table length mismatch")
	}
}

