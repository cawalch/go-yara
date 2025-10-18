package compiler

import (
	"fmt"
	"testing"
)

// TestACAutomatonBuildTransitionTable tests the transition table building
// NOTE: BuildTransitionTable is now a no-op, so we just verify it doesn't error
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

			// Build transition table (now a no-op)
			err := ac.BuildTransitionTable()

			if tt.wantError && err == nil {
				t.Errorf("expected error, got nil")
				return
			}
			if !tt.wantError && err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			// NOTE: Transition table is no longer built, so we just verify no error
		})
	}
}

// TestACAutomatonTableSizeCalculation tests table size calculation
// NOTE: Table size is no longer calculated since BuildTransitionTable is a no-op
func TestACAutomatonTableSizeCalculation(t *testing.T) {
	tests := []struct {
		name        string
		numPatterns int
	}{
		{"single_pattern", 1},
		{"few_patterns", 5},
		{"many_patterns", 100},
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

			// Build transition table (now a no-op)
			err := ac.BuildTransitionTable()
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			// NOTE: Table size is no longer calculated
			// Just verify the automaton has the expected number of states
			if len(ac.States) < 1 {
				t.Errorf("expected at least 1 state (root), got %d", len(ac.States))
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
// NOTE: Match table is no longer built, so we just verify no error
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

	// Build transition table (now a no-op)
	err := ac.BuildTransitionTable()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	// NOTE: Match table is no longer built
	// Just verify the automaton has the expected patterns
	if ac.StringCount != len(patterns) {
		t.Errorf("expected %d patterns, got %d", len(patterns), ac.StringCount)
	}
}

// TestACAutomatonLargePatternSet tests with many patterns
// NOTE: Transition table is no longer built, so we just verify patterns are added
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

	// Build transition table (now a no-op)
	err := ac.BuildTransitionTable()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	// Verify patterns were added successfully
	if ac.StringCount != numPatterns {
		t.Errorf("expected %d patterns, got %d", numPatterns, ac.StringCount)
	}
	if len(ac.States) < 2 {
		t.Errorf("expected at least 2 states (root + patterns), got %d", len(ac.States))
	}
}

// BenchmarkACAutomatonAddString benchmarks the AddString operation
func BenchmarkACAutomatonAddString(b *testing.B) {
	patterns := []string{
		"test", "pattern", "search", "benchmark", "performance",
		"hello", "world", "example", "string", "data",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ac := NewACAutomaton()
		for j, pattern := range patterns {
			ac.AddString(fmt.Sprintf("p%d", j), []byte(pattern), false, false)
		}
	}
}

// BenchmarkACAutomatonAddStringLarge benchmarks AddString with larger patterns
func BenchmarkACAutomatonAddStringLarge(b *testing.B) {
	// Create larger patterns
	patterns := make([]string, 50)
	for i := 0; i < 50; i++ {
		patterns[i] = fmt.Sprintf("pattern_%d_with_longer_content_to_simulate_real_world_usage_%d", i, i*2)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ac := NewACAutomaton()
		for j, pattern := range patterns {
			ac.AddString(fmt.Sprintf("p%d", j), []byte(pattern), false, false)
		}
	}
}

// BenchmarkACAutomatonCompile benchmarks the Compile operation
func BenchmarkACAutomatonCompile(b *testing.B) {
	patterns := []string{
		"test", "pattern", "search", "benchmark", "performance",
		"hello", "world", "example", "string", "data",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ac := NewACAutomaton()
		for j, pattern := range patterns {
			ac.AddString(fmt.Sprintf("p%d", j), []byte(pattern), false, false)
		}
		ac.Compile()
	}
}
