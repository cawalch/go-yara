package compiler

import (
	"fmt"
	"testing"
)

// TestACAutomaton tests the Aho-Corasick automaton
func TestACAutomaton(t *testing.T) {
	ac := NewACAutomaton()

	// Test adding strings
	testStrings := []struct {
		id   string
		data string
	}{
		{"test1", "hello"},
		{"test2", "world"},
		{"test3", "hello world"},
	}

	for _, ts := range testStrings {
		err := ac.AddString(ts.id, []byte(ts.data), false, false)
		if err != nil {
			t.Errorf("Failed to add string %s: %v", ts.id, err)
		}
	}

	// Test compilation
	err := ac.Compile()
	if err != nil {
		t.Errorf("Automaton compilation failed: %v", err)
	}

	// Test search
	testData := []byte("hello world")
	matches := ac.Search(testData)

	if len(matches) == 0 {
		t.Error("Expected matches but found none")
	}

	// Check that we found our test strings
	found := make(map[string]bool)
	for _, match := range matches {
		found[match.StringID] = true
	}

	for _, ts := range testStrings {
		if !found[ts.id] {
			t.Errorf("Expected to find string %s in matches", ts.id)
		}
	}
}

// TestACAutomatonSearch tests pattern searching
func TestACAutomatonSearch(t *testing.T) {
	ac := NewACAutomaton()

	// Add test patterns
	patterns := []string{"test", "pattern", "search"}
	for i, pattern := range patterns {
		err := ac.AddString(fmt.Sprintf("p%d", i), []byte(pattern), false, false)
		if err != nil {
			t.Errorf("Failed to add pattern %s: %v", pattern, err)
		}
	}

	// Compile automaton
	err := ac.Compile()
	if err != nil {
		t.Errorf("Automaton compilation failed: %v", err)
	}

	// Test search
	testData := []byte("This is a test pattern for searching")
	matches := ac.Search(testData)

	if len(matches) == 0 {
		t.Error("Expected to find matches in test data")
	}

	// Verify matches
	foundPatterns := make(map[string]bool)
	for _, match := range matches {
		foundPatterns[match.StringID] = true
	}

	// Should find "test" and "pattern"
	if !foundPatterns["p0"] || !foundPatterns["p1"] {
		t.Error("Expected to find test and pattern matches")
	}
}

// TestACAutomatonClone tests Clone method
func TestACAutomatonClone(t *testing.T) {
	ac := NewACAutomaton()
	if err := ac.AddString("test", []byte("test"), false, false); err != nil {
		t.Fatalf("Failed to add string: %v", err)
	}
	if err := ac.Compile(); err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	cloned := ac.Clone()
	if cloned == nil {
		t.Errorf("Clone() returned nil")
		return
	}

	// Clone is a simplified version that copies basic info
	if cloned.StringCount != ac.StringCount {
		t.Errorf("Clone() StringCount = %d, want %d", cloned.StringCount, ac.StringCount)
	}

	if len(cloned.Strings) != len(ac.Strings) {
		t.Errorf("Clone() Strings length = %d, want %d", len(cloned.Strings), len(ac.Strings))
	}
}

// TestACAutomatonEdgeCases tests edge cases in Aho-Corasick automaton
func TestACAutomatonEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		strings []string
		wantErr bool
	}{
		{
			name:    "empty_automaton",
			strings: []string{},
			wantErr: false,
		},
		{
			name:    "single_string",
			strings: []string{"test"},
			wantErr: false,
		},
		{
			name:    "duplicate_strings",
			strings: []string{"test", "test"},
			wantErr: false,
		},
		{
			name:    "overlapping_strings",
			strings: []string{"test", "est", "st"},
			wantErr: false,
		},
		{
			name:    "prefix_strings",
			strings: []string{"a", "ab", "abc", "abcd"},
			wantErr: false,
		},
		{
			name:    "suffix_strings",
			strings: []string{"d", "cd", "bcd", "abcd"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ac := NewACAutomaton()
			for _, s := range tt.strings {
				if err := ac.AddString(s, []byte(s), false, false); err != nil {
					t.Fatalf("Failed to add string %s: %v", s, err)
				}
			}
			err := ac.Compile()
			if (err != nil) != tt.wantErr {
				t.Errorf("Compile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestACTransitionGetStateIndex tests GetStateIndex method
func TestACTransitionGetStateIndex(t *testing.T) {
	transition := ACMakeTransition(42, 10)
	index := transition.GetStateIndex()
	if index != 42 {
		t.Errorf("GetStateIndex() = %d, want 42", index)
	}
}

// TestACTransitionGetOffset tests GetOffset method
func TestACTransitionGetOffset(t *testing.T) {
	transition := ACMakeTransition(42, 10)
	offset := transition.GetOffset()
	if offset != 10 {
		t.Errorf("GetOffset() = %d, want 10", offset)
	}
}

// TestACAutomatonGetTransitionTable tests GetTransitionTable method
// NOTE: Transition table is no longer built, so this returns nil
func TestACAutomatonGetTransitionTable(t *testing.T) {
	ac := NewACAutomaton()
	if err := ac.AddString("test", []byte("test"), false, false); err != nil {
		t.Fatalf("Failed to add string: %v", err)
	}
	if err := ac.Compile(); err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	table := ac.GetTransitionTable()
	if table != nil {
		t.Errorf("GetTransitionTable() returned %v, want nil", table)
	}
}

// TestACAutomatonGetMatchTable tests GetMatchTable method
// NOTE: Match table is no longer built, so this returns nil
func TestACAutomatonGetMatchTable(t *testing.T) {
	ac := NewACAutomaton()
	if err := ac.AddString("test", []byte("test"), false, false); err != nil {
		t.Fatalf("Failed to add string: %v", err)
	}
	if err := ac.Compile(); err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	table := ac.GetMatchTable()
	if table != nil {
		t.Errorf("GetMatchTable() returned %v, want nil", table)
	}
}

// TestACAutomatonGetTableSize tests GetTableSize method
// NOTE: Table size is no longer calculated, so this returns 0
func TestACAutomatonGetTableSize(t *testing.T) {
	ac := NewACAutomaton()
	if err := ac.AddString("test", []byte("test"), false, false); err != nil {
		t.Fatalf("Failed to add string: %v", err)
	}
	if err := ac.Compile(); err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	size := ac.GetTableSize()
	if size != 0 {
		t.Errorf("GetTableSize() = %d, want 0", size)
	}
}

// TestACAutomatonPrintDebug tests PrintDebug method
func TestACAutomatonPrintDebug(_ *testing.T) {
	ac := NewACAutomaton()
	if err := ac.AddString("test", []byte("test"), false, false); err != nil {
		// Since this is a debug function that just shouldn't panic, we can log the error
		return
	}
	if err := ac.Compile(); err != nil {
		// Since this is a debug function that just shouldn't panic, we can log the error
		return
	}

	// This should not panic
	ac.PrintDebug()
}
