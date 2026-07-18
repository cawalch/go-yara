package compiler

import (
	"bytes"
	"fmt"
	"slices"
	"testing"

	"github.com/cawalch/go-yara/regex"
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
	var matches []ACMatch
	for match := range ac.SearchIter(testData) {
		matches = append(matches, match)
	}

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
	var matches []ACMatch
	for match := range ac.SearchIter(testData) {
		matches = append(matches, match)
	}

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

func TestACAutomatonSinglePatternFastPath(t *testing.T) {
	tests := []struct {
		name    string
		pattern []byte
		flags   regex.Flags
		data    []byte
		want    []int
	}{
		{
			name:    "case sensitive overlaps",
			pattern: []byte("aba"),
			data:    []byte("ababa"),
			want:    []int{0, 2},
		},
		{
			name:    "nocase overlaps",
			pattern: []byte("aba"),
			flags:   regex.FlagsNoCase,
			data:    []byte("AbABa"),
			want:    []int{0, 2},
		},
		{
			name:    "nocase frequent first byte without match",
			pattern: []byte("exp"),
			flags:   regex.FlagsNoCase,
			data:    bytes.Repeat([]byte("e"), 256),
		},
		{
			name:    "wide nocase",
			pattern: []byte{'h', 0, 'i', 0},
			flags:   regex.FlagsWide | regex.FlagsNoCase,
			data:    []byte{'x', 0, 'H', 0, 'I', 0, 'x'},
			want:    []int{2},
		},
		{
			name:    "pattern longer than data",
			pattern: []byte("long pattern"),
			data:    []byte("short"),
		},
		{
			name:    "dense matches fall back to automaton",
			pattern: []byte("aa"),
			data:    []byte("aaaaaaaaaaaa"),
			want:    []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ac := NewACAutomaton()
			if err := ac.AddStringWithFlags("single", tt.pattern, false, false, tt.flags); err != nil {
				t.Fatal(err)
			}
			if err := ac.Compile(); err != nil {
				t.Fatal(err)
			}

			var got []int
			for match := range ac.SearchIter(tt.data) {
				got = append(got, match.Backtrack)
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("match offsets = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRootCandidateCursorAdvancesEachLaneMonotonically(t *testing.T) {
	cursor := newRootCandidateCursor([]byte{'c', 'n'})
	data := []byte("nxn--c-n")
	for _, query := range []struct {
		from int
		want int
	}{
		{from: 0, want: 0},
		{from: 1, want: 2},
		{from: 3, want: 5},
		{from: 6, want: 7},
		{from: 8, want: -1},
	} {
		if got := cursor.next(data, query.from); got != query.want {
			t.Fatalf("next(from=%d) = %d, want %d", query.from, got, query.want)
		}
	}
}

func TestACAutomatonSparseRootsWithAbsentAndDenseLanes(t *testing.T) {
	patterns := []string{"cardnumber", "cardnum", "ccnumber", "cardholder", "nameoncard"}
	ac := NewACAutomaton()
	for _, pattern := range patterns {
		if err := ac.AddString(pattern, []byte(pattern), false, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := ac.Compile(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ac.rootBytes, []byte{'c', 'n'}) {
		t.Fatalf("root bytes = %q, want %q", ac.rootBytes, []byte{'c', 'n'})
	}

	data := bytes.Repeat([]byte("benignFillerCode123 "), 32)
	data = append(data, []byte("cardnumber cardnum ccnumber cardholder nameoncard")...)
	counts := make(map[string]int, len(patterns))
	for match := range ac.SearchIter(data) {
		counts[match.StringID]++
	}
	for _, pattern := range patterns {
		want := 1
		if pattern == "cardnum" {
			want = 2
		}
		if counts[pattern] != want {
			t.Errorf("%s matches = %d, want %d", pattern, counts[pattern], want)
		}
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
