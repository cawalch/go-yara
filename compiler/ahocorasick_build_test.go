package compiler

import (
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/regex"
)

func TestACConstructionGrowth(t *testing.T) {
	for _, length := range []int{1024, 32768, 65536} {
		t.Run(strconv.Itoa(length), func(t *testing.T) {
			// A long prefix crosses the growth threshold; suffixes exercise failure
			// outputs, duplicates, case aliases, and branches after reallocation.
			prefix := strings.Repeat("\x00", length)
			patterns := []string{prefix + "b", "ab", prefix + "c", "b", prefix + "b"}
			grown := newacAutomaton()
			reserved := newacAutomatonWithCapacity(length+32, len(patterns), len(patterns))
			for iteration := range 2 {
				for i, p := range patterns {
					flags := regex.Flags(0)
					if i == 2 {
						flags = regex.FlagsNoCase
					}
					for _, ac := range []*acAutomaton{grown, reserved} {
						if err := ac.AddStringWithFlags(strconv.Itoa(i), []byte(p), false, false, flags); err != nil {
							t.Fatal(err)
						}
					}
				}
				grew := grown.compactStates
				if iteration == 0 && length == 65536 && !grew {
					t.Fatal("large trie did not exercise doubled growth")
				}
				for _, ac := range []*acAutomaton{grown, reserved} {
					if err := ac.Compile(); err != nil {
						t.Fatal(err)
					}
				}
				if !reflect.DeepEqual(grown.states, reserved.states) || !reflect.DeepEqual(grown.outputs, reserved.outputs) || !reflect.DeepEqual(grown.transitions16, reserved.transitions16) || !reflect.DeepEqual(grown.transitions32, reserved.transitions32) {
					t.Fatal("growth changed compiled states or outputs")
				}
				if grew && cap(grown.states) != len(grown.states) {
					t.Fatalf("retained spare state capacity: %d/%d", len(grown.states), cap(grown.states))
				}
				input := []byte(prefix + "b " + strings.ToUpper(prefix+"c"))
				want := collectACBuildMatches(reserved, input)
				if len(want) == 0 {
					t.Fatal("missing control matches")
				}
				for _, ac := range []*acAutomaton{grown, grown.Clone()} {
					if got := collectACBuildMatches(ac, input); !reflect.DeepEqual(got, want) {
						t.Fatal("growth or clone changed matches")
					}
				}
				grown.Reset()
				reserved.Reset()
			}
		})
	}
}

func collectACBuildMatches(ac *acAutomaton, data []byte) []acMatch {
	var matches []acMatch
	for match := range ac.SearchIter(data) {
		matches = append(matches, match)
	}
	return matches
}
