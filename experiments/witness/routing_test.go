package witness

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"testing"
)

func checkRouting(t testing.TB, rules []Rule, inputs [][]byte, active bool) *RoutedProgram {
	t.Helper()
	program, err := CompileRouted(rules)
	if err != nil {
		t.Fatal(err)
	}
	stats := program.Stats()
	if active && stats.Nodes <= stats.Leaves {
		t.Fatalf("fixture did not exercise routing: %+v", stats)
	}
	if stats.MaxLeaf > 8 {
		t.Fatalf("unbounded routed leaf: %+v", stats)
	}
	scanner := program.NewScanner()
	for _, data := range inputs {
		want := NoMatch
		if referenceMatch(rules, data) {
			want = Match
		}
		for _, budget := range []int{1 << 20, 0, 1, 16} {
			scanner.exact.budgetLimit = budget
			got := scanner.Match(data)
			if got == Unknown {
				if !scanner.exact.exhausted || budget == 1<<20 {
					t.Fatalf("unexpected exhaustion with budget %d, input %x", budget, data)
				}
			} else if got != want {
				t.Fatalf("budget %d, input %x: %v != %v", budget, data, got, want)
			}
		}
	}
	return program
}

func routingSet(first, last byte) (set [4]uint64) {
	for b := int(first); b <= int(last); b++ {
		set[b/64] |= uint64(1) << (b % 64)
	}
	return
}

func TestRoutingSignedContextsAndPhases(t *testing.T) {
	anchor := []byte("WITNESS_SHARED_0123456789")
	for _, backwards := range []bool{false, true} {
		t.Run(fmt.Sprint(backwards), func(t *testing.T) {
			var rules []Rule
			var inputs [][]byte
			for i := 0; i < 24; i++ {
				guard := Term{Set: routingSet(byte('A'+i), byte('A'+i)), Min: 1, Max: 1}
				sequence := Sequence{{Literal: anchor}, guard}
				if backwards {
					sequence = Sequence{guard, {Literal: anchor}}
				}
				rules = append(rules, Rule{All: []Pattern{{Any: []Sequence{sequence}}}})
			}
			for offset := 0; offset < 32; offset++ {
				for tail := 0; tail < 8; tail++ {
					body := append(bytes.Clone(anchor), byte('A'+offset%24))
					if backwards {
						body = append([]byte{byte('A' + offset%24)}, anchor...)
					}
					data := append(bytes.Repeat([]byte{0xff}, offset), body...)
					data = append(data, bytes.Repeat([]byte{0xff}, tail)...)
					if !referenceMatch(rules, data) {
						t.Fatal("oracle rejected constructed positive")
					}
					inputs = append(inputs, data)
				}
			}
			inputs = append(inputs, nil, anchor, anchor[:7], bytes.Repeat([]byte{0}, 64))
			program := checkRouting(t, rules, inputs, true)
			for _, node := range program.nodes[1:] {
				if node.count == 0 && (backwards && node.offset >= 0 || !backwards && node.offset < 8) {
					t.Fatalf("routing fixture did not probe expected side: %+v", node)
				}
			}
		})
	}
}

func TestRoutingVariableClassesAndAlternatives(t *testing.T) {
	anchor := []byte("VARIABLE_SHARED_0123456789")
	var rules []Rule
	var inputs [][]byte
	for i := 0; i < 16; i++ {
		var alternatives []Sequence
		for shift := 0; shift < 2; shift++ {
			first := byte(32 + 8*i + 4*shift)
			set := routingSet(first, first+4)
			alternatives = append(alternatives, Sequence{{Literal: []byte("!")}, {Set: set, Min: 1, Max: 3}, {Literal: anchor}, {Set: routingSet('0', '9'), Max: 2}})
			for length := 1; length <= 3; length++ {
				body := append([]byte("!"), bytes.Repeat([]byte{first + 2}, length)...)
				body = append(body, anchor...)
				body = append(body, []byte("7 ok")...)
				inputs = append(inputs, body, append([]byte("ok "), body...))
			}
		}
		rules = append(rules, Rule{All: []Pattern{{Any: alternatives}, {Any: []Sequence{{{Literal: []byte("ok")}}}}}})
	}
	for _, data := range inputs {
		if !referenceMatch(rules, data) {
			t.Fatal("oracle rejected class/alternative positive")
		}
	}
	inputs = append(inputs, anchor, append([]byte("ok !"), anchor...), append([]byte("!"), append(bytes.Repeat([]byte{0xff}, 3), anchor...)...), nil)
	checkRouting(t, rules, inputs, true)
}

func TestRoutingProjectionAndCaseAliases(t *testing.T) {
	var rules []Rule
	var inputs [][]byte
	for i, first := range []byte{0, 0x20, 0x80, 0xa0, '@', '`', 'A', 'a', 'B', 'b', 'C', 'c', 'D', 'd', 'E', 'e'} {
		literal := append([]byte{first}, []byte("SameWord_0123456789ABCDE")...)
		rules = append(rules, Rule{All: []Pattern{{Any: []Sequence{{{Literal: literal, NoCase: i%3 == 0}}}}}})
		inputs = append(inputs, literal, bytes.ToUpper(literal), bytes.ToLower(literal))
	}
	inputs = append(inputs, []byte("SameWord_0123456789ABCDE"), []byte("zSameWord_0123456789ABCDE"), nil)
	checkRouting(t, rules, inputs, true)
}

func TestRoutingDeclinesAndCompileBounds(t *testing.T) {
	for length := 1; length < 15; length++ {
		rules := []Rule{{All: []Pattern{{Any: []Sequence{{{Literal: bytes.Repeat([]byte{'X'}, length)}}}}}}}
		if program, err := CompileRouted(rules); !errors.Is(err, ErrIneligible) || program != nil {
			t.Fatalf("short witness %d: program=%v error=%v", length, program, err)
		}
		if !referenceMatch(rules, bytes.Repeat([]byte{'X'}, length)) {
			t.Fatal("declined portfolio has a real positive")
		}
	}
	anchor := []byte("long_shared_0123456789")
	rules := []Rule{{All: []Pattern{{Any: []Sequence{{{Literal: anchor}}, {{Literal: []byte("X")}}}}}}}
	if _, err := CompileRouted(rules); !errors.Is(err, ErrIneligible) {
		t.Fatalf("short alternative: %v", err)
	}
	var unresolved []Rule
	for i := 0; i < 32; i++ {
		unresolved = append(unresolved, Rule{All: []Pattern{{Any: []Sequence{{{Literal: bytes.Repeat([]byte{'a'}, 128)}}}}, {Any: []Sequence{{{Literal: []byte{byte(i)}}}}}}})
	}
	if program, err := CompileRouted(unresolved); !errors.Is(err, ErrIneligible) || program != nil {
		t.Fatalf("unresolvable fanout: program=%v error=%v", program, err)
	}
	for _, sequence := range []Sequence{nil, {{Min: 1, Max: 2}}, {{Literal: anchor}, {Min: 2, Max: 1}}, append(make(Sequence, 64), Term{Literal: anchor})} {
		if _, err := CompileRouted([]Rule{{All: []Pattern{{Any: []Sequence{sequence}}}}}); err == nil {
			t.Fatal("accepted malformed sequence")
		}
	}
	checkRouting(t, nil, [][]byte{nil, anchor}, false)
	checkRouting(t, []Rule{{}}, [][]byte{nil, anchor}, false)
}

func TestRoutingOwnershipBudgetAndUnconstrainedEdges(t *testing.T) {
	anchor := []byte("OWNED_SHARED_0123456789")
	var rules []Rule
	for i := 0; i < 16; i++ {
		rules = append(rules, Rule{All: []Pattern{{Any: []Sequence{{{Set: routingSet(byte(i), byte(i)), Min: 1, Max: 1}, {Literal: anchor}}}}}})
	}
	positive := append([]byte{0}, anchor...)
	program := checkRouting(t, rules, [][]byte{positive, nil, anchor, positive}, true)
	anchor[0] = 'x'
	rules[0].All[0].Any[0][0].Set = [4]uint64{}
	scanner := program.NewScanner()
	scanner.exact.budgetLimit = 1
	if got := scanner.Match(positive); got != Unknown {
		t.Fatalf("budget exhaustion = %v", got)
	}
	scanner.exact.budgetLimit = 16384
	if got := scanner.Match(positive); got != Match {
		t.Fatalf("copy or budget reset lost positive: %v", got)
	}
	// Removing a mandatory guard can make its byte unavailable for the entire bucket.
	rules = append(rules, Rule{All: []Pattern{{Any: []Sequence{{{Literal: anchor}}}}}})
	for i := range rules[:16] {
		rules[i].All[0].Any[0][0].Set = routingSet(byte(i), byte(i))
	}
	program, err := CompileRouted(rules)
	if err != nil && !errors.Is(err, ErrIneligible) {
		t.Fatal(err)
	}
	if err == nil {
		checkRouting(t, rules, [][]byte{anchor, append(anchor, 0)}, false)
	}
}

func FuzzRoutingParity(f *testing.F) {
	f.Add([]byte("near shared anchor"), []byte("sample"))
	f.Add([]byte{0, 0xff, 0x80}, []byte{0, 0xff})
	f.Fuzz(func(t *testing.T, data, middle []byte) {
		if len(data) > 128 {
			data = data[:128]
		}
		if len(middle) > 31 {
			middle = middle[:31]
		}
		anchor := append(append([]byte("routed_"), middle...), []byte("_0123456789ABCDE")...)
		var rules []Rule
		for i := 0; i < 9; i++ {
			rules = append(rules, Rule{All: []Pattern{{Any: []Sequence{{
				{Literal: []byte("!")}, {Set: routingSet(byte(128+i), byte(128+i)), Min: 1, Max: 2},
				{Literal: anchor, NoCase: i%2 == 0}, {Set: [4]uint64{math.MaxUint64, math.MaxUint64, math.MaxUint64, math.MaxUint64}, Max: 2},
			}}}}})
		}
		positive := append(append(append(bytes.Clone(data), '!'), 128), anchor...)
		if !referenceMatch(rules, positive) {
			t.Fatal("oracle rejected constructed positive")
		}
		checkRouting(t, rules, [][]byte{data, positive, nil}, true)
	})
}
