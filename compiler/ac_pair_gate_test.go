package compiler

import (
	"math/rand"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/regex"
)

func TestACPairGateParity(t *testing.T) {
	var fixtures [][]byte
	for i, root := range "ABCDEFGHIJKLMNOPQRSTUVWX" {
		fixtures = append(fixtures, []byte(string(root)+"event"+strings.Repeat("a", i)+"__token"))
	}
	build := func(patterns [][]byte) *ACAutomaton {
		t.Helper()
		ac := NewACAutomaton()
		for _, p := range patterns {
			if err := ac.AddString(string(p), p, false, false); err != nil {
				t.Fatal(err)
			}
		}
		if err := ac.Compile(); err != nil {
			t.Fatal(err)
		}
		return ac
	}
	ac := build(fixtures)
	for _, pairOffset := range []int{0, 1, 4094, 4095, 4096, 8190, 8191, 8192} {
		offset := max(0, pairOffset-ac.pairGate.lookbehind)
		data := append([]byte(strings.Repeat(".", offset)), fixtures[23]...)
		gate := ac.pairGate
		ac.pairGate = nil
		want := slices.Collect(ac.SearchIter(data))
		ac.pairGate = gate
		if got := slices.Collect(ac.SearchIter(data)); !reflect.DeepEqual(got, want) {
			t.Fatalf("offset %d mismatch", offset)
		}
		if got := slices.Collect(ac.searchIterWithCancel(data, make(chan struct{}))); !reflect.DeepEqual(got, want) {
			t.Fatalf("offset %d cancelable mismatch", offset)
		}
	}
	r := rand.New(rand.NewSource(72))
	for iteration := 0; iteration < 80; iteration++ {
		patterns := slices.Clone(fixtures)
		for range 20 {
			p := make([]byte, 2+r.Intn(18))
			r.Read(p)
			patterns = append(patterns, p)
		}
		patterns = append(patterns, []byte("aba"), []byte("ababa"), []byte("ba"))
		ac := build(patterns)
		if ac.pairGate == nil {
			t.Fatal("missing gate")
		}
		for _, short := range [][]byte{nil, {}, {0}, {255}} {
			if got := slices.Collect(ac.SearchIter(short)); len(got) > 0 {
				t.Fatal("short input matched")
			}
		}
		data := make([]byte, 8193+r.Intn(20))
		r.Read(data)
		for _, offset := range []int{0, 1, 4050, 4094, 4095, 4096, 8190} {
			copy(data[offset:], patterns[r.Intn(len(patterns))])
		}
		copy(data[5000:], "abababa")
		gate := ac.pairGate
		ac.pairGate = nil
		want := slices.Collect(ac.SearchIter(data))
		ac.pairGate = gate
		got := slices.Collect(ac.SearchIter(data))
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("iteration%d plain mismatch", iteration)
		}
		done := make(chan struct{})
		got = slices.Collect(ac.searchIterWithCancel(data, done))
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("iteration%d cancelable mismatch", iteration)
		}
		close(done)
		if got := slices.Collect(ac.searchIterWithCancel(data, done)); len(got) != 0 {
			t.Fatal("canceled scan matched")
		}
		if got := slices.Collect(ac.Clone().SearchIter(data)); !reflect.DeepEqual(got, want) {
			t.Fatal("clone mismatch")
		}
		ac.Reset()
		if ac.pairGate != nil {
			t.Fatal("reset retained gate")
		}
	}
	for _, extra := range [][]byte{nil, {'a'}} {
		patterns := append(slices.Clone(fixtures), extra)
		ac := build(patterns)
		if ac.pairGate != nil {
			t.Fatal("short pattern enabled gate")
		}
	}
	ac = NewACAutomaton()
	for i, p := range fixtures {
		flags := regex.Flags(0)
		if i == 0 {
			flags = regex.FlagsNoCase
		}
		if err := ac.AddStringWithFlags(string(p), p, false, false, flags); err != nil {
			t.Fatal(err)
		}
	}
	if err := ac.Compile(); err != nil {
		t.Fatal(err)
	}
	if ac.pairGate != nil {
		t.Fatal("nocase enabled gate")
	}
}
