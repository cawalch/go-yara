package wordmatch

import (
	"crypto/sha256"
	"fmt"
	"math"
	"testing"
)

func TestCompactMandatoryFeatures(t *testing.T) {
	anchor := []byte("SHARED_Anchor_0123456789ABCDE")
	for _, minimum := range []int{0, 1, 2, 255, 256, 257, math.MaxInt} {
		for _, variable := range []bool{false, true} {
			maximum := minimum
			if variable && maximum < math.MaxInt {
				maximum++
			}
			seq := sequence{anchor: 2, terms: Sequence{{Literal: []byte("before")}, {Set: literalSet('x', false), Min: minimum, Max: maximum}, {Literal: anchor, NoCase: true}, {Set: literalSet('y', false), Min: minimum, Max: maximum}, {Literal: []byte("after")}}}
			for phase := 0; phase < 8; phase++ {
				offset := len(anchor) - 15 + phase
				p := &RoutedProgram{}
				features, ok := p.routingFeatures(&seq, offset)
				if !ok {
					t.Fatal("small feature extraction declined")
				}
				want := referenceFeatures(&seq, offset)
				if len(features.sets) != len(want) {
					t.Fatalf("feature count: %d != %d", len(features.sets), len(want))
				}
				for pos := -257; pos <= 257; pos++ {
					got, present := features.at(pos)
					expected, exists := want[pos]
					if got != expected || present != exists {
						t.Fatalf("minimum=%d variable=%v phase=%d offset=%d: compact=%x,%v reference=%x,%v", minimum, variable, phase, pos, got, present, expected, exists)
					}
				}
			}
		}
	}
}

func TestGroupedBuilderPreservesTree(t *testing.T) {
	// Digests captured from the previous map/scoring builder on these ordered inputs.
	expected := []string{
		"da691d6ecb3c879e563fd1d273450f4987323b1f43218074a1e979049cadcef9",
		"7ecf07912ef6e875e50a9ce875d9b3e32a7378270ccd67f7ab8f188b72736807",
		"efabce45da790be504c75a84be2c2450c5fc3b53262543ef7f3ceee3ee7d77f8",
		"d0d92a73ba38f0a915f0e7f6c3268fbd67f427480bd936c008fc6627a62d2ce8",
	}
	for fixture, want := range expected {
		var refs []routeRef
		p := &RoutedProgram{base: &program{postings: make([]posting, 65)}, nodes: []routeNode{{}}}
		for i := 0; i < 32; i++ {
			left := Term{Set: routingSet(byte(i+32), byte(i+33)), Min: 1, Max: 1}
			right := Term{Set: routingSet(byte(128+i%8), byte(129+i%8)), Min: 1, Max: 1}
			if fixture == 1 || fixture == 2 {
				right.Set = literalSet(byte(128+i), false)
			}
			if fixture == 1 {
				left.Min, left.Max = i%3, i%3+1
			}
			if fixture == 2 {
				left.Min, left.Max = 0, 1
				right.Set = literalSet(byte(159-i), false)
			}
			if fixture == 3 {
				left.Set = literalSet(byte('A'+i%20), true)
			}
			seq := sequence{anchor: 1, terms: Sequence{left, {Literal: []byte("SHARED_Anchor_0123456789ABCDE"), NoCase: fixture == 3}, right}}
			features, ok := p.routingFeatures(&seq, 12)
			if !ok {
				t.Fatal("feature budget")
			}
			refs = append(refs, routeRef{id: uint32(i + 1), features: features})
		}
		remaining := 12 * len(refs)
		if _, ok := p.build(refs, buildState{remaining: &remaining}); !ok {
			t.Fatalf("fixture%d declined", fixture)
		}
		got := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%v|%v|%d", p.nodes, p.refs, remaining))))
		if got != want {
			t.Fatalf("fixture%d changed tree, masks or child order: %s", fixture, got)
		}
	}
}

func TestRoutingBuildCaps(t *testing.T) {
	p := &RoutedProgram{}
	if !p.spendBuild(maxRoutingWork) || p.spendBuild(1) || p.work != maxRoutingWork {
		t.Fatal("work cap exceeded")
	}
	seq := sequence{terms: Sequence{{Literal: []byte("long_Anchor_0123456789")}}, anchor: 0}
	p = &RoutedProgram{featureCount: maxRoutingFeatures}
	if _, ok := p.routingFeatures(&seq, 0); ok || p.featureCount != maxRoutingFeatures {
		t.Fatal("feature allocation crossed cap")
	}
	p = &RoutedProgram{work: maxRoutingWork - 1}
	if _, ok := p.routingFeatures(&seq, 0); ok || p.featureCount != 0 {
		t.Fatal("feature allocation preceded work check")
	}
	p = &RoutedProgram{base: &program{postings: make([]posting, 20)}, nodes: []routeNode{{}}, work: maxRoutingWork}
	remaining := 100
	if _, ok := p.build([]routeRef{{id: 1}}, buildState{remaining: &remaining}); ok || len(p.nodes) != 1 || len(p.refs) != 0 {
		t.Fatal("tree mutated after exhausted work")
	}
}

func referenceFeatures(seq *sequence, offset int) map[int]byteSet {
	features := make(map[int]byteSet)
	put := func(pos int, set byteSet) {
		if pos >= -256 && pos <= 256 && (pos < 0 || pos >= 8) {
			features[pos] = set
		}
	}
	anchor := seq.terms[seq.anchor]
	for i := max(0, offset-256); i < len(anchor.Literal) && i <= offset+256; i++ {
		put(i-offset, literalSet(anchor.Literal[i], anchor.NoCase))
	}
	for _, direction := range []int{-1, 1} {
		pos := -offset - 1
		if direction == 1 {
			pos = len(anchor.Literal) - offset
		}
		for i := seq.anchor + direction; i >= 0 && i < len(seq.terms); i += direction {
			term := seq.terms[i]
			length := len(term.Literal)
			if length == 0 {
				length = term.Min
			}
			for j := 0; j < length && pos >= -256 && pos <= 256; j++ {
				set := term.Set
				if len(term.Literal) > 0 {
					index := j
					if direction == -1 {
						index = length - 1 - j
					}
					set = literalSet(term.Literal[index], term.NoCase)
				}
				put(pos, set)
				pos += direction
			}
			if pos < -256 || pos > 256 || len(term.Literal) == 0 && term.Min != term.Max {
				break
			}
		}
	}
	return features
}
