package wordmatch

import (
	"errors"
	"fmt"
	"math/bits"
	"sort"
)

var ErrIneligible = errors.New("portfolio unsuitable for witness routing")

type byteSet = [4]uint64
type routeNode struct {
	allowed, test byteSet
	yes, no       uint32
	first, count  uint32
	offset        int
}

// RoutedProgram is immutable and may be shared between scanners.
type RoutedProgram struct {
	base  *program
	roots []uint32
	nodes []routeNode
	refs  []uint32
	work  int
}

// RoutedScanner reuses scratch storage and is not safe for concurrent use.
type RoutedScanner struct {
	plan  *RoutedProgram
	exact *verifier
}
type routeRef struct {
	id       uint32
	features map[int]byteSet
}

func CompileRouted(rules []Rule) (*RoutedProgram, error) {
	base, err := compile(rules)
	if err != nil {
		return nil, err
	}
	p := &RoutedProgram{base: base, roots: make([]uint32, len(base.postings)), nodes: []routeNode{{}}}
	for _, slot := range base.lane.table {
		var ids []uint32
		for id := slot.head; id != 0; id = base.postings[id].next {
			ids = append(ids, id)
		}
		if len(ids) <= 8 {
			continue
		}
		refs := make([]routeRef, len(ids))
		for i, id := range ids {
			ref := base.postings[id]
			r := &base.rules[ref.rule]
			seq := &r.all[r.trigger].alternatives[ref.alternative]
			refs[i] = routeRef{id: id, features: routingFeatures(seq, ref.offset)}
		}
		remaining := len(ids) * 12
		root, ok := p.build(refs, 0, &remaining)
		if !ok {
			return nil, fmt.Errorf("%w: unresolved bucket or compile limit", ErrIneligible)
		}
		p.roots[slot.head] = root
	}
	return p, nil
}

func (p *RoutedProgram) NewScanner() *RoutedScanner {
	return &RoutedScanner{plan: p, exact: &verifier{budgetLimit: 16384}}
}

func literalSet(b byte, nocase bool) (set byteSet) {
	set[b/64] |= uint64(1) << (b % 64)
	if nocase && (b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z') {
		b ^= 32
		set[b/64] |= uint64(1) << (b % 64)
	}
	return
}

func routingFeatures(seq *sequence, offset int) map[int]byteSet {
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

func intersects(a, b byteSet) bool {
	return a[0]&b[0]|a[1]&b[1]|a[2]&b[2]|a[3]&b[3] != 0
}
func complement(a byteSet) byteSet { return byteSet{^a[0], ^a[1], ^a[2], ^a[3]} }
func union(a, b byteSet) byteSet {
	return byteSet{a[0] | b[0], a[1] | b[1], a[2] | b[2], a[3] | b[3]}
}

var bitTests = func() []byteSet {
	tests := make([]byteSet, 8)
	for bit := range tests {
		for b := 0; b < 256; b++ {
			if b&(1<<bit) != 0 {
				tests[bit][b/64] |= uint64(1) << (b % 64)
			}
		}
	}
	return tests
}()

func (p *RoutedProgram) build(refs []routeRef, depth int, remaining *int) (uint32, bool) {
	if len(p.nodes) >= 2*len(p.base.postings)+1 {
		return 0, false
	}
	index := uint32(len(p.nodes))
	p.nodes = append(p.nodes, routeNode{})
	if len(refs) <= 8 {
		p.nodes[index] = routeNode{first: uint32(len(p.refs)), count: uint32(len(refs))}
		for _, ref := range refs {
			p.refs = append(p.refs, ref.id)
		}
		return index, true
	}
	if depth == 12 {
		return 0, false
	}
	positions := make([]int, 0, len(refs[0].features))
	for pos := range refs[0].features {
		positions = append(positions, pos)
	}
	sort.Ints(positions)
	bestMax, bestTotal := len(refs), len(refs)*2+1
	var best routeNode
	for _, pos := range positions {
		var allowed byteSet
		tests := append([]byteSet(nil), bitTests...)
		common := true
		for _, ref := range refs {
			set, present := ref.features[pos]
			if !present {
				common = false
				break
			}
			allowed = union(allowed, set)
			population := 0
			for _, word := range set {
				population += bits.OnesCount64(word)
			}
			if population > 1 && population < 256 && len(tests) < 24 {
				seen := false
				for _, test := range tests {
					seen = seen || test == set
				}
				if !seen {
					tests = append(tests, set)
				}
			}
		}
		if !common {
			continue
		}
		for _, test := range tests {
			yes, no := 0, 0
			inverse := complement(test)
			for _, ref := range refs {
				p.work++
				if p.work > 128_000_000 {
					return 0, false
				}
				set := ref.features[pos]
				if intersects(set, test) {
					yes++
				}
				if intersects(set, inverse) {
					no++
				}
			}
			largest, total := max(yes, no), yes+no
			if total > len(refs)*5/4 || largest >= len(refs) {
				continue
			}
			if largest < bestMax || largest == bestMax && total < bestTotal {
				bestMax, bestTotal = largest, total
				best = routeNode{offset: pos, allowed: allowed, test: test}
			}
		}
	}
	if bestMax == len(refs) || bestTotal > *remaining {
		return 0, false
	}
	*remaining -= bestTotal
	yes, no := make([]routeRef, 0, bestMax), make([]routeRef, 0, bestMax)
	for _, ref := range refs {
		set := ref.features[best.offset]
		if intersects(set, best.test) {
			yes = append(yes, ref)
		}
		if intersects(set, complement(best.test)) {
			no = append(no, ref)
		}
	}
	var ok bool
	best.yes, ok = p.build(yes, depth+1, remaining)
	if !ok {
		return 0, false
	}
	best.no, ok = p.build(no, depth+1, remaining)
	p.nodes[index] = best
	return index, ok
}

func (s *RoutedScanner) Match(data []byte) Decision {
	p := s.plan
	if p.base.constant {
		return Match
	}
	s.exact.remaining, s.exact.exhausted = s.exact.budgetLimit, false
	if len(p.base.lane.table) == 0 {
		return NoMatch
	}
	lane := &p.base.lane
	mask := uint64(len(lane.table) - 1)
	for pos := 0; pos <= len(data)-8; pos += 8 {
		word := readWord(data[pos:])
		index := hash(word, lane.shift)
		for lane.table[index].head != 0 {
			entry := lane.table[index]
			if entry.word == word {
				decision := s.bucket(data, pos, entry.head)
				if decision != NoMatch {
					return decision
				}
				break
			}
			index = (index + 1) & mask
		}
	}
	return NoMatch
}

func (s *RoutedScanner) bucket(data []byte, pos int, head uint32) Decision {
	p := s.plan
	root := p.roots[head]
	if root == 0 {
		for id := head; id != 0; id = p.base.postings[id].next {
			if result := s.verify(data, pos, id); result != NoMatch {
				return result
			}
		}
		return NoMatch
	}
	for {
		node := &p.nodes[root]
		if node.count != 0 {
			for _, id := range p.refs[node.first : node.first+node.count] {
				if result := s.verify(data, pos, id); result != NoMatch {
					return result
				}
			}
			return NoMatch
		}
		if !s.exact.spend(1) {
			return Unknown
		}
		if node.offset < -pos || node.offset >= len(data)-pos {
			return NoMatch
		}
		b := data[pos+node.offset]
		bit := uint64(1) << (b % 64)
		if node.allowed[b/64]&bit == 0 {
			return NoMatch
		}
		root = node.no
		if node.test[b/64]&bit != 0 {
			root = node.yes
		}
	}
}

func (s *RoutedScanner) verify(data []byte, pos int, id uint32) Decision {
	if !s.exact.spend(1) {
		return Unknown
	}
	ref := s.plan.base.postings[id]
	r := &s.plan.base.rules[ref.rule]
	seq := &r.all[r.trigger].alternatives[ref.alternative]
	if s.exact.verifySequence(data, seq, pos-ref.offset) && s.exact.verifyRule(data, r) {
		return Match
	}
	if s.exact.exhausted {
		return Unknown
	}
	return NoMatch
}
