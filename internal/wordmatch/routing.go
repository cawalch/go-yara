package wordmatch

import (
	"errors"
	"fmt"
	"math/bits"
)

var ErrIneligible = errors.New("portfolio unsuitable for witness routing")

const (
	maxRoutingWork     = 16_000_000
	maxRoutingFeatures = 1_000_000
)

type byteSet = [4]uint64
type routeNode struct {
	allowed, test byteSet
	yes, no       uint32
	first, count  uint32
	offset        int
}

// RoutedProgram is immutable and may be shared between scanners.
type RoutedProgram struct {
	base               *program
	roots              []uint32
	nodes              []routeNode
	refs               []uint32
	work, featureCount int
}

// RoutedScanner reuses scratch storage and is not safe for concurrent use.
type RoutedScanner struct {
	plan  *RoutedProgram
	exact *verifier
}
type routeRef struct {
	id       uint32
	features routeFeatures
}

type routeFeatures struct {
	start int
	sets  []byteSet
}

type buildState struct {
	depth     int
	remaining *int
	uniform   [8]uint64
	scratch   *groupScratch
}

func (f routeFeatures) at(pos int) (byteSet, bool) {
	if pos >= 8 {
		pos -= 8
	} else if pos >= 0 {
		return byteSet{}, false
	}
	index := pos - f.start
	if index < 0 || index >= len(f.sets) {
		return byteSet{}, false
	}
	return f.sets[index], true
}

func (p *RoutedProgram) spendBuild(n int) bool {
	if n > maxRoutingWork-p.work {
		return false
	}
	p.work += n
	return true
}

func CompileRouted(rules []Rule) (*RoutedProgram, error) {
	base, err := compile(rules)
	if err != nil {
		return nil, err
	}
	p := &RoutedProgram{base: base, roots: make([]uint32, len(base.postings)), nodes: []routeNode{{}}}
	scratch := &groupScratch{}
	for _, slot := range base.lane.table {
		var ids []uint32
		for id := slot.head; id != 0; id = base.postings[id].next {
			if !p.spendBuild(2) {
				return nil, ErrIneligible
			}
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
			features, ok := p.routingFeatures(seq, ref.offset)
			if !ok {
				return nil, ErrIneligible
			}
			refs[i] = routeRef{id: id, features: features}
		}
		remaining := len(ids) * 12
		root, ok := p.build(refs, buildState{remaining: &remaining, scratch: scratch})
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

// Mandatory context is contiguous; offsets 0..7 are omitted from the sorted slab.
func (p *RoutedProgram) routingFeatures(seq *sequence, offset int) (routeFeatures, bool) {
	if !p.spendBuild(2 * len(seq.terms)) {
		return routeFeatures{}, false
	}
	anchor := seq.terms[seq.anchor]
	before := mandatoryLength(seq.terms[:seq.anchor], true, max(0, 256-offset))
	after := mandatoryLength(seq.terms[seq.anchor+1:], false, max(0, 257-len(anchor.Literal)+offset))
	start := max(-offset, -256) - before
	count := min(len(anchor.Literal)-offset, 257) + after - 8 - start
	if count > maxRoutingFeatures-p.featureCount || !p.spendBuild(2*count+8) {
		return routeFeatures{}, false
	}
	p.featureCount += count
	features := routeFeatures{start: start, sets: make([]byteSet, count)}
	put := func(pos int, set byteSet) {
		if pos >= 8 {
			pos -= 8
		} else if pos >= 0 {
			return
		}
		features.sets[pos-start] = set
	}
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
	return features, true
}

func mandatoryLength(terms Sequence, backwards bool, limit int) int {
	length := 0
	for i := range terms {
		if length == limit {
			break
		}
		term := terms[i]
		if backwards {
			term = terms[len(terms)-1-i]
		}
		width := len(term.Literal)
		if width == 0 {
			width = term.Min
		}
		length += min(width, limit-length)
		if len(term.Literal) == 0 && term.Min != term.Max {
			break
		}
	}
	return length
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

func (p *RoutedProgram) build(refs []routeRef, state buildState) (uint32, bool) {
	if state.scratch == nil {
		state.scratch = &groupScratch{}
	}
	if !p.spendBuild(1) || len(p.nodes) >= 2*len(p.base.postings)+1 {
		return 0, false
	}
	index := uint32(len(p.nodes))
	p.nodes = append(p.nodes, routeNode{})
	if len(refs) <= 8 {
		if !p.spendBuild(len(refs)) {
			return 0, false
		}
		p.nodes[index] = routeNode{first: uint32(len(p.refs)), count: uint32(len(refs))}
		for _, ref := range refs {
			p.refs = append(p.refs, ref.id)
		}
		return index, true
	}
	if state.depth == 12 {
		return 0, false
	}
	bestMax, bestTotal := len(refs), len(refs)*2+1
	var best routeNode
	if !p.spendBuild(len(refs[0].features.sets)) {
		return 0, false
	}
	for i := range refs[0].features.sets {
		compressed := refs[0].features.start + i
		bit := uint64(1) << uint((compressed+256)%64)
		if state.uniform[(compressed+256)/64]&bit != 0 {
			continue
		}
		pos := compressed
		if pos >= 0 {
			pos += 8
		}
		if !p.spendBuild(len(refs) + len(state.scratch.groups) + 1) {
			return 0, false
		}
		groups, common := state.scratch.group(refs, pos)
		if !common {
			continue
		}
		if len(groups) == 1 {
			state.uniform[(compressed+256)/64] |= bit
			continue
		}
		var allowed byteSet
		var storage [24]byteSet
		copy(storage[:], bitTests)
		tests := storage[:8]
		if !p.spendBuild(len(groups)) {
			return 0, false
		}
		for _, group := range groups {
			set := group.set
			allowed = union(allowed, set)
			population := 0
			for _, word := range set {
				population += bits.OnesCount64(word)
			}
			if population > 1 && population < 256 && len(tests) < 24 {
				if !p.spendBuild(len(tests)) {
					return 0, false
				}
				seen := false
				for _, test := range tests {
					seen = seen || test == set
				}
				if !seen {
					tests = append(tests, set)
				}
			}
		}
		for _, test := range tests {
			yes, no := 0, 0
			inverse := complement(test)
			if !intersects(allowed, test) || !intersects(allowed, inverse) {
				continue
			}
			if !p.spendBuild(len(groups)) {
				return 0, false
			}
			for _, group := range groups {
				if intersects(group.set, test) {
					yes += group.count
				}
				if intersects(group.set, inverse) {
					no += group.count
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
	if bestMax == len(refs) || bestTotal > *state.remaining {
		return 0, false
	}
	*state.remaining -= bestTotal
	if !p.spendBuild(len(refs) + bestTotal) {
		return 0, false
	}
	yes, no := make([]routeRef, 0, bestMax), make([]routeRef, 0, bestMax)
	for _, ref := range refs {
		set, _ := ref.features.at(best.offset)
		if intersects(set, best.test) {
			yes = append(yes, ref)
		}
		if intersects(set, complement(best.test)) {
			no = append(no, ref)
		}
	}
	var ok bool
	state.depth++
	best.yes, ok = p.build(yes, state)
	if !ok {
		return 0, false
	}
	best.no, ok = p.build(no, state)
	p.nodes[index] = best
	return index, ok
}

type countedSet struct {
	set   byteSet
	count int
}

type groupScratch struct {
	groups  []countedSet
	indexes map[byteSet]int
}

func (s *groupScratch) group(refs []routeRef, pos int) ([]countedSet, bool) {
	for _, group := range s.groups {
		delete(s.indexes, group.set)
	}
	s.groups = s.groups[:0]
	first, ok := refs[0].features.at(pos)
	if !ok {
		return nil, false
	}
	s.groups = append(s.groups, countedSet{first, 1})
	for _, ref := range refs[1:] {
		set, present := ref.features.at(pos)
		if !present {
			return nil, false
		}
		if set == first {
			s.groups[0].count++
			continue
		}
		if s.indexes == nil {
			s.indexes = make(map[byteSet]int)
		}
		if index, found := s.indexes[set]; found {
			s.groups[index].count++
			continue
		}
		s.indexes[set] = len(s.groups)
		s.groups = append(s.groups, countedSet{set, 1})
	}
	return s.groups, true
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
