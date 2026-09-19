package witness

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/bits"
)

type sequence struct {
	terms  Sequence
	anchor int
}
type pattern struct{ alternatives []sequence }
type rule struct {
	all     []pattern
	trigger int
}
type posting struct {
	rule, alternative, offset int
	next                      uint32
}
type slot struct {
	word uint64
	head uint32
}
type lane struct {
	width, shift int
	table        []slot
	pending      map[uint64][]posting
}
type Program struct {
	rules    []rule
	lanes    []lane
	postings []posting
	constant bool
	stats    Stats
}
type Scanner struct {
	program                *Program
	budgetLimit, remaining int
	exhausted              bool
	left, right            []uint64
}

func Compile(rules []Rule) (*Program, error) {
	p := &Program{postings: []posting{{}}}
	frequencies := make(map[string]int)
	for _, r := range rules {
		for _, pat := range r.All {
			for _, seq := range pat.Any {
				for _, term := range seq {
					if len(term.Literal) > 0 {
						frequencies[string(term.Literal)]++
					}
				}
			}
		}
	}
	for ri, r := range rules {
		if len(r.All) == 0 {
			p.constant = true
			continue
		}
		cr := rule{trigger: 0}
		bestPattern := -1
		for pi, pat := range r.All {
			if len(pat.Any) == 0 {
				return nil, fmt.Errorf("rule %d: empty alternatives", ri)
			}
			cp := pattern{}
			score := int(^uint(0) >> 1)
			for _, seq := range pat.Any {
				if len(seq) == 0 || len(seq) > 64 {
					return nil, fmt.Errorf("rule %d: sequence needs 1..64 terms", ri)
				}
				cs := sequence{anchor: -1, terms: make(Sequence, len(seq))}
				best := -1
				for ti, t := range seq {
					if len(t.Literal) > 0 {
						t.Literal = bytes.Clone(t.Literal)
						// Prefer long, less-shared witnesses; the shortest alternative bounds a pattern's selectivity.
						weight := len(t.Literal) * 256 / frequencies[string(t.Literal)]
						if weight > best {
							best = weight
							cs.anchor = ti
						}
					} else if t.Min < 0 || t.Max < t.Min || (t.Max > 0 && t.Set == [4]uint64{}) {
						return nil, fmt.Errorf("rule %d: invalid byte run", ri)
					}
					cs.terms[ti] = t
				}
				if cs.anchor < 0 {
					return nil, fmt.Errorf("rule %d: sequence has no literal witness", ri)
				}
				score = min(score, best)
				cp.alternatives = append(cp.alternatives, cs)
				p.stats.Sequences++
			}
			if score > bestPattern {
				bestPattern = score
				cr.trigger = pi
			}
			cr.all = append(cr.all, cp)
		}
		p.rules = append(p.rules, cr)
	}
	for _, width := range []int{8, 4, 2, 1} {
		p.lanes = append(p.lanes, lane{width: width, pending: make(map[uint64][]posting)})
	}
	for ri, r := range p.rules {
		for ai, seq := range r.all[r.trigger].alternatives {
			literal := seq.terms[seq.anchor].Literal
			for li := range p.lanes {
				l := &p.lanes[li]
				if len(literal) < 2*l.width-1 {
					continue
				}
				window := len(literal) - (2*l.width - 1)
				for phase := 0; phase < l.width; phase++ {
					offset := window + phase
					word := readWord(literal[offset:], l.width)
					l.pending[word] = append(l.pending[word], posting{rule: ri, alternative: ai, offset: offset})
					p.stats.Witnesses++
				}
				break
			}
		}
	}
	active := p.lanes[:0]
	for _, l := range p.lanes {
		if len(l.pending) == 0 {
			continue
		}
		size := 1
		for size < len(l.pending)*2 {
			size *= 2
		}
		l.table = make([]slot, size)
		l.shift = 64 - bits.TrailingZeros(uint(size))
		p.stats.Signatures += len(l.pending)
		p.stats.Slots += size
		p.stats.TableBytes += size * 16
		for word, refs := range l.pending {
			index := hash(word, l.shift)
			for l.table[index].head != 0 {
				index = (index + 1) & uint64(size-1)
			}
			head := uint32(0)
			for _, ref := range refs {
				ref.next = head
				p.postings = append(p.postings, ref)
				head = uint32(len(p.postings) - 1)
			}
			l.table[index] = slot{word: word, head: head}
		}
		l.pending = nil
		active = append(active, l)
	}
	p.lanes = active
	p.stats.Rules = len(rules)
	return p, nil
}
func (p *Program) Stats() Stats         { return p.stats }
func (p *Program) NewScanner() *Scanner { return &Scanner{program: p, budgetLimit: 16384} }
func hash(word uint64, shift int) uint64 {
	return ((word ^ (word >> 33)) * 0x9e3779b185ebca87) >> shift
}
func readWord(data []byte, width int) uint64 {
	switch width {
	case 8:
		return binary.LittleEndian.Uint64(data) | 0x2020202020202020
	case 4:
		return uint64(binary.LittleEndian.Uint32(data) | 0x20202020)
	case 2:
		return uint64(binary.LittleEndian.Uint16(data) | 0x2020)
	default:
		return uint64(data[0] | 0x20)
	}
}
func (s *Scanner) Match(data []byte) Decision {
	if s.program.constant {
		return Match
	}
	s.remaining = s.budgetLimit
	s.exhausted = false
	for li := range s.program.lanes {
		l := &s.program.lanes[li]
		mask := uint64(len(l.table) - 1)
		for pos := 0; pos <= len(data)-l.width; pos += l.width {
			word := readWord(data[pos:], l.width)
			index := hash(word, l.shift)
			for {
				entry := l.table[index]
				if entry.head == 0 {
					break
				}
				if entry.word == word {
					for head := entry.head; head != 0; {
						if !s.spend(1) {
							return Unknown
						}
						ref := s.program.postings[head]
						r := &s.program.rules[ref.rule]
						seq := &r.all[r.trigger].alternatives[ref.alternative]
						if s.verifySequence(data, seq, pos-ref.offset) && s.verifyRule(data, r) {
							return Match
						}
						if s.exhausted {
							return Unknown
						}
						head = ref.next
					}
					break
				}
				index = (index + 1) & mask
			}
		}
	}
	return NoMatch
}
func (s *Scanner) spend(n int) bool {
	if s.remaining < n {
		s.exhausted = true
		return false
	}
	s.remaining -= n
	return true
}
func equalLiteral(data []byte, t *Term) bool {
	if !t.NoCase {
		return bytes.Equal(data, t.Literal)
	}
	for i, b := range data {
		a := t.Literal[i]
		if b >= 'A' && b <= 'Z' {
			b += 32
		}
		if a >= 'A' && a <= 'Z' {
			a += 32
		}
		if a != b {
			return false
		}
	}
	return true
}
func (s *Scanner) verifyRule(data []byte, r *rule) bool {
	for i := range r.all {
		if i != r.trigger && !s.verifyPattern(data, &r.all[i]) {
			return false
		}
	}
	return true
}
func (s *Scanner) verifyPattern(data []byte, p *pattern) bool {
	for i := range p.alternatives {
		seq := &p.alternatives[i]
		term := &seq.terms[seq.anchor]
		for start := 0; start <= len(data)-len(term.Literal); {
			pos := -1
			if term.NoCase {
				for j := start; j <= len(data)-len(term.Literal); j++ {
					if !s.spend(1) {
						return false
					}
					if equalLiteral(data[j:j+len(term.Literal)], term) {
						pos = j
						break
					}
				}
			} else {
				if !s.spend(1) {
					return false
				}
				if n := bytes.Index(data[start:], term.Literal); n >= 0 {
					pos = start + n
				}
			}
			if pos < 0 {
				break
			}
			if s.verifySequence(data, seq, pos) {
				return true
			}
			if s.exhausted {
				return false
			}
			start = pos + 1
		}
	}
	return false
}
func (s *Scanner) verifySequence(data []byte, seq *sequence, start int) bool {
	anchor := &seq.terms[seq.anchor]
	if start < 0 || start > len(data)-len(anchor.Literal) {
		return false
	}
	if !s.spend(len(anchor.Literal)) || !equalLiteral(data[start:start+len(anchor.Literal)], anchor) {
		return false
	}
	return s.join(data, seq.terms[:seq.anchor], start, true) && s.join(data, seq.terms[seq.anchor+1:], start+len(anchor.Literal), false)
}
func (s *Scanner) join(data []byte, terms Sequence, start int, backwards bool) bool {
	if len(terms) == 0 {
		return true
	}
	words := (len(data) + 64) / 64
	if cap(s.left) < words {
		s.left = make([]uint64, words)
		s.right = make([]uint64, words)
	}
	current, next := s.left[:words], s.right[:words]
	clear(current)
	current[start/64] |= uint64(1) << (start % 64)
	for i := range terms {
		t := &terms[i]
		if backwards {
			t = &terms[len(terms)-1-i]
		}
		clear(next)
		found := false
		for wi, word := range current {
			for word != 0 {
				pos := wi*64 + bits.TrailingZeros64(word)
				word &= word - 1
				if !s.spend(1) {
					return false
				}
				if len(t.Literal) > 0 {
					begin, end := pos, pos+len(t.Literal)
					if backwards {
						begin, end = pos-len(t.Literal), pos
					}
					if begin >= 0 && end <= len(data) && s.spend(len(t.Literal)) && equalLiteral(data[begin:end], t) {
						target := end
						if backwards {
							target = begin
						}
						next[target/64] |= uint64(1) << (target % 64)
						found = true
					}
				} else {
					limit := min(t.Max, len(data)-pos)
					if backwards {
						limit = min(t.Max, pos)
					}
					run := 0
					for run < limit {
						if !s.spend(1) {
							return false
						}
						offset := pos + run
						if backwards {
							offset = pos - run - 1
						}
						b := data[offset]
						if t.Set[b/64]&(uint64(1)<<(b%64)) == 0 {
							break
						}
						run++
					}
					if run >= t.Min {
						lo, hi := pos+t.Min, pos+run
						if backwards {
							lo, hi = pos-run, pos-t.Min
						}
						if !s.spend((hi-lo)/64 + 1) {
							return false
						}
						setRange(next, lo, hi)
						found = true
					}
				}
				if s.exhausted {
					return false
				}
			}
		}
		if !found {
			return false
		}
		current, next = next, current
	}
	return true
}
func setRange(set []uint64, lo, hi int) {
	first, last := lo/64, hi/64
	if first == last {
		set[first] |= (^uint64(0) << uint(lo%64)) & (^uint64(0) >> uint(63-hi%64))
		return
	}
	set[first] |= ^uint64(0) << uint(lo%64)
	for i := first + 1; i < last; i++ {
		set[i] = ^uint64(0)
	}
	set[last] |= ^uint64(0) >> uint(63-hi%64)
}
