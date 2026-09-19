package wordmatch

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
	shift int
	table []slot
}
type program struct {
	rules    []rule
	lane     lane
	postings []posting
	constant bool
}
type verifier struct {
	budgetLimit, remaining int
	exhausted              bool
	left, right            []uint64
}

func compile(rules []Rule) (*program, error) {
	if !boundedInput(rules) {
		return nil, fmt.Errorf("%w: input limit", ErrIneligible)
	}
	p := &program{postings: []posting{{}}}
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
			}
			if score > bestPattern {
				bestPattern = score
				cr.trigger = pi
			}
			cr.all = append(cr.all, cp)
		}
		p.rules = append(p.rules, cr)
	}
	l := &p.lane
	pending := make(map[uint64][]posting)
	for ri, r := range p.rules {
		for ai, seq := range r.all[r.trigger].alternatives {
			literal := seq.terms[seq.anchor].Literal
			if len(literal) < 15 {
				return nil, fmt.Errorf("%w: short witness", ErrIneligible)
			}
			window := len(literal) - 15
			for phase := 0; phase < 8; phase++ {
				offset := window + phase
				word := readWord(literal[offset:])
				pending[word] = append(pending[word], posting{rule: ri, alternative: ai, offset: offset})
			}
		}
	}
	if len(pending) == 0 {
		return p, nil
	}
	size := 1
	for size < len(pending)*2 {
		size *= 2
	}
	l.table = make([]slot, size)
	l.shift = 64 - bits.TrailingZeros(uint(size))
	probes := 1 << 20
	for word, refs := range pending {
		index := hash(word, l.shift)
		for l.table[index].head != 0 {
			if probes == 0 {
				return nil, fmt.Errorf("%w: table probe limit", ErrIneligible)
			}
			probes--
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
	return p, nil
}

// Bound work and owned input before cloning or building hash tables.
func boundedInput(rules []Rule) bool {
	if len(rules) > 4096 {
		return false
	}
	patterns, sequences, terms, literalBytes := 8192, 16384, 65536, 1<<20
	for _, r := range rules {
		if len(r.All) > patterns {
			return false
		}
		patterns -= len(r.All)
		for _, pattern := range r.All {
			if len(pattern.Any) > sequences {
				return false
			}
			sequences -= len(pattern.Any)
			for _, sequence := range pattern.Any {
				if len(sequence) > terms {
					return false
				}
				terms -= len(sequence)
				for _, term := range sequence {
					if len(term.Literal) > literalBytes {
						return false
					}
					literalBytes -= len(term.Literal)
				}
			}
		}
	}
	return true
}
func hash(word uint64, shift int) uint64 {
	return ((word ^ (word >> 33)) * 0x9e3779b185ebca87) >> shift
}
func readWord(data []byte) uint64 {
	return binary.LittleEndian.Uint64(data) | 0x2020202020202020
}
