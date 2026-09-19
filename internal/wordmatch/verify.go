package wordmatch

import (
	"bytes"
	"math/bits"
)

func (s *verifier) spend(n int) bool {
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
func (s *verifier) verifyRule(data []byte, r *rule) bool {
	for i := range r.all {
		if i != r.trigger && !s.verifyPattern(data, &r.all[i]) {
			return false
		}
	}
	return true
}
func (s *verifier) verifyPattern(data []byte, p *pattern) bool {
	for i := range p.alternatives {
		seq := &p.alternatives[i]
		term := &seq.terms[seq.anchor]
		for start := 0; start <= len(data)-len(term.Literal); {
			pos := -1
			//nolint:nestif // retain the measured literal search hot path
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
func (s *verifier) verifySequence(data []byte, seq *sequence, start int) bool {
	anchor := &seq.terms[seq.anchor]
	if start < 0 || start > len(data)-len(anchor.Literal) {
		return false
	}
	if !s.spend(len(anchor.Literal)) || !equalLiteral(data[start:start+len(anchor.Literal)], anchor) {
		return false
	}
	return s.join(data, seq.terms[:seq.anchor], start, true) && s.join(data, seq.terms[seq.anchor+1:], start+len(anchor.Literal), false)
}

//nolint:revive // argument-limit: directional byte-run hot path
func (s *verifier) join(data []byte, terms Sequence, start int, backwards bool) bool {
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
				//nolint:nestif // byte-run and literal transitions share the position-set loop
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
