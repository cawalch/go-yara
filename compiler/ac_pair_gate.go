package compiler

import "github.com/cawalch/go-yara/regex"

type acPairGate struct {
	pairs      [1024]uint64
	lookbehind int
}

func (ac *ACAutomaton) buildPairGate() {
	if len(ac.strings) < 16 || len(ac.rootBytes) <= maxSparseRootTransitions {
		return
	}
	for _, s := range ac.strings {
		if len(s.Data) < 2 || s.Flags&regex.FlagsNoCase != 0 {
			return
		}
	}
	gate := &acPairGate{}
	for _, s := range ac.strings {
		best, score := 0, int(^uint(0)>>1)
		for i := 0; i+1 < len(s.Data); i++ {
			weight := acByteWeight(s.Data[i]) * acByteWeight(s.Data[i+1])
			if weight < score {
				best, score = i, weight
			}
		}
		pair := uint16(s.Data[best])<<8 | uint16(s.Data[best+1])
		gate.pairs[pair>>6] |= uint64(1) << (pair & 63)
		gate.lookbehind = max(gate.lookbehind, best)
	}
	ac.pairGate = gate
}

// Approximate ASCII frequencies rank mandatory pairs; they do not affect correctness.
func acByteWeight(b byte) int {
	lower := b | 32
	if lower >= 'a' && lower <= 'z' {
		n := [26]int{8, 1, 3, 4, 12, 2, 2, 6, 7, 1, 1, 4, 2, 7, 8, 2, 1, 6, 6, 9, 3, 1, 2, 1, 2, 1}[lower-'a']
		if b == lower {
			return n * 4
		}
		return n
	}
	if b >= '0' && b <= '9' {
		return 12
	}
	if b == ' ' {
		return 80
	}
	return 1
}

func (gate *acPairGate) firstPair(data []byte) int {
	for i := 1; i < len(data); i++ {
		pair := uint16(data[i-1])<<8 | uint16(data[i])
		if gate.pairs[pair>>6]&(uint64(1)<<(pair&63)) != 0 {
			return i - 1
		}
	}
	return -1
}

func (gate *acPairGate) start(data []byte) int {
	if pair := gate.firstPair(data); pair >= 0 {
		// Earlier starts would place their mandatory pair before this first hit.
		return max(0, pair-gate.lookbehind)
	}
	return -1
}

func (gate *acPairGate) startWithCancel(data []byte, done <-chan struct{}) int {
	for from := 0; from+1 < len(data); from += scanCancellationInterval {
		if scanCanceled(done) {
			return -1
		}
		end := min(from+scanCancellationInterval+1, len(data))
		if pair := gate.firstPair(data[from:end]); pair >= 0 {
			return max(0, from+pair-gate.lookbehind)
		}
	}
	return -1
}
