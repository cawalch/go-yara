package compiler

import "github.com/cawalch/go-yara/regex"

// teddyPrefilter defines the interface for high-throughput multi-literal
// SIMD prefiltering before invoking Aho-Corasick state transitions.
type teddyPrefilter interface {
	findCandidate(data []byte, from int) int
	findCandidateWithCancel(data []byte, from int, done <-chan struct{}) int
}

type corpusTeddyPrefilter struct{ teddyPrefilter }

// mayMatch is a reject-only tier. A candidate leaves exact scanning to the
// existing scalar path, avoiding a slower per-byte loop on dense prefixes.
func (t *corpusTeddyPrefilter) mayMatch(data []byte, done <-chan struct{}) bool {
	if done == nil {
		return t.windowMayMatch(data)
	}
	// Overlap by the longest prefix minus one so a prefix crossing a
	// cancellation checkpoint cannot disappear between windows.
	const window = 64 << 10
	for start := 0; start < len(data); start += window - 2 {
		if scanCanceled(done) {
			return false
		}
		if t.windowMayMatch(data[start:min(start+window, len(data))]) {
			return true
		}
	}
	return false
}

func (t *corpusTeddyPrefilter) windowMayMatch(data []byte) bool {
	if t.findCandidate(data, 0) >= 0 {
		return true
	}
	// Concrete kernels keep their padded tail on the stack. Passing that
	// temporary through findCandidate's interface would allocate per scan.
	if tail, ok := t.teddyPrefilter.(interface{ tailMayMatch([]byte) bool }); ok {
		return tail.tailMayMatch(data[max(0, len(data)-31):])
	}
	return true
}

const (
	// Bound the legacy pattern count and the ARM64 large-corpus prefix cover.
	maxTeddyPatterns = 64
	minTeddyPatterns = 2
)

// TeddySIMDSupported reports whether SIMD Teddy prefiltering is enabled in this build.
func TeddySIMDSupported() bool {
	return teddySIMDEnabled
}

// newTeddyPrefilter constructs a SIMD prefilter if the automaton strings
// are eligible for vectorized multi-literal prefiltering.
func newTeddyPrefilter(strings []acStringInfo) teddyPrefilter {
	if !teddySIMDEnabled || len(strings) < minTeddyPatterns {
		return nil
	}
	for _, info := range strings {
		if len(info.Data) == 0 {
			return nil
		}
	}
	return newTeddyPlatform(strings)
}

// teddyPrefixCover keeps a representative for every distinct prefix byte set.
// All prefixes use the shortest pattern's width, so a short pattern can never
// be lost behind a longer representative. Case variants of a nocase prefix
// share a key; exact and folded alphabetic bytes remain distinct.
func teddyPrefixCover(strings []acStringInfo) []acStringInfo {
	width := 3
	for _, info := range strings {
		width = min(width, len(info.Data))
	}
	if width == 0 {
		return nil
	}
	seen := make(map[[6]byte]struct{}, min(len(strings), maxTeddyPatterns))
	cover := make([]acStringInfo, 0, min(len(strings), maxTeddyPatterns))
	for _, info := range strings {
		var key [6]byte
		for i, b := range info.Data[:width] {
			other := b
			if info.Flags&regex.FlagsNoCase != 0 {
				other = flipASCIICase(b)
			}
			key[2*i], key[2*i+1] = min(b, other), max(b, other)
		}
		if _, exists := seen[key]; exists {
			continue
		}
		if len(cover) == maxTeddyPatterns {
			return nil // An incomplete cover could hide a valid match.
		}
		seen[key] = struct{}{}
		info.Data = info.Data[:width]
		cover = append(cover, info)
	}
	return cover
}
