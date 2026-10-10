package compiler

// teddyPrefilter defines the interface for high-throughput multi-literal
// SIMD prefiltering before invoking Aho-Corasick state transitions.
type teddyPrefilter interface {
	findCandidate(data []byte, from int) int
	findCandidateWithCancel(data []byte, from int, done <-chan struct{}) int
}

const (
	// maxTeddyPatterns is the maximum pattern count eligible for SIMD Teddy prefiltering.
	// Automata with more patterns fall back to standard Aho-Corasick DFA traversal.
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
	if len(strings) < minTeddyPatterns || len(strings) > maxTeddyPatterns {
		return nil
	}
	for _, info := range strings {
		if len(info.Data) == 0 {
			return nil
		}
	}
	return newTeddyPlatform(strings)
}
